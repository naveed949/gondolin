const std = @import("std");
const sandboxd = @import("sandboxd");
const protocol = sandboxd.protocol;
const posix = sandboxd.posix;
const file_requests = @import("file_requests.zig");
const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("fcntl.h");
    @cInclude("limits.h");
    @cInclude("linux/landlock.h");
    @cInclude("pty.h");
    @cInclude("sched.h");
    @cInclude("stdlib.h");
    @cInclude("sys/prctl.h");
    @cInclude("sys/mount.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/syscall.h");
    @cInclude("unistd.h");
    @cInclude("sys/ioctl.h");
});

const log = std.log.scoped(.sandboxd);
pub const std_options: std.Options = .{
    .log_level = .info,
};

/// ReleaseSmall marker inspected by the image manifest builder
pub export var descendant_denial_feature_marker: [43]u8 =
    "gondolin-feature:exec.descendants-denied/v1".*;

test {
    _ = file_requests;
}

fn syncIo() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn milliTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return @as(i64, @intCast(ts.sec)) * 1000 + @as(i64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}

/// max buffered stdin per exec session in `bytes`
const max_queued_stdin_bytes: usize = 4 * 1024 * 1024;

const Termination = struct {
    exit_code: i32,
    signal: ?i32,
};

const StdinChunk = struct {
    data: []u8,
    eof: bool,
};

const ExecControlMessage = union(enum) {
    stdin: StdinChunk,
    resize: protocol.PtyResize,
    window: protocol.ExecWindow,
};

const OwnedExecRequest = struct {
    id: u32,
    cmd: []u8,
    argv: []const []const u8,
    env: []const []const u8,
    clear_env: bool,
    allowed_executables: []const []const u8,
    allowed_writable_paths: []const []const u8,
    deny_descendants: bool,
    resource_limits: ?protocol.ExecResourceLimits,
    isolate_ipc: bool,
    isolate_devices: bool,
    cwd: ?[]u8,
    stdin: bool,
    pty: bool,
    stdout_window: u32,
    stderr_window: u32,

    fn deinit(self: *OwnedExecRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.cmd);
        for (self.argv) |arg| allocator.free(arg);
        allocator.free(self.argv);
        for (self.env) |entry| allocator.free(entry);
        allocator.free(self.env);
        for (self.allowed_executables) |entry| allocator.free(entry);
        allocator.free(self.allowed_executables);
        for (self.allowed_writable_paths) |entry| allocator.free(entry);
        allocator.free(self.allowed_writable_paths);
        if (self.cwd) |cwd| allocator.free(cwd);
    }
};

const VirtioTx = struct {
    fd: posix.fd_t,
    mutex: std.Io.Mutex = .init,

    pub fn sendPayload(self: *VirtioTx, payload: []const u8) !void {
        self.mutex.lockUncancelable(syncIo());
        defer self.mutex.unlock(syncIo());
        try protocol.writeFrame(self.fd, payload);
    }

    fn sendError(self: *VirtioTx, allocator: std.mem.Allocator, id: u32, code: []const u8, message: []const u8) !void {
        self.mutex.lockUncancelable(syncIo());
        defer self.mutex.unlock(syncIo());
        try protocol.sendError(allocator, self.fd, id, code, message);
    }

    fn sendStdinWindow(self: *VirtioTx, allocator: std.mem.Allocator, id: u32, stdin: u32) !void {
        self.mutex.lockUncancelable(syncIo());
        defer self.mutex.unlock(syncIo());
        try protocol.sendStdinWindow(allocator, self.fd, id, stdin);
    }

    fn sendVfsReady(self: *VirtioTx, allocator: std.mem.Allocator) !void {
        self.mutex.lockUncancelable(syncIo());
        defer self.mutex.unlock(syncIo());
        try protocol.sendVfsReady(allocator, self.fd);
    }

    fn sendVfsError(self: *VirtioTx, allocator: std.mem.Allocator, message: []const u8) !void {
        self.mutex.lockUncancelable(syncIo());
        defer self.mutex.unlock(syncIo());
        try protocol.sendVfsError(allocator, self.fd, message);
    }
};

const ExecSession = struct {
    allocator: std.mem.Allocator,
    tx: *VirtioTx,
    req: OwnedExecRequest,
    mutex: std.Io.Mutex = .init,
    control_cv: std.Io.Condition = .init,
    controls: std.ArrayList(ExecControlMessage) = .empty,
    /// stdin bytes buffered in the control queue in `bytes`
    stdin_queued_bytes: usize = 0,
    /// stdin credits granted to the host but not yet received in `bytes`
    stdin_credit_inflight: usize = 0,
    done: bool = false,
    thread: ?std.Thread = null,
    wake_read_fd: ?posix.fd_t = null,
    wake_write_fd: ?posix.fd_t = null,

    fn init(allocator: std.mem.Allocator, tx: *VirtioTx, req: OwnedExecRequest) !ExecSession {
        const wake_pipe = try posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });

        return .{
            .allocator = allocator,
            .tx = tx,
            .req = req,
            .controls = .empty,
            .wake_read_fd = wake_pipe[0],
            .wake_write_fd = wake_pipe[1],
        };
    }

    fn deinit(self: *ExecSession) void {
        if (self.wake_read_fd) |fd| {
            posix.close(fd);
            self.wake_read_fd = null;
        }
        if (self.wake_write_fd) |fd| {
            posix.close(fd);
            self.wake_write_fd = null;
        }

        for (self.controls.items) |msg| {
            switch (msg) {
                .stdin => |chunk| self.allocator.free(chunk.data),
                else => {},
            }
        }
        self.controls.deinit(self.allocator);
        self.req.deinit(self.allocator);
    }
};

fn cloneExecRequest(allocator: std.mem.Allocator, req: protocol.ExecRequest) !OwnedExecRequest {
    var argv = try allocator.alloc([]const u8, req.argv.len);
    var argv_len: usize = 0;
    errdefer {
        for (argv[0..argv_len]) |arg| allocator.free(arg);
        allocator.free(argv);
    }
    for (req.argv) |arg| {
        argv[argv_len] = try allocator.dupe(u8, arg);
        argv_len += 1;
    }

    var env = try allocator.alloc([]const u8, req.env.len);
    var env_len: usize = 0;
    errdefer {
        for (env[0..env_len]) |entry| allocator.free(entry);
        allocator.free(env);
    }
    for (req.env) |entry| {
        env[env_len] = try allocator.dupe(u8, entry);
        env_len += 1;
    }

    var allowed_executables = try allocator.alloc([]const u8, req.allowed_executables.len);
    var allowed_len: usize = 0;
    errdefer {
        for (allowed_executables[0..allowed_len]) |entry| allocator.free(entry);
        allocator.free(allowed_executables);
    }
    for (req.allowed_executables) |entry| {
        allowed_executables[allowed_len] = try allocator.dupe(u8, entry);
        allowed_len += 1;
    }

    var allowed_writable_paths = try allocator.alloc([]const u8, req.allowed_writable_paths.len);
    var writable_len: usize = 0;
    errdefer {
        for (allowed_writable_paths[0..writable_len]) |entry| allocator.free(entry);
        allocator.free(allowed_writable_paths);
    }
    for (req.allowed_writable_paths) |entry| {
        allowed_writable_paths[writable_len] = try allocator.dupe(u8, entry);
        writable_len += 1;
    }

    const cwd = if (req.cwd) |value| try allocator.dupe(u8, value) else null;
    errdefer if (cwd) |value| allocator.free(value);

    const cmd = try allocator.dupe(u8, req.cmd);
    errdefer allocator.free(cmd);

    return .{
        .id = req.id,
        .cmd = cmd,
        .argv = argv,
        .env = env,
        .clear_env = req.clear_env,
        .allowed_executables = allowed_executables,
        .allowed_writable_paths = allowed_writable_paths,
        .deny_descendants = req.deny_descendants,
        .resource_limits = req.resource_limits,
        .isolate_ipc = req.isolate_ipc,
        .isolate_devices = req.isolate_devices,
        .cwd = cwd,
        .stdin = req.stdin,
        .pty = req.pty,
        .stdout_window = req.stdout_window,
        .stderr_window = req.stderr_window,
    };
}

fn markSessionDone(session: *ExecSession) void {
    session.mutex.lockUncancelable(syncIo());
    session.done = true;
    session.control_cv.broadcast(syncIo());
    session.mutex.unlock(syncIo());
}

fn notifyExecWorker(session: *ExecSession) void {
    const fd = session.wake_write_fd orelse return;
    const byte: [1]u8 = .{1};

    while (true) {
        _ = posix.write(fd, &byte) catch |err| switch (err) {
            error.WouldBlock, error.BrokenPipe => return,
            else => return,
        };
        return;
    }
}

fn drainExecWakeFd(fd: posix.fd_t) void {
    var buffer: [64]u8 = undefined;

    while (true) {
        const n = posix.read(fd, &buffer) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return,
        };

        if (n == 0) return;
    }
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    log.info("starting ({s})", .{descendant_denial_feature_marker});

    const virtio_fd = try openVirtioPort();
    defer posix.close(virtio_fd);

    var tx = VirtioTx{ .fd = virtio_fd };

    log.info("opened virtio port", .{});

    sendVfsStatus(allocator, &tx) catch |err| {
        log.err("failed to send vfs status: {s}", .{@errorName(err)});
    };

    var exec_sessions = std.AutoHashMap(u32, *ExecSession).init(allocator);
    defer cleanupAllExecSessions(allocator, &exec_sessions);

    var waiting_for_reconnect = false;

    while (true) {
        cleanupFinishedExecSessions(allocator, &exec_sessions);

        const frame = protocol.readFrame(allocator, virtio_fd) catch |err| {
            if (err == error.EndOfStream) {
                if (!waiting_for_reconnect) {
                    log.info("virtio port closed, waiting for reconnect", .{});
                    waiting_for_reconnect = true;
                }
                waitForVirtioData(virtio_fd);
                continue;
            }
            log.err("failed to read frame: {s}", .{@errorName(err)});
            continue;
        };
        defer allocator.free(frame);

        waiting_for_reconnect = false;
        log.info("received frame ({} bytes)", .{frame.len});

        const exec_req = protocol.decodeExecRequest(allocator, frame) catch |err| switch (err) {
            protocol.ProtocolError.UnexpectedType => null,
            else => {
                log.err("invalid exec_request: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, 0, "invalid_request", "invalid exec_request") catch {};
                continue;
            },
        };

        if (exec_req) |req| {
            log.info("exec request id={} cmd={s}", .{ req.id, req.cmd });
            defer {
                allocator.free(req.argv);
                allocator.free(req.env);
                allocator.free(req.allowed_executables);
                allocator.free(req.allowed_writable_paths);
            }

            startExecSession(&exec_sessions, &tx, req) catch |err| {
                log.err("exec start failed: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, req.id, "exec_failed", "failed to execute") catch {};
            };
            continue;
        }

        const routed_input = protocol.decodeRoutedInputMessage(allocator, frame) catch |err| switch (err) {
            protocol.ProtocolError.UnexpectedType => null,
            else => {
                log.err("invalid exec input: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, 0, "invalid_request", "invalid exec input") catch {};
                continue;
            },
        };

        if (routed_input) |routed| {
            if (exec_sessions.get(routed.id)) |session| {
                enqueueExecInput(session, routed.message) catch |err| switch (err) {
                    error.StdinBackpressure => {
                        _ = tx.sendError(allocator, routed.id, "stdin_backpressure", "stdin queue full") catch {};
                    },
                    error.StdinChunkTooLarge => {
                        _ = tx.sendError(allocator, routed.id, "stdin_chunk_too_large", "stdin chunk exceeds queue limit") catch {};
                    },
                    else => {
                        log.err("failed to queue exec input id={}: {s}", .{ routed.id, @errorName(err) });
                        _ = tx.sendError(allocator, routed.id, "exec_failed", "failed to queue exec input") catch {};
                    },
                };
            } else {
                _ = tx.sendError(allocator, routed.id, "unknown_id", "request id not found") catch {};
            }
            continue;
        }

        const file_read_req = protocol.decodeFileReadRequest(allocator, frame) catch |err| switch (err) {
            protocol.ProtocolError.UnexpectedType => null,
            else => {
                log.err("invalid file_read_request: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, 0, "invalid_request", "invalid file_read_request") catch {};
                continue;
            },
        };

        if (file_read_req) |req| {
            file_requests.handleFileRead(allocator, &tx, "/", req) catch |err| {
                log.err("file read failed: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, req.id, "file_read_failed", @errorName(err)) catch {};
            };
            continue;
        }

        const file_write_req = protocol.decodeFileWriteRequest(allocator, frame) catch |err| switch (err) {
            protocol.ProtocolError.UnexpectedType => null,
            else => {
                log.err("invalid file_write_request: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, 0, "invalid_request", "invalid file_write_request") catch {};
                continue;
            },
        };

        if (file_write_req) |req| {
            file_requests.handleFileWrite(allocator, virtio_fd, &tx, "/", req) catch |err| {
                log.err("file write failed: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, req.id, "file_write_failed", @errorName(err)) catch {};
            };
            continue;
        }

        const file_delete_req = protocol.decodeFileDeleteRequest(allocator, frame) catch |err| switch (err) {
            protocol.ProtocolError.UnexpectedType => null,
            else => {
                log.err("invalid file_delete_request: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, 0, "invalid_request", "invalid file_delete_request") catch {};
                continue;
            },
        };

        if (file_delete_req) |req| {
            file_requests.handleFileDelete(allocator, &tx, "/", req) catch |err| {
                log.err("file delete failed: {s}", .{@errorName(err)});
                _ = tx.sendError(allocator, req.id, "file_delete_failed", @errorName(err)) catch {};
            };
            continue;
        }

        _ = tx.sendError(allocator, 0, "invalid_request", "unsupported request type") catch {};
    }
}

fn startExecSession(
    sessions: *std.AutoHashMap(u32, *ExecSession),
    tx: *VirtioTx,
    req: protocol.ExecRequest,
) !void {
    if (sessions.get(req.id)) |existing| {
        existing.mutex.lockUncancelable(syncIo());
        const done = existing.done;
        existing.mutex.unlock(syncIo());

        if (!done) {
            return error.DuplicateRequestId;
        }

        if (existing.thread) |thread| {
            thread.join();
            existing.thread = null;
        }
        existing.deinit();
        const sess_alloc = existing.allocator;
        _ = sessions.remove(req.id);
        sess_alloc.destroy(existing);
    }

    const allocator = std.heap.page_allocator;
    var owned_opt: ?OwnedExecRequest = try cloneExecRequest(allocator, req);
    errdefer if (owned_opt) |owned| {
        var temp = owned;
        temp.deinit(allocator);
    };

    const session = try allocator.create(ExecSession);
    errdefer allocator.destroy(session);

    session.* = try ExecSession.init(allocator, tx, owned_opt.?);
    owned_opt = null;
    errdefer session.deinit();

    try sessions.put(req.id, session);
    errdefer _ = sessions.remove(req.id);

    const thread = try std.Thread.spawn(.{}, execWorker, .{session});
    session.thread = thread;
}

fn enqueueExecInput(session: *ExecSession, input: protocol.InputMessage) !void {
    session.mutex.lockUncancelable(syncIo());
    defer session.mutex.unlock(syncIo());

    if (session.done) return;

    switch (input) {
        .stdin => |chunk| {
            if (chunk.data.len > max_queued_stdin_bytes) {
                return error.StdinChunkTooLarge;
            }

            if (session.stdin_queued_bytes + chunk.data.len > max_queued_stdin_bytes) {
                return error.StdinBackpressure;
            }

            // Flow control: the host must not send more stdin bytes than the guest
            // has advertised via stdin_window.
            if (chunk.data.len > session.stdin_credit_inflight) {
                return error.StdinBackpressure;
            }
            session.stdin_credit_inflight -= chunk.data.len;

            const copied = try session.allocator.alloc(u8, chunk.data.len);
            errdefer session.allocator.free(copied);
            std.mem.copyForwards(u8, copied, chunk.data);
            try session.controls.append(session.allocator, .{ .stdin = .{ .data = copied, .eof = chunk.eof } });
            session.stdin_queued_bytes += copied.len;
        },
        .resize => |size| {
            try session.controls.append(session.allocator, .{ .resize = size });
        },
        .window => |window| {
            try session.controls.append(session.allocator, .{ .window = window });
        },
    }

    session.control_cv.signal(syncIo());
    notifyExecWorker(session);
}

fn cleanupFinishedExecSessions(
    allocator: std.mem.Allocator,
    sessions: *std.AutoHashMap(u32, *ExecSession),
) void {
    var done_ids = std.ArrayList(u32).empty;
    defer done_ids.deinit(allocator);

    var it = sessions.iterator();
    while (it.next()) |entry| {
        const id = entry.key_ptr.*;
        const session = entry.value_ptr.*;

        session.mutex.lockUncancelable(syncIo());
        const done = session.done;
        session.mutex.unlock(syncIo());

        if (done) {
            done_ids.append(allocator, id) catch return;
        }
    }

    for (done_ids.items) |id| {
        const session = sessions.get(id) orelse continue;
        if (session.thread) |thread| {
            thread.join();
            session.thread = null;
        }
        session.deinit();
        const sess_alloc = session.allocator;
        _ = sessions.remove(id);
        sess_alloc.destroy(session);
    }
}

fn cleanupAllExecSessions(
    allocator: std.mem.Allocator,
    sessions: *std.AutoHashMap(u32, *ExecSession),
) void {
    cleanupFinishedExecSessions(allocator, sessions);

    var ids = std.ArrayList(u32).empty;
    defer ids.deinit(allocator);

    var it = sessions.iterator();
    while (it.next()) |entry| {
        ids.append(allocator, entry.key_ptr.*) catch break;
    }

    for (ids.items) |id| {
        const session = sessions.get(id) orelse continue;
        if (session.thread) |thread| {
            thread.join();
            session.thread = null;
        }
        session.deinit();
        const sess_alloc = session.allocator;
        _ = sessions.remove(id);
        sess_alloc.destroy(session);
    }

    sessions.deinit();
}

fn sendVfsStatus(allocator: std.mem.Allocator, tx: *VirtioTx) !void {
    if (try readVfsErrorMessage(allocator)) |message| {
        defer allocator.free(message);
        const trimmed = std.mem.trim(u8, message, " \r\n\t");
        const detail = if (trimmed.len > 0) trimmed else "vfs mount not ready";
        try tx.sendVfsError(allocator, detail);
        return;
    }

    try tx.sendVfsReady(allocator);
}

fn readVfsErrorMessage(allocator: std.mem.Allocator) !?[]u8 {
    const fd = posix.open("/run/sandboxfs.failed", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer posix.close(fd);

    var out = std.ArrayList(u8).empty;
    var buffer: [512]u8 = undefined;
    while (out.items.len < 4096) {
        const max_read = @min(buffer.len, 4096 - out.items.len);
        const n = try posix.read(fd, buffer[0..max_read]);
        if (n == 0) break;
        try out.appendSlice(allocator, buffer[0..n]);
    }
    return try out.toOwnedSlice(allocator);
}

fn tryOpenVirtioPath(path: []const u8) !?posix.fd_t {
    const fd = posix.open(path, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0) catch |err| switch (err) {
        error.FileNotFound, error.NoDevice => return null,
        else => return err,
    };

    const original_flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    const nonblock_flag: c_int = @bitCast(posix.O{ .NONBLOCK = true });
    _ = try posix.fcntl(fd, posix.F.SETFL, original_flags & ~nonblock_flag);

    return fd;
}

fn scanVirtioPorts() !?posix.fd_t {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    var dev_dir = std.Io.Dir.openDirAbsolute(io, "/dev", .{ .iterate = true }) catch return null;
    defer dev_dir.close(io);

    var it = dev_dir.iterate();
    var path_buf: [64]u8 = undefined;
    while (try it.next(io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "vport")) continue;
        if (!virtioPortMatches(entry.name, "virtio-port")) continue;
        const path = try std.fmt.bufPrint(&path_buf, "/dev/{s}", .{entry.name});
        if (try tryOpenVirtioPath(path)) |fd| return fd;
    }

    return null;
}

fn virtioPortMatches(port_name: []const u8, expected: []const u8) bool {
    var path_buf: [128]u8 = undefined;
    const sys_path = std.fmt.bufPrint(&path_buf, "/sys/class/virtio-ports/{s}/name", .{port_name}) catch return false;
    const fd = posix.open(sys_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return false;
    defer posix.close(fd);

    var name_buf: [64]u8 = undefined;
    const size = posix.read(fd, &name_buf) catch return false;
    const trimmed = std.mem.trim(u8, name_buf[0..size], " \r\n\t");
    return std.mem.eql(u8, trimmed, expected);
}

fn openVirtioPort() !posix.fd_t {
    const paths = [_][]const u8{
        "/dev/virtio-ports/virtio-port",
    };

    var warned = false;

    while (true) {
        for (paths) |path| {
            if (try tryOpenVirtioPath(path)) |fd| return fd;
        }

        if (try scanVirtioPorts()) |fd| return fd;

        if (!warned) {
            log.info("waiting for virtio port", .{});
            warned = true;
        }

        posix.nanosleep(0, 100 * std.time.ns_per_ms);
    }
}

fn waitForVirtioData(virtio_fd: posix.fd_t) void {
    while (true) {
        var pollfds: [1]posix.pollfd = .{.{
            .fd = virtio_fd,
            .events = posix.POLL.IN,
            .revents = 0,
        }};

        const res = posix.poll(pollfds[0..], -1) catch return;
        if (res <= 0) continue;

        const revents = pollfds[0].revents;
        if ((revents & posix.POLL.HUP) != 0) {
            posix.nanosleep(0, 100 * std.time.ns_per_ms);
            continue;
        }

        if ((revents & posix.POLL.IN) != 0) return;
    }
}

fn execWorker(session: *ExecSession) void {
    runExecSession(session) catch |err| {
        log.err("exec handling failed id={}: {s}", .{ session.req.id, @errorName(err) });
        const code: []const u8 = switch (err) {
            error.ResourceControllerUnavailable,
            error.ResourceStartGateMissing,
            error.ResourceStartGateClosed,
            => "resource_controller_unavailable",
            error.NamespaceIsolationUnavailable => "namespace_isolation_unavailable",
            error.CapabilityPolicyUnavailable => "capability_policy_unavailable",
            else => "exec_failed",
        };
        const message: []const u8 = if (std.mem.eql(
            u8,
            code,
            "namespace_isolation_unavailable",
        ))
            "required namespace isolation could not be installed before launch"
        else if (std.mem.eql(u8, code, "capability_policy_unavailable"))
            "required executable or writable policy could not be installed before launch"
        else if (std.mem.eql(u8, code, "resource_controller_unavailable"))
            "required resource controllers could not be installed before launch"
        else
            "failed to execute";
        _ = session.tx.sendError(session.allocator, session.req.id, code, message) catch {};
    };

    markSessionDone(session);
}

fn runExecSession(session: *ExecSession) !void {
    const req = session.req;

    var arena = std.heap.ArenaAllocator.init(session.allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const argv = try buildArgv(arena_alloc, req.cmd, req.argv);
    const envp = try buildEnvp(
        arena_alloc,
        session.allocator,
        req.env,
        req.clear_env,
    );

    const use_pty = req.pty;
    const wants_stdin = req.stdin or use_pty;

    var resource_group = if (req.resource_limits != null or req.deny_descendants)
        try ResourceGroup.create(
            arena_alloc,
            req.id,
            req.resource_limits,
            req.deny_descendants,
        )
    else
        null;
    var resource_usage: ?protocol.ExecResourceUsage = null;
    defer if (resource_group) |*group| {
        if (resource_usage == null) resource_usage = group.settle();
    };

    var start_gate: ?[2]posix.fd_t = if (resource_group != null)
        try posix.pipe2(.{ .CLOEXEC = true })
    else
        null;
    errdefer if (start_gate) |gate| {
        posix.close(gate[0]);
        posix.close(gate[1]);
    };
    const needs_setup_status = req.isolate_ipc or
        req.isolate_devices or
        req.allowed_executables.len > 0 or
        req.allowed_writable_paths.len > 0;
    var setup_gate: ?[2]posix.fd_t = if (needs_setup_status)
        try posix.pipe2(.{ .CLOEXEC = true })
    else
        null;
    errdefer if (setup_gate) |gate| {
        posix.close(gate[0]);
        posix.close(gate[1]);
    };

    var stdout_fd: ?posix.fd_t = null;
    var stderr_fd: ?posix.fd_t = null;
    var stdin_fd: ?posix.fd_t = null;
    var pty_master: ?posix.fd_t = null;

    var stdout_pipe: ?[2]posix.fd_t = null;
    var stderr_pipe: ?[2]posix.fd_t = null;
    var stdin_pipe: ?[2]posix.fd_t = null;

    var pid: posix.pid_t = 0;

    if (use_pty) {
        var master: c_int = 0;
        const forked = c.forkpty(&master, null, null, null);
        if (forked < 0) {
            return error.OpenPtyFailed;
        }
        pid = @intCast(forked);
        if (pid == 0) {
            awaitResourceStartGate(start_gate) catch posix.exit(126);
            applyNamespaceIsolation(req.isolate_ipc, req.isolate_devices) catch {
                reportExecSetup(setup_gate, .namespace_failed);
                posix.exit(126);
            };
            applyCapabilityPolicy(req.allowed_executables, req.allowed_writable_paths) catch {
                reportExecSetup(setup_gate, .policy_failed);
                posix.exit(126);
            };
            reportExecSetup(setup_gate, .ready);
            if (req.cwd) |cwd| {
                _ = posix.chdir(cwd) catch posix.exit(127);
            }

            posix.execvpeZ(argv[0].?, argv, envp) catch {
                const msg = "exec failed\n";
                _ = posix.write(posix.STDERR_FILENO, msg) catch {};
                posix.exit(127);
            };
        }

        pty_master = @intCast(master);
        errdefer {
            if (pty_master) |fd| posix.close(fd);
        }

        try releaseResourceStartGate(&resource_group, &start_gate, pid);
        awaitExecSetup(&setup_gate) catch |err| {
            _ = posix.kill(pid, posix.SIG.KILL) catch {};
            _ = posix.waitpid(pid, 0);
            return err;
        };

        stdout_fd = pty_master;
        stdin_fd = pty_master;
    } else {
        stdout_pipe = try posix.pipe2(.{ .CLOEXEC = true });
        errdefer {
            posix.close(stdout_pipe.?[0]);
            posix.close(stdout_pipe.?[1]);
        }

        stderr_pipe = try posix.pipe2(.{ .CLOEXEC = true });
        errdefer {
            posix.close(stderr_pipe.?[0]);
            posix.close(stderr_pipe.?[1]);
        }

        if (wants_stdin) {
            stdin_pipe = try posix.pipe2(.{ .CLOEXEC = true });
            errdefer {
                posix.close(stdin_pipe.?[0]);
                posix.close(stdin_pipe.?[1]);
            }
        }

        stdout_fd = stdout_pipe.?[0];
        stderr_fd = stderr_pipe.?[0];
        if (wants_stdin) stdin_fd = stdin_pipe.?[1];

        pid = try posix.fork();
        if (pid == 0) {
            awaitResourceStartGate(start_gate) catch posix.exit(126);
            if (wants_stdin) {
                try posix.dup2(stdin_pipe.?[0], posix.STDIN_FILENO);
            } else {
                const devnull = posix.openZ("/dev/null", .{ .ACCMODE = .RDONLY }, 0) catch posix.exit(127);
                try posix.dup2(devnull, posix.STDIN_FILENO);
                posix.close(devnull);
            }

            try posix.dup2(stdout_pipe.?[1], posix.STDOUT_FILENO);
            try posix.dup2(stderr_pipe.?[1], posix.STDERR_FILENO);

            posix.close(stdout_pipe.?[0]);
            posix.close(stdout_pipe.?[1]);
            posix.close(stderr_pipe.?[0]);
            posix.close(stderr_pipe.?[1]);

            if (wants_stdin) {
                posix.close(stdin_pipe.?[0]);
                posix.close(stdin_pipe.?[1]);
            }

            applyNamespaceIsolation(req.isolate_ipc, req.isolate_devices) catch {
                reportExecSetup(setup_gate, .namespace_failed);
                posix.exit(126);
            };

            applyCapabilityPolicy(req.allowed_executables, req.allowed_writable_paths) catch {
                reportExecSetup(setup_gate, .policy_failed);
                posix.exit(126);
            };
            reportExecSetup(setup_gate, .ready);

            if (req.cwd) |cwd| {
                _ = posix.chdir(cwd) catch posix.exit(127);
            }

            posix.execvpeZ(argv[0].?, argv, envp) catch {
                const msg = "exec failed\n";
                _ = posix.write(posix.STDERR_FILENO, msg) catch {};
                posix.exit(127);
            };
        }
        try releaseResourceStartGate(&resource_group, &start_gate, pid);
        awaitExecSetup(&setup_gate) catch |err| {
            _ = posix.kill(pid, posix.SIG.KILL) catch {};
            _ = posix.waitpid(pid, 0);
            return err;
        };
    }

    errdefer {
        if (pid > 0) {
            _ = posix.kill(pid, posix.SIG.KILL) catch {};
            _ = posix.waitpid(pid, 0);
        }
    }

    if (!use_pty) {
        posix.close(stdout_pipe.?[1]);
        posix.close(stderr_pipe.?[1]);
        if (wants_stdin) posix.close(stdin_pipe.?[0]);
    }

    var stdout_open = stdout_fd != null;
    var stderr_open = stderr_fd != null;
    var stdin_open = wants_stdin and stdin_fd != null;
    const close_stdin_on_eof = !use_pty;

    var status: ?u32 = null;
    var tree_killed = false;

    if (wants_stdin) {
        const grant_bytes: usize = @min(max_queued_stdin_bytes, @as(usize, std.math.maxInt(u32)));
        session.mutex.lockUncancelable(syncIo());
        session.stdin_credit_inflight = grant_bytes;
        session.mutex.unlock(syncIo());
        _ = session.tx.sendStdinWindow(session.allocator, req.id, @intCast(grant_bytes)) catch {};
    }

    // PTY mode: after the main PID exits, we stop waiting for EOF (other
    // processes may still hold the slave open) but do a short best-effort drain
    // of already-buffered output before forcing the PTY closed.
    var pty_close_deadline_ms: ?i64 = null;
    var pty_exit_drain_remaining: ?usize = null;

    var buffer: [8192]u8 = undefined;

    const max_total_credit: usize = 16 * 1024 * 1024;

    const max_stdout_credit: usize = @min(max_total_credit, @as(usize, @intCast(req.stdout_window)));
    const max_stderr_credit: usize = @min(max_total_credit, @as(usize, @intCast(req.stderr_window)));

    var stdout_credit: usize = max_stdout_credit;
    var stderr_credit: usize = max_stderr_credit;

    // Once a pipe has hung up, poll() may keep reporting POLLHUP even if
    // .events=0. If we're currently not allowed to read (no credits), keep it
    // out of the poll set to avoid a tight wakeup loop.
    var stdout_hup_seen = false;
    var stderr_hup_seen = false;

    var local_controls = std.ArrayList(ExecControlMessage).empty;
    defer {
        for (local_controls.items) |msg| {
            switch (msg) {
                .stdin => |chunk| session.allocator.free(chunk.data),
                else => {},
            }
        }
        local_controls.deinit(session.allocator);
    }

    while (true) {
        if (resource_group) |*group| {
            if (!tree_killed and group.pollExhaustion()) {
                group.killAll();
                tree_killed = true;
            }
        }
        session.mutex.lockUncancelable(syncIo());
        std.mem.swap(std.ArrayList(ExecControlMessage), &local_controls, &session.controls);
        session.mutex.unlock(syncIo());

        for (local_controls.items) |msg| {
            switch (msg) {
                .stdin => |data| {
                    const data_len = data.data.len;

                    if (stdin_fd) |fd| {
                        if (data_len > 0) {
                            protocol.writeAll(fd, data.data) catch {
                                posix.close(fd);
                                stdin_fd = null;
                                stdin_open = false;
                            };
                        }
                        if (data.eof) {
                            if (close_stdin_on_eof) {
                                posix.close(fd);
                                stdin_fd = null;
                            } else {
                                const eot: [1]u8 = .{4};
                                _ = protocol.writeAll(fd, &eot) catch {};
                            }
                            stdin_open = false;
                        }
                    }

                    session.allocator.free(data.data);

                    var grant: usize = 0;
                    session.mutex.lockUncancelable(syncIo());
                    if (session.stdin_queued_bytes >= data_len) {
                        session.stdin_queued_bytes -= data_len;
                    } else {
                        session.stdin_queued_bytes = 0;
                    }

                    // Credit-based stdin flow control.
                    // Maintain: stdin_queued_bytes + stdin_credit_inflight <= max_queued_stdin_bytes
                    const used = session.stdin_queued_bytes + session.stdin_credit_inflight;
                    if (data_len > 0 and used < max_queued_stdin_bytes) {
                        const free = max_queued_stdin_bytes - used;
                        grant = @min(data_len, free);
                        session.stdin_credit_inflight += grant;
                    }

                    session.control_cv.signal(syncIo());
                    session.mutex.unlock(syncIo());

                    if (grant > 0) {
                        _ = session.tx.sendStdinWindow(session.allocator, req.id, @intCast(grant)) catch {};
                    }
                },
                .resize => |size| {
                    if (pty_master) |fd| {
                        applyPtyResize(fd, size.rows, size.cols);
                    }
                },
                .window => |win| {
                    if (win.stdout > 0) {
                        const add: usize = @intCast(win.stdout);
                        stdout_credit = @min(max_stdout_credit, stdout_credit + add);
                    }
                    if (win.stderr > 0) {
                        const add: usize = @intCast(win.stderr);
                        stderr_credit = @min(max_stderr_credit, stderr_credit + add);
                    }
                },
            }
        }
        local_controls.clearRetainingCapacity();

        if (status != null and !stdout_open and !stderr_open) break;

        var pollfds: [3]posix.pollfd = undefined;
        var nfds: usize = 0;
        var stdout_index: ?usize = null;
        var stderr_index: ?usize = null;
        var wake_index: ?usize = null;

        const stdout_can_read = stdout_credit > 0;
        const stderr_can_read = stderr_credit > 0;

        if (use_pty and pty_master != null and pty_close_deadline_ms != null) {
            const now_ms = milliTimestamp();
            const deadline_ms = pty_close_deadline_ms.?;

            var should_close = now_ms >= deadline_ms;
            if (!should_close) {
                if (pty_exit_drain_remaining) |rem| {
                    if (rem == 0) should_close = true;
                }
            }

            if (should_close) {
                const fd = pty_master.?;
                posix.close(fd);
                pty_master = null;

                stdout_fd = null;
                stdin_fd = null;
                stdout_open = false;
                stdin_open = false;
            }
        }

        if (stdout_open and stdout_hup_seen and !stdout_can_read) {
            if (stdout_fd) |fd| {
                if (bytesAvailable(fd)) |avail| {
                    if (avail == 0) {
                        stdout_open = false;
                        posix.close(fd);
                        stdout_fd = null;
                        if (use_pty) {
                            pty_master = null;
                            if (stdin_fd != null) {
                                stdin_fd = null;
                                stdin_open = false;
                            }
                        }
                    }
                }
            }
        }
        if (stderr_open and stderr_hup_seen and !stderr_can_read) {
            if (stderr_fd) |fd| {
                if (bytesAvailable(fd)) |avail| {
                    if (avail == 0) {
                        stderr_open = false;
                        posix.close(fd);
                        stderr_fd = null;
                    }
                }
            }
        }

        if (stdout_open) {
            const can_read = stdout_can_read;
            if (can_read or !stdout_hup_seen) {
                stdout_index = nfds;
                const events: i16 = if (can_read) posix.POLL.IN else 0;
                pollfds[nfds] = .{ .fd = stdout_fd.?, .events = events, .revents = 0 };
                nfds += 1;
            }
        }
        if (stderr_open) {
            const can_read = stderr_can_read;
            if (can_read or !stderr_hup_seen) {
                stderr_index = nfds;
                const events: i16 = if (can_read) posix.POLL.IN else 0;
                pollfds[nfds] = .{ .fd = stderr_fd.?, .events = events, .revents = 0 };
                nfds += 1;
            }
        }

        if (session.wake_read_fd) |wake_fd| {
            wake_index = nfds;
            pollfds[nfds] = .{ .fd = wake_fd, .events = posix.POLL.IN, .revents = 0 };
            nfds += 1;
        }

        if (nfds > 0) {
            _ = try posix.poll(pollfds[0..nfds], 100);
        } else {
            if (status == null) {
                const res = posix.waitpid(pid, posix.W.NOHANG);
                if (res.pid != 0) {
                    status = res.status;
                } else {
                    // Avoid a tight busy loop when the child stays alive after
                    // closing stdout/stderr early.
                    posix.nanosleep(0, 1 * std.time.ns_per_ms);
                }
            } else {
                // The child is already dead. If output remains but credits are
                // exhausted, wait until new control messages arrive.
                posix.nanosleep(0, 10 * std.time.ns_per_ms);
            }
            continue;
        }

        if (wake_index) |windex| {
            const revents = pollfds[windex].revents;
            if ((revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR)) != 0) {
                drainExecWakeFd(pollfds[windex].fd);
            }
        }

        if (stdout_index) |sindex| {
            const revents = pollfds[sindex].revents;
            if ((revents & posix.POLL.HUP) != 0) stdout_hup_seen = true;

            if (stdout_credit > 0 and (revents & (posix.POLL.IN | posix.POLL.HUP)) != 0) {
                const max_read: usize = @min(buffer.len, stdout_credit);
                const n = posix.read(stdout_fd.?, buffer[0..max_read]) catch |err| blk: {
                    if (use_pty and err == error.InputOutput) {
                        break :blk 0;
                    }
                    return err;
                };
                if (n == 0) {
                    stdout_open = false;
                    if (stdout_fd) |fd| posix.close(fd);
                    stdout_fd = null;
                    if (use_pty) {
                        pty_master = null;
                        if (stdin_fd != null) {
                            stdin_fd = null;
                            stdin_open = false;
                        }
                    }
                } else {
                    if (use_pty and pty_exit_drain_remaining != null) {
                        const rem = pty_exit_drain_remaining.?;
                        pty_exit_drain_remaining = if (n >= rem) 0 else rem - n;
                    }

                    stdout_credit -= n;
                    const payload = try protocol.encodeExecOutput(session.allocator, req.id, "stdout", buffer[0..n]);
                    defer session.allocator.free(payload);
                    try session.tx.sendPayload(payload);
                }
            } else if ((revents & posix.POLL.HUP) != 0) {
                if (stdout_fd) |fd| {
                    if (bytesAvailable(fd)) |avail| {
                        if (avail == 0) {
                            stdout_open = false;
                            posix.close(fd);
                            stdout_fd = null;
                            if (use_pty) {
                                pty_master = null;
                                if (stdin_fd != null) {
                                    stdin_fd = null;
                                    stdin_open = false;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (stderr_index) |sindex| {
            const revents = pollfds[sindex].revents;
            if ((revents & posix.POLL.HUP) != 0) stderr_hup_seen = true;

            if (stderr_credit > 0 and (revents & (posix.POLL.IN | posix.POLL.HUP)) != 0) {
                const max_read: usize = @min(buffer.len, stderr_credit);
                const n = try posix.read(stderr_fd.?, buffer[0..max_read]);
                if (n == 0) {
                    stderr_open = false;
                    if (stderr_fd) |fd| posix.close(fd);
                    stderr_fd = null;
                } else {
                    stderr_credit -= n;
                    const payload = try protocol.encodeExecOutput(session.allocator, req.id, "stderr", buffer[0..n]);
                    defer session.allocator.free(payload);
                    try session.tx.sendPayload(payload);
                }
            } else if ((revents & posix.POLL.HUP) != 0) {
                if (stderr_fd) |fd| {
                    if (bytesAvailable(fd)) |avail| {
                        if (avail == 0) {
                            stderr_open = false;
                            posix.close(fd);
                            stderr_fd = null;
                        }
                    }
                }
            }
        }

        if (status == null) {
            const res = posix.waitpid(pid, posix.W.NOHANG);
            if (res.pid != 0) {
                status = res.status;
                if (resource_group) |*group| {
                    group.killAll();
                    tree_killed = true;
                }

                if (use_pty and pty_master != null and pty_close_deadline_ms == null) {
                    pty_close_deadline_ms = milliTimestamp() + 250;
                    pty_exit_drain_remaining = 64 * 1024;
                }
            }
        }
    }

    if (!use_pty) {
        if (stdin_fd) |fd| posix.close(fd);
    }

    if (status == null) {
        status = posix.waitpid(pid, 0).status;
    }

    if (resource_group) |*group| {
        group.killAll();
        resource_usage = group.settle();
    }

    const term = parseStatus(status.?);
    const response = try protocol.encodeExecResponse(session.allocator, req.id, term.exit_code, term.signal, resource_usage);
    defer session.allocator.free(response);
    try session.tx.sendPayload(response);
}

fn bytesAvailable(fd: posix.fd_t) ?usize {
    var n: c_int = 0;

    // ioctl(FIONREAD) can fail transiently (e.g. EINTR).  If it fails we return
    // null (unknown) rather than guessing drained/not-drained, to avoid output
    // truncation.
    var attempts: usize = 0;
    while (true) : (attempts += 1) {
        const rc = c.ioctl(fd, c.FIONREAD, &n);
        if (rc == 0) break;
        const err = posix.errno(rc);
        if (err == .INTR and attempts < 3) continue;
        return null;
    }

    if (n <= 0) return 0;
    return @intCast(n);
}

fn applyPtyResize(fd: posix.fd_t, rows: u32, cols: u32) void {
    const Field = @TypeOf(@as(c.struct_winsize, undefined).ws_row);
    const max = std.math.maxInt(Field);
    const safe_rows: Field = @intCast(if (rows > max) max else rows);
    const safe_cols: Field = @intCast(if (cols > max) max else cols);

    var winsize = c.struct_winsize{
        .ws_row = safe_rows,
        .ws_col = safe_cols,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };
    _ = c.ioctl(fd, c.TIOCSWINSZ, &winsize);
}

fn flushWriter(virtio_fd: posix.fd_t, writer: *protocol.FrameWriter) !void {
    while (writer.hasPending()) {
        var pollfds: [1]posix.pollfd = .{.{
            .fd = virtio_fd,
            .events = posix.POLL.OUT,
            .revents = 0,
        }};

        _ = try posix.poll(pollfds[0..], 100);
        const revents = pollfds[0].revents;
        if ((revents & posix.POLL.OUT) != 0) {
            try writer.flush(virtio_fd);
        }
        if ((revents & posix.POLL.HUP) != 0) return error.EndOfStream;
    }
}

fn parseStatus(status: u32) Termination {
    if (posix.W.IFEXITED(status)) {
        return .{ .exit_code = @as(i32, @intCast(posix.W.EXITSTATUS(status))), .signal = null };
    }
    if (posix.W.IFSIGNALED(status)) {
        const sig = @as(i32, @intCast(@intFromEnum(posix.W.TERMSIG(status))));
        return .{ .exit_code = 128 + sig, .signal = sig };
    }
    return .{ .exit_code = 1, .signal = null };
}

fn buildArgv(
    allocator: std.mem.Allocator,
    cmd: []const u8,
    argv: []const []const u8,
) ![*:null]const ?[*:0]const u8 {
    const total = argv.len + 1;
    const argv_buf = try allocator.allocSentinel(?[*:0]const u8, total, null);
    argv_buf[0] = (try allocator.dupeZ(u8, cmd)).ptr;
    for (argv, 0..) |arg, idx| {
        argv_buf[idx + 1] = (try allocator.dupeZ(u8, arg)).ptr;
    }
    return argv_buf.ptr;
}

fn awaitResourceStartGate(gate: ?[2]posix.fd_t) !void {
    if (gate) |fds| {
        posix.close(fds[1]);
        var byte: [1]u8 = undefined;
        const n = try posix.read(fds[0], &byte);
        posix.close(fds[0]);
        if (n != 1) return error.ResourceStartGateClosed;
    }
}

const ExecSetupStatus = enum(u8) {
    ready = 1,
    namespace_failed = 2,
    policy_failed = 3,
};

fn reportExecSetup(gate: ?[2]posix.fd_t, status: ExecSetupStatus) void {
    const fds = gate orelse return;
    posix.close(fds[0]);
    const payload: [1]u8 = .{@intFromEnum(status)};
    _ = posix.write(fds[1], &payload) catch {};
    posix.close(fds[1]);
}

fn awaitExecSetup(gate: *?[2]posix.fd_t) !void {
    const fds = gate.* orelse return;
    posix.close(fds[1]);
    var payload: [1]u8 = undefined;
    const length = posix.read(fds[0], &payload) catch 0;
    posix.close(fds[0]);
    gate.* = null;
    if (length != 1) return error.CapabilityPolicyUnavailable;
    switch (payload[0]) {
        @intFromEnum(ExecSetupStatus.ready) => return,
        @intFromEnum(ExecSetupStatus.namespace_failed) => return error.NamespaceIsolationUnavailable,
        @intFromEnum(ExecSetupStatus.policy_failed) => return error.CapabilityPolicyUnavailable,
        else => return error.CapabilityPolicyUnavailable,
    }
}

fn releaseResourceStartGate(
    group: *?ResourceGroup,
    gate: *?[2]posix.fd_t,
    pid: posix.pid_t,
) !void {
    if (group.*) |*resource_group| {
        const fds = gate.* orelse return error.ResourceStartGateMissing;
        posix.close(fds[0]);
        resource_group.attach(pid) catch {
            posix.close(fds[1]);
            gate.* = null;
            _ = posix.kill(pid, posix.SIG.KILL) catch {};
            _ = posix.waitpid(pid, 0);
            return error.ResourceControllerUnavailable;
        };
        const byte: [1]u8 = .{1};
        protocol.writeAll(fds[1], &byte) catch {
            posix.close(fds[1]);
            gate.* = null;
            return error.ResourceStartGateClosed;
        };
        posix.close(fds[1]);
        gate.* = null;
    }
}

const ResourceGroup = struct {
    path: []const u8,
    limits: ?protocol.ExecResourceLimits,
    deny_descendants: bool,
    exhausted: ?protocol.ExecResourceExhaustion = null,
    descendant_denied: bool = false,

    fn create(
        allocator: std.mem.Allocator,
        id: u32,
        limits: ?protocol.ExecResourceLimits,
        deny_descendants: bool,
    ) !ResourceGroup {
        try requireControlFile("/sys/fs/cgroup/cgroup.controllers");
        try writeControlFile(
            "/sys/fs/cgroup/cgroup.subtree_control",
            if (limits != null) "+memory +pids" else "+pids",
        );
        const group_path = try std.fmt.allocPrint(allocator, "/sys/fs/cgroup/gondolin-exec-{d}", .{id});
        const group_path_z = try allocator.dupeZ(u8, group_path);
        if (c.mkdir(group_path_z.ptr, 0o700) != 0) return error.ResourceControllerUnavailable;
        errdefer _ = c.rmdir(group_path_z.ptr);

        var path_buf: [256]u8 = undefined;
        if (limits) |configured| {
            const memory_max = try std.fmt.bufPrint(&path_buf, "{d}", .{configured.memory_bytes});
            try writeGroupControl(group_path, "memory.max", memory_max);
        }
        const pids_limit: u32 = if (deny_descendants) 1 else limits.?.pids;
        const pids_max = try std.fmt.bufPrint(&path_buf, "{d}", .{pids_limit});
        try writeGroupControl(group_path, "pids.max", pids_max);

        for ([_][]const u8{
            "cgroup.procs",
            "cgroup.kill",
            "pids.events",
            "pids.peak",
        }) |name| try requireGroupControl(group_path, name);
        if (limits != null) {
            for ([_][]const u8{
                "cpu.stat",
                "memory.events",
                "memory.peak",
            }) |name| try requireGroupControl(group_path, name);
        }

        return .{
            .path = group_path,
            .limits = limits,
            .deny_descendants = deny_descendants,
        };
    }

    fn attach(self: *ResourceGroup, pid: posix.pid_t) !void {
        var buffer: [32]u8 = undefined;
        const value = try std.fmt.bufPrint(&buffer, "{d}", .{pid});
        try writeGroupControl(self.path, "cgroup.procs", value);
    }

    fn pollExhaustion(self: *ResourceGroup) bool {
        if (self.exhausted != null) return true;
        if (self.limits) |limits| {
            const memory_events = readGroupControl(self.path, "memory.events") catch return false;
            if (controlCounter(memory_events, "oom_kill") > 0 or controlCounter(memory_events, "oom") > 0 or controlCounter(memory_events, "max") > 0) {
                self.exhausted = .memory;
                return true;
            }
            const cpu_stat = readGroupControl(self.path, "cpu.stat") catch return false;
            const cpu_ms = controlCounter(cpu_stat, "usage_usec") / 1000;
            if (cpu_ms >= limits.cpu_time_ms) {
                self.exhausted = .cpu;
                return true;
            }
        }
        const pids_events = readGroupControl(self.path, "pids.events") catch return false;
        if (controlCounter(pids_events, "max") > 0) {
            if (self.deny_descendants) {
                self.descendant_denied = true;
            } else {
                self.exhausted = .pids;
            }
            return true;
        }
        return false;
    }

    fn killAll(self: *ResourceGroup) void {
        writeGroupControl(self.path, "cgroup.kill", "1") catch {};
    }

    fn settle(self: *ResourceGroup) protocol.ExecResourceUsage {
        _ = self.pollExhaustion();
        self.killAll();
        var attempts: usize = 0;
        while (attempts < 100) : (attempts += 1) {
            const procs = readGroupControl(self.path, "cgroup.procs") catch break;
            if (std.mem.trim(u8, procs, " \r\n\t").len == 0) break;
            posix.nanosleep(0, 1 * std.time.ns_per_ms);
        }

        const cpu_ms = blk: {
            const value = readGroupControl(self.path, "cpu.stat") catch break :blk 0;
            break :blk controlCounter(value, "usage_usec") / 1000;
        };
        const memory_peak = blk: {
            const value = readGroupControl(self.path, "memory.peak") catch break :blk 0;
            break :blk parseControlInteger(value);
        };
        const pids_peak = blk: {
            const value = readGroupControl(self.path, "pids.peak") catch break :blk 0;
            break :blk parseControlInteger(value);
        };
        const group_path_z = std.heap.page_allocator.dupeZ(u8, self.path) catch null;
        var removed = false;
        if (group_path_z) |path_z| {
            defer std.heap.page_allocator.free(path_z);
            removed = c.rmdir(path_z.ptr) == 0;
        }
        return .{
            .cpu_time_ms = cpu_ms,
            .memory_peak_bytes = memory_peak,
            .pids_peak = pids_peak,
            .exhausted = self.exhausted,
            .descendant_denied = self.descendant_denied,
            .resource_group_removed = removed,
        };
    }
};

threadlocal var control_read_buffer: [4096]u8 = undefined;

fn controlPath(buffer: []u8, group: []const u8, name: []const u8) ![]const u8 {
    return try std.fmt.bufPrint(buffer, "{s}/{s}", .{ group, name });
}

fn requireControlFile(file_path: []const u8) !void {
    const file_path_z = try std.heap.page_allocator.dupeZ(u8, file_path);
    defer std.heap.page_allocator.free(file_path_z);
    const fd = c.open(file_path_z.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return error.ResourceControllerUnavailable;
    _ = c.close(fd);
}

fn requireGroupControl(group: []const u8, name: []const u8) !void {
    var buffer: [256]u8 = undefined;
    try requireControlFile(try controlPath(&buffer, group, name));
}

fn writeControlFile(file_path: []const u8, value: []const u8) !void {
    const file_path_z = try std.heap.page_allocator.dupeZ(u8, file_path);
    defer std.heap.page_allocator.free(file_path_z);
    const fd = c.open(file_path_z.ptr, c.O_WRONLY | c.O_CLOEXEC);
    if (fd < 0) return error.ResourceControllerUnavailable;
    defer _ = c.close(fd);
    protocol.writeAll(fd, value) catch return error.ResourceControllerUnavailable;
}

fn writeGroupControl(group: []const u8, name: []const u8, value: []const u8) !void {
    var buffer: [256]u8 = undefined;
    try writeControlFile(try controlPath(&buffer, group, name), value);
}

fn readGroupControl(group: []const u8, name: []const u8) ![]const u8 {
    var path_buffer: [256]u8 = undefined;
    const file_path = try controlPath(&path_buffer, group, name);
    const file_path_z = try std.heap.page_allocator.dupeZ(u8, file_path);
    defer std.heap.page_allocator.free(file_path_z);
    const fd = c.open(file_path_z.ptr, c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return error.ResourceControllerUnavailable;
    defer _ = c.close(fd);
    const length = posix.read(fd, &control_read_buffer) catch return error.ResourceControllerUnavailable;
    return control_read_buffer[0..length];
}

fn controlCounter(contents: []const u8, key: []const u8) u64 {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const found_key = fields.next() orelse continue;
        if (!std.mem.eql(u8, found_key, key)) continue;
        return std.fmt.parseInt(u64, fields.next() orelse return 0, 10) catch 0;
    }
    return 0;
}

fn parseControlInteger(contents: []const u8) u64 {
    return std.fmt.parseInt(u64, std.mem.trim(u8, contents, " \r\n\t"), 10) catch 0;
}

/// Install optional per-exec IPC and device mount namespaces before Landlock.
fn applyNamespaceIsolation(isolate_ipc: bool, isolate_devices: bool) !void {
    if (!isolate_ipc and !isolate_devices) return;

    var flags: c_int = 0;
    if (isolate_ipc) flags |= c.CLONE_NEWIPC;
    if (isolate_devices) flags |= c.CLONE_NEWNS;
    if (c.unshare(flags) != 0) return error.NamespaceIsolationUnavailable;

    if (!isolate_devices) return;
    if (c.mount(null, "/", null, c.MS_REC | c.MS_PRIVATE, null) != 0) {
        return error.NamespaceIsolationUnavailable;
    }
    const isolated_mounts = [_][]const u8{ "/dev", "/run", "/tmp" };
    for (isolated_mounts) |mount_path| {
        const mount_path_z = try std.heap.page_allocator.dupeZ(u8, mount_path);
        defer std.heap.page_allocator.free(mount_path_z);
        if (c.mount(
            "tmpfs",
            mount_path_z.ptr,
            "tmpfs",
            c.MS_NOSUID | c.MS_NODEV | c.MS_NOEXEC,
            "mode=000,size=4096",
        ) != 0) return error.NamespaceIsolationUnavailable;
    }
}

/// Install inherited Linux Landlock execute and exact-write allow-lists.
fn applyCapabilityPolicy(executables: []const []const u8, writable_paths: []const []const u8) !void {
    if (executables.len == 0 and writable_paths.len == 0) return;

    if (executables.len > 0) {
        try makeRootTreeNoExec();
        try makeRuntimeLibrariesExecutable();
    }

    var ruleset_attr: c.struct_landlock_ruleset_attr = std.mem.zeroes(c.struct_landlock_ruleset_attr);
    // Scoped invocations expose only pre-created exact writable files.  Handle
    // every namespace-mutating right as well as writes/truncation so an
    // invocation cannot create unaccounted state in guest tmpfs mounts such as
    // /tmp, /run, /root, or cache directories.
    ruleset_attr.handled_access_fs = c.LANDLOCK_ACCESS_FS_EXECUTE |
        c.LANDLOCK_ACCESS_FS_WRITE_FILE |
        c.LANDLOCK_ACCESS_FS_REMOVE_DIR |
        c.LANDLOCK_ACCESS_FS_REMOVE_FILE |
        c.LANDLOCK_ACCESS_FS_MAKE_CHAR |
        c.LANDLOCK_ACCESS_FS_MAKE_DIR |
        c.LANDLOCK_ACCESS_FS_MAKE_REG |
        c.LANDLOCK_ACCESS_FS_MAKE_SOCK |
        c.LANDLOCK_ACCESS_FS_MAKE_FIFO |
        c.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
        c.LANDLOCK_ACCESS_FS_MAKE_SYM |
        c.LANDLOCK_ACCESS_FS_REFER |
        c.LANDLOCK_ACCESS_FS_TRUNCATE;
    const ruleset_fd_raw = c.syscall(
        c.SYS_landlock_create_ruleset,
        &ruleset_attr,
        @as(usize, @sizeOf(c.struct_landlock_ruleset_attr)),
        @as(c_uint, 0),
    );
    if (ruleset_fd_raw < 0) return error.LandlockUnavailable;
    const ruleset_fd: c_int = @intCast(ruleset_fd_raw);
    defer _ = c.close(ruleset_fd);

    for (executables) |executable| {
        const executable_z = try std.heap.page_allocator.dupeZ(u8, executable);
        defer std.heap.page_allocator.free(executable_z);

        var resolved: [c.PATH_MAX]u8 = undefined;
        const resolved_ptr = c.realpath(executable_z.ptr, &resolved) orelse return error.InvalidExecutable;
        const resolved_path = std.mem.span(resolved_ptr);
        if (!std.mem.eql(u8, executable, resolved_path)) return error.AliasedExecutable;

        const executable_fd = c.open(executable_z.ptr, c.O_PATH | c.O_CLOEXEC);
        if (executable_fd < 0) return error.InvalidExecutable;
        defer _ = c.close(executable_fd);

        var stat: std.os.linux.Statx = undefined;
        if (std.c.statx(executable_fd, "", std.os.linux.AT.EMPTY_PATH, .{ .NLINK = true }, &stat) != 0 or
            !stat.mask.NLINK or stat.nlink != 1)
        {
            return error.AliasedExecutable;
        }

        // Landlock identifies objects by inode, so it cannot distinguish an
        // admitted file from a symlink alias to the same file.  A private
        // noexec root plus an exact executable bind mount supplies the path
        // distinction; Landlock remains the inherited complete-tree policy.
        if (c.mount(
            executable_z.ptr,
            executable_z.ptr,
            null,
            c.MS_BIND,
            null,
        ) != 0) {
            return error.ExecutableMountPolicyUnavailable;
        }
        if (c.mount(
            null,
            executable_z.ptr,
            null,
            c.MS_BIND | c.MS_REMOUNT | c.MS_RDONLY | c.MS_NOSUID | c.MS_NODEV,
            null,
        ) != 0) return error.ExecutableMountPolicyUnavailable;

        var path_attr: c.struct_landlock_path_beneath_attr = std.mem.zeroes(c.struct_landlock_path_beneath_attr);
        path_attr.allowed_access = c.LANDLOCK_ACCESS_FS_EXECUTE;
        path_attr.parent_fd = executable_fd;
        if (c.syscall(
            c.SYS_landlock_add_rule,
            ruleset_fd,
            c.LANDLOCK_RULE_PATH_BENEATH,
            &path_attr,
            @as(c_uint, 0),
        ) < 0) return error.LandlockRuleFailed;
    }

    for (writable_paths) |writable_path| {
        const writable_z = try std.heap.page_allocator.dupeZ(u8, writable_path);
        defer std.heap.page_allocator.free(writable_z);

        var resolved: [c.PATH_MAX]u8 = undefined;
        const resolved_ptr = c.realpath(writable_z.ptr, &resolved) orelse return error.InvalidWritablePath;
        const resolved_path = std.mem.span(resolved_ptr);
        if (!std.mem.eql(u8, writable_path, resolved_path)) return error.AliasedWritablePath;

        const writable_fd = c.open(writable_z.ptr, c.O_PATH | c.O_CLOEXEC);
        if (writable_fd < 0) return error.InvalidWritablePath;
        defer _ = c.close(writable_fd);

        var path_attr: c.struct_landlock_path_beneath_attr = std.mem.zeroes(c.struct_landlock_path_beneath_attr);
        path_attr.allowed_access = c.LANDLOCK_ACCESS_FS_WRITE_FILE | c.LANDLOCK_ACCESS_FS_TRUNCATE;
        path_attr.parent_fd = writable_fd;
        if (c.syscall(
            c.SYS_landlock_add_rule,
            ruleset_fd,
            c.LANDLOCK_RULE_PATH_BENEATH,
            &path_attr,
            @as(c_uint, 0),
        ) < 0) return error.LandlockRuleFailed;
    }

    if (c.prctl(c.PR_SET_NO_NEW_PRIVS, @as(c_ulong, 1), @as(c_ulong, 0), @as(c_ulong, 0), @as(c_ulong, 0)) != 0) {
        return error.NoNewPrivilegesFailed;
    }
    if (c.syscall(c.SYS_landlock_restrict_self, ruleset_fd, @as(c_uint, 0)) < 0) {
        return error.LandlockRestrictFailed;
    }
}

/// Create a private root view where only later exact-file binds are executable.
fn makeRootTreeNoExec() !void {
    if (c.unshare(c.CLONE_NEWNS) != 0) {
        return error.ExecutableMountPolicyUnavailable;
    }
    if (c.mount(null, "/", null, c.MS_REC | c.MS_PRIVATE, null) != 0) {
        return error.ExecutableMountPolicyUnavailable;
    }
    if (c.mount("/", "/", null, c.MS_BIND | c.MS_REC, null) != 0) {
        return error.ExecutableMountPolicyUnavailable;
    }
    if (c.mount(
        null,
        "/",
        null,
        c.MS_BIND | c.MS_REMOUNT | c.MS_RDONLY | c.MS_NOEXEC | c.MS_NOSUID | c.MS_NODEV,
        null,
    ) != 0) return error.ExecutableMountPolicyUnavailable;
}

/// Restore executable mappings for runtime libraries without granting execve.
fn makeRuntimeLibrariesExecutable() !void {
    const library_paths = [_][]const u8{ "/lib", "/usr/lib" };
    for (library_paths) |library_path| {
        const path_z = try std.heap.page_allocator.dupeZ(u8, library_path);
        defer std.heap.page_allocator.free(path_z);
        if (c.access(path_z.ptr, c.F_OK) != 0) continue;
        if (c.mount(path_z.ptr, path_z.ptr, null, c.MS_BIND | c.MS_REC, null) != 0) {
            return error.ExecutableMountPolicyUnavailable;
        }
        if (c.mount(
            null,
            path_z.ptr,
            null,
            c.MS_BIND | c.MS_REMOUNT | c.MS_RDONLY | c.MS_NOSUID | c.MS_NODEV,
            null,
        ) != 0) return error.ExecutableMountPolicyUnavailable;
    }
}

fn buildEnvp(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    env: []const []const u8,
    clear_env: bool,
) ![*:null]const ?[*:0]const u8 {
    if (env.len == 0 and !clear_env) {
        return @ptrCast(std.c.environ);
    }

    var entries = std.ArrayList(?[*:0]const u8).empty;
    defer entries.deinit(allocator);

    if (!clear_env) {
        var current_idx: usize = 0;
        while (std.c.environ[current_idx]) |entry_z| : (current_idx += 1) {
            const entry = std.mem.span(entry_z);
            if (isEnvOverridden(entry, env)) continue;
            try entries.append(allocator, entry_z);
        }
    }

    for (env) |entry| {
        if (std.mem.findScalar(u8, entry, '=') == null) return protocol.ProtocolError.InvalidValue;
        const entry_z = try arena.dupeZ(u8, entry);
        try entries.append(allocator, entry_z.ptr);
    }

    const envp_buf = try arena.allocSentinel(?[*:0]const u8, entries.items.len, null);
    @memcpy(envp_buf[0..entries.items.len], entries.items);
    return envp_buf.ptr;
}

fn isEnvOverridden(entry: []const u8, overrides: []const []const u8) bool {
    const sep = std.mem.findScalar(u8, entry, '=') orelse return false;
    const key = entry[0..sep];
    for (overrides) |override| {
        if (override.len <= key.len or override[key.len] != '=') continue;
        if (std.mem.eql(u8, override[0..key.len], key)) return true;
    }
    return false;
}
