//! Kernel-assisted live root-tree resolution and operation table.
//! Path walks use `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS`.
const std = @import("std");
const linux = std.os.linux;

pub const RootKind = enum { repository, cache, temp };

pub const Identity = struct {
    /// Filesystem device major identity
    dev_major: u32,
    /// Filesystem device minor identity
    dev_minor: u32,
    /// Directory inode identity
    ino: u64,
    /// Creation time seconds from `statx` `btime`
    btime_sec: i64,
    /// Creation time nanoseconds from `statx` `btime` in `ns`
    btime_nsec: u32,
};

pub const Error = error{
    Denied,
    Unsupported,
    Invalid,
    IdentityMismatch,
    Unavailable,
};

const OpenHow = extern struct {
    flags: u64,
    mode: u64,
    resolve: u64,
};

const resolve_live: u64 = 0x08 | 0x02; // BENEATH | NO_MAGICLINKS
const identity_mask = linux.STATX{ .TYPE = true, .MODE = true, .INO = true, .BTIME = true, .SIZE = true, .NLINK = true };

fn openat2Fd(dirfd: i32, path: [*:0]const u8, how: *const OpenHow) Error!i32 {
    const rc = linux.syscall4(
        .openat2,
        @as(usize, @bitCast(@as(isize, dirfd))),
        @intFromPtr(path),
        @intFromPtr(how),
        @sizeOf(OpenHow),
    );
    const err = linux.errno(rc);
    if (err == .SUCCESS) return @intCast(rc);
    return switch (err) {
        .NOENT, .ACCES, .PERM, .XDEV, .LOOP, .NOTDIR, .ISDIR, .EXIST, .INVAL, .NAMETOOLONG => error.Denied,
        .NOSYS, .OPNOTSUPP => error.Unsupported,
        else => error.Unavailable,
    };
}

fn closeFd(fd: i32) void {
    _ = linux.close(fd);
}

fn flagsValue(flags: linux.O) u64 {
    return @as(u32, @bitCast(flags));
}

fn identityFromStatx(stx: linux.Statx) Error!Identity {
    if (!stx.mask.TYPE or !stx.mask.INO or !stx.mask.BTIME) return error.Unavailable;
    return .{
        .dev_major = stx.dev_major,
        .dev_minor = stx.dev_minor,
        .ino = stx.ino,
        .btime_sec = stx.btime.sec,
        .btime_nsec = stx.btime.nsec,
    };
}

fn statxFd(fd: i32) Error!linux.Statx {
    var stx: linux.Statx = undefined;
    const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, identity_mask, &stx);
    if (linux.errno(rc) != .SUCCESS) return error.Unavailable;
    return stx;
}

fn copyZ(buf: *[std.fs.max_path_bytes:0]u8, value: []const u8) Error![:0]const u8 {
    if (value.len >= buf.len) return error.Denied;
    @memcpy(buf[0..value.len], value);
    buf[value.len] = 0;
    return buf[0..value.len :0];
}

fn parentName(relative: [*:0]const u8) Error!struct { parent: []const u8, name: []const u8 } {
    const span = std.mem.span(relative);
    if (span.len == 0) return error.Invalid;
    const slash = std.mem.lastIndexOfScalar(u8, span, '/');
    if (slash == null) return .{ .parent = ".", .name = span };
    if (slash.? == 0 or slash.? + 1 >= span.len) return error.Denied;
    return .{ .parent = span[0..slash.?], .name = span[slash.? + 1 ..] };
}

const HandleSlot = struct {
    /// Session-local handle identity, never reused after close
    id: u32,
    /// Owned kernel descriptor for the opened regular file
    fd: i32,
};

pub const Root = struct {
    /// Live root kind
    kind: RootKind,
    /// Pinned directory descriptor
    fd: i32,
    /// Admitted directory identity
    identity: Identity,
    /// Closed-descriptor flag
    closed: bool = false,
    /// Open-handle table; closed IDs are never reused
    handles: [32]?HandleSlot = .{null} ** 32,
    /// Next unused handle identity
    next_handle_id: u32 = 1,

    pub fn pin(kind: RootKind, host_path: [*:0]const u8) Error!Root {
        var how = OpenHow{
            .flags = flagsValue(.{ .ACCMODE = .RDONLY, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }),
            .mode = 0,
            .resolve = 0,
        };
        const fd = try openat2Fd(linux.AT.FDCWD, host_path, &how);
        errdefer closeFd(fd);
        const stx = try statxFd(fd);
        if (!linux.S.ISDIR(stx.mode)) return error.Invalid;
        return .{
            .kind = kind,
            .fd = fd,
            .identity = try identityFromStatx(stx),
        };
    }

    pub fn verify(self: *const Root) Error!void {
        if (self.closed) return error.Unavailable;
        const stx = try statxFd(self.fd);
        if (!linux.S.ISDIR(stx.mode)) return error.IdentityMismatch;
        const actual = try identityFromStatx(stx);
        if (actual.dev_major != self.identity.dev_major or
            actual.dev_minor != self.identity.dev_minor or
            actual.ino != self.identity.ino or
            actual.btime_sec != self.identity.btime_sec or
            actual.btime_nsec != self.identity.btime_nsec) return error.IdentityMismatch;
    }

    pub fn close(self: *Root) void {
        if (self.closed) return;
        for (&self.handles) |*slot| {
            if (slot.*) |owned| closeFd(owned.fd);
            slot.* = null;
        }
        closeFd(self.fd);
        self.closed = true;
    }

    fn isPrivate(self: *const Root) bool {
        return self.kind != .repository;
    }

    fn openPath(self: *const Root, relative: [*:0]const u8, flags: linux.O, mode: u64) Error!i32 {
        if (self.closed) return error.Unavailable;
        var how = OpenHow{
            .flags = flagsValue(flags),
            .mode = mode,
            .resolve = resolve_live,
        };
        return openat2Fd(self.fd, relative, &how);
    }

    pub fn lookupFile(self: *const Root, relative: [*:0]const u8) Error!void {
        const fd = try self.openPath(relative, .{ .PATH = true, .CLOEXEC = true }, 0);
        defer closeFd(fd);
        const stx = try statxFd(fd);
        if (!linux.S.ISREG(stx.mode) and !linux.S.ISDIR(stx.mode)) return error.Denied;
    }

    pub fn readFile(self: *const Root, relative: [*:0]const u8, buffer: []u8) Error!usize {
        const fd = try self.openPath(relative, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
        defer closeFd(fd);
        const stx = try statxFd(fd);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
        const n = linux.read(fd, buffer.ptr, buffer.len);
        if (linux.errno(n) != .SUCCESS) return error.Unavailable;
        return n;
    }

    pub fn createFile(self: *const Root, relative: [*:0]const u8) Error!void {
        if (!self.isPrivate()) return error.Denied;
        const fd = try self.openPath(relative, .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .EXCL = true,
            .NONBLOCK = true,
            .CLOEXEC = true,
        }, 0o600);
        defer closeFd(fd);
        const stx = try statxFd(fd);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
    }

    pub fn writeFile(self: *const Root, relative: [*:0]const u8, data: []const u8) Error!void {
        if (!self.isPrivate()) return error.Denied;
        const fd = try self.openPath(relative, .{ .ACCMODE = .RDWR, .NONBLOCK = true, .CLOEXEC = true }, 0);
        defer closeFd(fd);
        const stx = try statxFd(fd);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
        if (linux.errno(linux.ftruncate(fd, 0)) != .SUCCESS) return error.Unavailable;
        const n = linux.write(fd, data.ptr, data.len);
        if (linux.errno(n) != .SUCCESS) return error.Unavailable;
    }

    pub fn unlinkFile(self: *const Root, relative: [*:0]const u8) Error!void {
        if (!self.isPrivate()) return error.Denied;
        const inspect = try self.openPath(relative, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer closeFd(inspect);
        const stx = try statxFd(inspect);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
        const parts = try parentName(relative);
        var parent_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        var name_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        const parent_z = try copyZ(&parent_buf, parts.parent);
        const name_z = try copyZ(&name_buf, parts.name);
        const parent_fd = try self.openPath(parent_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        defer closeFd(parent_fd);
        if (linux.errno(linux.unlinkat(parent_fd, name_z, 0)) != .SUCCESS) return error.Denied;
    }

    pub fn renameSameDirectory(self: *const Root, old_name: [*:0]const u8, new_name: [*:0]const u8) Error!void {
        if (!self.isPrivate()) return error.Denied;
        const old_parts = try parentName(old_name);
        const new_parts = try parentName(new_name);
        if (!std.mem.eql(u8, old_parts.parent, new_parts.parent)) return error.Denied;
        const inspect = try self.openPath(old_name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer closeFd(inspect);
        const stx = try statxFd(inspect);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
        var parent_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        var old_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        var new_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        const parent_z = try copyZ(&parent_buf, old_parts.parent);
        const old_z = try copyZ(&old_buf, old_parts.name);
        const new_z = try copyZ(&new_buf, new_parts.name);
        const parent_fd = try self.openPath(parent_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        defer closeFd(parent_fd);
        if (linux.errno(linux.renameat(parent_fd, old_z, parent_fd, new_z)) != .SUCCESS) return error.Denied;
    }

    pub fn linkSameDirectory(self: *const Root, existing_name: [*:0]const u8, new_name: [*:0]const u8) Error!void {
        if (!self.isPrivate()) return error.Denied;
        const existing_parts = try parentName(existing_name);
        const new_parts = try parentName(new_name);
        if (!std.mem.eql(u8, existing_parts.parent, new_parts.parent)) return error.Denied;
        const inspect = try self.openPath(existing_name, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        defer closeFd(inspect);
        const stx = try statxFd(inspect);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
        var parent_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        var existing_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        var new_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        const parent_z = try copyZ(&parent_buf, existing_parts.parent);
        const existing_z = try copyZ(&existing_buf, existing_parts.name);
        const new_z = try copyZ(&new_buf, new_parts.name);
        const parent_fd = try self.openPath(parent_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        defer closeFd(parent_fd);
        if (linux.errno(linux.linkat(parent_fd, existing_z, parent_fd, new_z, 0)) != .SUCCESS) return error.Denied;
    }

    pub fn openHandle(self: *Root, relative: [*:0]const u8) Error!u32 {
        const fd = try self.openPath(relative, .{ .ACCMODE = .RDONLY, .NONBLOCK = true, .CLOEXEC = true }, 0);
        errdefer closeFd(fd);
        const stx = try statxFd(fd);
        if (!linux.S.ISREG(stx.mode)) return error.Denied;
        for (&self.handles) |*slot| {
            if (slot.* == null) {
                const id = self.next_handle_id;
                self.next_handle_id += 1;
                slot.* = .{ .id = id, .fd = fd };
                return id;
            }
        }
        closeFd(fd);
        return error.Unavailable;
    }

    pub fn readHandle(self: *const Root, id: u32, buffer: []u8) Error!usize {
        for (self.handles) |slot| {
            if (slot) |owned| {
                if (owned.id == id) {
                    const n = linux.read(owned.fd, buffer.ptr, buffer.len);
                    if (linux.errno(n) != .SUCCESS) return error.Unavailable;
                    return n;
                }
            }
        }
        return error.Denied;
    }

    pub fn closeHandle(self: *Root, id: u32) Error!void {
        for (&self.handles) |*slot| {
            if (slot.*) |owned| {
                if (owned.id == id) {
                    closeFd(owned.fd);
                    slot.* = null;
                    return;
                }
            }
        }
        return error.Denied;
    }

    pub fn mkdirDenied(_: *const Root, _: [*:0]const u8) Error!void {
        return error.Denied;
    }

    pub fn symlinkDenied(_: *const Root, _: [*:0]const u8, _: [*:0]const u8) Error!void {
        return error.Denied;
    }
};

pub fn identitiesEqual(left: Identity, right: Identity) bool {
    return left.dev_major == right.dev_major and
        left.dev_minor == right.dev_minor and
        left.ino == right.ino and
        left.btime_sec == right.btime_sec and
        left.btime_nsec == right.btime_nsec;
}

fn dirAbs(tmp: anytype, name: []const u8, buf: *[std.fs.max_path_bytes:0]u8) ![:0]const u8 {
    var sub = try tmp.dir.openDir(std.testing.io, name, .{});
    defer sub.close(std.testing.io);
    const n = try sub.realPath(std.testing.io, buf);
    buf[n] = 0;
    return buf[0..n :0];
}

test "live root pins identity and rejects pathname replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root-a");
    try tmp.dir.createDirPath(std.testing.io, "root-b");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root-a/file.txt", .data = "inside-a" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root-b/file.txt", .data = "inside-b" });

    var path_a: [std.fs.max_path_bytes:0]u8 = undefined;
    const root_a_path = try dirAbs(&tmp, "root-a", &path_a);
    var root = try Root.pin(.repository, root_a_path);
    defer root.close();
    try root.verify();
    try root.lookupFile("file.txt");

    try tmp.dir.rename("root-a", tmp.dir, "root-a-moved", std.testing.io);
    try tmp.dir.rename("root-b", tmp.dir, "root-a", std.testing.io);
    try root.verify();
    var buffer: [16]u8 = undefined;
    const n = try root.readFile("file.txt", &buffer);
    try std.testing.expectEqualStrings("inside-a", buffer[0..n]);

    var replaced = try Root.pin(.repository, root_a_path);
    defer replaced.close();
    try std.testing.expect(!identitiesEqual(root.identity, replaced.identity));
}

test "openat2 denies escapes, magic links, and outside symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "root");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "root/inside.txt", .data = "ok" });
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "secret.txt", .data = "no" });
    try tmp.dir.symLink(std.testing.io, "../secret.txt", "root/outside", .{});
    try tmp.dir.symLink(std.testing.io, "inside.txt", "root/inside-link", .{});
    try tmp.dir.symLink(std.testing.io, "/proc/self/root/etc/passwd", "root/magic", .{});

    var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    var root = try Root.pin(.repository, try dirAbs(&tmp, "root", &path_buf));
    defer root.close();

    try root.lookupFile("inside-link");
    try std.testing.expectError(error.Denied, root.lookupFile("../secret.txt"));
    try std.testing.expectError(error.Denied, root.lookupFile("outside"));
    try std.testing.expectError(error.Denied, root.lookupFile("magic"));
    var ignore: [1]u8 = undefined;
    try std.testing.expectError(error.Denied, root.readFile("outside", &ignore));

    var fifo_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    const fifo_path = try std.fmt.bufPrintZ(&fifo_buf, "{s}/fifo", .{try dirAbs(&tmp, "root", &path_buf)});
    if (linux.errno(linux.mknod(fifo_path, linux.S.IFIFO | 0o600, 0)) == .SUCCESS) {
        try std.testing.expectError(error.Denied, root.lookupFile("fifo"));
        try std.testing.expectError(error.Denied, root.readFile("fifo", &ignore));
    }
}

test "operation table denies repository writes and private directory mutations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "repo");
    try tmp.dir.createDirPath(std.testing.io, "cache/nested");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "repo/a.txt", .data = "repo" });

    var repo_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    var cache_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    var repo = try Root.pin(.repository, try dirAbs(&tmp, "repo", &repo_buf));
    defer repo.close();
    var cache = try Root.pin(.cache, try dirAbs(&tmp, "cache", &cache_buf));
    defer cache.close();

    try std.testing.expectError(error.Denied, repo.createFile("new.txt"));
    try std.testing.expectError(error.Denied, repo.writeFile("a.txt", "x"));
    try std.testing.expectError(error.Denied, repo.unlinkFile("a.txt"));
    try std.testing.expectError(error.Denied, repo.mkdirDenied("dir"));
    try std.testing.expectError(error.Denied, cache.mkdirDenied("other"));
    try std.testing.expectError(error.Denied, cache.symlinkDenied("a", "b"));
    try std.testing.expectError(error.Denied, cache.renameSameDirectory("nested/x", "y"));

    try cache.createFile("late-root.txt");
    try cache.writeFile("late-root.txt", "root-file");
    try cache.linkSameDirectory("late-root.txt", "late-link.txt");
    try cache.renameSameDirectory("late-root.txt", "late-renamed.txt");
    try cache.unlinkFile("late-link.txt");
    try cache.createFile("nested/late.txt");
    try cache.writeFile("nested/late.txt", "created-after-admission");
    try cache.renameSameDirectory("nested/late.txt", "nested/moved.txt");
    try cache.linkSameDirectory("nested/moved.txt", "nested/linked.txt");
    const handle = try cache.openHandle("nested/linked.txt");
    try cache.unlinkFile("nested/linked.txt");
    var handle_buf: [32]u8 = undefined;
    const hn = try cache.readHandle(handle, &handle_buf);
    try std.testing.expectEqualStrings("created-after-admission", handle_buf[0..hn]);
    try cache.closeHandle(handle);
    try std.testing.expectError(error.Denied, cache.readHandle(handle, &handle_buf));
}

test "live tree sees files created after pinning" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, "repo");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "repo/early.txt", .data = "early" });
    var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
    var root = try Root.pin(.repository, try dirAbs(&tmp, "repo", &path_buf));
    defer root.close();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "repo/late.txt", .data = "late" });
    var buffer: [8]u8 = undefined;
    const n = try root.readFile("late.txt", &buffer);
    try std.testing.expectEqualStrings("late", buffer[0..n]);
}
