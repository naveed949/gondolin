//! Exact execve-name admission using the kernel-owned linux_binprm filename.
//! The caller installs this before admitting a process to its cgroup and keeps
//! the pinned link until the entire cgroup is empty. Landlock remains responsible
//! for filesystem access; this guard distinguishes direct loader and alias names.
const std = @import("std");
const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("fcntl.h");
    @cInclude("linux/bpf.h");
    @cInclude("sys/syscall.h");
    @cInclude("unistd.h");
});

const path_size = 4096;
const Attr = struct {
    bytes: [144]u8 align(8) = @splat(0),
    fn put(self: *Attr, comptime T: type, offset: usize, value: T) void {
        std.mem.writeInt(T, self.bytes[offset..][0..@sizeOf(T)], value, .little);
    }
};

/// A pinned kernel policy whose lifetime must encompass all invocation tasks
pub const Guard = struct {
    allocator: std.mem.Allocator,
    pin_path: [:0]u8,
    link_fd: c_int,

    /// Release only after independently confirming that the cgroup is empty
    pub fn close(self: *Guard) void {
        _ = c.unlink(self.pin_path.ptr);
        _ = c.close(self.link_fd);
        self.allocator.free(self.pin_path);
        self.* = undefined;
    }
};

fn bpf(command: c_uint, attr: *Attr, size: usize) !c_int {
    const result = c.syscall(c.SYS_bpf, command, &attr.bytes, size);
    if (result < 0) return error.ExecGuardUnavailable;
    return @intCast(result);
}

fn readBtf(allocator: std.mem.Allocator) ![]u8 {
    const fd = c.open("/sys/kernel/btf/vmlinux", c.O_RDONLY | c.O_CLOEXEC);
    if (fd < 0) return error.ExecGuardBtfUnavailable;
    defer _ = c.close(fd);
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    var buffer: [8192]u8 = undefined;
    while (true) {
        const size = c.read(fd, &buffer, buffer.len);
        if (size < 0) return error.ExecGuardBtfUnavailable;
        if (size == 0) break;
        if (result.items.len + @as(usize, @intCast(size)) > 64 * 1024 * 1024) return error.InvalidExecGuardBtf;
        try result.appendSlice(allocator, buffer[0..@intCast(size)]);
    }
    return result.toOwnedSlice(allocator);
}

const BtfLayout = struct { filename_offset: u32, hook_id: u32 };

fn word(bytes: []const u8, offset: usize) !u32 {
    if (offset > bytes.len or bytes.len - offset < 4) return error.InvalidExecGuardBtf;
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

fn btfName(strings: []const u8, offset: u32) ![]const u8 {
    if (offset >= strings.len) return error.InvalidExecGuardBtf;
    const tail = strings[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return error.InvalidExecGuardBtf;
    return tail[0..end];
}

fn parseBtf(bytes: []const u8) !BtfLayout {
    if (bytes.len < 24 or bytes[0] != 0x9f or bytes[1] != 0xeb or bytes[2] != 1) return error.InvalidExecGuardBtf;
    const header_size = try word(bytes, 4);
    if (header_size < 24 or header_size > bytes.len) return error.InvalidExecGuardBtf;
    const payload = bytes[header_size..];
    const type_offset = try word(bytes, 8);
    const type_length = try word(bytes, 12);
    const string_offset = try word(bytes, 16);
    const string_length = try word(bytes, 20);
    if (type_offset > payload.len or type_length > payload.len - type_offset or
        string_offset > payload.len or string_length > payload.len - string_offset) return error.InvalidExecGuardBtf;
    const types = payload[type_offset..][0..type_length];
    const strings = payload[string_offset..][0..string_length];
    var offset: usize = 0;
    var id: u32 = 1;
    var filename_offset: ?u32 = null;
    var hook_id: ?u32 = null;
    while (offset < types.len) : (id += 1) {
        const name = try btfName(strings, try word(types, offset));
        const info = try word(types, offset + 4);
        _ = try word(types, offset + 8);
        const kind = (info >> 24) & 0x1f;
        const count: usize = info & 0xffff;
        const extra: usize = switch (kind) {
            1, 14, 17 => 4,
            2, 7, 8, 9, 10, 11, 12, 16, 18 => 0,
            3 => 12,
            4, 5, 15, 19 => 12 * count,
            6, 13 => 8 * count,
            else => return error.InvalidExecGuardBtf,
        };
        if (types.len - offset < 12 or extra > types.len - offset - 12) return error.InvalidExecGuardBtf;
        if (kind == 12 and std.mem.eql(u8, name, "bpf_lsm_bprm_check_security")) {
            if (hook_id != null) return error.InvalidExecGuardBtf;
            hook_id = id;
        }
        if (kind == 4 and std.mem.eql(u8, name, "linux_binprm")) {
            for (0..count) |index| {
                const member = offset + 12 + index * 12;
                if (!std.mem.eql(u8, try btfName(strings, try word(types, member)), "filename")) continue;
                var bits = try word(types, member + 8);
                if ((info & 0x80000000) != 0) {
                    if (bits >> 24 != 0) return error.InvalidExecGuardBtf;
                    bits &= 0xffffff;
                }
                if (bits % 8 != 0 or bits / 8 > 32767 or filename_offset != null) return error.InvalidExecGuardBtf;
                filename_offset = bits / 8;
            }
        }
        offset += 12 + extra;
    }
    return .{
        .filename_offset = filename_offset orelse return error.ExecGuardBtfUnavailable,
        .hook_id = hook_id orelse return error.ExecGuardBtfUnavailable,
    };
}

const Insn = extern struct { code: u8, registers: u8, offset: i16 = 0, immediate: i32 = 0 };
const Program = struct {
    items: [640]Insn = undefined,
    len: usize = 0,
    fn emit(self: *Program, code: u8, dst: u4, src: u4, offset: i16, immediate: i32) usize {
        const index = self.len;
        self.items[index] = .{ .code = code, .registers = @as(u8, dst) | (@as(u8, src) << 4), .offset = offset, .immediate = immediate };
        self.len += 1;
        return index;
    }
    fn jump(self: *Program, index: usize, destination: usize) void {
        self.items[index].offset = @intCast(destination - index - 1);
    }
    fn imm64(self: *Program, dst: u4, src: u4, value: u64) void {
        _ = self.emit(0x18, dst, src, 0, @bitCast(@as(u32, @truncate(value))));
        _ = self.emit(0, 0, 0, 0, @bitCast(@as(u32, @truncate(value >> 32))));
    }
    fn call(self: *Program, helper: i32) void {
        _ = self.emit(0x85, 0, 0, 0, helper);
    }
};

fn program(cgroup_id: u64, allowed_fd: c_int, scratch_fd: c_int, filename_offset: u32) Program {
    var p = Program{};
    _ = p.emit(0xbf, 6, 1, 0, 0); // r6 = LSM context
    _ = p.emit(0x79, 0, 6, 8, 0); // preserve the preceding LSM result
    const prior_denial = p.emit(0x55, 0, 0, 0, 0);
    p.call(c.BPF_FUNC_get_current_cgroup_id);
    p.imm64(7, 0, cgroup_id);
    const other_cgroup = p.emit(0x5d, 0, 7, 0, 0);
    _ = p.emit(0x62, 10, 0, -4, 0); // scratch key = 0
    p.imm64(1, c.BPF_PSEUDO_MAP_FD, @intCast(scratch_fd));
    _ = p.emit(0xbf, 2, 10, 0, 0);
    _ = p.emit(0x07, 2, 0, 0, -4);
    p.call(c.BPF_FUNC_map_lookup_elem);
    const no_scratch = p.emit(0x15, 0, 0, 0, 0);
    _ = p.emit(0xbf, 7, 0, 0, 0);
    // Clear the full fixed-size hash key, including bytes past the terminating NUL.
    for (0..path_size / 8) |index| _ = p.emit(0x7a, 7, 0, @intCast(index * 8), 0);
    _ = p.emit(0x79, 3, 6, 0, 0); // kernel linux_binprm pointer
    _ = p.emit(0x07, 3, 0, 0, @intCast(filename_offset));
    _ = p.emit(0xbf, 1, 10, 0, 0);
    _ = p.emit(0x07, 1, 0, 0, -16);
    _ = p.emit(0xb7, 2, 0, 0, 8);
    p.call(c.BPF_FUNC_probe_read_kernel);
    const bad_pointer = p.emit(0x55, 0, 0, 0, 0);
    _ = p.emit(0xbf, 1, 7, 0, 0);
    _ = p.emit(0xb7, 2, 0, 0, path_size);
    _ = p.emit(0x79, 3, 10, -16, 0);
    p.call(c.BPF_FUNC_probe_read_kernel_str);
    const bad_name = p.emit(0xc5, 0, 0, 0, 1); // signed r0 < 1
    const truncated_name = p.emit(0x35, 0, 0, 0, path_size); // includes ambiguous exact-limit result
    p.imm64(1, c.BPF_PSEUDO_MAP_FD, @intCast(allowed_fd));
    _ = p.emit(0xbf, 2, 7, 0, 0);
    p.call(c.BPF_FUNC_map_lookup_elem);
    const admitted = p.emit(0x55, 0, 0, 0, 0);
    const deny = p.emit(0xb7, 0, 0, 0, -13); // -EACCES
    const denied_exit = p.emit(0x95, 0, 0, 0, 0);
    const allow = p.emit(0xb7, 0, 0, 0, 0);
    _ = p.emit(0x95, 0, 0, 0, 0);
    p.jump(prior_denial, denied_exit);
    p.jump(other_cgroup, allow);
    for ([_]usize{ no_scratch, bad_pointer, bad_name, truncated_name }) |index| p.jump(index, deny);
    p.jump(admitted, allow);
    return p;
}

fn createMap(map_type: u32, key_size: u32, value_size: u32, count: u32, flags: u32) !c_int {
    var attr = Attr{};
    attr.put(u32, 0, map_type);
    attr.put(u32, 4, key_size);
    attr.put(u32, 8, value_size);
    attr.put(u32, 12, count);
    attr.put(u32, 16, flags);
    return bpf(c.BPF_MAP_CREATE, &attr, 20);
}

/// Install before opening the payload's start gate; bpffs must already be mounted
pub fn install(allocator: std.mem.Allocator, cgroup_path: []const u8, executables: []const []const u8) !Guard {
    if (executables.len == 0 or executables.len > 1024) return error.InvalidExecGuardPolicy;
    const cgroup_z = try allocator.dupeZ(u8, cgroup_path);
    defer allocator.free(cgroup_z);
    var stat: std.os.linux.Statx = undefined;
    if (std.c.statx(std.os.linux.AT.FDCWD, cgroup_z.ptr, 0, .{ .INO = true }, &stat) != 0 or !stat.mask.INO) return error.ExecGuardCgroupUnavailable;
    const btf = try readBtf(allocator);
    defer allocator.free(btf);
    const layout = try parseBtf(btf);
    const allowed_fd = try createMap(c.BPF_MAP_TYPE_HASH, path_size, 1, @intCast(executables.len), c.BPF_F_RDONLY_PROG);
    defer _ = c.close(allowed_fd);
    for (executables) |executable| {
        if (executable.len == 0 or executable[0] != '/' or executable.len >= path_size - 1 or std.mem.indexOfScalar(u8, executable, 0) != null) return error.InvalidExecGuardPolicy;
        var key: [path_size]u8 = @splat(0);
        @memcpy(key[0..executable.len], executable);
        var value: u8 = 1;
        var update = Attr{};
        update.put(u32, 0, @intCast(allowed_fd));
        update.put(u64, 8, @intFromPtr(&key));
        update.put(u64, 16, @intFromPtr(&value));
        _ = try bpf(c.BPF_MAP_UPDATE_ELEM, &update, 32);
    }
    var freeze = Attr{};
    freeze.put(u32, 0, @intCast(allowed_fd));
    _ = try bpf(c.BPF_MAP_FREEZE, &freeze, 4);
    const scratch_fd = try createMap(c.BPF_MAP_TYPE_PERCPU_ARRAY, 4, path_size, 1, 0);
    defer _ = c.close(scratch_fd);
    var instructions = program(stat.ino, allowed_fd, scratch_fd, layout.filename_offset);
    var log_buffer: [65536]u8 = @splat(0);
    var load_attr = Attr{};
    load_attr.put(u32, 0, c.BPF_PROG_TYPE_LSM);
    load_attr.put(u32, 4, @intCast(instructions.len));
    load_attr.put(u64, 8, @intFromPtr(&instructions.items));
    load_attr.put(u64, 16, @intFromPtr("GPL"));
    load_attr.put(u32, 24, 1);
    load_attr.put(u32, 28, log_buffer.len);
    load_attr.put(u64, 32, @intFromPtr(&log_buffer));
    load_attr.put(u32, 68, c.BPF_LSM_MAC);
    load_attr.put(u32, 108, layout.hook_id);
    const program_fd = bpf(c.BPF_PROG_LOAD, &load_attr, 112) catch |err| {
        const end = std.mem.indexOfScalar(u8, &log_buffer, 0) orelse log_buffer.len;
        std.log.err("exec guard verifier: {s}", .{log_buffer[0..end]});
        return err;
    };
    defer _ = c.close(program_fd);
    var link_attr = Attr{};
    link_attr.put(u32, 0, @intCast(program_fd));
    link_attr.put(u32, 8, c.BPF_LSM_MAC);
    const link_fd = try bpf(c.BPF_LINK_CREATE, &link_attr, 16);
    errdefer _ = c.close(link_fd);
    const pin_path = try std.fmt.allocPrintSentinel(allocator, "/sys/fs/bpf/gondolin-exec-{d}", .{stat.ino}, 0);
    errdefer allocator.free(pin_path);
    var pin_attr = Attr{};
    pin_attr.put(u64, 0, @intFromPtr(pin_path.ptr));
    pin_attr.put(u32, 8, @intCast(link_fd));
    _ = try bpf(c.BPF_OBJ_PIN, &pin_attr, 16);
    return .{ .allocator = allocator, .pin_path = pin_path, .link_fd = link_fd };
}

test "reject malformed BTF without accepting fixed kernel offsets" {
    try std.testing.expectError(error.InvalidExecGuardBtf, parseBtf(""));
    var bytes: [24]u8 = @splat(0);
    bytes[0] = 0x9f;
    bytes[1] = 0xeb;
    bytes[2] = 1;
    std.mem.writeInt(u32, bytes[4..8], 24, .little);
    std.mem.writeInt(u32, bytes[12..16], 4096, .little);
    try std.testing.expectError(error.InvalidExecGuardBtf, parseBtf(&bytes));
}

test "program handles full paths and preserves earlier LSM denial" {
    const p = program(0x123456789abcdef0, 7, 8, 96);
    try std.testing.expect(p.len < p.items.len);
    const previous_denial_target = 2 + 1 + @as(usize, @intCast(p.items[2].offset));
    try std.testing.expectEqual(@as(u8, 0x95), p.items[previous_denial_target].code);
    var clear_count: usize = 0;
    for (p.items[0..p.len]) |instruction| {
        if (instruction.code == 0x7a) clear_count += 1;
    }
    try std.testing.expectEqual(@as(usize, path_size / 8), clear_count);
}

test "empty policy never attaches a permissive guard" {
    try std.testing.expectError(error.InvalidExecGuardPolicy, install(std.testing.allocator, "/missing", &.{}));
}

test "BTF determines filename member and hook independently of kernel layout" {
    const names = "\x00linux_binprm\x00filename\x00bpf_lsm_bprm_check_security\x00";
    var bytes: [24 + 36 + names.len]u8 = @splat(0);
    bytes[0] = 0x9f;
    bytes[1] = 0xeb;
    bytes[2] = 1;
    std.mem.writeInt(u32, bytes[4..8], 24, .little);
    std.mem.writeInt(u32, bytes[12..16], 36, .little);
    std.mem.writeInt(u32, bytes[16..20], 36, .little);
    std.mem.writeInt(u32, bytes[20..24], names.len, .little);
    std.mem.writeInt(u32, bytes[24..28], 1, .little);
    std.mem.writeInt(u32, bytes[28..32], (4 << 24) | 1, .little);
    std.mem.writeInt(u32, bytes[32..36], 256, .little);
    std.mem.writeInt(u32, bytes[36..40], 14, .little);
    std.mem.writeInt(u32, bytes[44..48], 136 * 8, .little);
    std.mem.writeInt(u32, bytes[48..52], 23, .little);
    std.mem.writeInt(u32, bytes[52..56], 12 << 24, .little);
    @memcpy(bytes[60..], names);
    const layout = try parseBtf(&bytes);
    try std.testing.expectEqual(@as(u32, 136), layout.filename_offset);
    try std.testing.expectEqual(@as(u32, 2), layout.hook_id);
    std.mem.writeInt(u32, bytes[44..48], 136 * 8 + 1, .little);
    try std.testing.expectError(error.InvalidExecGuardBtf, parseBtf(&bytes));
}
