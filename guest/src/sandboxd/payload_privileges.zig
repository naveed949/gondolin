//! Irreversible privilege ceiling for a forked capability payload and its descendants.
//! Call after privileged mount/Landlock setup and before executing caller code.
const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const Filter = extern struct { code: u16, jt: u8 = 0, jf: u8 = 0, k: u32 };
const Program = extern struct { len: u16, filter: [*]const Filter };
// Linux's cap header contains a 32-bit pid even on 64-bit targets.
const CapHeader = extern struct { version: u32 = 0x20080522, pid: u32 = 0 };
const CapData = extern struct { effective: u32 = 0, permitted: u32 = 0, inheritable: u32 = 0 };
const pr_set_securebits = 28;
const pr_get_securebits = 27;
const pr_capbset_read = 23;
const pr_capbset_drop = 24;
const pr_cap_ambient = 47;
const pr_cap_ambient_clear_all = 4;
const pr_set_no_new_privs = 38;
const pr_get_no_new_privs = 39;
// NOROOT + NO_SETUID_FIXUP locked, KEEP_CAPS off and locked, ambient raising locked.
const securebits = 1 | 2 | 4 | 8 | 32 | 64 | 128;
const ret_allow: u32 = 0x7fff0000;
const ret_kill_process: u32 = 0x80000000;
const ret_eperm: u32 = 0x00050000 | @as(u32, @intFromEnum(linux.E.PERM));
const ret_enosys: u32 = 0x00050000 | @as(u32, @intFromEnum(linux.E.NOSYS));
const audit_arch: u32 = switch (builtin.cpu.arch) {
    .x86_64 => 0xc000003e,
    .aarch64 => 0xc00000b7,
    else => @compileError("Capability payload seccomp supports only x86_64 and aarch64"),
};
// All namespace-creation flags, plus CLONE_PTRACE. Normal process/thread clones remain valid.
const forbidden_clone_flags: u32 = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x00002000;
const forbidden_syscalls = [_][]const u8{
    "bpf",               "ptrace",         "process_vm_readv",  "process_vm_writev", "pidfd_getfd",
    "mount",             "umount2",        "unshare",           "setns",             "pivot_root",
    "chroot",            "fsopen",         "fsconfig",          "fsmount",           "fspick",
    "open_tree",         "move_mount",     "mount_setattr",     "perf_event_open",   "init_module",
    "finit_module",      "delete_module",  "kexec_load",        "kexec_file_load",   "reboot",
    "io_uring_setup",    "io_uring_enter", "io_uring_register", "userfaultfd",       "open_by_handle_at",
    "name_to_handle_at", "iopl",           "ioperm",            "modify_ldt",        "add_key",
    "request_key",       "keyctl",         "swapon",            "swapoff",
};

const filters = blk: {
    @setEvalBranchQuota(10000);
    var out: [256]Filter = undefined;
    var n: usize = 0;
    // Reject alternate syscall ABIs before inspecting architecture-specific numbers.
    out[n] = .{ .code = 0x20, .k = 4 };
    n += 1; // LD W ABS seccomp_data.arch
    out[n] = .{ .code = 0x15, .jt = 1, .k = audit_arch };
    n += 1;
    out[n] = .{ .code = 0x06, .k = ret_kill_process };
    n += 1;
    out[n] = .{ .code = 0x20, .k = 0 };
    n += 1; // seccomp_data.nr
    if (builtin.cpu.arch == .x86_64) {
        out[n] = .{ .code = 0x45, .jf = 1, .k = 0x40000000 };
        n += 1; // x32 ABI
        out[n] = .{ .code = 0x06, .k = ret_kill_process };
        n += 1;
    }
    for (forbidden_syscalls) |name| {
        if (@hasField(linux.SYS, name)) {
            out[n] = .{ .code = 0x15, .jf = 1, .k = @intFromEnum(@field(linux.SYS, name)) };
            n += 1;
            out[n] = .{ .code = 0x06, .k = ret_eperm };
            n += 1;
        }
    }
    // clone3's pointed-to flags cannot be safely inspected by classic seccomp BPF.
    // ENOSYS preserves libc's fallback to clone for ordinary thread creation.
    out[n] = .{ .code = 0x15, .jf = 1, .k = @intFromEnum(linux.SYS.clone3) };
    n += 1;
    out[n] = .{ .code = 0x06, .k = ret_enosys };
    n += 1;
    out[n] = .{ .code = 0x15, .jf = 3, .k = @intFromEnum(linux.SYS.clone) };
    n += 1;
    out[n] = .{ .code = 0x20, .k = 16 };
    n += 1; // low word of args[0], both supported ABIs
    out[n] = .{ .code = 0x45, .jf = 1, .k = forbidden_clone_flags };
    n += 1;
    out[n] = .{ .code = 0x06, .k = ret_eperm };
    n += 1;
    out[n] = .{ .code = 0x06, .k = ret_allow };
    n += 1;
    break :blk out[0..n].*;
};

fn checked(result: usize) !void {
    if (linux.errno(result) != .SUCCESS) return error.PayloadPrivilegeSetupFailed;
}

/// Irreversible payload-only ceiling; any failure must abort the pending exec
pub fn drop() !void {
    try checked(linux.prctl(pr_set_no_new_privs, 1, 0, 0, 0));
    try checked(linux.prctl(pr_set_securebits, securebits, 0, 0, 0));
    try checked(linux.prctl(pr_cap_ambient, pr_cap_ambient_clear_all, 0, 0, 0));
    // Query the kernel rather than assuming its highest capability number.
    var capability: usize = 0;
    while (capability < 64) : (capability += 1) {
        const present = linux.prctl(pr_capbset_read, capability, 0, 0, 0);
        if (linux.errno(present) == .INVAL) break;
        try checked(present);
        if (present != 0) try checked(linux.prctl(pr_capbset_drop, capability, 0, 0, 0));
    }
    var header: CapHeader = .{};
    const data = [_]CapData{ .{}, .{} };
    try checked(linux.syscall2(.capset, @intFromPtr(&header), @intFromPtr(&data)));
    try installFilter();
}

fn installFilter() !void {
    try checked(linux.prctl(pr_set_no_new_privs, 1, 0, 0, 0));
    const program: Program = .{ .len = filters.len, .filter = &filters };
    try checked(linux.syscall3(.seccomp, linux.SECCOMP.SET_MODE_FILTER, 0, @intFromPtr(&program)));
}

fn verifyDropped() !void {
    var header: CapHeader = .{};
    var data = [_]CapData{ .{}, .{} };
    try checked(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&data)));
    for (data) |word| {
        try std.testing.expectEqual(@as(u32, 0), word.effective | word.permitted | word.inheritable);
    }
    try std.testing.expectEqual(@as(usize, securebits), linux.prctl(pr_get_securebits, 0, 0, 0, 0));
    try std.testing.expectEqual(@as(usize, 1), linux.prctl(pr_get_no_new_privs, 0, 0, 0, 0));
    for (0..64) |capability| {
        const present = linux.prctl(pr_capbset_read, capability, 0, 0, 0);
        if (linux.errno(present) == .INVAL) break;
        try std.testing.expectEqual(@as(usize, 0), present);
        try std.testing.expectEqual(@as(usize, 0), linux.prctl(pr_cap_ambient, 1, capability, 0, 0));
    }
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.prctl(pr_set_securebits, 0, 0, 0, 0)));
    try verifyFilter();
}

fn verifyFilter() !void {
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.syscall3(.bpf, 0, 0, 0)));
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.syscall4(.ptrace, 0, 0, 0, 0)));
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.syscall6(.process_vm_writev, 0, 0, 0, 0, 0, 0)));
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.syscall2(.io_uring_setup, 0, 0)));
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.unshare(0)));
    try std.testing.expectEqual(linux.E.NOSYS, linux.errno(linux.syscall2(.clone3, 0, 0)));
    try std.testing.expectEqual(linux.E.PERM, linux.errno(linux.syscall5(.clone, 0x10000000, 0, 0, 0, 0)));
    // Ordinary descendants remain possible and inherit the same ceiling.
    const child = linux.fork();
    try checked(child);
    if (child == 0) {
        if (linux.errno(linux.syscall3(.bpf, 0, 0, 0)) != .PERM) linux.exit(1);
        linux.exit(0);
    }
    var status: u32 = 0;
    try checked(linux.waitpid(@intCast(child), &status, 0));
    try std.testing.expectEqual(@as(u32, 0), status);
}

test "payload ceiling drops every capability and inherits syscall restrictions across fork" {
    var header: CapHeader = .{};
    var data = [_]CapData{ .{}, .{} };
    try checked(linux.syscall2(.capget, @intFromPtr(&header), @intFromPtr(&data)));
    // Rootless CI cannot set/lock securebits; the guest integration runs as privileged init.
    if ((data[0].effective & (1 << 8)) == 0) return error.SkipZigTest;
    const child = linux.fork();
    try checked(child);
    if (child == 0) {
        drop() catch linux.exit(90);
        verifyDropped() catch linux.exit(91);
        linux.exit(0);
    }
    var status: u32 = 0;
    try checked(linux.waitpid(@intCast(child), &status, 0));
    try std.testing.expectEqual(@as(u32, 0), status);
}

test "payload seccomp denies injection and namespace creation but permits ordinary descendants" {
    const child = linux.fork();
    try checked(child);
    if (child == 0) {
        installFilter() catch linux.exit(90);
        verifyFilter() catch linux.exit(91);
        linux.exit(0);
    }
    var status: u32 = 0;
    try checked(linux.waitpid(@intCast(child), &status, 0));
    try std.testing.expectEqual(@as(u32, 0), status);
}

// Evaluate the emitted classic BPF against adversarial ABI and clone inputs.
fn verdict(arch: u32, syscall: u32, flags: u32) u32 {
    var accumulator: u32 = 0;
    var pc: usize = 0;
    while (pc < filters.len) {
        const instruction = filters[pc];
        pc += 1;
        switch (instruction.code) {
            0x20 => accumulator = switch (instruction.k) {
                0 => syscall,
                4 => arch,
                16 => flags,
                else => unreachable,
            },
            0x15 => pc += if (accumulator == instruction.k) instruction.jt else instruction.jf,
            0x45 => pc += if (accumulator & instruction.k != 0) instruction.jt else instruction.jf,
            0x06 => return instruction.k,
            else => unreachable,
        }
    }
    unreachable;
}

test "seccomp rejects alternate ABIs and every namespace clone flag" {
    try std.testing.expectEqual(ret_kill_process, verdict(0x40000003, @intFromEnum(linux.SYS.read), 0));
    if (builtin.cpu.arch == .x86_64) {
        try std.testing.expectEqual(ret_kill_process, verdict(audit_arch, 0x40000000 | @intFromEnum(linux.SYS.read), 0));
    }
    inline for (forbidden_syscalls) |name| {
        if (@hasField(linux.SYS, name)) {
            try std.testing.expectEqual(ret_eperm, verdict(audit_arch, @intFromEnum(@field(linux.SYS, name)), 0));
        }
    }
    for (0..32) |bit| {
        const flag = @as(u32, 1) << @intCast(bit);
        if (flag & forbidden_clone_flags == 0) continue;
        try std.testing.expectEqual(ret_eperm, verdict(audit_arch, @intFromEnum(linux.SYS.clone), flag));
    }
    try std.testing.expectEqual(ret_enosys, verdict(audit_arch, @intFromEnum(linux.SYS.clone3), 0));
    try std.testing.expectEqual(ret_allow, verdict(audit_arch, @intFromEnum(linux.SYS.clone), 0x100 | 0x10000 | 0x800));
    inline for (.{ "read", "write", "execve", "wait4", "mmap", "mprotect", "futex" }) |name| {
        try std.testing.expectEqual(ret_allow, verdict(audit_arch, @intFromEnum(@field(linux.SYS, name)), 0));
    }
}
