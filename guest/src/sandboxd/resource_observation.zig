//! Strict cgroup accounting inputs; unavailable observations never become zero.
const std = @import("std");

pub const ObservationError = error{ InvalidCounter, CounterRegression };

pub const cpu_allowance_usec: u64 = 5_000;

pub fn cpuAgrees(cgroup_usec: u64, wait4_usec: u64) bool {
    const hi = @max(cgroup_usec, wait4_usec);
    const lo = @min(cgroup_usec, wait4_usec);
    return hi - lo <= cpu_allowance_usec;
}

pub fn integer(contents: []const u8) ObservationError!u64 {
    const value = std.mem.trim(u8, contents, " \r\n\t");
    if (value.len == 0) return error.InvalidCounter;
    for (value) |byte| if (byte < '0' or byte > '9') return error.InvalidCounter;
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidCounter;
}

pub fn counter(contents: []const u8, key: []const u8) ObservationError!u64 {
    var found: ?u64 = null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const name = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, key)) continue;
        if (found != null) return error.InvalidCounter;
        found = try integer(fields.next() orelse return error.InvalidCounter);
        if (fields.next() != null) return error.InvalidCounter;
    }
    return found orelse error.InvalidCounter;
}

pub const Sample = struct {
    /// Cumulative payload cgroup CPU in `us`, or unavailable without resource limits
    cpu_usec: ?u64,
    /// Cgroup charged memory peak in `bytes`, or unavailable without resource limits
    memory_peak: ?u64,
    /// Peak simultaneous entrypoint and descendant membership
    pids_peak: u64,
    /// Cumulative memory ceiling events, or unavailable without resource limits
    memory_max: ?u64,
    /// Cumulative out-of-memory events, or unavailable without resource limits
    memory_oom: ?u64,
    /// Cumulative out-of-memory kills, or unavailable without resource limits
    memory_oom_kill: ?u64,
    /// Cumulative PID ceiling events
    pids_max: u64,

    pub fn checkAfter(self: Sample, previous: Sample) ObservationError!void {
        inline for (std.meta.fields(Sample)) |field| {
            const current: ?u64 = @field(self, field.name);
            const prior: ?u64 = @field(previous, field.name);
            if ((current == null) != (prior == null)) return error.CounterRegression;
            if (current != null and current.? < prior.?) return error.CounterRegression;
        }
    }
};

test "missing, malformed, duplicate and overflowing counters are unavailable" {
    try std.testing.expectEqual(@as(u64, 0), try counter("max 0\n", "max"));
    try std.testing.expectEqual(@as(u64, 123), try counter("user_usec 3\nusage_usec\t123\n", "usage_usec"));
    for ([_][]const u8{ "", "other 0\n", "max\n", "max -1\n", "max +1\n", "max 1_0\n", "max 1 extra\n", "max 0\nmax 1\n", "max 18446744073709551616\n" }) |bad| {
        try std.testing.expectError(error.InvalidCounter, counter(bad, "max"));
    }
    for ([_][]const u8{ "", "-1", "+0", "1_000", "1 2", "18446744073709551616" }) |bad| {
        try std.testing.expectError(error.InvalidCounter, integer(bad));
    }
}

test "cgroup and wait4 CPU must agree within 5 ms" {
    try std.testing.expect(cpuAgrees(1_000, 5_999));
    try std.testing.expect(cpuAgrees(8_000, 3_000));
    try std.testing.expect(!cpuAgrees(0, 5_001));
}

test "any accounting counter regression rejects the observation" {
    const baseline: Sample = .{ .cpu_usec = 4, .memory_peak = 8, .pids_peak = 2, .memory_max = 2, .memory_oom = 2, .memory_oom_kill = 2, .pids_max = 2 };
    try baseline.checkAfter(baseline);
    inline for (std.meta.fields(Sample)) |field| {
        var changed = baseline;
        @field(changed, field.name) = 0;
        try std.testing.expectError(error.CounterRegression, changed.checkAfter(baseline));
    }
    var missing = baseline;
    missing.cpu_usec = null;
    try std.testing.expectError(error.CounterRegression, missing.checkAfter(baseline));
}
