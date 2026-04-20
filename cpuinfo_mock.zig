const std = @import("std");
const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("stdio.h");
});
const hook = @import("hook.zig");

var fopen_hook = hook.HookEntry{ .symbol = "fopen", .original = null };

const fake_cpuinfo =
    \\processor : 0
    \\vendor_id : GenuineIntel
    \\flags     : fpu hypervisor sse sse2
    \\
;

export fn fopen(path: [*:0]const u8, mode: [*:0]const u8) ?*c.FILE {
    if (std.mem.eql(u8, std.mem.span(path), "/proc/cpuinfo"))
        return c.fmemopen(@constCast(fake_cpuinfo.ptr), fake_cpuinfo.len, "r");

    const original_fn: *const fn ([*:0]const u8, [*:0]const u8) ?*c.FILE =
        @ptrCast(hook.resolve_original(&fopen_hook) orelse return null);
    return original_fn(path, mode);
}
