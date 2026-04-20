const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("stdio.h");
    @cInclude("unistd.h");
});
const hook = @import("hook.zig");

var puts_hook  = hook.HookEntry{ .symbol = "puts",  .original = null };
var fopen_hook = hook.HookEntry{ .symbol = "fopen", .original = null };
var read_hook  = hook.HookEntry{ .symbol = "read",  .original = null };

export fn puts(str: [*:0]const u8) c_int {
    _ = c.fprintf(c.stderr, "[HOOKED] puts called with: %s\n", str);
    const original_fn: *const fn ([*:0]const u8) c_int =
        @ptrCast(hook.resolve_original(&puts_hook) orelse return -1);
    return original_fn(str);
}

export fn fopen(filename: [*:0]const u8, mode: [*:0]const u8) ?*c.FILE {
    _ = c.fprintf(c.stderr, "[HOOKED] fopen called with: %s (mode: %s)\n", filename, mode);
    const original_fn: *const fn ([*:0]const u8, [*:0]const u8) ?*c.FILE =
        @ptrCast(hook.resolve_original(&fopen_hook) orelse return null);
    return original_fn(filename, mode);
}

export fn read(fd: c_int, buf: ?*anyopaque, count: usize) isize {
    const original_fn: *const fn (c_int, ?*anyopaque, usize) isize =
        @ptrCast(hook.resolve_original(&read_hook) orelse return -1);
    const bytes_read = original_fn(fd, buf, count);
    if (bytes_read > 0)
        _ = c.fprintf(c.stderr, "[HOOKED] read called with: fd=%d, bytes_read=%zd\n", fd, bytes_read);
    return bytes_read;
}
