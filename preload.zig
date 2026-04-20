const std = @import("std");
const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("dlfcn.h");
    @cInclude("stdio.h");
    @cInclude("unistd.h");
});

const HookEntry = struct {
    symbol: [*:0]const u8,
    original: ?*anyopaque,
};

var puts_hook = HookEntry{ .symbol = "puts", .original = null };
var fopen_hook = HookEntry{ .symbol = "fopen", .original = null };
var read_hook = HookEntry{ .symbol = "read", .original = null };

fn resolve_original(entry: *HookEntry) ?*anyopaque {
    if (entry.original == null) {
        entry.original = c.dlsym(c.RTLD_NEXT, entry.symbol);
    }
    return entry.original;
}

export fn puts(str: [*:0]const u8) c_int {
    _ = c.fprintf(c.stderr, "[HOOKED] %s called with: %s\n", puts_hook.symbol, str);
    const original_ptr = resolve_original(&puts_hook) orelse return -1;
    const original_fn: *const fn ([*:0]const u8) c_int = @ptrCast(original_ptr);
    return original_fn(str);
}

export fn fopen(filename: [*:0]const u8, mode: [*:0]const u8) ?*c.FILE {
    _ = c.fprintf(c.stderr, "[HOOKED] fopen called with: %s (mode: %s)\n", filename, mode);
    const original_ptr = resolve_original(&fopen_hook) orelse return null;
    const original_fn: *const fn ([*:0]const u8, [*:0]const u8) ?*c.FILE = @ptrCast(original_ptr);
    return original_fn(filename, mode);
}

export fn read(fd: c_int, buf: ?*anyopaque, count: usize) isize {
    const original_ptr = resolve_original(&read_hook) orelse return -1;
    const original_fn: *const fn (c_int, ?*anyopaque, usize) isize = @ptrCast(original_ptr);
    const bytes_read = original_fn(fd, buf, count);
    if (bytes_read > 0) {
        _ = c.fprintf(c.stderr, "[HOOKED] read called with: fd=%d, bytes_read=%zd\n", fd, bytes_read);
    }
    return bytes_read;
}
