const std = @import("std");
const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("dlfcn.h");
    @cInclude("stdio.h");
});

const HookEntry = struct {
    symbol: [*:0]const u8,
    original: ?*anyopaque,
};

var puts_hook = HookEntry{ .symbol = "puts", .original = null };
var fopen_hook = HookEntry{ .symbol = "fopen", .original = null };
var read_hook = HookEntry{ .symbol = "read", .original = null };

fn resolve_original(entry: *HookEntry) ?*anyopaque {
    if (entry.original == null)
        entry.original = c.dlsym(c.RTLD_NEXT, entry.symbol);
    return entry.original;
}

export fn puts(str: [*:0]const u8) c_int {
    const original_fn: *const fn ([*:0]const u8) c_int = @ptrCast(resolve_original(&puts_hook) orelse return -1);
    return original_fn(str);
}

export fn fopen(filename: [*:0]const u8, mode: [*:0]const u8) ?*c.FILE {
    const original_fn: *const fn ([*:0]const u8, [*:0]const u8) ?*c.FILE = @ptrCast(resolve_original(&fopen_hook) orelse return null);
    return original_fn(filename, mode);
}

export fn read(fd: c_int, buf: ?*anyopaque, count: usize) isize {
    const original_fn: *const fn (c_int, ?*anyopaque, usize) isize = @ptrCast(resolve_original(&read_hook) orelse return -1);
    return original_fn(fd, buf, count);
}
