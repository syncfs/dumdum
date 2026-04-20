const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("dlfcn.h");
});

pub const HookEntry = struct {
    symbol: [*:0]const u8,
    original: ?*anyopaque,
};

pub fn resolve_original(entry: *HookEntry) ?*anyopaque {
    if (entry.original == null)
        entry.original = c.dlsym(c.RTLD_NEXT, entry.symbol);
    return entry.original;
}
