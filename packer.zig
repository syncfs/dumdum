const std = @import("std");

const max_file_size = 10 * 1024 * 1024;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: packer <input> <output> <key>\n", .{});
        return error.InvalidArgs;
    }

    const key: u8 = try std.fmt.parseInt(u8, args[3], 0);

    const input_file = try std.fs.cwd().openFile(args[1], .{});
    defer input_file.close();

    const input_data = try input_file.readToEndAlloc(allocator, max_file_size);
    defer allocator.free(input_data);

    for (input_data, 0..) |*byte, i| byte.* ^= @truncate(key +% i);

    const output_file = try std.fs.cwd().createFile(args[2], .{});
    defer output_file.close();

    try output_file.writeAll(input_data);

    std.debug.print("Packed {} bytes with key 0x{x:0>2}\n", .{ input_data.len, key });
}
