pub fn crypt(data: []u8, key: u8) void {
    for (data, 0..) |*byte, i| byte.* ^= @truncate(key +% i);
}
