//! Cross-implementation interoperability tests.
//! A RAF file created by libaegis's C implementation must be readable by this Zig port, and vice versa.
//! Only runs when libaegis is checked out as a sibling directory (see build.zig).
//! Invoke it with `zig build test-interop`.
const std = @import("std");
const testing = std.testing;
const aegis_c = @import("aegis_c");
const aegis_stream = @import("aegis_stream");

const Aegis128LRaf = aegis_stream.Aegis128LRaf(aegis_stream.MemoryStorage);
const Aegis256Raf = aegis_stream.Aegis256Raf(aegis_stream.MemoryStorage);

var prng = std.Random.DefaultPrng.init(0xC0FFEE);
const random = prng.random();

// Mirrors the in-memory `aegis_raf_io` backend from libaegis's own
// src/test/raf_test.zig, so both sides of the interop test share the same
// buffer behavior.
const CFile = struct {
    data: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    fn deinit(self: *CFile) void {
        self.data.deinit(self.allocator);
    }

    fn readAt(user: ?*anyopaque, buf: [*c]u8, len: usize, off: u64) callconv(.c) c_int {
        const self: *CFile = @ptrCast(@alignCast(user));
        const offset: usize = @intCast(off);
        if (offset + len > self.data.items.len) return -1;
        @memcpy(buf[0..len], self.data.items[offset..][0..len]);
        return 0;
    }

    fn writeAt(user: ?*anyopaque, buf: [*c]const u8, len: usize, off: u64) callconv(.c) c_int {
        const self: *CFile = @ptrCast(@alignCast(user));
        const offset: usize = @intCast(off);
        const end = offset + len;
        if (end > self.data.items.len) return -1;
        @memcpy(self.data.items[offset..end], buf[0..len]);
        return 0;
    }

    fn getSize(user: ?*anyopaque, size: [*c]u64) callconv(.c) c_int {
        const self: *CFile = @ptrCast(@alignCast(user));
        size[0] = self.data.items.len;
        return 0;
    }

    fn setSize(user: ?*anyopaque, size: u64) callconv(.c) c_int {
        const self: *CFile = @ptrCast(@alignCast(user));
        self.data.resize(self.allocator, @intCast(size)) catch return -1;
        return 0;
    }

    fn sync(_: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn io(self: *CFile) aegis_c.aegis_raf_io {
        return .{
            .user = self,
            .read_at = readAt,
            .write_at = writeAt,
            .get_size = getSize,
            .set_size = setSize,
            .sync = sync,
        };
    }
};

fn cRandomFill(_: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    random.bytes(out[0..len]);
    return 0;
}

fn cRng() aegis_c.aegis_raf_rng {
    return .{ .user = null, .random = cRandomFill };
}

fn randomPayload(allocator: std.mem.Allocator, len: usize) ![]u8 {
    const buf = try allocator.alloc(u8, len);
    random.bytes(buf);
    return buf;
}

test "interop: libaegis creates AEGIS-128L RAF, this port reads it" {
    try testing.expectEqual(0, aegis_c.aegis_init());

    var key: [16]u8 = undefined;
    random.bytes(&key);
    const plaintext = try randomPayload(testing.allocator, 3000);
    defer testing.allocator.free(plaintext);

    var c_file = CFile{ .allocator = testing.allocator };
    defer c_file.deinit();

    var scratch_buf: [aegis_c.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis_c.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis_c.aegis_raf_scratch{ .buf = &scratch_buf, .len = scratch_buf.len };
    const cfg = aegis_c.aegis_raf_config{ .chunk_size = 1024, .flags = aegis_c.AEGIS_RAF_CREATE, .scratch = &scratch };

    var c_ctx: aegis_c.aegis128l_raf_ctx align(32) = undefined;
    try testing.expectEqual(0, aegis_c.aegis128l_raf_create(&c_ctx, &c_file.io(), &cRng(), &cfg, &key));

    var bytes_written: usize = undefined;
    try testing.expectEqual(0, aegis_c.aegis128l_raf_write(&c_ctx, &bytes_written, plaintext.ptr, plaintext.len, 0));
    aegis_c.aegis128l_raf_close(&c_ctx);

    var mem = aegis_stream.MemoryStorage.init(testing.allocator);
    defer mem.deinit();
    try mem.bytes.appendSlice(testing.allocator, c_file.data.items);

    var zig_ctx = try Aegis128LRaf.open(testing.allocator, &mem, random, &key);
    defer zig_ctx.close();

    try testing.expectEqual(plaintext.len, zig_ctx.length());
    const buf = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(buf);
    const n = try zig_ctx.read(buf, 0);
    try testing.expectEqualSlices(u8, plaintext, buf[0..n]);
}

test "interop: this port creates AEGIS-128L RAF, libaegis reads it" {
    try testing.expectEqual(0, aegis_c.aegis_init());

    var key: [16]u8 = undefined;
    random.bytes(&key);
    const plaintext = try randomPayload(testing.allocator, 3000);
    defer testing.allocator.free(plaintext);

    var mem = aegis_stream.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    {
        var zig_ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
        defer zig_ctx.close();
        _ = try zig_ctx.write(plaintext, 0);
    }

    var c_file = CFile{ .allocator = testing.allocator };
    defer c_file.deinit();
    try c_file.data.appendSlice(testing.allocator, mem.bytes.items);

    var scratch_buf: [aegis_c.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis_c.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis_c.aegis_raf_scratch{ .buf = &scratch_buf, .len = scratch_buf.len };
    const open_cfg = aegis_c.aegis_raf_config{ .chunk_size = 0, .flags = 0, .scratch = &scratch };

    var c_ctx: aegis_c.aegis128l_raf_ctx align(32) = undefined;
    try testing.expectEqual(0, aegis_c.aegis128l_raf_open(&c_ctx, &c_file.io(), &cRng(), &open_cfg, &key));
    defer aegis_c.aegis128l_raf_close(&c_ctx);

    var size: u64 = undefined;
    try testing.expectEqual(0, aegis_c.aegis128l_raf_get_size(&c_ctx, &size));
    try testing.expectEqual(plaintext.len, size);

    const buf = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(buf);
    var bytes_read: usize = undefined;
    try testing.expectEqual(0, aegis_c.aegis128l_raf_read(&c_ctx, buf.ptr, &bytes_read, plaintext.len, 0));
    try testing.expectEqualSlices(u8, plaintext, buf[0..bytes_read]);
}

test "interop: libaegis creates AEGIS-256 RAF, this port reads it" {
    try testing.expectEqual(0, aegis_c.aegis_init());

    var key: [32]u8 = undefined;
    random.bytes(&key);
    const plaintext = try randomPayload(testing.allocator, 3000);
    defer testing.allocator.free(plaintext);

    var c_file = CFile{ .allocator = testing.allocator };
    defer c_file.deinit();

    var scratch_buf: [aegis_c.AEGIS256_RAF_SCRATCH_SIZE(1024)]u8 align(aegis_c.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis_c.aegis_raf_scratch{ .buf = &scratch_buf, .len = scratch_buf.len };
    const cfg = aegis_c.aegis_raf_config{ .chunk_size = 1024, .flags = aegis_c.AEGIS_RAF_CREATE, .scratch = &scratch };

    var c_ctx: aegis_c.aegis256_raf_ctx = undefined;
    try testing.expectEqual(0, aegis_c.aegis256_raf_create(&c_ctx, &c_file.io(), &cRng(), &cfg, &key));

    var bytes_written: usize = undefined;
    try testing.expectEqual(0, aegis_c.aegis256_raf_write(&c_ctx, &bytes_written, plaintext.ptr, plaintext.len, 0));
    aegis_c.aegis256_raf_close(&c_ctx);

    var mem = aegis_stream.MemoryStorage.init(testing.allocator);
    defer mem.deinit();
    try mem.bytes.appendSlice(testing.allocator, c_file.data.items);

    var zig_ctx = try Aegis256Raf.open(testing.allocator, &mem, random, &key);
    defer zig_ctx.close();

    try testing.expectEqual(plaintext.len, zig_ctx.length());
    const buf = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(buf);
    const n = try zig_ctx.read(buf, 0);
    try testing.expectEqualSlices(u8, plaintext, buf[0..n]);
}

test "interop: this port creates AEGIS-256 RAF, libaegis reads it" {
    try testing.expectEqual(0, aegis_c.aegis_init());

    var key: [32]u8 = undefined;
    random.bytes(&key);
    const plaintext = try randomPayload(testing.allocator, 3000);
    defer testing.allocator.free(plaintext);

    var mem = aegis_stream.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    {
        var zig_ctx = try Aegis256Raf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
        defer zig_ctx.close();
        _ = try zig_ctx.write(plaintext, 0);
    }

    var c_file = CFile{ .allocator = testing.allocator };
    defer c_file.deinit();
    try c_file.data.appendSlice(testing.allocator, mem.bytes.items);

    var scratch_buf: [aegis_c.AEGIS256_RAF_SCRATCH_SIZE(1024)]u8 align(aegis_c.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis_c.aegis_raf_scratch{ .buf = &scratch_buf, .len = scratch_buf.len };
    const open_cfg = aegis_c.aegis_raf_config{ .chunk_size = 0, .flags = 0, .scratch = &scratch };

    var c_ctx: aegis_c.aegis256_raf_ctx = undefined;
    try testing.expectEqual(0, aegis_c.aegis256_raf_open(&c_ctx, &c_file.io(), &cRng(), &open_cfg, &key));
    defer aegis_c.aegis256_raf_close(&c_ctx);

    var size: u64 = undefined;
    try testing.expectEqual(0, aegis_c.aegis256_raf_get_size(&c_ctx, &size));
    try testing.expectEqual(plaintext.len, size);

    const buf = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(buf);
    var bytes_read: usize = undefined;
    try testing.expectEqual(0, aegis_c.aegis256_raf_read(&c_ctx, buf.ptr, &bytes_read, plaintext.len, 0));
    try testing.expectEqualSlices(u8, plaintext, buf[0..bytes_read]);
}
