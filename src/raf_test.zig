//! Behavioral tests for the RAF port, adapted from libaegis's
//! src/test/raf_test.zig (which exercises the C implementation through
//! translate-c bindings) to exercise this pure-Zig implementation instead.
const std = @import("std");
const testing = std.testing;
const raf = @import("raf.zig");

const Aegis128LRaf = raf.Aegis128LRaf(raf.MemoryStorage);
const Aegis256Raf = raf.Aegis256Raf(raf.MemoryStorage);

var prng = std.Random.DefaultPrng.init(0xAE615);
const random = prng.random();

fn newKey(comptime RafT: type) [RafT.key_length]u8 {
    var key: [RafT.key_length]u8 = undefined;
    random.bytes(&key);
    return key;
}

test "MemoryStorage: reading past EOF returns zero instead of panicking" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    var buf: [16]u8 = undefined;
    try testing.expectEqual(0, try mem.readPositionalAll(&buf, 0));
    try testing.expectEqual(0, try mem.readPositionalAll(&buf, 1));
    try testing.expectEqual(0, try mem.readPositionalAll(&buf, 1000));

    try mem.setLength(4);
    try testing.expectEqual(0, try mem.readPositionalAll(&buf, 4));
    try testing.expectEqual(0, try mem.readPositionalAll(&buf, 5));
}

test "aegis128l_raf: create and basic write/read" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
    defer ctx.close();

    try testing.expectEqual(0, ctx.length());

    const data = "Hello, AEGIS RAF!";
    try testing.expectEqual(data.len, try ctx.write(data, 0));
    try testing.expectEqual(data.len, ctx.length());

    var buf: [64]u8 = undefined;
    const n = try ctx.read(&buf, 0);
    try testing.expectEqualSlices(u8, data, buf[0..n]);
}

test "aegis128l_raf: open existing file" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
        _ = try ctx.write("Test data for re-open", 0);
        ctx.close();
    }

    var ctx = try Aegis128LRaf.open(testing.allocator, &mem, random, .{}, &key);
    defer ctx.close();

    try testing.expectEqual("Test data for re-open".len, ctx.length());

    var buf: [64]u8 = undefined;
    const n = try ctx.read(&buf, 0);
    try testing.expectEqualSlices(u8, "Test data for re-open", buf[0..n]);
}

test "aegis128l_raf: random access write" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    const data1 = "First block";
    const data2 = "Second block at offset 2048";
    _ = try ctx.write(data1, 0);
    _ = try ctx.write(data2, 2048);

    try testing.expectEqual(2048 + data2.len, ctx.length());

    var buf1: [32]u8 = undefined;
    var n = try ctx.read(buf1[0..data1.len], 0);
    try testing.expectEqualSlices(u8, data1, buf1[0..n]);

    var buf2: [64]u8 = undefined;
    n = try ctx.read(buf2[0..data2.len], 2048);
    try testing.expectEqualSlices(u8, data2, buf2[0..n]);

    var zeros: [100]u8 = undefined;
    n = try ctx.read(&zeros, 100);
    try testing.expectEqual(100, n);
    for (zeros[0..n]) |b| try testing.expectEqual(0, b);
}

test "aegis128l_raf: truncate shrink" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    var data: [2048]u8 = undefined;
    random.bytes(&data);
    _ = try ctx.write(&data, 0);

    try ctx.setLength(500);
    try testing.expectEqual(500, ctx.length());

    var buf: [500]u8 = undefined;
    const n = try ctx.read(&buf, 0);
    try testing.expectEqual(500, n);
    try testing.expectEqualSlices(u8, data[0..500], buf[0..500]);
}

test "aegis128l_raf: cross-chunk operations" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    const chunk_size = 1024;
    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = chunk_size }, &key);
    defer ctx.close();

    var data: [2000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);

    const n_written = try ctx.write(&data, chunk_size - 500);
    try testing.expectEqual(data.len, n_written);

    var buf: [2000]u8 = undefined;
    const n_read = try ctx.read(&buf, chunk_size - 500);
    try testing.expectEqual(data.len, n_read);
    try testing.expectEqualSlices(u8, &data, buf[0..n_read]);
}

test "aegis128l_raf: header tampering is detected" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
        _ = try ctx.write("Test data", 0);
        ctx.close();
    }

    mem.bytes.items[20] ^= 0x01;

    try testing.expectError(error.AuthenticationFailed, Aegis128LRaf.open(testing.allocator, &mem, random, .{}, &key));
}

test "aegis128l_raf: chunk tampering is detected" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    var data: [1024]u8 = undefined;
    random.bytes(&data);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
        _ = try ctx.write(&data, 0);
        ctx.close();
    }

    const chunk_offset = raf.header_size + Aegis128LRaf.nonce_length + 512;
    mem.bytes.items[chunk_offset] ^= 0x01;

    var ctx = try Aegis128LRaf.open(testing.allocator, &mem, random, .{}, &key);
    defer ctx.close();

    var buf: [1024]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, ctx.read(&buf, 0));
}

test "aegis128l_raf: wrong key is detected" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key1 = newKey(Aegis128LRaf);
    const key2 = newKey(Aegis128LRaf);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key1);
        _ = try ctx.write("Secret data", 0);
        ctx.close();
    }

    try testing.expectError(error.AuthenticationFailed, Aegis128LRaf.open(testing.allocator, &mem, random, .{}, &key2));
}

test "aegis256_raf: basic operations" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis256Raf);

    {
        var ctx = try Aegis256Raf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
        _ = try ctx.write("AEGIS-256 RAF test data", 0);
        ctx.close();
    }

    var ctx = try Aegis256Raf.open(testing.allocator, &mem, random, .{}, &key);
    defer ctx.close();

    var buf: [64]u8 = undefined;
    const n = try ctx.read(&buf, 0);
    try testing.expectEqualSlices(u8, "AEGIS-256 RAF test data", buf[0..n]);
}

test "aegis_raf: algorithm mismatch is detected" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key128 = newKey(Aegis128LRaf);
    var key256: [Aegis256Raf.key_length]u8 = undefined;
    @memcpy(key256[0..16], &key128);
    @memcpy(key256[16..32], &key128);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key128);
        _ = try ctx.write("Test", 0);
        ctx.close();
    }

    try testing.expectError(error.AlgorithmMismatch, Aegis256Raf.open(testing.allocator, &mem, random, .{}, &key256));
}

test "aegis128l_raf: EOF behavior" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
    defer ctx.close();

    _ = try ctx.write("Short data", 0);

    var buf: [100]u8 = undefined;
    try testing.expectEqual(0, try ctx.read(&buf, 100));
    try testing.expectEqual("Short data".len, try ctx.read(&buf, 0));
}

test "aegis128l_raf: empty file" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
        try testing.expectEqual(0, ctx.length());
        var buf: [100]u8 = undefined;
        try testing.expectEqual(0, try ctx.read(&buf, 0));
        ctx.close();
    }

    var ctx = try Aegis128LRaf.open(testing.allocator, &mem, random, .{}, &key);
    defer ctx.close();
    try testing.expectEqual(0, ctx.length());
}

test "aegis128l_raf: create flag semantics" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
        _ = try ctx.write("Test data", 0);
        ctx.close();
    }

    try testing.expectError(error.FileExists, Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key));

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096, .truncate = true }, &key);
    defer ctx.close();
    try testing.expectEqual(0, ctx.length());
}

test "aegis128l_raf: create without create flag fails on missing file" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    try testing.expectError(error.FileNotFound, Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096, .create = false }, &key));
}

test "aegis128l_raf: truncate grow within same chunk" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    const data = "Hello, grow test!";
    _ = try ctx.write(data, 0);
    try ctx.setLength(800);
    try testing.expectEqual(800, ctx.length());

    var buf: [64]u8 = undefined;
    var n = try ctx.read(buf[0..data.len], 0);
    try testing.expectEqualSlices(u8, data, buf[0..n]);

    var zeros: [100]u8 = undefined;
    n = try ctx.read(&zeros, data.len);
    try testing.expectEqual(100, n);
    for (zeros[0..n]) |b| try testing.expectEqual(0, b);
}

test "aegis128l_raf: truncate grow across chunk boundaries" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    const chunk_size = 1024;
    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = chunk_size }, &key);
    defer ctx.close();

    var data: [1500]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i);
    _ = try ctx.write(&data, 0);

    try ctx.setLength(3500);
    try testing.expectEqual(3500, ctx.length());

    var buf: [1500]u8 = undefined;
    var n = try ctx.read(&buf, 0);
    try testing.expectEqual(data.len, n);
    try testing.expectEqualSlices(u8, &data, buf[0..n]);

    var zeros: [500]u8 = undefined;
    n = try ctx.read(&zeros, 2500);
    try testing.expectEqual(500, n);
    for (zeros[0..n]) |b| try testing.expectEqual(0, b);

    ctx.close();
    ctx = try Aegis128LRaf.open(testing.allocator, &mem, random, .{}, &key);
    try testing.expectEqual(3500, ctx.length());
    n = try ctx.read(&buf, 0);
    try testing.expectEqualSlices(u8, &data, buf[0..n]);
}

test "aegis128l_raf: shrink then grow within same chunk" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    const chunk_size = 1024;
    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = chunk_size }, &key);
    defer ctx.close();

    var data: [800]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i ^ 0xAB);
    _ = try ctx.write(&data, 0);

    try ctx.setLength(500);
    try ctx.setLength(700);
    try testing.expectEqual(700, ctx.length());

    var buf: [500]u8 = undefined;
    var n = try ctx.read(&buf, 0);
    try testing.expectEqual(500, n);
    try testing.expectEqualSlices(u8, data[0..500], buf[0..500]);

    var grown: [200]u8 = undefined;
    n = try ctx.read(&grown, 500);
    try testing.expectEqual(200, n);
    for (grown[0..n]) |b| try testing.expectEqual(0, b);
}

test "aegis_raf: probe reads header without a key" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);

    {
        var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key);
        _ = try ctx.write("Probe test data", 0);
        ctx.close();
    }

    const info = try raf.probe(&mem);
    try testing.expectEqual(raf.AlgId.aegis128l, info.alg_id);
    try testing.expectEqual(4096, info.chunk_size);
    try testing.expectEqual("Probe test data".len, info.file_size);
}

test "deriveMasterKey: same context is deterministic, different context diverges" {
    var master_key: [16]u8 = undefined;
    random.bytes(&master_key);

    const derived_a1 = try raf.deriveMasterKey(16, &master_key, "file-a");
    const derived_a2 = try raf.deriveMasterKey(16, &master_key, "file-a");
    const derived_b = try raf.deriveMasterKey(16, &master_key, "file-b");

    try testing.expectEqualSlices(u8, &derived_a1, &derived_a2);
    try testing.expect(!std.mem.eql(u8, &derived_a1, &derived_b));
    try testing.expect(!std.mem.eql(u8, &derived_a1, &master_key));
}

test "deriveMasterKey: context longer than the KDF block rejects instead of overflowing" {
    var master_key16: [16]u8 = undefined;
    random.bytes(&master_key16);
    var master_key32: [32]u8 = undefined;
    random.bytes(&master_key32);

    var context_121: [121]u8 = undefined;
    random.bytes(&context_121);
    var context_73: [73]u8 = undefined;
    random.bytes(&context_73);

    try testing.expectError(error.ContextTooLong, raf.deriveMasterKey(16, &master_key16, &context_121));
    try testing.expectError(error.ContextTooLong, raf.deriveMasterKey(32, &master_key32, &context_73));

    // The limits themselves (120 and 72 bytes) must still be accepted.
    _ = try raf.deriveMasterKey(16, &master_key16, context_121[0..120]);
    _ = try raf.deriveMasterKey(32, &master_key32, context_73[0..72]);
}

// A backing store that can be told to refuse or tear one write, or to fail one length change.
const FailingStorage = struct {
    pub const Error = raf.MemoryStorage.Error || error{InjectedFailure};

    inner: raf.MemoryStorage,
    partially_fail_next_header_write: bool = false,
    fail_next_shrink: bool = false,
    // The next write that starts at this offset is refused as a whole.
    // The header is at offset 0, a chunk record at its `chunkOffset`.
    fail_next_write_at: ?u64 = null,
    set_length_calls: usize = 0,

    fn deinit(self: *FailingStorage) void {
        self.inner.deinit();
    }

    pub fn readPositionalAll(self: *FailingStorage, buffer: []u8, offset: u64) Error!usize {
        return self.inner.readPositionalAll(buffer, offset);
    }

    pub fn writePositionalAll(self: *FailingStorage, bytes: []const u8, offset: u64) Error!void {
        if (offset == 0 and self.partially_fail_next_header_write) {
            self.partially_fail_next_header_write = false;
            try self.inner.writePositionalAll(bytes[0..24], offset);
            return error.InjectedFailure;
        }
        if (self.fail_next_write_at == offset) {
            self.fail_next_write_at = null;
            return error.InjectedFailure;
        }
        return self.inner.writePositionalAll(bytes, offset);
    }

    pub fn readPositionalVecAll(self: *FailingStorage, buffers: [][]u8, offset: u64) Error!usize {
        return self.inner.readPositionalVecAll(buffers, offset);
    }

    pub fn writePositionalVecAll(self: *FailingStorage, buffers: [][]const u8, offset: u64) Error!void {
        if (self.fail_next_write_at == offset) {
            self.fail_next_write_at = null;
            return error.InjectedFailure;
        }
        return self.inner.writePositionalVecAll(buffers, offset);
    }

    pub fn length(self: *FailingStorage) Error!u64 {
        return self.inner.length();
    }

    pub fn setLength(self: *FailingStorage, new_length: u64) Error!void {
        self.set_length_calls += 1;
        if (self.fail_next_shrink and new_length < self.inner.bytes.items.len) {
            self.fail_next_shrink = false;
            return error.InjectedFailure;
        }
        return self.inner.setLength(new_length);
    }

    pub fn sync(self: *FailingStorage) Error!void {
        return self.inner.sync();
    }
};

test "aegis128l_raf: a failed write requires reopen and does not lose data" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 4096 }, &key);
    defer ctx.close();

    storage.fail_next_write_at = 0;
    try testing.expectError(error.InjectedFailure, ctx.write("hello", 0));

    // The write may have left a chunk record on disk without a header that
    // acknowledges it. Every further call must fail until the file is reopened.
    var buf: [5]u8 = undefined;
    try testing.expectError(error.ContextFailed, ctx.read(&buf, 0));
    try testing.expectError(error.ContextFailed, ctx.write("hello", 0));

    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);

    // The header write never landed, so the file is still empty.
    try testing.expectEqual(0, ctx.length());
    try testing.expectEqual(5, try ctx.write("hello", 0));
    try testing.expectEqual(5, ctx.length());
    try testing.expectEqual(5, try ctx.read(&buf, 0));
    try testing.expectEqualSlices(u8, "hello", &buf);
}

test "aegis128l_raf: a torn header write recovers the preceding header" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    try testing.expectEqual(3, try ctx.write("old", 0));
    storage.partially_fail_next_header_write = true;
    try testing.expectError(error.InjectedFailure, ctx.write("new", 3));
    try testing.expectError(error.ContextFailed, ctx.read(&.{}, 0));

    // Verification must recover without repairing or removing the trailer.
    const before = try testing.allocator.dupe(u8, storage.inner.bytes.items);
    defer testing.allocator.free(before);
    const info = try RafT.verify(&storage, &key);
    try testing.expectEqual(3, info.file_size);
    try testing.expectEqualSlices(u8, before, storage.inner.bytes.items);

    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);

    try testing.expectEqual(3, ctx.length());
    var buf: [3]u8 = undefined;
    try testing.expectEqual(3, try ctx.read(&buf, 0));
    try testing.expectEqualSlices(u8, "old", &buf);

    // A later mutation repairs the primary header and removes the recovery
    // trailer before changing the recovered file.
    try testing.expectEqual(1, try ctx.write("!", 3));
    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);
    try testing.expectEqual(4, ctx.length());
    var repaired: [4]u8 = undefined;
    try testing.expectEqual(4, try ctx.read(&repaired, 0));
    try testing.expectEqualSlices(u8, "old!", &repaired);
    try testing.expectEqual(raf.header_size + RafT.nonce_length + 1024 + raf.tag_bytes, try storage.length());
}

test "aegis128l_raf: a torn shrink header recovers the preceding file" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    var data: [2000]u8 = undefined;
    random.bytes(&data);
    try testing.expectEqual(data.len, try ctx.write(&data, 0));

    storage.partially_fail_next_header_write = true;
    try testing.expectError(error.InjectedFailure, ctx.setLength(500));

    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);

    try testing.expectEqual(data.len, ctx.length());
    var recovered: [2000]u8 = undefined;
    try testing.expectEqual(data.len, try ctx.read(&recovered, 0));
    try testing.expectEqualSlices(u8, &data, &recovered);
}

test "aegis128l_raf: a failed shrink requires reopen and does not lose data" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    var data: [2000]u8 = undefined;
    random.bytes(&data);
    _ = try ctx.write(&data, 0);

    storage.fail_next_write_at = 0;
    try testing.expectError(error.InjectedFailure, ctx.setLength(500));
    try testing.expectError(error.ContextFailed, ctx.setLength(500));

    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);

    // The smaller header never landed, so the original 2000 bytes survive.
    try testing.expectEqual(2000, ctx.length());
    var buf: [2000]u8 = undefined;
    try testing.expectEqual(2000, try ctx.read(&buf, 0));
    try testing.expectEqualSlices(u8, &data, &buf);

    try ctx.setLength(500);
    try testing.expectEqual(500, ctx.length());
}

test "aegis128l_raf: reopening after a failed physical shrink lets a same-size retry finish it" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    var data: [2048]u8 = undefined;
    random.bytes(&data);
    _ = try ctx.write(&data, 0);

    storage.fail_next_shrink = true;
    try testing.expectError(error.InjectedFailure, ctx.setLength(0));
    try testing.expectError(error.ContextFailed, ctx.setLength(0));

    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);

    // The header already committed size 0. Only the backing store is still oversized.
    try testing.expectEqual(0, ctx.length());
    try ctx.setLength(0);
    try testing.expectEqual(raf.header_size, try storage.length());
}

test "aegis128l_raf: an overflowing write is rejected without poisoning the context" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(Aegis128LRaf);
    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    try testing.expectError(error.Overflow, ctx.write("x", std.math.maxInt(u64)));

    // Rejected before touching storage: the context is still usable.
    try testing.expectEqual(4, try ctx.write("test", 0));
}

test "aegis128l_raf: create refuses to replace a short existing file without truncate" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();
    try mem.setLength(13);
    random.bytes(mem.bytes.items);
    var original: [13]u8 = undefined;
    @memcpy(&original, mem.bytes.items);

    const key = newKey(Aegis128LRaf);
    try testing.expectError(error.FileExists, Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096 }, &key));

    // A rejected create() must not have touched the existing file at all.
    try testing.expectEqualSlices(u8, &original, mem.bytes.items);

    var ctx = try Aegis128LRaf.create(testing.allocator, &mem, random, .{ .chunk_size = 4096, .truncate = true }, &key);
    defer ctx.close();
    try testing.expectEqual(0, ctx.length());
}

test "MemoryStorage: an offset near u64's max does not overflow the bounds check" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();
    try mem.setLength(4);

    var one_byte = [_]u8{0xAA};
    try testing.expectError(error.OutOfBounds, mem.writePositionalAll(&one_byte, std.math.maxInt(u64)));
}

fn roundTrip(comptime Variant: fn (type) type, chunk_size: u32) !void {
    const RafT = Variant(raf.MemoryStorage);

    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(RafT);

    var data: [5000]u8 = undefined;
    random.bytes(&data);

    {
        var ctx = try RafT.create(testing.allocator, &mem, random, .{ .chunk_size = chunk_size }, &key);
        defer ctx.close();
        _ = try ctx.write(&data, 0);
    }

    var ctx = try RafT.open(testing.allocator, &mem, random, .{}, &key);
    defer ctx.close();

    var buf: [5000]u8 = undefined;
    const n = try ctx.read(&buf, 0);
    try testing.expectEqual(data.len, n);
    try testing.expectEqualSlices(u8, &data, buf[0..n]);
}

test "aegis128l_raf: FileStorage round-trips through a real file" {
    const io = testing.io;
    const RafT = raf.Aegis128LRaf(raf.FileStorage);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try tmp.dir.createFile(io, "raf.bin", .{ .read = true });
    defer file.close(io);
    var storage = raf.FileStorage.init(file, io);

    // 70 chunks: more than one run on both paths.
    const data = try testing.allocator.alloc(u8, 70 * 1024 + 3);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 13);

    const buf = try testing.allocator.dupe(u8, data);
    defer testing.allocator.free(buf);

    const key = newKey(RafT);

    {
        var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
        defer ctx.close();
        try testing.expectEqual(buf.len, try ctx.writeInPlace(buf, 0));
    }

    // Reopen to confirm the header and chunks actually made it to disk,
    // rather than just checking the still-open context's own state.
    var ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);
    defer ctx.close();

    const out = try testing.allocator.alloc(u8, data.len);
    defer testing.allocator.free(out);
    try testing.expectEqual(data.len, try ctx.read(out, 0));
    try testing.expectEqualSlices(u8, data, out);
}

test "all variants round-trip" {
    try roundTrip(raf.Aegis128LRaf, 1024);
    try roundTrip(raf.Aegis128X2Raf, 1024);
    try roundTrip(raf.Aegis128X4Raf, 1024);
    try roundTrip(raf.Aegis256Raf, 1024);
    try roundTrip(raf.Aegis256X2Raf, 1024);
    try roundTrip(raf.Aegis256X4Raf, 1024);
}

test "aegis128x2_raf: whole chunks decrypt straight into the caller's buffer" {
    const RafT = raf.Aegis128X2Raf(raf.MemoryStorage);

    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    // 200 chunks: more than one run, plus a partial chunk at the end.
    const data = try testing.allocator.alloc(u8, 200 * 1024 + 7);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 31);

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();
    try testing.expectEqual(data.len, try ctx.write(data, 0));

    const out = try testing.allocator.alloc(u8, data.len + 100);
    defer testing.allocator.free(out);

    try testing.expectEqual(data.len, try ctx.read(out, 0));
    try testing.expectEqualSlices(u8, data, out[0..data.len]);
}

test "aegis128x2_raf: writeInPlace round-trips and leaves ciphertext behind" {
    const RafT = raf.Aegis128X2Raf(raf.MemoryStorage);

    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const data = try testing.allocator.alloc(u8, 100 * 1024 + 7);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 17);

    const buf = try testing.allocator.dupe(u8, data);
    defer testing.allocator.free(buf);

    const key = newKey(RafT);
    {
        var ctx = try RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
        defer ctx.close();
        // Unaligned start and end: a partial chunk on both sides of the whole ones.
        try testing.expectEqual(buf.len, try ctx.writeInPlace(buf, 500));
    }

    // Whole chunks were encrypted where they were, the partial one at the start was not.
    try testing.expect(!std.mem.eql(u8, data[524..][0..1024], buf[524..][0..1024]));
    try testing.expectEqualSlices(u8, data[0..524], buf[0..524]);

    var ctx = try RafT.open(testing.allocator, &mem, random, .{}, &key);
    defer ctx.close();
    try testing.expectEqual(500 + data.len, ctx.length());

    const out = try testing.allocator.alloc(u8, 500 + data.len);
    defer testing.allocator.free(out);
    try testing.expectEqual(out.len, try ctx.read(out, 0));
    const zeros: [500]u8 = @splat(0);
    try testing.expectEqualSlices(u8, &zeros, out[0..500]);
    try testing.expectEqualSlices(u8, data, out[500..]);
}

test "aegis128x2_raf: a damaged record fails a whole-chunk read" {
    const RafT = raf.Aegis128X2Raf(raf.MemoryStorage);

    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const data = try testing.allocator.alloc(u8, 8 * 1024);
    defer testing.allocator.free(data);
    @memset(data, 0x5a);

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();
    _ = try ctx.write(data, 0);

    // One byte of the ciphertext of chunk 3.
    const record: usize = @intCast(RafT.chunkOffset(1024, 3));
    mem.bytes.items[record + RafT.nonce_length + 10] ^= 1;

    const out = try testing.allocator.alloc(u8, data.len);
    defer testing.allocator.free(out);
    @memset(out, 0xff);
    try testing.expectError(error.AuthenticationFailed, ctx.read(out, 0));

    // A failed read must clear both plaintext and ciphertext from the output.
    try testing.expect(std.mem.allEqual(u8, out, 0));
    @memset(out[0..100], 0xff);
    try testing.expectError(error.AuthenticationFailed, ctx.read(out[0..100], 3 * 1024 + 10));
    try testing.expect(std.mem.allEqual(u8, out[0..100], 0));

    // The chunks before the damaged one still read on their own.
    try testing.expectEqual(3 * 1024, try ctx.read(out[0 .. 3 * 1024], 0));
    try testing.expectEqualSlices(u8, data[0 .. 3 * 1024], out[0 .. 3 * 1024]);
}

test "aegis128x2_raf: verify authenticates file metadata" {
    const RafT = raf.Aegis128X2Raf(raf.MemoryStorage);

    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(RafT);
    const wrong = newKey(RafT);
    try testing.expectError(error.InvalidHeader, RafT.verify(&mem, &key));
    {
        var ctx = try RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024 }, &key);
        defer ctx.close();
        _ = try ctx.write("twelve bytes", 0);
    }

    const info = try RafT.verify(&mem, &key);
    try testing.expectEqual(12, info.file_size);
    try testing.expectEqual(1024, info.chunk_size);
    try testing.expectEqual(.aegis128x2, info.alg_id);

    try testing.expectError(error.AuthenticationFailed, RafT.verify(&mem, &wrong));
    try testing.expectError(error.AlgorithmMismatch, raf.Aegis128LRaf(raf.MemoryStorage).verify(&mem, &key));

    // Valid authentication doesn't excuse missing records.
    try mem.setLength(mem.bytes.items.len - 1);
    try testing.expectError(error.InvalidHeader, RafT.verify(&mem, &key));
}

test "aegis128x2_raf: batched writes preserve data outside the request" {
    const RafT = raf.Aegis128X2Raf(raf.MemoryStorage);

    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();

    const key = newKey(RafT);
    try testing.expectError(error.InvalidArgument, RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024, .scratch_chunks = 0 }, &key));
    try testing.expectError(error.InvalidArgument, RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024, .scratch_chunks = raf.scratch_chunks_max + 1 }, &key));

    // Exercise multiple batches and a partial tail.
    const data = try testing.allocator.alloc(u8, 200 * 1024 + 7);
    defer testing.allocator.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 29);
    const out = try testing.allocator.alloc(u8, data.len);
    defer testing.allocator.free(out);

    {
        var ctx = try RafT.create(testing.allocator, &mem, random, .{ .chunk_size = 1024, .scratch_chunks = 8 }, &key);
        defer ctx.close();

        // Spare scratch capacity mustn't extend the write.
        try testing.expectEqual(3 * 1024, try ctx.write(data[0 .. 3 * 1024], 0));
        try testing.expectEqual(3 * 1024, ctx.length());
        try testing.expectEqual(RafT.chunkOffset(1024, 3), try mem.length());

        try testing.expectEqual(data.len, try ctx.write(data, 0));
        try testing.expectEqual(data.len, ctx.length());
        try testing.expectEqual(RafT.chunkOffset(1024, 201), try mem.length());

        const patch: [5 * 1024]u8 = @splat('p');
        try testing.expectEqual(patch.len, try ctx.write(&patch, 10 * 1024));
        @memcpy(data[10 * 1024 ..][0..patch.len], &patch);
        try testing.expectEqual(data.len, try ctx.read(out, 0));
        try testing.expectEqualSlices(u8, data, out);
    }

    // Reopening may change the scratch capacity.
    try testing.expectError(error.InvalidArgument, RafT.open(testing.allocator, &mem, random, .{ .scratch_chunks = 0 }, &key));
    var ctx = try RafT.open(testing.allocator, &mem, random, .{ .scratch_chunks = 4 }, &key);
    defer ctx.close();
    try testing.expectEqual(data.len, try ctx.read(out, 0));
    try testing.expectEqualSlices(u8, data, out);
    try testing.expectEqual(RafT.chunkOffset(1024, 201), try mem.length());
}

test "aegis128l_raf: resize call counts for growth, overwrite, and shrink" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    // Reserve and remove the recovery trailer without extra resizes.
    storage.set_length_calls = 0;
    var data: [3000]u8 = undefined;
    random.bytes(&data);
    _ = try ctx.write(&data, 0);
    try testing.expectEqual(2, storage.set_length_calls);
    try testing.expectEqual(RafT.chunkOffset(1024, 3), try storage.length());

    storage.set_length_calls = 0;
    _ = try ctx.write(data[0..10], 100);
    try testing.expectEqual(0, storage.set_length_calls);

    storage.set_length_calls = 0;
    try ctx.setLength(1000);
    try testing.expectEqual(2, storage.set_length_calls);
    try testing.expectEqual(RafT.chunkOffset(1024, 1), try storage.length());
}

test "aegis128l_raf: a record write that fails as a whole leaves every chunk readable" {
    const RafT = raf.Aegis128LRaf(FailingStorage);

    var storage = FailingStorage{ .inner = raf.MemoryStorage.init(testing.allocator) };
    defer storage.deinit();

    const key = newKey(RafT);
    var ctx = try RafT.create(testing.allocator, &storage, random, .{ .chunk_size = 1024 }, &key);
    defer ctx.close();

    const old: [2048]u8 = @splat('o');
    try testing.expectEqual(old.len, try ctx.write(&old, 0));

    // No write ever starts inside a record, so a trap there never springs.
    var fresh: [2048]u8 = @splat('n');
    storage.fail_next_write_at = RafT.chunkOffset(1024, 1) + RafT.nonce_length;
    try testing.expectEqual(fresh.len, try ctx.writeInPlace(&fresh, 0));
    try testing.expect(storage.fail_next_write_at != null);
    storage.fail_next_write_at = null;

    // A run that is refused as a whole leaves the previous records in place.
    fresh = @splat('p');
    storage.fail_next_write_at = RafT.chunkOffset(1024, 0);
    try testing.expectError(error.InjectedFailure, ctx.writeInPlace(&fresh, 0));

    ctx.close();
    ctx = try RafT.open(testing.allocator, &storage, random, .{}, &key);

    var out: [2048]u8 = undefined;
    try testing.expectEqual(out.len, try ctx.read(&out, 0));
    const expected: [2048]u8 = @splat('n');
    try testing.expectEqualSlices(u8, &expected, &out);
}
