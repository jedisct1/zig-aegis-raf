//! Behavioral tests for the RAF port, adapted from libaegis's
//! src/test/raf_test.zig (which exercises the C implementation through
//! translate-c bindings) to exercise this pure-Zig implementation instead.
const std = @import("std");
const testing = std.testing;
const raf = @import("raf.zig");

var prng = std.Random.DefaultPrng.init(0xAE615);
const random = prng.random();

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

test "MemoryStorage: an offset near u64's max does not overflow the bounds check" {
    var mem = raf.MemoryStorage.init(testing.allocator);
    defer mem.deinit();
    try mem.setLength(4);

    var one_byte = [_]u8{0xAA};
    try testing.expectError(error.OutOfBounds, mem.writePositionalAll(&one_byte, std.math.maxInt(u64)));
}
