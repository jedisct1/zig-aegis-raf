const std = @import("std");
const Io = std.Io;
const aegis_raf = @import("aegis_raf");

const RafFile = aegis_raf.Aegis128LRaf(aegis_raf.MemoryStorage);

// A short demo: it creates a RAF file in memory, writes a message, reopens
// the file, and reads the message back. Run it by hand with `zig build run`.
//
// The real test suite lives in src/raf_test.zig.
pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;

    var random_source = std.Random.IoSource{ .io = io };
    const random = random_source.interface();

    var key: [RafFile.key_length]u8 = undefined;
    random.bytes(&key);

    var storage = aegis_raf.MemoryStorage.init(gpa);
    const message = "Hello from AEGIS-RAF!";

    {
        var raf = try RafFile.create(gpa, &storage, random, .{ .chunk_size = 4096 }, &key);
        defer raf.close();
        _ = try raf.write(message, 0);
    }

    var raf = try RafFile.open(gpa, &storage, random, .{}, &key);
    defer raf.close();

    var buf: [message.len]u8 = undefined;
    const n = try raf.read(&buf, 0);

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout_writer = &stdout_file_writer.interface;
    try stdout_writer.print("Decrypted {d} bytes: {s}\n", .{ n, buf[0..n] });
    try stdout_writer.flush();
}
