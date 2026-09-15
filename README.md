# AEGIS-RAF for Zig

AEGIS RAF is a way to store data in a single encrypted file and provides random access without decrypting the entire file first.

It's useful for large files that must remain confidential while supporting efficient reads and writes, such as local databases, append-only logs, and mailboxes.

The file is divided into fixed-size chunks, and each chunk is encrypted and authenticated independently.

If someone changes a byte or you open the file with the wrong key, the operation returns an authentication error instead of corrupted data.

The RAF format comes from [libaegis](https://github.com/jedisct1/libaegis).

This library implements the format in Zig, with no C compiler or external dependencies required.

The implementations are interoperable: files written by this library can be opened by libaegis, and files written by libaegis can be opened here.

## Ok, what do we get from this?

- Read or write at any offset without processing the rest of the file.
- Detect tampering and incorrect keys through per-chunk authentication.
- Choose from six AEGIS variants with 16-byte or 32-byte keys.
- Store the file in memory or on disk.
- Build using only Zig's standard library.

The optional Merkle-tree commitments supported by libaegis aren't implemented.
They don't change the file layout, so files remain compatible with libaegis.

## Quick start

First, choose an AEGIS variant and a storage backend.
Both are part of the RAF type, so define the type once near the top of your file.

```zig
const std = @import("std");
const aegis = @import("aegis_raf");

const Raf = aegis.Aegis128LRaf(aegis.MemoryStorage);

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;

    var random_source = std.Random.IoSource{ .io = io };
    const random = random_source.interface();

    var key: [Raf.key_length]u8 = undefined;
    random.bytes(&key);

    var storage = aegis.MemoryStorage.init(gpa);
    defer storage.deinit();

    {
        var raf = try Raf.create(gpa, &storage, random, .{ .chunk_size = 4096 }, &key);
        defer raf.close();
        _ = try raf.write("Hello from AEGIS-RAF!", 0);
    }

    var raf = try Raf.open(gpa, &storage, random, &key);
    defer raf.close();

    var buf: [64]u8 = undefined;
    const n = try raf.read(&buf, 0);
    std.debug.print("read {d} bytes: {s}\n", .{ n, buf[0..n] });
}
```

This program creates a file in memory, writes a message at offset zero, closes the file, reopens it, and reads the message back.

Both RAF values use `defer raf.close()` so that their keys are wiped from memory and their working buffers are freed, even if an error causes the block to return early.

## Choosing a variant

The variant determines the key length and the number of parallel AEGIS lanes.

Always open a file with the variant that created it and a key of the corresponding length.
Using a different variant returns `error.AlgorithmMismatch`.

| Variant         | Key size | Parallel lanes |
| --------------- | -------- | -------------- |
| `Aegis128LRaf`  | 16 bytes | 1              |
| `Aegis128X2Raf` | 16 bytes | 2              |
| `Aegis128X4Raf` | 16 bytes | 4              |
| `Aegis256Raf`   | 32 bytes | 1              |
| `Aegis256X2Raf` | 32 bytes | 2              |
| `Aegis256X4Raf` | 32 bytes | 4              |

The `x2` and `x4` variants process two or four AEGIS lanes in parallel and may be faster on supported hardware.

## Storage implementations

`MemoryStorage` keeps everything in RAM, while `FileStorage` writes to a file you already opened.

```zig
const io = init.io;
const Raf = aegis.Aegis128LRaf(aegis.FileStorage);

const file = try std.Io.Dir.cwd().createFile(io, "data.raf", .{ .read = true });
defer file.close(io);

var storage = aegis.FileStorage.init(file, io);
var raf = try Raf.create(gpa, &storage, random, .{ .chunk_size = 4096 }, &key);
defer raf.close();
```

`FileStorage` borrows the file handle rather than taking ownership of it.
Keep the file open for the lifetime of the `raf` value, then close it yourself.

## Keys

The master key protects the file.

It's either 16 or 32 bytes long, and it's never stored in the file.

If you lose the key, the data can't be recovered. If the key is compromised, the file can be read and modified.

You can use one master key for multiple files because each file has a random ID.
The ID is used to derive per-file encryption keys, so files protected by the same master key still use different encryption keys.

If you'd rather keep separate keys for separate purposes, you can derive one from a key you already have:

```zig
const Aegis256Raf = aegis.Aegis256Raf(aegis.MemoryStorage);

const app_key: [32]u8 = ...;
const file_key = try aegis.deriveMasterKey(32, &app_key, "photos");

var raf = try Aegis256Raf.create(gpa, &storage, random, .{ .chunk_size = 4096 }, &file_key);
```

Using a different label with the same starting key produces an independent key.

The label can be up to 120 bytes for a 16-byte key or 72 bytes for a 32-byte key.
A longer label returns `error.ContextTooLong`.

## Creating a file

Choose the chunk size when creating the file. It can't be changed later.

| Option       | Default | Meaning                                            |
| ------------ | ------- | -------------------------------------------------- |
| `chunk_size` | none    | Required. 1024 to 1048576 bytes, a multiple of 16. |
| `create`     | `true`  | Allow creating the file when it doesn't exist.     |
| `truncate`   | `false` | Allow overwriting the file when it already exists. |

`create` and `truncate` behave like the `O_CREAT` and `O_TRUNC` flags.
Any existing destination counts as a file, even if it isn't in RAF format.
Set `truncate` to overwrite it; otherwise, `create` returns `error.FileExists`.

Choosing a chunk size involves a trade-off.

Larger chunks improve sequential-read performance because fewer chunks need to be authenticated.

Smaller chunks reduce the work required for small random writes because modifying one byte rewrites the entire chunk.

The example uses 4096 bytes, which is a reasonable starting point.

## Reading and writing

```zig
var raf = try Raf.open(gpa, &storage, random, &key);
defer raf.close();

// Overwrite bytes 1024 through 1033.
_ = try raf.write("0123456789", 1024);

// Read them back.
var buf: [10]u8 = undefined;
const n = try raf.read(&buf, 1024);
std.debug.print("{s}\n", .{buf[0..n]});

// Extend the file: the gap fills with zero bytes.
_ = try raf.write("tail", 8192);

// Resize. Growing fills with zeros, shrinking discards the tail.
try raf.setLength(500);

try raf.sync(); // Push the data out to the file.
```

Each read or write takes a byte offset from the beginning of the file.

`read` returns the number of bytes read, which may be smaller than the requested length at the end of the file.

`write` writes the entire input and grows the file when necessary.

Call `sync` when the data must be flushed to disk.

Call `close` when finished to wipe the keys from memory and free the working buffers.

## Looking at a file without the key

`probe` reads basic file metadata without a key, including the variant and chunk size.

```zig
const info = try aegis.probe(&storage);
switch (info.alg_id) {
    .aegis128l => { /* open with Aegis128LRaf */ },
    else => {},
}
```

`probe` doesn't authenticate the metadata, so treat its result only as a hint.
Use `open` to verify the file with a key.

## Things to keep in mind

- The chunk size is fixed when the file is created and can't be changed later.
- Your key is never stored, so losing it means losing the data.
- Merkle-tree commitments from libaegis aren't supported.
- A `raf` value isn't thread-safe because its working state is mutable.
