const std = @import("std");
const aegis_aead = std.crypto.aead.aegis;
const aegis_mac = std.crypto.auth.aegis;
const kdf = @import("kdf.zig");

pub const magic = "AEGISRAF";
pub const header_size = 64;
pub const file_id_bytes = 24;
pub const tag_bytes = 16;
pub const version = 1;

pub const chunk_size_min = 1024;
pub const chunk_size_max = 1 << 20;

/// The AEGIS variant a RAF file was encrypted with, stored as a single byte in its header.
pub const AlgId = enum(u8) {
    aegis128l = 1,
    aegis128x2 = 2,
    aegis128x4 = 3,
    aegis256 = 4,
    aegis256x2 = 5,
    aegis256x4 = 6,
};

/// An in-memory backing store, mainly for tests, but also handy for
/// building a RAF file in memory before writing it out in one shot.
///
/// This also works as the reference implementation of the storage interface
/// `Raf()` expects as a type parameter: a type with a `pub const Error`, plus
/// `readPositionalAll`, `writePositionalAll`, `length`, `setLength`, and
/// `sync` methods matching the ones below.
/// Naming and short-read behavior mirror `std.Io.File`.
pub const MemoryStorage = struct {
    pub const Error = std.mem.Allocator.Error || error{OutOfBounds};

    bytes: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MemoryStorage {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MemoryStorage) void {
        self.bytes.deinit(self.allocator);
    }

    pub fn readPositionalAll(self: *MemoryStorage, buffer: []u8, offset: u64) Error!usize {
        if (offset >= self.bytes.items.len) return 0;
        // Safe: offset < items.len (a usize) was just checked above.
        const start: usize = @intCast(offset);
        const n = @min(buffer.len, self.bytes.items.len - start);
        @memcpy(buffer[0..n], self.bytes.items[start..][0..n]);
        return n;
    }

    pub fn writePositionalAll(self: *MemoryStorage, bytes: []const u8, offset: u64) Error!void {
        // Checked as two comparisons, rather than offset + bytes.len > items.len,
        // so an offset near u64's max cannot wrap the addition around to a small value.
        if (offset > self.bytes.items.len) return error.OutOfBounds;
        // Safe: offset <= items.len (a usize) was just checked above.
        const start: usize = @intCast(offset);
        if (bytes.len > self.bytes.items.len - start) return error.OutOfBounds;
        @memcpy(self.bytes.items[start..][0..bytes.len], bytes);
    }

    pub fn length(self: *MemoryStorage) Error!u64 {
        return self.bytes.items.len;
    }

    pub fn setLength(self: *MemoryStorage, new_length: u64) Error!void {
        // On a 32-bit target, new_length can exceed what usize can hold.
        const len = std.math.cast(usize, new_length) orelse return error.OutOfBounds;
        try self.bytes.resize(self.allocator, len);
    }

    pub fn sync(self: *MemoryStorage) Error!void {
        _ = self;
    }
};

fn isValidChunkSize(chunk_size: u32) bool {
    return chunk_size >= chunk_size_min and chunk_size <= chunk_size_max and std.mem.isAlignedGeneric(u32, chunk_size, 16);
}

/// File metadata as reported by `probe()`.
/// Enough to pick the right variant and chunk size before authenticating anything.
pub const Info = struct {
    /// The logical (plaintext) size of the file, in bytes.
    file_size: u64,
    /// The size of each chunk, in bytes.
    chunk_size: u32,
    /// Which AEGIS variant encrypted the file.
    alg_id: AlgId,
};

pub const ProbeError = error{InvalidHeader};

// Parses a header and checks its shape (magic, size, version, chunk size,
// algorithm id) without checking its MAC.
//
// Shared by `probe()`, which stops here, and `verifyHeader()`, which also
// checks the algorithm id against its own variant and verifies the MAC.
fn parseHeaderFields(hdr: *const [header_size]u8) ProbeError!Info {
    if (!std.mem.eql(u8, hdr[0..8], magic)) return error.InvalidHeader;
    if (std.mem.readInt(u16, hdr[8..10], .little) != header_size) return error.InvalidHeader;
    if (hdr[10] != version) return error.InvalidHeader;

    const chunk_size = std.mem.readInt(u32, hdr[12..16], .little);
    if (!isValidChunkSize(chunk_size)) return error.InvalidHeader;

    const alg_id = std.enums.fromInt(AlgId, hdr[11]) orelse return error.InvalidHeader;

    return .{
        .file_size = std.mem.readInt(u64, hdr[16..24], .little),
        .chunk_size = chunk_size,
        .alg_id = alg_id,
    };
}

/// Reads and parses a RAF header without validating its MAC.
/// Lets a caller discover which variant and chunk size a file uses before opening it.
/// `storage` can be any type satisfying the interface documented on `MemoryStorage`.
pub fn probe(storage: anytype) (ProbeError || @TypeOf(storage.*).Error)!Info {
    var hdr: [header_size]u8 = undefined;
    const n = try storage.readPositionalAll(&hdr, 0);
    if (n != hdr.len) return error.InvalidHeader;
    return parseHeaderFields(&hdr);
}

pub const DeriveMasterKeyError = error{ContextTooLong};

/// Derives a context-bound RAF master key from an application master key.
/// The same master key, used with a different context, gives an unrelated key.
/// `master_key` and the returned key are both 16 or 32 bytes.
/// Mirrors libaegis's `aegis_raf_derive_master_key()`.
pub fn deriveMasterKey(comptime key_len: usize, master_key: *const [key_len]u8, context: []const u8) DeriveMasterKeyError![key_len]u8 {
    comptime std.debug.assert(key_len == 16 or key_len == 32);

    // Matches libaegis's own limit: the context, the KDF's label, and the key
    // must all fit in one Keccak block, alongside the length-prefixed context.
    // See kdf.zig for where that block-size limit comes from.
    const max_context_len = if (key_len == 16) 120 else 72;
    if (context.len > max_context_len) return error.ContextTooLong;

    const derive_context = "aegis-raf-master-key-v1";
    var file_id_buf: [8 + 120]u8 = undefined;
    std.mem.writeInt(u64, file_id_buf[0..8], context.len, .little);
    @memcpy(file_id_buf[8..][0..context.len], context);

    var out: [key_len]u8 = undefined;
    if (key_len == 16) {
        kdf.aegisKdf128(&out, derive_context, master_key, file_id_buf[0 .. 8 + context.len]);
    } else {
        kdf.aegisKdf256(&out, derive_context, master_key, file_id_buf[0 .. 8 + context.len]);
    }
    return out;
}
