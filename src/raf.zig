//! AEGIS-RAF: a random-access encrypted file format built on top of AEGIS.
//!
//! This is a Zig port of the RAF layer from libaegis (src/raf/).
//! It reuses the AEGIS encryption and authentication code already in `std.crypto`, and reimplements the on-disk layout around it.
//! That layout is a fixed 64-byte authenticated header, followed by fixed-size chunks.
//! Each chunk is encrypted on its own, with its own random nonce.
//! A file written by one implementation can always be read back by the other.
//!
//! One piece of libaegis is missing here: the optional Merkle-tree commitment feature.
//! It only touches a buffer the caller provides, and it is never written to the file, so leaving it out does not affect compatibility.
//! It can be added later without touching anything below.
//!
//! Whole chunks never pass through an internal buffer.
//! `read` decrypts them inside the caller's buffer, and `writeInPlace` encrypts them there.
//! Only a partial chunk, at either end of a request, goes through the scratch buffer.
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

// The most chunks one run moves at once, which bounds the stack space of a run.
const max_run = 64;

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
/// `readPositionalAll`, `writePositionalAll`, `readPositionalVecAll`,
/// `writePositionalVecAll`, `length`, `setLength`, and `sync` methods
/// matching the ones below.
/// Naming and short-read behavior mirror `std.Io.File`.
/// `FileStorage` below is the same interface, backed by a real file instead of memory.
///
/// The vectored pair moves several buffers with one call and may shorten the entries of the slice it receives.
/// A vectored write that fails must leave the store untouched, so this one checks the whole range before it copies.
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

    pub fn readPositionalVecAll(self: *MemoryStorage, buffers: [][]u8, offset: u64) Error!usize {
        var total: usize = 0;
        for (buffers) |buffer| {
            const n = try self.readPositionalAll(buffer, offset + total);
            total += n;
            if (n != buffer.len) break;
        }
        return total;
    }

    pub fn writePositionalVecAll(self: *MemoryStorage, buffers: [][]const u8, offset: u64) Error!void {
        var total: u64 = 0;
        for (buffers) |bytes| total += bytes.len;
        if (offset > self.bytes.items.len) return error.OutOfBounds;
        if (total > self.bytes.items.len - offset) return error.OutOfBounds;

        var pos: usize = @intCast(offset);
        for (buffers) |bytes| {
            @memcpy(self.bytes.items[pos..][0..bytes.len], bytes);
            pos += bytes.len;
        }
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

/// A backing store over an already-open `std.Io.File`, for saving a RAF
/// file to disk instead of keeping it in memory.
///
/// Every method here just calls the matching `std.Io.File` method with the
/// same offset, so it satisfies the interface documented on `MemoryStorage`
/// without redefining it.
///
/// The caller opens and closes the file. `FileStorage` only borrows it, the
/// same way `Raf()` only borrows a `*Storage`.
pub const FileStorage = struct {
    pub const Error = std.Io.File.ReadPositionalError ||
        std.Io.File.WritePositionalError ||
        std.Io.File.LengthError ||
        std.Io.File.SetLengthError ||
        std.Io.File.SyncError;

    file: std.Io.File,
    io: std.Io,

    pub fn init(file: std.Io.File, io: std.Io) FileStorage {
        return .{ .file = file, .io = io };
    }

    pub fn readPositionalAll(self: *FileStorage, buffer: []u8, offset: u64) Error!usize {
        return self.file.readPositionalAll(self.io, buffer, offset);
    }

    pub fn writePositionalAll(self: *FileStorage, bytes: []const u8, offset: u64) Error!void {
        return self.file.writePositionalAll(self.io, bytes, offset);
    }

    pub fn readPositionalVecAll(self: *FileStorage, buffers: [][]u8, offset: u64) Error!usize {
        var remaining = buffers;
        var total: usize = 0;
        while (remaining.len != 0) {
            const n = try self.file.readPositional(self.io, remaining, offset + total);
            if (n == 0) break;
            total += n;
            remaining = advance([]u8, remaining, n);
        }
        return total;
    }

    pub fn writePositionalVecAll(self: *FileStorage, buffers: [][]const u8, offset: u64) Error!void {
        var remaining = buffers;
        var total: u64 = 0;
        while (remaining.len != 0) {
            const n = try self.file.writePositional(self.io, remaining, offset + total);
            total += n;
            remaining = advance([]const u8, remaining, n);
        }
    }

    // What is left to move once `n` bytes went through.
    fn advance(comptime Slice: type, buffers: []Slice, n: usize) []Slice {
        var remaining = buffers;
        var skip = n;
        while (remaining.len != 0 and skip >= remaining[0].len) {
            skip -= remaining[0].len;
            remaining = remaining[1..];
        }
        if (remaining.len != 0) remaining[0] = remaining[0][skip..];
        return remaining;
    }

    pub fn length(self: *FileStorage) Error!u64 {
        return self.file.length(self.io);
    }

    pub fn setLength(self: *FileStorage, new_length: u64) Error!void {
        return self.file.setLength(self.io, new_length);
    }

    pub fn sync(self: *FileStorage) Error!void {
        return self.file.sync(self.io);
    }
};

fn isValidChunkSize(chunk_size: u32) bool {
    return chunk_size >= chunk_size_min and chunk_size <= chunk_size_max and std.mem.isAlignedGeneric(u32, chunk_size, 16);
}

fn chunkCount(chunk_size: u32, file_size: u64) u64 {
    return std.math.divCeil(u64, file_size, chunk_size) catch unreachable;
}

/// Splits off the next transfer at `position`: which chunk it falls in, the
/// offset within that chunk, and how many bytes can move before crossing
/// into the next chunk or running out of `remaining`.
///
/// Shared by `read()` and the write loop in `writeImpl()`.
fn chunkSlice(chunk_size: u32, position: u64, remaining: u64) struct { idx: u64, offset: u32, len: usize } {
    const offset: u32 = @intCast(position % chunk_size);
    return .{
        .idx = position / chunk_size,
        .offset = offset,
        .len = @intCast(@min(chunk_size - offset, remaining)),
    };
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

/// Options for creating a new RAF file.
/// Mirrors the independent AEGIS_RAF_CREATE / AEGIS_RAF_TRUNCATE flags in libaegis, which behave like POSIX O_CREAT / O_TRUNC.
pub const CreateOptions = struct {
    /// Must be within `chunk_size_min` and `chunk_size_max`, and a multiple of 16.
    chunk_size: u32,
    /// Allows creating the file when it does not exist yet.
    create: bool = true,
    /// Allows overwriting the file when it already exists.
    truncate: bool = false,
};

const aad_bytes = file_id_bytes + 8 + 4;

fn buildAad(out: *[aad_bytes]u8, file_id: *const [file_id_bytes]u8, chunk_idx: u64, chunk_size: u32) void {
    @memcpy(out[0..file_id_bytes], file_id);
    std.mem.writeInt(u64, out[file_id_bytes..][0..8], chunk_idx, .little);
    std.mem.writeInt(u32, out[file_id_bytes + 8 ..][0..4], chunk_size, .little);
}

/// Builds a RAF implementation over a given AEGIS AEAD variant and backing store.
///
/// `Aead` and `Mac` must be a matching pair sharing the same underlying state (e.g. `std.crypto.aead.aegis.Aegis128L` and `std.crypto.auth.aegis.Aegis128LMac_128`).
/// RAF always uses the 128-bit-tag flavor of each variant, regardless of key size, because that is what libaegis's chunk and header MACs use.
///
/// `Storage` must satisfy the interface documented on `MemoryStorage`.
///
/// A mutation (`write`, `setLength`) that returns an error may have left the
/// backing store partially updated. From that point on, every call returns
/// `error.ContextFailed`, until the caller closes this context and reopens the file.
///
/// Header updates keep the previous authenticated header as a temporary
/// trailer, so reopening can recover from a torn write to the primary header.
/// Reopening does not undo chunk writes that completed before the error.
pub fn Raf(comptime Aead: type, comptime Mac: type, comptime alg_id: AlgId, comptime Storage: type) type {
    comptime std.debug.assert(Aead.tag_length == tag_bytes);
    comptime std.debug.assert(Mac.mac_length == tag_bytes);
    comptime std.debug.assert(Mac.key_length == Aead.key_length);

    return struct {
        const Self = @This();

        pub const key_length = Aead.key_length;
        pub const nonce_length = Aead.nonce_length;
        pub const Error = error{
            InvalidArgument,
            FileExists,
            FileNotFound,
            InvalidHeader,
            AlgorithmMismatch,
            AuthenticationFailed,
            Overflow,
            ShortRead,
            ContextFailed,
        } || Storage.Error || std.mem.Allocator.Error;

        allocator: std.mem.Allocator,
        storage: *Storage,
        // Must be a cryptographically secure random source: it generates
        // the file id at creation and, from then on, every chunk nonce.
        random: std.Random,

        enc_key: [key_length]u8,
        hdr_key: [key_length]u8,
        file_id: [file_id_bytes]u8,
        file_size: u64,
        chunk_size: u32,

        // Set when open() had to fall back to the recovery trailer because the
        // primary header was torn. Reads work right away.
        //
        // The next mutation repairs the primary header and removes the trailer
        // first, so a later resize cannot end up discarding the only valid header.
        recovered_header: bool = false,

        // True from the moment a mutation starts touching the backing store
        // until it either finishes or fails. Left true after a failure, so
        // every later call is rejected instead of building on state that
        // may be half-written.
        failed: bool = false,

        // The chunk AAD is file_id || chunk_idx || chunk_size. Only chunk_idx
        // changes between chunks, so it is built once and patched in place,
        // instead of rebuilt on every read or write.
        aad: [aad_bytes]u8,

        // Scratch for a partial chunk, zeroized in `close()`.
        chunk_buf: []u8,

        /// Bytes one record takes on disk: nonce, ciphertext of one chunk, tag.
        pub fn recordSize(chunk_size: u32) u64 {
            return nonce_length + chunk_size + tag_bytes;
        }

        /// Where the record of a chunk starts in the file.
        pub fn chunkOffset(chunk_size: u32, chunk_idx: u64) u64 {
            return header_size + chunk_idx * recordSize(chunk_size);
        }

        fn backingSizeForChunks(chunk_size: u32, num_chunks: u64) Error!u64 {
            const chunks_size = std.math.mul(u64, num_chunks, recordSize(chunk_size)) catch return error.Overflow;
            return std.math.add(u64, header_size, chunks_size) catch return error.Overflow;
        }

        fn checkUsable(self: *const Self) Error!void {
            if (self.failed) return error.ContextFailed;
        }

        fn deriveKeys(enc_key: *[key_length]u8, hdr_key: *[key_length]u8, master_key: *const [key_length]u8, file_id: *const [file_id_bytes]u8) void {
            var key_material: [key_length * 2]u8 = undefined;
            const context = "aegis-raf-kdf-v1";
            if (key_length == 16) {
                kdf.aegisKdf128(&key_material, context, master_key, file_id);
            } else {
                kdf.aegisKdf256(&key_material, context, master_key, file_id);
            }
            @memcpy(enc_key, key_material[0..key_length]);
            @memcpy(hdr_key, key_material[key_length..]);
        }

        // Takes the file size explicitly, so the header can be committed to
        // disk before self.file_size itself changes.
        fn buildHeader(self: *const Self, file_size: u64) [header_size]u8 {
            var hdr: [header_size]u8 = undefined;
            @memcpy(hdr[0..8], magic);
            std.mem.writeInt(u16, hdr[8..10], header_size, .little);
            hdr[10] = version;
            hdr[11] = @backingInt(alg_id);
            std.mem.writeInt(u32, hdr[12..16], self.chunk_size, .little);
            std.mem.writeInt(u64, hdr[16..24], file_size, .little);
            @memcpy(hdr[24..48], &self.file_id);

            var mac: [tag_bytes]u8 = undefined;
            Mac.create(&mac, hdr[0 .. header_size - tag_bytes], &self.hdr_key);
            @memcpy(hdr[header_size - tag_bytes ..], &mac);

            return hdr;
        }

        fn writeHeader(self: *Self, file_size: u64) Error!void {
            const hdr = self.buildHeader(file_size);
            try self.storage.writePositionalAll(&hdr, 0);
        }

        // Appends the current header as a trailer before writing the new
        // primary header. If that write tears, open() can authenticate the
        // trailer and recover the previous state. The trailer is removed once
        // the new header has landed, so the file matches the normal libaegis
        // format again.
        //
        // `recovery_offset` is where the trailer goes: the backing store's
        // length right before this call. It is passed in, instead of queried
        // here, because the growing-write caller already knows it for free.
        fn commitHeader(self: *Self, new_file_size: u64, recovery_offset: u64, canonical_backing_size: u64) Error!void {
            const recovery_hdr = self.buildHeader(self.file_size);
            const recovery_end = std.math.add(u64, recovery_offset, header_size) catch return error.Overflow;

            try self.storage.setLength(recovery_end);
            try self.storage.writePositionalAll(&recovery_hdr, recovery_offset);
            try self.writeHeader(new_file_size);
            try self.storage.setLength(canonical_backing_size);
        }

        fn repairRecoveredHeader(self: *Self) Error!void {
            if (!self.recovered_header) return;

            self.failed = true;
            const canonical_backing_size = try backingSizeForChunks(self.chunk_size, chunkCount(self.chunk_size, self.file_size));
            // The recovery trailer remains intact until this write succeeds.
            try self.writeHeader(self.file_size);
            try self.storage.setLength(canonical_backing_size);
            self.recovered_header = false;
            self.failed = false;
        }

        /// Parses and authenticates a header already known to belong to this variant.
        /// The caller either checked `alg_id` via `probe()`, or is re-deriving `hdr_key` for exactly this variant.
        fn verifyHeader(hdr: *const [header_size]u8, hdr_key: *const [key_length]u8) Error!Info {
            const parsed = try parseHeaderFields(hdr);
            if (parsed.alg_id != alg_id) return error.AlgorithmMismatch;

            var expected_mac: [tag_bytes]u8 = undefined;
            Mac.create(&expected_mac, hdr[0 .. header_size - tag_bytes], hdr_key);
            if (!std.crypto.timing_safe.eql([tag_bytes]u8, expected_mac, hdr[header_size - tag_bytes ..][0..tag_bytes].*)) {
                return error.AuthenticationFailed;
            }

            return parsed;
        }

        // Decrypts up to `max_run` whole chunks straight into `out`. Returns the bytes read.
        fn readRun(self: *Self, out: []u8, first_idx: u64) Error!usize {
            const count: usize = @min(out.len / self.chunk_size, max_run);
            var nonces: [max_run][nonce_length]u8 = undefined;
            var tags: [max_run][tag_bytes]u8 = undefined;
            var buffers: [max_run * 3][]u8 = undefined;

            for (0..count) |i| {
                buffers[i * 3] = &nonces[i];
                buffers[i * 3 + 1] = out[i * self.chunk_size ..][0..self.chunk_size];
                buffers[i * 3 + 2] = &tags[i];
            }

            const got = try self.storage.readPositionalVecAll(buffers[0 .. count * 3], chunkOffset(self.chunk_size, first_idx));
            if (got != count * recordSize(self.chunk_size)) return error.ShortRead;

            for (0..count) |i| {
                const chunk = out[i * self.chunk_size ..][0..self.chunk_size];
                std.mem.writeInt(u64, self.aad[file_id_bytes..][0..8], first_idx + i, .little);
                Aead.decrypt(chunk, chunk, tags[i], &self.aad, nonces[i], self.enc_key) catch {
                    return error.AuthenticationFailed;
                };
            }
            return count * self.chunk_size;
        }

        fn readChunk(self: *Self, chunk_idx: u64) Error!void {
            _ = try self.readRun(self.chunk_buf, chunk_idx);
        }

        // Encrypts up to `max_run` whole chunks of `src` into `dst`, which may be `src` itself. Returns the bytes consumed.
        fn writeRun(self: *Self, dst: []u8, src: []const u8, first_idx: u64) Error!usize {
            const count: usize = @min(dst.len / self.chunk_size, max_run);
            std.debug.assert(src.len >= count * self.chunk_size);
            var nonces: [max_run][nonce_length]u8 = undefined;
            var tags: [max_run][tag_bytes]u8 = undefined;
            var buffers: [max_run * 3][]const u8 = undefined;

            // One draw per run: a draw has a fixed cost that shows with small chunks.
            self.random.bytes(std.mem.sliceAsBytes(nonces[0..count]));

            for (0..count) |i| {
                const ciphertext = dst[i * self.chunk_size ..][0..self.chunk_size];
                const plaintext = src[i * self.chunk_size ..][0..self.chunk_size];
                std.mem.writeInt(u64, self.aad[file_id_bytes..][0..8], first_idx + i, .little);
                Aead.encrypt(ciphertext, &tags[i], plaintext, &self.aad, nonces[i], self.enc_key);
                buffers[i * 3] = &nonces[i];
                buffers[i * 3 + 1] = ciphertext;
                buffers[i * 3 + 2] = &tags[i];
            }

            try self.storage.writePositionalVecAll(buffers[0 .. count * 3], chunkOffset(self.chunk_size, first_idx));
            return count * self.chunk_size;
        }

        fn writeChunk(self: *Self, plaintext_len: usize, chunk_idx: u64) Error!void {
            if (plaintext_len < self.chunk_size) {
                @memset(self.chunk_buf[plaintext_len..], 0);
            }
            _ = try self.writeRun(self.chunk_buf, self.chunk_buf, chunk_idx);
        }

        /// Creates a new RAF file.
        /// `options.create`/`options.truncate` control whether an existing or missing file is acceptable, like POSIX O_CREAT/O_TRUNC.
        /// `random` must be a cryptographically secure random source: it generates the file id and every chunk nonce.
        pub fn create(
            allocator: std.mem.Allocator,
            storage: *Storage,
            random: std.Random,
            options: CreateOptions,
            master_key: *const [key_length]u8,
        ) Error!Self {
            if (!isValidChunkSize(options.chunk_size)) return error.InvalidArgument;

            const backing_size = try storage.length();
            // Any nonempty backing store counts as an existing file. A short or
            // foreign file is not a valid RAF file, but it is still somebody's
            // data, and it must not be silently replaced unless truncate is true.
            const file_exists = backing_size > 0;
            if (file_exists and !options.truncate) return error.FileExists;
            if (!file_exists and !options.create) return error.FileNotFound;

            var file_id: [file_id_bytes]u8 = undefined;
            random.bytes(&file_id);

            var enc_key: [key_length]u8 = undefined;
            var hdr_key: [key_length]u8 = undefined;
            deriveKeys(&enc_key, &hdr_key, master_key, &file_id);

            var aad: [aad_bytes]u8 = undefined;
            buildAad(&aad, &file_id, 0, options.chunk_size);

            const chunk_buf = try allocator.alloc(u8, options.chunk_size);
            errdefer allocator.free(chunk_buf);

            try storage.setLength(header_size);

            var self = Self{
                .allocator = allocator,
                .storage = storage,
                .random = random,
                .enc_key = enc_key,
                .hdr_key = hdr_key,
                .file_id = file_id,
                .file_size = 0,
                .chunk_size = options.chunk_size,
                .recovered_header = false,
                .aad = aad,
                .chunk_buf = chunk_buf,
            };
            try self.writeHeader(0);
            return self;
        }

        /// Opens an existing RAF file, authenticating its header with a key derived from `master_key` and the file's own file_id.
        /// `random` must be a cryptographically secure random source: it generates every chunk nonce written from now on.
        pub fn open(
            allocator: std.mem.Allocator,
            storage: *Storage,
            random: std.Random,
            master_key: *const [key_length]u8,
        ) Error!Self {
            const backing_size = try storage.length();
            if (backing_size < header_size) return error.InvalidHeader;

            var hdr: [header_size]u8 = undefined;
            const n = try storage.readPositionalAll(&hdr, 0);
            if (n != hdr.len) return error.InvalidHeader;

            var enc_key: [key_length]u8 = undefined;
            var hdr_key: [key_length]u8 = undefined;
            var file_id: [file_id_bytes]u8 = undefined;
            var recovered_header = false;
            var authenticated_backing_size = backing_size;

            @memcpy(&file_id, hdr[24..48]);
            deriveKeys(&enc_key, &hdr_key, master_key, &file_id);

            const parsed = verifyHeader(&hdr, &hdr_key) catch |primary_error| recover: {
                if (backing_size < header_size * 2) return primary_error;

                const recovery_offset = backing_size - header_size;
                var recovery_hdr: [header_size]u8 = undefined;
                const recovery_n = try storage.readPositionalAll(&recovery_hdr, recovery_offset);
                if (recovery_n != recovery_hdr.len) return primary_error;

                @memcpy(&file_id, recovery_hdr[24..48]);
                deriveKeys(&enc_key, &hdr_key, master_key, &file_id);
                const recovery_parsed = verifyHeader(&recovery_hdr, &hdr_key) catch return primary_error;

                recovered_header = true;
                authenticated_backing_size = recovery_offset;
                break :recover recovery_parsed;
            };

            const max_chunks = chunkCount(parsed.chunk_size, parsed.file_size);
            const backing_needed = try backingSizeForChunks(parsed.chunk_size, max_chunks);
            if (authenticated_backing_size < backing_needed) return error.InvalidHeader;

            var aad: [aad_bytes]u8 = undefined;
            buildAad(&aad, &file_id, 0, parsed.chunk_size);

            const chunk_buf = try allocator.alloc(u8, parsed.chunk_size);
            errdefer allocator.free(chunk_buf);

            return Self{
                .allocator = allocator,
                .storage = storage,
                .random = random,
                .enc_key = enc_key,
                .hdr_key = hdr_key,
                .file_id = file_id,
                .file_size = parsed.file_size,
                .chunk_size = parsed.chunk_size,
                .recovered_header = recovered_header,
                .aad = aad,
                .chunk_buf = chunk_buf,
            };
        }

        /// Reads up to `out.len` bytes starting at `offset`.
        /// Returns the number of bytes actually read, which is short only at EOF.
        /// Whole chunks are decrypted inside `out` itself, so after an error `out` holds nothing usable.
        pub fn read(self: *Self, out: []u8, offset: u64) Error!usize {
            try self.checkUsable();
            if (out.len == 0 or offset >= self.file_size) return 0;

            const len: usize = @intCast(@min(out.len, self.file_size - offset));

            var total_read: usize = 0;
            while (total_read < len) {
                const s = chunkSlice(self.chunk_size, offset + total_read, len - total_read);
                if (s.offset == 0 and s.len == self.chunk_size) {
                    total_read += try self.readRun(out[total_read..len], s.idx);
                    continue;
                }
                try self.readChunk(s.idx);
                @memcpy(out[total_read..][0..s.len], self.chunk_buf[s.offset..][0..s.len]);
                total_read += s.len;
            }
            return total_read;
        }

        // Shared by write(), writeInPlace() and the growth path of setLength().
        // It still runs the gap-filling logic for a zero-length input, which
        // is exactly how a grow through setLength() works below.
        fn writeImpl(self: *Self, comptime in_place: bool, in: if (in_place) []u8 else []const u8, offset: u64) Error!usize {
            const new_file_size = std.math.add(u64, offset, in.len) catch return error.Overflow;

            const old_num_chunks = chunkCount(self.chunk_size, self.file_size);
            const new_num_chunks = chunkCount(self.chunk_size, new_file_size);
            const new_backing_size = try backingSizeForChunks(self.chunk_size, new_num_chunks);

            try self.repairRecoveredHeader();

            // From here on, a failure may leave the backing store partially
            // updated. The caller must reopen before doing anything else.
            self.failed = true;

            if (new_file_size > self.file_size) {
                try self.storage.setLength(new_backing_size);
            }

            if (offset > self.file_size) {
                const gap_start = self.file_size;
                const gap_end = offset;
                const first_gap_chunk = gap_start / self.chunk_size;
                const last_gap_chunk = if (gap_end > 0) (gap_end - 1) / self.chunk_size else 0;

                var ci = first_gap_chunk;
                while (ci <= last_gap_chunk and ci < new_num_chunks) : (ci += 1) {
                    const chunk_start = ci * self.chunk_size;
                    const chunk_end = chunk_start + self.chunk_size;

                    if (ci < old_num_chunks) {
                        try self.readChunk(ci);
                    } else {
                        @memset(self.chunk_buf, 0);
                    }

                    const zero_start: u32 = if (gap_start > chunk_start) @intCast(gap_start - chunk_start) else 0;
                    const zero_end: u32 = if (gap_end < chunk_end) @intCast(gap_end - chunk_start) else self.chunk_size;
                    if (zero_end > zero_start) @memset(self.chunk_buf[zero_start..zero_end], 0);

                    const chunk_valid_len: u32 = if (chunk_end <= new_file_size)
                        self.chunk_size
                    else
                        @intCast(new_file_size - chunk_start);

                    try self.writeChunk(chunk_valid_len, ci);
                }
            }

            var total_written: usize = 0;
            while (total_written < in.len) {
                const s = chunkSlice(self.chunk_size, offset + total_written, in.len - total_written);

                if (s.offset == 0 and s.len == self.chunk_size) {
                    // A whole chunk is encrypted where it is, or through the scratch buffer when `in` must stay intact.
                    const src = in[total_written..];
                    const dst: []u8 = if (in_place) src else self.chunk_buf;
                    total_written += try self.writeRun(dst, src, s.idx);
                    continue;
                }

                // A partial chunk keeps the bytes around the request, so its record is read first unless it lies past the end.
                const chunk_start = s.idx * self.chunk_size;
                if (chunk_start < self.file_size) {
                    try self.readChunk(s.idx);
                } else {
                    @memset(self.chunk_buf, 0);
                }

                @memcpy(self.chunk_buf[s.offset..][0..s.len], in[total_written..][0..s.len]);

                const effective_file_size = @max(new_file_size, self.file_size);
                const chunk_end_offset = (s.idx + 1) * self.chunk_size;
                const chunk_valid_len: u32 = if (chunk_end_offset <= effective_file_size)
                    self.chunk_size
                else
                    @intCast(effective_file_size - s.idx * self.chunk_size);

                try self.writeChunk(chunk_valid_len, s.idx);
                total_written += s.len;
            }

            if (new_file_size > self.file_size) {
                // Storage was just resized to new_backing_size above, so that
                // is already its current length: no need to ask it again.
                try self.commitHeader(new_file_size, new_backing_size, new_backing_size);
                self.file_size = new_file_size;
            }

            self.failed = false;
            return total_written;
        }

        /// Encrypts and writes `in` at `offset`, extending the file (with zero-filled chunks over any gap) if it writes past the current end.
        /// Always writes all of `in`.
        pub fn write(self: *Self, in: []const u8, offset: u64) Error!usize {
            try self.checkUsable();
            if (in.len == 0) return 0;
            return self.writeImpl(false, in, offset);
        }

        /// Like `write`, but whole chunks are encrypted inside `buf` itself and written from there, so no byte is copied.
        /// On return every whole chunk of `buf` holds ciphertext, and a partial chunk at either end keeps its bytes.
        /// Treat the whole buffer as consumed.
        pub fn writeInPlace(self: *Self, buf: []u8, offset: u64) Error!usize {
            try self.checkUsable();
            if (buf.len == 0) return 0;
            return self.writeImpl(true, buf, offset);
        }

        /// Resizes the file.
        /// Shrinking discards data beyond `new_length`. Growing fills the new range with zeros.
        pub fn setLength(self: *Self, new_length: u64) Error!void {
            try self.checkUsable();

            if (new_length > self.file_size) {
                _ = try self.writeImpl(false, &.{}, new_length);
                return;
            }

            // No early return for new_length == self.file_size: retrying the
            // same size is how a caller finishes a shrink whose physical
            // resize below failed after the smaller header already landed.
            const new_num_chunks = chunkCount(self.chunk_size, new_length);
            const new_backing_size = try backingSizeForChunks(self.chunk_size, new_num_chunks);

            try self.repairRecoveredHeader();

            if (new_length == self.file_size) {
                self.failed = true;
                try self.storage.setLength(new_backing_size);
                self.failed = false;
                return;
            }

            // Publish the smaller logical size before discarding the
            // now out-of-range chunk records. If the physical shrink below
            // then fails, the file is still valid to reopen, just carrying
            // unused trailing chunk records.
            self.failed = true;
            const recovery_offset = try self.storage.length();
            try self.commitHeader(new_length, recovery_offset, new_backing_size);
            self.file_size = new_length;
            self.failed = false;
        }

        /// The logical (plaintext) size of the file.
        pub fn length(self: *const Self) u64 {
            return self.file_size;
        }

        /// Flushes writes to the backing store.
        pub fn sync(self: *Self) Error!void {
            try self.checkUsable();
            try self.storage.sync();
        }

        /// Zeroizes key material and releases scratch buffers.
        /// Does not sync. Call `sync()` first if that matters to the caller.
        pub fn close(self: *Self) void {
            std.crypto.secureZero(u8, &self.enc_key);
            std.crypto.secureZero(u8, &self.hdr_key);
            std.crypto.secureZero(u8, self.chunk_buf);
            self.allocator.free(self.chunk_buf);
            self.* = undefined;
        }
    };
}

/// AEGIS-128L RAF: single-lane AEGIS-128L, keyed with 16 bytes.
pub fn Aegis128LRaf(comptime Storage: type) type {
    return Raf(aegis_aead.Aegis128L, aegis_mac.Aegis128LMac_128, .aegis128l, Storage);
}
/// AEGIS-128X2 RAF: two parallel AEGIS-128L lanes for higher throughput, keyed with 16 bytes.
pub fn Aegis128X2Raf(comptime Storage: type) type {
    return Raf(aegis_aead.Aegis128X2, aegis_mac.Aegis128X2Mac_128, .aegis128x2, Storage);
}
/// AEGIS-128X4 RAF: four parallel AEGIS-128L lanes for higher throughput, keyed with 16 bytes.
pub fn Aegis128X4Raf(comptime Storage: type) type {
    return Raf(aegis_aead.Aegis128X4, aegis_mac.Aegis128X4Mac_128, .aegis128x4, Storage);
}
/// AEGIS-256 RAF: single-lane AEGIS-256, keyed with 32 bytes.
pub fn Aegis256Raf(comptime Storage: type) type {
    return Raf(aegis_aead.Aegis256, aegis_mac.Aegis256Mac_128, .aegis256, Storage);
}
/// AEGIS-256X2 RAF: two parallel AEGIS-256 lanes for higher throughput, keyed with 32 bytes.
pub fn Aegis256X2Raf(comptime Storage: type) type {
    return Raf(aegis_aead.Aegis256X2, aegis_mac.Aegis256X2Mac_128, .aegis256x2, Storage);
}
/// AEGIS-256X4 RAF: four parallel AEGIS-256 lanes for higher throughput, keyed with 32 bytes.
pub fn Aegis256X4Raf(comptime Storage: type) type {
    return Raf(aegis_aead.Aegis256X4, aegis_mac.Aegis256X4Mac_128, .aegis256x4, Storage);
}
