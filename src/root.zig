//! AEGIS-RAF: a pure-Zig port of libaegis's random-access encrypted file
//! format, built on the AEGIS implementations in `std.crypto.aegis`.
//!
//! Files produced by this module and by libaegis's C implementation are
//! wire-compatible: either side can create a file and the other can open
//! it, given the same master key.
const raf = @import("raf.zig");

pub const MemoryStorage = raf.MemoryStorage;
pub const Info = raf.Info;
pub const AlgId = raf.AlgId;
pub const CreateOptions = raf.CreateOptions;

pub const chunk_size_min = raf.chunk_size_min;
pub const chunk_size_max = raf.chunk_size_max;
pub const header_size = raf.header_size;
pub const file_id_bytes = raf.file_id_bytes;

pub const probe = raf.probe;
pub const deriveMasterKey = raf.deriveMasterKey;

pub const Raf = raf.Raf;
pub const Aegis128LRaf = raf.Aegis128LRaf;
pub const Aegis128X2Raf = raf.Aegis128X2Raf;
pub const Aegis128X4Raf = raf.Aegis128X4Raf;
pub const Aegis256Raf = raf.Aegis256Raf;
pub const Aegis256X2Raf = raf.Aegis256X2Raf;
pub const Aegis256X4Raf = raf.Aegis256X4Raf;

test {
    _ = @import("kdf.zig");
    _ = @import("raf.zig");
    _ = @import("raf_test.zig");
}
