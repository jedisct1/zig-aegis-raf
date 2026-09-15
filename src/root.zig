const raf = @import("raf.zig");

pub const MemoryStorage = raf.MemoryStorage;
pub const Info = raf.Info;
pub const AlgId = raf.AlgId;
pub const chunk_size_min = raf.chunk_size_min;
pub const chunk_size_max = raf.chunk_size_max;
pub const header_size = raf.header_size;
pub const file_id_bytes = raf.file_id_bytes;
pub const probe = raf.probe;
pub const deriveMasterKey = raf.deriveMasterKey;

test {
    _ = @import("kdf.zig");
    _ = @import("raf.zig");
    _ = @import("raf_test.zig");
}
