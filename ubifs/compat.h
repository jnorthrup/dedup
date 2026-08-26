/*
 * compat.h — macOS/Linux compatibility shims for btrfs on-disk format.
 *
 * Instead of pulling in the vendored UAPI headers (which depend on
 * linux/types.h, linux/ioctl.h, etc.), this file defines the minimal
 * subset of btrfs structures and constants we need for superblock +
 * root-node formatting.
 */

#ifndef UBIFS_COMPAT_H
#define UBIFS_COMPAT_H

/* ── Standard integer types ────────────────────────────────────────────── */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

/* ── Kernel integer types ──────────────────────────────────────────────── */

typedef uint8_t   __u8;
typedef uint16_t  __u16;
typedef uint32_t  __u32;
typedef uint64_t  __u64;
typedef int64_t   __s64;
typedef int32_t   __s32;

/* Little-endian aliases — on LE hosts these are identity types */
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;

/* ── Byte-order helpers (LE hosts — x86_64, arm64) ────────────────────── */

#ifndef cpu_to_le64
#define cpu_to_le64(x) ((uint64_t)(x))
#endif
#ifndef cpu_to_le32
#define cpu_to_le32(x) ((uint32_t)(x))
#endif
#ifndef cpu_to_le16
#define cpu_to_le16(x) ((uint16_t)(x))
#endif
#ifndef le64_to_cpu
#define le64_to_cpu(x) ((uint64_t)(x))
#endif
#ifndef le32_to_cpu
#define le32_to_cpu(x) ((uint32_t)(x))
#endif
#ifndef le16_to_cpu
#define le16_to_cpu(x) ((uint16_t)(x))
#endif

/* ── btrfs UUID/FSID sizes ─────────────────────────────────────────────── */

#define BTRFS_FSID_SIZE          16
#define BTRFS_UUID_SIZE          16
#define BTRFS_UUID_UNPARSED_SIZE 37
#define BTRFS_LABEL_SIZE         256
#define BTRFS_CSUM_SIZE          32   /* max csum field (for struct layout) */

/* ── btrfs superblock constants ────────────────────────────────────────── */

/* Magic: ASCII for "_BHRfS_M", no terminating NUL */
#define BTRFS_SUPER_MAGIC        0x4D5F53665248425FULL

/* Alternate: BTRFS_MAGIC is the same value, used by btrfs_tree.h */
#define BTRFS_MAGIC              0x4D5F53665248425FULL

/* Superblock lives at byte offset 64 KiB */
#define BTRFS_SUPER_INFO_OFFSET  (65536)
#define BTRFS_SUPER_INFO_SIZE    (4096)

/* Mirror configuration */
#define BTRFS_SUPER_MIRROR_MAX   3
#define BTRFS_SUPER_MIRROR_SHIFT 12
#define BTRFS_SB_MIRROR_OFFSET(m) \
    ((uint64_t)(16384) << (BTRFS_SUPER_MIRROR_SHIFT * (m)))

/* ── btrfs tree/object constants ───────────────────────────────────────── */

#define BTRFS_ROOT_TREE_OBJECTID      1ULL
#define BTRFS_EXTENT_TREE_OBJECTID    2ULL
#define BTRFS_CHUNK_TREE_OBJECTID     3ULL
#define BTRFS_DEV_TREE_OBJECTID       4ULL
#define BTRFS_FS_TREE_OBJECTID        5ULL
#define BTRFS_ROOT_TREE_DIR_OBJECTID  6ULL

/* ── btrfs feature flags ───────────────────────────────────────────────── */

#define BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA  (1ULL << 8)
#define BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF    (1ULL << 6)
#define BTRFS_FEATURE_INCOMPAT_NO_HOLES         (1ULL << 9)

/* ── btrfs header / superblock flags ───────────────────────────────────── */

#define BTRFS_HEADER_FLAG_WRITTEN  (1ULL << 0)
#define BTRFS_HEADER_FLAG_RELOC    (1ULL << 1)

/* ── btrfs checksum types ──────────────────────────────────────────────── */

#define BTRFS_CSUM_TYPE_CRC32   0
#define BTRFS_CSUM_TYPE_XXHASH  1
#define BTRFS_CSUM_TYPE_SHA256  2
#define BTRFS_CSUM_TYPE_BLAKE2  3

/* ── System chunk array size ───────────────────────────────────────────── */

#define BTRFS_SYSTEM_CHUNK_ARRAY_SIZE 2048

/* ── Backup root count ─────────────────────────────────────────────────── */

#define BTRFS_NUM_BACKUP_ROOTS  4

/* ── Default geometry ──────────────────────────────────────────────────── */

#ifndef UBT_DEFAULT_NODESIZE
#define UBT_DEFAULT_NODESIZE   16384
#endif

#ifndef UBT_DEFAULT_SECTORSIZE
#define UBT_DEFAULT_SECTORSIZE 4096
#endif

/* ── On-disk structures ────────────────────────────────────────────────── */

/*
 * struct btrfs_dev_item — describes a single device.
 * Kept minimal; only fields referenced by superblock formatting are present.
 */
struct btrfs_dev_item {
    __le64 devid;
    __le64 total_bytes;
    __le64 bytes_used;
    __le32 io_align;
    __le32 io_width;
    __le32 sector_size;
    __le64 type;
    __le64 generation;
    __le64 start_offset;
    __le32 dev_group;
    __u8   seek_speed;
    __u8   bandwidth;
    __u8   uuid[BTRFS_UUID_SIZE];
    __u8   fsid[BTRFS_FSID_SIZE];
} __attribute__((packed));

/*
 * struct btrfs_root_backup — superblock backup root descriptors.
 */
struct btrfs_root_backup {
    __le64 tree_root;
    __le64 tree_root_gen;
    __le64 chunk_root;
    __le64 chunk_root_gen;
    __le64 extent_root;
    __le64 extent_root_gen;
    __le64 fs_root;
    __le64 fs_root_gen;
    __le64 dev_root;
    __le64 dev_root_gen;
    __le64 csum_root;
    __le64 csum_root_gen;
    __le64 total_bytes;
    __le64 bytes_used;
    __le64 num_devices;
    __le64 unused_64[4];
    __u8   tree_root_level;
    __u8   chunk_root_level;
    __u8   extent_root_level;
    __u8   fs_root_level;
    __u8   dev_root_level;
    __u8   csum_root_level;
    __u8   unused_8[10];
} __attribute__((packed));

/*
 * struct btrfs_super_block — the on-disk superblock (4 KiB).
 *
 * Layout mirrors the upstream definition in btrfs-progs exactly so that
 * btrfs inspect-internal dump-super can parse it.
 */
struct btrfs_super_block {
    /* The first four fields must match struct btrfs_header */
    __u8   csum[BTRFS_CSUM_SIZE];
    __u8   fsid[BTRFS_FSID_SIZE];
    __le64 bytenr;
    __le64 flags;

    /* Allowed to be different from btrfs_header from here on */
    __le64 magic;
    __le64 generation;
    __le64 root;
    __le64 chunk_root;
    __le64 log_root;
    __le64 __unused_log_root_transid;
    __le64 total_bytes;
    __le64 bytes_used;
    __le64 root_dir_objectid;
    __le64 num_devices;
    __le32 sectorsize;
    __le32 nodesize;
    __le32 __unused_leafsize;
    __le32 stripesize;
    __le32 sys_chunk_array_size;
    __le64 chunk_root_generation;
    __le64 compat_flags;
    __le64 compat_ro_flags;
    __le64 incompat_flags;
    __le16 csum_type;
    __u8   root_level;
    __u8   chunk_root_level;
    __u8   log_root_level;
    struct btrfs_dev_item dev_item;

    char   label[BTRFS_LABEL_SIZE];

    __le64 cache_generation;
    __le64 uuid_tree_generation;
    __u8   metadata_uuid[BTRFS_FSID_SIZE];

    __u64  nr_global_roots;
    __le64 remap_root;
    __le64 remap_root_generation;
    __u8   remap_root_level;

    /* Future expansion */
    __u8   reserved[199];
    __u8   sys_chunk_array[BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
    struct btrfs_root_backup super_roots[BTRFS_NUM_BACKUP_ROOTS];

    /* Padded to 4096 bytes */
    __u8   padding[565];
} __attribute__((packed));

/*
 * struct btrfs_disk_key — on-disk key (byte order).
 */
struct btrfs_disk_key {
    __le64 objectid;
    __u8   type;
    __le64 offset;
} __attribute__((packed));

/*
 * struct btrfs_header — common header for all btree blocks.
 */
struct btrfs_header {
    __u8   csum[BTRFS_CSUM_SIZE];
    __u8   fsid[BTRFS_FSID_SIZE];
    __le64 bytenr;
    __le64 flags;
    __u8   chunk_tree_uuid[BTRFS_UUID_SIZE];
    __le64 generation;
    __le64 owner;
    __le32 nritems;
    __u8   level;
} __attribute__((packed));

/*
 * struct btrfs_item — describes one item in a leaf node.
 */
struct btrfs_item {
    struct btrfs_disk_key key;
    __le32 offset;
    __le32 size;
} __attribute__((packed));

/*
 * struct btrfs_leaf — a leaf btree node.
 */
struct btrfs_leaf {
    struct btrfs_header header;
    struct btrfs_item   items[];
} __attribute__((packed));

/*
 * struct btrfs_key_ptr — internal node pointer.
 */
struct btrfs_key_ptr {
    struct btrfs_disk_key key;
    __le64 blockptr;
    __le64 generation;
} __attribute__((packed));

/*
 * struct btrfs_node — an internal (non-leaf) btree node.
 */
struct btrfs_node {
    struct btrfs_header header;
    struct btrfs_key_ptr ptrs[];
} __attribute__((packed));

/* ── dev_item type constant ────────────────────────────────────────────── */

#define BTRFS_DEV_ITEM_INODE  0ULL

#endif /* UBIFS_COMPAT_H */
