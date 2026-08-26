/*
 * super.c — Write a valid btrfs superblock and minimal root-tree leaf.
 *
 * The on-disk layout produced:
 *
 *   Offset        Content
 *   ────────────  ────────────────────────────────────────
 *   0 … 63 KiB   Unused (zero-filled)
 *   64 KiB        Superblock (4 KiB, padded)
 *   68 … 127 KiB  Unused
 *   128 KiB       Root-tree leaf node (nodesize bytes)
 *
 * Mirror copies of the superblock are also written at:
 *   Mirror 1:  16 KiB << 12  =  64 MiB
 *   Mirror 2:  16 KiB << 24  = 256 GiB   (only if image is large enough)
 */

#include "compat.h"
#include "ubt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

/* ── CRC32C (Castagnoli) implementation ───────────────────────────────── */

static uint32_t crc32c_table[256];
static int     crc32c_ready;

static void
crc32c_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (c >> 1) ^ 0x82F63B78u : (c >> 1);
        crc32c_table[i] = c;
    }
    crc32c_ready = 1;
}

static uint32_t
crc32c_calc(const uint8_t *buf, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    if (!crc32c_ready)
        crc32c_init();
    for (size_t i = 0; i < len; i++)
        crc = crc32c_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* ── Write helper ─────────────────────────────────────────────────────── */

static int
pwrite_full(int fd, const void *buf, size_t count, off_t offset)
{
    const uint8_t *p = buf;
    while (count > 0) {
        ssize_t n = pwrite(fd, p, count, offset);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        p       += n;
        count   -= (size_t)n;
        offset  += n;
    }
    return 0;
}

/* ── Compute CRC32C for a superblock ──────────────────────────────────── */

static void
superblock_set_csum(struct btrfs_super_block *sb)
{
    /* Zero the csum field before computing */
    memset(sb->csum, 0, sizeof(sb->csum));

    /* CRC32C is computed over the entire 4096-byte superblock,
     * then stored in the first 4 bytes. */
    uint32_t csum = crc32c_calc((const uint8_t *)sb,
                                BTRFS_SUPER_INFO_SIZE);
    memcpy(sb->csum, &csum, sizeof(csum));
}

/* ── Generate a deterministic fake FSID ───────────────────────────────── */

static void
fake_fsid(uint8_t out[BTRFS_FSID_SIZE])
{
    for (int i = 0; i < BTRFS_FSID_SIZE; i++)
        out[i] = (uint8_t)(i * 0x37 + 0xA5);
    /* Make it look like a UUID v4 */
    out[6] = (out[6] & 0x0F) | 0x40;
    out[8] = (out[8] & 0x3F) | 0x80;
}

/* ── Build and write a superblock ─────────────────────────────────────── */

static int
write_superblock(int fd, uint64_t sb_bytenr, uint64_t root_bytenr)
{
    struct btrfs_super_block sb;

    memset(&sb, 0, sizeof(sb));

    /* Magic and geometry */
    sb.magic           = cpu_to_le64(BTRFS_SUPER_MAGIC);
    sb.bytenr          = cpu_to_le64(sb_bytenr);
    sb.flags           = cpu_to_le64(0);
    sb.generation      = cpu_to_le64(1);
    sb.root            = cpu_to_le64(root_bytenr);
    sb.chunk_root      = cpu_to_le64(BTRFS_CHUNK_TREE_OBJECTID);
    sb.log_root        = cpu_to_le64(0);
    sb.__unused_log_root_transid = cpu_to_le64(0);
    sb.total_bytes     = cpu_to_le64(256ULL * 1024 * 1024);
    sb.bytes_used      = cpu_to_le64(0);
    sb.root_dir_objectid = cpu_to_le64(BTRFS_ROOT_TREE_DIR_OBJECTID);
    sb.num_devices     = cpu_to_le64(1);
    sb.sectorsize      = cpu_to_le32(UBT_DEFAULT_SECTORSIZE);
    sb.nodesize        = cpu_to_le32(UBT_DEFAULT_NODESIZE);
    sb.__unused_leafsize = cpu_to_le32(UBT_DEFAULT_NODESIZE);
    sb.stripesize      = cpu_to_le32(4096);
    sb.sys_chunk_array_size = cpu_to_le32(0);
    sb.chunk_root_generation = cpu_to_le64(1);
    sb.compat_flags    = cpu_to_le64(0);
    sb.compat_ro_flags = cpu_to_le64(0);
    sb.incompat_flags  = cpu_to_le64(BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA);

    sb.csum_type       = cpu_to_le16(BTRFS_CSUM_TYPE_CRC32);
    sb.root_level      = 0;
    sb.chunk_root_level = 0;
    sb.log_root_level  = 0;

    /* FSID */
    fake_fsid(sb.fsid);

    /* Metadata UUID — same as fsid */
    memcpy(sb.metadata_uuid, sb.fsid, BTRFS_FSID_SIZE);

    /* Label — empty */
    memset(sb.label, 0, sizeof(sb.label));

    /* dev_item */
    memset(&sb.dev_item, 0, sizeof(sb.dev_item));
    sb.dev_item.devid       = cpu_to_le64(1);
    sb.dev_item.total_bytes = sb.total_bytes;
    sb.dev_item.bytes_used  = sb.bytes_used;
    sb.dev_item.io_align    = cpu_to_le32(4096);
    sb.dev_item.io_width    = cpu_to_le32(4096);
    sb.dev_item.sector_size = cpu_to_le32(UBT_DEFAULT_SECTORSIZE);
    sb.dev_item.type        = cpu_to_le64(BTRFS_DEV_ITEM_INODE);
    memcpy(sb.dev_item.uuid, sb.fsid, BTRFS_UUID_SIZE);
    memcpy(sb.dev_item.fsid, sb.fsid, BTRFS_FSID_SIZE);

    /* Compute CRC32C checksum */
    superblock_set_csum(&sb);

    /* Write superblock at the primary offset */
    if (pwrite_full(fd, &sb, sizeof(sb), (off_t)sb_bytenr) != 0)
        return -1;

    /* Write mirror copies (if image is large enough) */
    for (int m = 1; m < BTRFS_SUPER_MIRROR_MAX; m++) {
        uint64_t mirror_off = BTRFS_SB_MIRROR_OFFSET(m);
        struct stat st;
        if (fstat(fd, &st) != 0)
            return -1;
        if (mirror_off + sizeof(sb) > (uint64_t)st.st_size)
            break;
        /* Fix the bytenr in the mirror copy */
        sb.bytenr = cpu_to_le64(mirror_off);
        superblock_set_csum(&sb);
        if (pwrite_full(fd, &sb, sizeof(sb), (off_t)mirror_off) != 0)
            return -1;
    }

    return 0;
}

/* ── Write a minimal root-tree leaf node ──────────────────────────────── */

static int
write_root_leaf(int fd, uint64_t bytenr)
{
    struct btrfs_header hdr;

    memset(&hdr, 0, sizeof(hdr));

    /* fsid — must match the superblock */
    fake_fsid(hdr.fsid);

    hdr.bytenr      = cpu_to_le64(bytenr);
    hdr.flags       = cpu_to_le64(BTRFS_HEADER_FLAG_WRITTEN);
    hdr.generation  = cpu_to_le64(1);
    hdr.owner       = cpu_to_le64(BTRFS_ROOT_TREE_OBJECTID);
    hdr.nritems     = cpu_to_le32(0);
    hdr.level       = 0;

    /* Write the leaf at the given bytenr */
    if (pwrite_full(fd, &hdr, sizeof(hdr), (off_t)bytenr) != 0)
        return -1;

    return 0;
}

/* ── Public entry point ───────────────────────────────────────────────── */

int
ubt_format_image(int fd)
{
    uint64_t sb_bytenr   = BTRFS_SUPER_INFO_OFFSET;   /* 64 KiB */
    uint64_t root_bytenr = 128ULL * 1024;              /* 128 KiB */

    if (write_root_leaf(fd, root_bytenr) != 0)
        return -1;

    if (write_superblock(fd, sb_bytenr, root_bytenr) != 0)
        return -1;

    return 0;
}
