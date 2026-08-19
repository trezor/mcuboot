/*
 * Founder-tree verification for the Trezor nRF (co-processor) image.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * See bootutil/image_pq.h. Every construction here mirrors the STM
 * (boot_header_merkle.h) and the host signer (nrf_tree.py) byte-for-byte.
 */

#include "bootutil/image_pq.h"

#include <string.h>

/*
 * Crypto, mirroring the STM's boot_header.c: SPHINCS+ (SLH-DSA) and ed25519-donna.
 *
 * Both are reached by RELATIVE path, and both live INSIDE this repository (an
 * ext/ submodule and a vendored copy) -- never by symlink into the trezor-firmware
 * monorepo. The monorepo pins this repo in nordic/trezor/west.yml, so a pointer back
 * the other way would make a dependency cycle and leave this repo un-buildable on its
 * own. See boot/bootutil/trezor-crypto/VENDOR.txt.
 *
 * Deliberately RELATIVE includes: sphincsplus ships generically-named headers
 * (sha2.h, params.h, api.h, utils.h) and putting its directory on the library-wide
 * include path would let them shadow trezor-crypto's same-named headers for other
 * translation units. Its own internal includes are all quoted and resolve next to
 * their source file, so it needs no -I at all -- only -DPARAMS=sphincs-sha2-128s.
 *
 * PQ_OMIT_SIGNATURE_VERIFY drops pq_image_verify() and with it this whole
 * crypto dependency, leaving the leaf/fold/shape logic (which needs nothing but
 * SHA-256). That exists so those parts can be cross-validated against the STM and
 * the Python signer without linking SPHINCS+ and ed25519-donna into the harness.
 * PRODUCTION BUILDS MUST NOT DEFINE IT -- without pq_image_verify there is no
 * signature check at all.
 */
#ifndef PQ_OMIT_SIGNATURE_VERIFY
#include "../../../ext/sphincsplus/ref/api.h"                  /* crypto_sign_verify */
#include "../trezor-crypto/ed25519-donna/ed25519.h"  /* ed25519_sign_open */
#endif

/*
 * SHA-256. In MCUboot this is the configured backend (PSA/mbedTLS/tinycrypt); the
 * host cross-validation defines PQ_HOST_TEST and supplies trezor-crypto's
 * sha2 instead, so the SAME code proves agreement with the STM and Python.
 */
#ifdef PQ_HOST_TEST
#include "sha2.h"
#define PQ_SHA_CTX SHA256_CTX
#define PQ_SHA_INIT(c) sha256_Init(c)
#define PQ_SHA_UPDATE(c, d, l) sha256_Update(c, d, l)
#define PQ_SHA_FINISH(c, o) sha256_Final(c, o)
#define PQ_SHA_DROP(c) ((void)0)
#else
#include "bootutil/crypto/sha.h"
#define PQ_SHA_CTX bootutil_sha_context
#define PQ_SHA_INIT(c) bootutil_sha_init(c)
#define PQ_SHA_UPDATE(c, d, l) bootutil_sha_update(c, d, l)
#define PQ_SHA_FINISH(c, o) bootutil_sha_finish(c, o)
#define PQ_SHA_DROP(c) bootutil_sha_drop(c)
#endif

/* MCUboot image_header field offsets. Only these four are needed, so they are
 * read positionally rather than via struct image_header -- this file must stay
 * usable by the host cross-validation, which has no Zephyr/MCUboot headers. */
#define HDR_OFF_MAGIC 0u
#define HDR_OFF_HDR_SIZE 8u   /* uint16 */
#define HDR_OFF_PROT_SIZE 10u /* uint16 */
#define HDR_OFF_IMG_SIZE 12u  /* uint32 */
#define HDR_MIN_LEN 16u

#define PQ_IMAGE_MAGIC 0x96f3b83dU
#define PQ_TLV_INFO_MAGIC 0x6907U /* unprotected TLV area */

/* Streaming read granularity for the leaf hash. Small enough to stay off the
 * bootloader's stack budget, large enough to keep the read overhead low. */
#define PQ_HASH_CHUNK 256u

static int read_u16(pq_read_fn read, void *ctx, uint32_t off, uint16_t *out)
{
    uint8_t b[2];
    if (read(ctx, off, b, sizeof(b)) != 0) {
        return -1;
    }
    *out = (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8)); /* little-endian */
    return 0;
}

static int read_u32(pq_read_fn read, void *ctx, uint32_t off, uint32_t *out)
{
    uint8_t b[4];
    if (read(ctx, off, b, sizeof(b)) != 0) {
        return -1;
    }
    *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
    return 0;
}

/*
 * Image layout as the founder rule sees it. `cut` is the leaf length; `tlv_end`
 * bounds the unprotected TLV area (mirrors MCUboot's own
 * tlv_end = hdr+img+prot + it_tlv_tot). Parsed once and shared, so the leaf rule
 * and the shape check can never disagree about where the boundary is.
 */
struct pq_layout {
    uint32_t cut;     /* leaf length */
    uint32_t tlv_end; /* end of the unprotected TLV area (== cut if none) */
    bool has_pq;
};

static int pq_parse_layout(pq_read_fn read, void *ctx,
                                uint32_t image_len,
                                struct pq_layout *out)
{
    if (read == NULL || out == NULL || image_len < HDR_MIN_LEN) {
        return -1;
    }

    uint32_t magic = 0;
    uint16_t hdr_size = 0;
    uint16_t prot_size = 0;
    uint32_t img_size = 0;
    if (read_u32(read, ctx, HDR_OFF_MAGIC, &magic) != 0 ||
        read_u16(read, ctx, HDR_OFF_HDR_SIZE, &hdr_size) != 0 ||
        read_u16(read, ctx, HDR_OFF_PROT_SIZE, &prot_size) != 0 ||
        read_u32(read, ctx, HDR_OFF_IMG_SIZE, &img_size) != 0) {
        return -1;
    }
    if (magic != PQ_IMAGE_MAGIC || hdr_size < HDR_MIN_LEN) {
        return -1;
    }

    /* The protected region (what MCUboot itself hashes) must fit in the image.
     * Widths are 16+32+16 bits summed into 64, so this cannot overflow. */
    uint64_t prot_end =
        (uint64_t)hdr_size + (uint64_t)img_size + (uint64_t)prot_size;
    if (prot_end == 0u || prot_end > (uint64_t)image_len) {
        return -1;
    }

    out->has_pq = false;
    out->cut = image_len;
    out->tlv_end = image_len;

    /* No unprotected TLV area -> nothing to exclude, whole image is covered. */
    uint32_t unprot_off = (uint32_t)prot_end;
    if ((uint64_t)unprot_off + 4u > (uint64_t)image_len) {
        return 0;
    }
    uint16_t info_magic = 0;
    uint16_t info_len = 0;
    if (read_u16(read, ctx, unprot_off, &info_magic) != 0 ||
        read_u16(read, ctx, unprot_off + 2u, &info_len) != 0) {
        return -1;
    }
    if (info_magic != PQ_TLV_INFO_MAGIC) {
        return 0;
    }

    uint64_t end = (uint64_t)unprot_off + (uint64_t)info_len;
    if (end > (uint64_t)image_len) {
        end = (uint64_t)image_len;
    }
    out->tlv_end = (uint32_t)end;

    /* Walk for the first founder record; absent -> the whole image is covered. */
    uint64_t p = (uint64_t)unprot_off + 4u;
    while (p + 4u <= end) {
        uint16_t type = 0;
        uint16_t len = 0;
        if (read_u16(read, ctx, (uint32_t)p, &type) != 0 ||
            read_u16(read, ctx, (uint32_t)p + 2u, &len) != 0) {
            return -1;
        }
        if (p + 4u + (uint64_t)len > end) {
            /* Malformed record; nothing founder-ish was found before it. */
            break;
        }
        if (type >= IMAGE_TLV_PQ_FIRST && type <= IMAGE_TLV_PQ_LAST) {
            out->cut = (uint32_t)p;
            out->has_pq = true;
            return 0;
        }
        p += 4u + (uint64_t)len;
    }

    return 0;
}

int pq_leaf_len(pq_read_fn read, void *ctx, uint32_t image_len,
                     uint32_t *out_len)
{
    struct pq_layout layout;

    if (out_len == NULL) {
        return -1;
    }
    if (pq_parse_layout(read, ctx, image_len, &layout) != 0) {
        return -1;
    }
    *out_len = layout.cut;
    return 0;
}

int pq_region_shape_ok(pq_read_fn read, void *ctx, uint32_t image_len,
                            bool *out_present)
{
    /* The exact record set expected in the uncovered region. Order-independent
     * (it has no bearing on security) but each must appear EXACTLY once. */
    static const struct {
        uint16_t type;
        uint16_t len; /* 0 => variable, validated separately */
    } expected[] = {
        {IMAGE_TLV_PQ_SLH_SIG_0, PQ_SLH_SIG_LEN},
        {IMAGE_TLV_PQ_SLH_SIG_1, PQ_SLH_SIG_LEN},
        {IMAGE_TLV_PQ_EC_SIG_0, PQ_EC_SIG_LEN},
        {IMAGE_TLV_PQ_EC_SIG_1, PQ_EC_SIG_LEN},
        {IMAGE_TLV_PQ_MERKLE_PROOF, 0},
    };
    const uint32_t all_seen = (1u << (sizeof(expected) / sizeof(expected[0]))) - 1u;

    struct pq_layout layout;
    uint32_t seen = 0;

    if (out_present != NULL) {
        *out_present = false;
    }
    if (pq_parse_layout(read, ctx, image_len, &layout) != 0) {
        return -1;
    }
    if (!layout.has_pq) {
        return 0; /* classic image: leaf covers everything, nothing to check */
    }
    if (out_present != NULL) {
        *out_present = true;
    }

    uint64_t p = (uint64_t)layout.cut;
    while (p < (uint64_t)layout.tlv_end) {
        if (p + 4u > (uint64_t)layout.tlv_end) {
            return -1; /* trailing stub too small to be a record */
        }
        uint16_t type = 0;
        uint16_t len = 0;
        if (read_u16(read, ctx, (uint32_t)p, &type) != 0 ||
            read_u16(read, ctx, (uint32_t)p + 2u, &len) != 0) {
            return -1;
        }
        if (p + 4u + (uint64_t)len > (uint64_t)layout.tlv_end) {
            return -1; /* record overruns the area */
        }

        /* Must be one of the expected records, and not a repeat. Anything else --
         * a rogue type, a duplicate, a wrong length -- fails. */
        bool matched = false;
        for (uint32_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
            if (type != expected[i].type) {
                continue;
            }
            if (seen & (1u << i)) {
                return -1; /* duplicate */
            }
            if (expected[i].len != 0) {
                if (len != expected[i].len) {
                    return -1;
                }
            } else {
                /* co-path: whole nodes, non-empty, bounded */
                if (len == 0 || (len % PQ_NODE_LEN) != 0 ||
                    (len / PQ_NODE_LEN) > PQ_MAX_MERKLE_PROOF_NODES) {
                    return -1;
                }
            }
            seen |= (1u << i);
            matched = true;
            break;
        }
        if (!matched) {
            return -1; /* rogue or unexpected record */
        }

        p += 4u + (uint64_t)len;
    }

    /* Every expected record present, and the last one ended exactly at tlv_end
     * (the loop condition guarantees the latter -- no slack is tolerated). */
    if (seen != all_seen) {
        return -1;
    }
    return 0;
}

int pq_leaf_hash(pq_read_fn read, void *ctx, uint32_t leaf_len,
                      uint8_t out_leaf[PQ_NODE_LEN])
{
    static const uint8_t prefix0[] = {0x00};
    uint8_t buf[PQ_HASH_CHUNK];
    PQ_SHA_CTX sha;
    int rc = -1;

    if (read == NULL || out_leaf == NULL || leaf_len == 0u) {
        return -1;
    }

    PQ_SHA_INIT(&sha);
    PQ_SHA_UPDATE(&sha, prefix0, sizeof(prefix0));

    uint32_t off = 0;
    while (off < leaf_len) {
        uint32_t chunk = leaf_len - off;
        if (chunk > sizeof(buf)) {
            chunk = sizeof(buf);
        }
        if (read(ctx, off, buf, chunk) != 0) {
            goto out;
        }
        PQ_SHA_UPDATE(&sha, buf, chunk);
        off += chunk;
    }

    PQ_SHA_FINISH(&sha, out_leaf);
    rc = 0;
out:
    PQ_SHA_DROP(&sha);
    return rc;
}

/* One fold step, in place: node = H(0x01 || min(node,sibling) || max(...)). Shared
 * so the buffered and streaming folds cannot diverge. */
static void fold_step(uint8_t node[PQ_NODE_LEN],
                      const uint8_t sibling[PQ_NODE_LEN])
{
    static const uint8_t prefix1[] = {0x01};
    PQ_SHA_CTX sha;

    PQ_SHA_INIT(&sha);
    PQ_SHA_UPDATE(&sha, prefix1, sizeof(prefix1));
    /* Sorted pair -> the proof needs no direction bits. */
    if (memcmp(node, sibling, PQ_NODE_LEN) < 0) {
        PQ_SHA_UPDATE(&sha, node, PQ_NODE_LEN);
        PQ_SHA_UPDATE(&sha, sibling, PQ_NODE_LEN);
    } else {
        PQ_SHA_UPDATE(&sha, sibling, PQ_NODE_LEN);
        PQ_SHA_UPDATE(&sha, node, PQ_NODE_LEN);
    }
    PQ_SHA_FINISH(&sha, node);
    PQ_SHA_DROP(&sha);
}

void pq_merkle_fold(const uint8_t leaf[PQ_NODE_LEN], const uint8_t *co_path,
                  uint32_t count, uint8_t out_root[PQ_NODE_LEN])
{
    uint8_t node[PQ_NODE_LEN];

    memcpy(node, leaf, PQ_NODE_LEN);
    for (uint32_t i = 0; i < count; i++) {
        fold_step(node, co_path + (size_t)i * PQ_NODE_LEN);
    }
    memcpy(out_root, node, PQ_NODE_LEN);
}

#ifndef PQ_OMIT_SIGNATURE_VERIFY
/* Which TLV area(s) to search. Callers state this explicitly rather than taking
 * "first match wins": the sigmask is only trustworthy from the PROTECTED area (an
 * unprotected copy would not be committed by the leaf), while the founder
 * signatures and co-path can only be UNPROTECTED (they commit to the leaf, so the
 * leaf cannot cover them). Being explicit also removes any question of a record in
 * one area shadowing the other. */
#define PQ_AREA_PROT 1u
#define PQ_AREA_UNPROT 2u

/* Locate a TLV by type in the requested area(s). Returns 0 and sets out_off/out_len
 * on success. Bounds-checked throughout. */
static int find_tlv(pq_read_fn read, void *ctx, uint32_t image_len,
                    uint16_t want, unsigned areas, uint32_t *out_off,
                    uint16_t *out_len)
{
    uint32_t magic = 0;
    uint16_t hdr_size = 0;
    uint16_t prot_size = 0;
    uint32_t img_size = 0;

    if (image_len < HDR_MIN_LEN) {
        return -1;
    }
    if (read_u32(read, ctx, HDR_OFF_MAGIC, &magic) != 0 ||
        read_u16(read, ctx, HDR_OFF_HDR_SIZE, &hdr_size) != 0 ||
        read_u16(read, ctx, HDR_OFF_PROT_SIZE, &prot_size) != 0 ||
        read_u32(read, ctx, HDR_OFF_IMG_SIZE, &img_size) != 0) {
        return -1;
    }
    if (magic != PQ_IMAGE_MAGIC || hdr_size < HDR_MIN_LEN) {
        return -1;
    }
    uint64_t prot_off = (uint64_t)hdr_size + (uint64_t)img_size;
    if (prot_off + (uint64_t)prot_size > (uint64_t)image_len) {
        return -1;
    }

    for (int area = 0; area < 2; area++) {
        uint64_t start;
        uint64_t end;
        if ((areas & (area == 0 ? PQ_AREA_PROT : PQ_AREA_UNPROT)) == 0u) {
            continue;
        }
        if (area == 0) {
            if (prot_size == 0) {
                continue;
            }
            start = prot_off + 4u; /* skip the protected TLV-info header */
            end = prot_off + (uint64_t)prot_size;
        } else {
            uint64_t unprot_off = prot_off + (uint64_t)prot_size;
            if (unprot_off + 4u > (uint64_t)image_len) {
                break;
            }
            uint16_t info_magic = 0;
            uint16_t info_len = 0;
            if (read_u16(read, ctx, (uint32_t)unprot_off, &info_magic) != 0 ||
                read_u16(read, ctx, (uint32_t)unprot_off + 2u, &info_len) != 0) {
                return -1;
            }
            if (info_magic != PQ_TLV_INFO_MAGIC) {
                break;
            }
            start = unprot_off + 4u;
            end = unprot_off + (uint64_t)info_len;
        }
        if (end > (uint64_t)image_len) {
            end = (uint64_t)image_len;
        }
        uint64_t p = start;
        while (p + 4u <= end) {
            uint16_t type = 0;
            uint16_t len = 0;
            if (read_u16(read, ctx, (uint32_t)p, &type) != 0 ||
                read_u16(read, ctx, (uint32_t)p + 2u, &len) != 0) {
                return -1;
            }
            if (p + 4u + (uint64_t)len > end) {
                break;
            }
            if (type == want) {
                *out_off = (uint32_t)(p + 4u);
                *out_len = len;
                return 0;
            }
            p += 4u + (uint64_t)len;
        }
    }
    return -1;
}

fih_ret pq_image_verify(pq_read_fn read, void *ctx, uint32_t image_len,
                   const uint8_t *const *pq_keys, const uint8_t *const *ec_keys,
                   uint32_t key_count, uint8_t *out_root)
{
    /* The SLH-DSA signature is far too large for the bootloader stack, so it is
     * staged in .bss and reused across the two slots (one verify at a time; the
     * bootloader is single-threaded and does one image at a time). */
    static uint8_t slh_sig[PQ_SLH_SIG_LEN];

    /* Base case is FAILURE and there is exactly ONE exit (FIH_RET at `out`), so
     * every early bail-out leaves the verdict failing and the CFI counter is
     * decremented exactly once. Success is written in one place, last, after all
     * checks have passed -- see the tail of this function. */
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    struct pq_layout layout;
    bool present = false;
    uint8_t root[PQ_NODE_LEN];
    uint8_t sigmask = 0;
    uint8_t sigmask_orig = 0;
    uint8_t sigmask_inv = 0; /* FIH: must end up equal to the value read */
    uint32_t off = 0;
    uint16_t len = 0;
    /* FIH: counts completed slots independently of the sigmask bookkeeping, so a
     * glitched loop bound has to be defeated twice to skip a verification. */
    uint32_t slots_done = 0;

    if (pq_keys == NULL || ec_keys == NULL || key_count == 0 ||
        key_count > PQ_MAX_KEYS) {
        goto out;
    }

    /* Founder material must be present AND be exactly the expected records --
     * otherwise MCUboot's own TLV whitelist would reject the image later. */
    const int shape_rc = pq_region_shape_ok(read, ctx, image_len, &present);
    if (FIH_NOT_EQ(shape_rc, 0) || FIH_NOT_EQ(present, true)) {
        goto out;
    }
    if (pq_parse_layout(read, ctx, image_len, &layout) != 0 ||
        FIH_NOT_EQ(layout.has_pq, true)) {
        goto out;
    }

    /* leaf -> modelRoot, folding the co-path node by node straight out of its TLV
     * (no 1 KB buffer needed). */
    if (pq_leaf_hash(read, ctx, layout.cut, root) != 0) {
        goto out;
    }
    if (find_tlv(read, ctx, image_len, IMAGE_TLV_PQ_MERKLE_PROOF,
                 PQ_AREA_UNPROT, &off, &len) != 0) {
        goto out;
    }
    if (len == 0 || (len % PQ_NODE_LEN) != 0 ||
        (len / PQ_NODE_LEN) > PQ_MAX_MERKLE_PROOF_NODES) {
        goto out;
    }
    for (uint16_t i = 0; i < len / PQ_NODE_LEN; i++) {
        uint8_t sibling[PQ_NODE_LEN];
        if (read(ctx, off + (uint32_t)i * PQ_NODE_LEN, sibling,
                 PQ_NODE_LEN) != 0) {
            goto out;
        }
        fold_step(root, sibling);
    }

    /* WHICH keys signed is DECLARED by the image, in the PROTECTED sigmask TLV --
     * inside MCUboot's image hash AND inside the founder leaf, so the founder
     * signature ATTESTS to the signer set rather than the verifier inferring it.
     * (The signer stamps it before the leaf is computed, exactly as it stamps the
     * STM boot header's sigmask, so rotating founder keys costs a re-sign, not an
     * nRF rebuild.) Mirrors boot_header_check_signature: slot i uses the i-th
     * LOWEST set bit, every named key must be consumed exactly once, and the
     * accumulated inverse must equal the value read -- an anti-glitch check whose
     * expected value comes from SIGNED data. */
    if (find_tlv(read, ctx, image_len, IMAGE_TLV_PQ_SIGMASK,
                 PQ_AREA_PROT, &off, &len) != 0 ||
        len != 1) {
        goto out;
    }
    if (read(ctx, off, &sigmask, 1) != 0 || sigmask == 0) {
        goto out;
    }
    sigmask_orig = sigmask;
    /* No bits outside the key pool. */
    if (FIH_NOT_EQ((sigmask & (uint8_t)~((1u << key_count) - 1u)), 0)) {
        goto out;
    }
    /* Exactly PQ_SIG_COUNT keys named -- a shorter mask must not pass as a
     * full threshold, and a longer one must not leave a key unverified. */
    if (FIH_NOT_EQ(__builtin_popcount((unsigned)sigmask), PQ_SIG_COUNT)) {
        goto out;
    }

    static const uint16_t slh_tlv[PQ_SIG_COUNT] = {
        IMAGE_TLV_PQ_SLH_SIG_0, IMAGE_TLV_PQ_SLH_SIG_1};
    static const uint16_t ec_tlv[PQ_SIG_COUNT] = {
        IMAGE_TLV_PQ_EC_SIG_0, IMAGE_TLV_PQ_EC_SIG_1};

    for (int slot = 0; slot < PQ_SIG_COUNT; slot++) {
        /* Slot i uses the i-th LOWEST set bit -- same convention as the STM. */
        if (sigmask == 0) {
            goto out;
        }
        int key_idx = 0;
        while (((sigmask >> key_idx) & 1u) == 0u) {
            key_idx++;
        }
        if ((uint32_t)key_idx >= key_count) {
            goto out;
        }

        /* Stage the PQ signature, then bind it into the EC message. */
        if (find_tlv(read, ctx, image_len, slh_tlv[slot], PQ_AREA_UNPROT, &off,
                     &len) != 0 ||
            FIH_NOT_EQ(len, PQ_SLH_SIG_LEN) ||
            read(ctx, off, slh_sig, PQ_SLH_SIG_LEN) != 0) {
            goto out;
        }

        uint8_t ec_sig[PQ_EC_SIG_LEN];
        if (find_tlv(read, ctx, image_len, ec_tlv[slot], PQ_AREA_UNPROT, &off,
                     &len) != 0 ||
            FIH_NOT_EQ(len, PQ_EC_SIG_LEN) ||
            read(ctx, off, ec_sig, PQ_EC_SIG_LEN) != 0) {
            goto out;
        }

        /* hash = SHA256(modelRoot || slh_signature): the EC signature commits to
         * the PQ signature as well, blocking a PQ-signature substitution. */
        uint8_t hash[PQ_NODE_LEN];
        PQ_SHA_CTX sha;
        PQ_SHA_INIT(&sha);
        PQ_SHA_UPDATE(&sha, root, PQ_NODE_LEN);
        PQ_SHA_UPDATE(&sha, slh_sig, PQ_SLH_SIG_LEN);
        PQ_SHA_FINISH(&sha, hash);
        PQ_SHA_DROP(&sha);

        /* Both verdicts are captured into locals PRE-SET to a failing value and
         * only then compared with FIH_NOT_EQ. Two reasons, both load-bearing:
         *
         *   - FIH_NOT_EQ double-evaluates its arguments under
         *     FIH_ENABLE_DOUBLE_VARS, so inlining a verify call would run the
         *     whole (7856-byte, hash-based) SLH-DSA verification TWICE;
         *   - an instruction-skip that jumps over the call itself leaves the
         *     sentinel behind, so the check fails closed rather than reading
         *     whatever happened to be in the register.
         *
         * The two verifies are not individually duplicated: both must pass, so a
         * single in-crypto fault is not sufficient -- an attacker needs two
         * independent successful glitches against two different algorithms.
         *
         * Cheap classical gate before the expensive PQ verify (as on the STM). */
        int ec_rc = -1;
        int pq_rc = -1;

        ec_rc = ed25519_sign_open(hash, sizeof(hash), ec_keys[key_idx], ec_sig);
        if (FIH_NOT_EQ(ec_rc, 0)) {
            goto out;
        }
        pq_rc = crypto_sign_verify(slh_sig, PQ_SLH_SIG_LEN, root, PQ_NODE_LEN,
                                   pq_keys[key_idx]);
        if (FIH_NOT_EQ(pq_rc, 0)) {
            goto out;
        }

        sigmask &= (uint8_t)~(1u << key_idx);
        sigmask_inv |= (uint8_t)(1u << key_idx);
        slots_done++;
    }

    /* Every named key used exactly once, nothing left over, and the reconstructed
     * set identical to the signed one. `slots_done` is the independent witness
     * that the loop really ran PQ_SIG_COUNT times. */
    if (FIH_NOT_EQ(slots_done, PQ_SIG_COUNT) || FIH_NOT_EQ(sigmask, 0) ||
        FIH_NOT_EQ(sigmask_inv, sigmask_orig)) {
        goto out;
    }

    if (out_root != NULL) {
        memcpy(out_root, root, PQ_NODE_LEN);
    }

    /* The ONLY success assignment, reached only by falling off the end of every
     * check above. fih_delay() makes the moment of the write less predictable. */
    if (fih_delay()) {
        FIH_SET(fih_rc, FIH_SUCCESS);
    }

out:
    FIH_RET(fih_rc);
}

#endif /* !PQ_OMIT_SIGNATURE_VERIFY */
