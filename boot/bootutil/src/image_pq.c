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

#ifdef PQ_HOST_TEST
/* The host cross-validation supplies the model it is testing. */
#ifndef MODEL_IDENTIFIER
#error "PQ_HOST_TEST must define MODEL_IDENTIFIER"
#endif
#else
#include "mcuboot_config/mcuboot_config.h" /* MODEL_IDENTIFIER */
#ifndef MODEL_IDENTIFIER
#error "CONFIG_MODEL_IDENTIFIER must be set: it is bound into the founder leaf"
#endif
#endif

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
    uint32_t prot_end;    /* hdr + payload + protected TLVs: the image-hash range */
    uint32_t unprot_end;  /* end of the unprotected TLV area (== prot_end if none) */
    bool has_unprot;
};

/*
 * `unprot_end` is the DECLARED extent from the unprotected TLV-info header, which
 * no signature covers. It is REJECTED if it overruns image_len rather than clamped
 * -- see the note at that check. pq_region_shape_ok is what actually constrains
 * this area, and every bound below is checked before it is used.
 *
 * Note what image_len is on the DEVICE path: bootutil_img_validate passes
 * it.tlv_end, which is itself hdr+img+prot+it_tlv_tot with no clamp of its own. So
 * there the declared extent cannot overrun the length derived from it, and the
 * check below is unreachable -- an inflated it_tlv_tot instead makes image_len
 * point into the flash slot past the image, and the walk rejects on the garbage it
 * finds (or on a failed read). Callers that pass a TRUE image length -- host tools
 * and the cross-validation harness -- do reach it.
 */
static int pq_parse_layout(pq_read_fn read, void *ctx, uint32_t image_len,
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

    /* Widths are 16+32+16 bits summed into 64, so this cannot overflow. */
    uint64_t prot_end =
        (uint64_t)hdr_size + (uint64_t)img_size + (uint64_t)prot_size;
    if (prot_end == 0u || prot_end > (uint64_t)image_len) {
        return -1;
    }
    out->prot_end = (uint32_t)prot_end;
    out->unprot_end = (uint32_t)prot_end;
    out->has_unprot = false;

    if (prot_end + 4u > (uint64_t)image_len) {
        return 0; /* no room for an unprotected area */
    }
    uint16_t info_magic = 0;
    uint16_t info_len = 0;
    if (read_u16(read, ctx, (uint32_t)prot_end, &info_magic) != 0 ||
        read_u16(read, ctx, (uint32_t)prot_end + 2u, &info_len) != 0) {
        return -1;
    }
    if (info_magic != PQ_TLV_INFO_MAGIC) {
        return 0; /* no unprotected area */
    }
    uint64_t end = prot_end + (uint64_t)info_len;
    if (end > (uint64_t)image_len) {
        /* REJECT, not clamp. Clamping is safe against an over-read but it makes
         * this parser disagree with the STM's, which refuses such an image
         * (nrf_image_verify.h): the STM must predict this verifier's verdict before
         * erasing the only slot, and a disagreement in that direction is a brick.
         * A well-formed image has prot_end + it_tlv_tot == image_len exactly, so
         * nothing legitimate is refused. */
        return -1;
    }
    out->unprot_end = (uint32_t)end;
    out->has_unprot = true;
    return 0;
}

int pq_image_hash(pq_read_fn read, void *ctx, uint32_t image_len,
                  uint8_t out_hash[PQ_NODE_LEN])
{
    static const uint8_t nothing[] = {0};
    struct pq_layout layout;
    uint8_t buf[PQ_HASH_CHUNK];
    PQ_SHA_CTX sha;
    int rc = -1;

    (void)nothing;
    if (out_hash == NULL || pq_parse_layout(read, ctx, image_len, &layout) != 0) {
        return -1;
    }

    /* SHA-256 over header + payload + protected TLVs: MCUboot's own image hash,
     * the value TLV 0x10 carries. bootutil_img_validate has usually computed this
     * already -- pq_image_verify takes it as a parameter for exactly that reason,
     * so this streaming path exists only for callers that have no hash to hand
     * (the host cross-validation, and pq_image_verify's NULL case). */
    PQ_SHA_INIT(&sha);
    uint32_t off = 0;
    while (off < layout.prot_end) {
        uint32_t chunk = layout.prot_end - off;
        if (chunk > sizeof(buf)) {
            chunk = sizeof(buf);
        }
        if (read(ctx, off, buf, chunk) != 0) {
            goto out;
        }
        PQ_SHA_UPDATE(&sha, buf, chunk);
        off += chunk;
    }
    PQ_SHA_FINISH(&sha, out_hash);
    rc = 0;
out:
    PQ_SHA_DROP(&sha);
    return rc;
}

int pq_region_shape_ok(pq_read_fn read, void *ctx, uint32_t image_len,
                            bool *out_present)
{
    /* The exact record set expected in the unprotected area. Order-independent
     * (it has no bearing on security) but each must appear EXACTLY once.
     *
     * The area is checked in FULL because the leaf covers none of it -- the image
     * hash stops at the protected TLVs -- so this is the only structural
     * constraint on the region, and the exactness is what does the work. Every
     * record's value is independently pinned: 0x10 by MCUboot comparing it against
     * the hash it computed (and that hash is what the fold commits), the four
     * signature records by the signature check itself, and the proof by the fold
     * reaching modelRoot. */
    static const struct {
        uint16_t type;
        uint16_t len; /* 0 => variable, validated separately */
    } expected[] = {
        {IMAGE_TLV_PQ_IMAGE_HASH, PQ_NODE_LEN},
        {IMAGE_TLV_PQ_SLH_SIG_0, PQ_SLH_SIG_LEN},
        {IMAGE_TLV_PQ_SLH_SIG_1, PQ_SLH_SIG_LEN},
        {IMAGE_TLV_PQ_EC_SIG_0, PQ_EC_SIG_LEN},
        {IMAGE_TLV_PQ_EC_SIG_1, PQ_EC_SIG_LEN},
        {IMAGE_TLV_PQ_MERKLE_PROOF, 0},
    };
    const uint32_t n_expected = (uint32_t)(sizeof(expected) / sizeof(expected[0]));
    const uint32_t all_seen = (1u << n_expected) - 1u;

    struct pq_layout layout;
    uint32_t seen = 0;
    bool saw_pq = false;

    if (out_present != NULL) {
        *out_present = false;
    }
    if (pq_parse_layout(read, ctx, image_len, &layout) != 0) {
        return -1;
    }
    if (!layout.has_unprot) {
        return 0; /* no unprotected area at all: nothing to check */
    }

    uint64_t p = (uint64_t)layout.prot_end + 4u; /* past the TLV-info header */
    const uint64_t tlv_end = (uint64_t)layout.unprot_end;
    while (p < tlv_end) {
        if (p + 4u > tlv_end) {
            return -1; /* trailing stub too small to be a record */
        }
        uint16_t type = 0;
        uint16_t len = 0;
        if (read_u16(read, ctx, (uint32_t)p, &type) != 0 ||
            read_u16(read, ctx, (uint32_t)p + 2u, &len) != 0) {
            return -1;
        }
        if (p + 4u + (uint64_t)len > tlv_end) {
            return -1; /* record overruns the area */
        }

        bool matched = false;
        for (uint32_t i = 0; i < n_expected; i++) {
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
            if (type >= IMAGE_TLV_PQ_FIRST && type <= IMAGE_TLV_PQ_LAST) {
                saw_pq = true;
            }
            break;
        }
        if (!matched) {
            /* A classic (Ed25519-only) image legitimately carries records this
             * whitelist does not list. Report "no founder material" rather than
             * malformed, and let the caller decide -- the classic scheme has its
             * own verification. */
            if (!saw_pq) {
                return 0;
            }
            return -1; /* rogue record alongside founder material */
        }
        p += 4u + (uint64_t)len;
    }

    if (!saw_pq) {
        return 0; /* classic image: nothing founder-ish present */
    }
    if (seen != all_seen) {
        return -1; /* founder material present but incomplete */
    }
    if (out_present != NULL) {
        *out_present = true;
    }
    return 0;
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

/* Uses find_tlv above, hence its position inside this region. */
int pq_image_security_counter(pq_read_fn read, void *ctx, uint32_t image_len,
                              uint32_t *out_cnt)
{
    uint32_t off = 0;
    uint16_t len = 0;

    if (out_cnt == NULL) {
        return -1;
    }
    *out_cnt = 0;

    /* PROTECTED area only -- see the header. An unprotected copy is not
     * founder-covered, so it is attacker-controlled and never consulted. */
    if (find_tlv(read, ctx, image_len, IMAGE_TLV_PQ_SEC_CNT, PQ_AREA_PROT, &off,
                 &len) != 0) {
        /* Absent is valid and fails SAFE: 0 is refused by any stored counter
         * above 0. Distinguishing "absent" from "malformed" is deliberate --
         * a wrong-sized record below is an error, not a zero. */
        return 0;
    }
    if (len != sizeof(*out_cnt)) {
        return -1;
    }

    uint8_t b[4];
    if (read(ctx, off, b, sizeof(b)) != 0) {
        return -1;
    }
    *out_cnt = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
               ((uint32_t)b[3] << 24); /* little-endian, as imgtool writes it */
    return 0;
}
fih_ret pq_image_verify(pq_read_fn read, void *ctx, uint32_t image_len,
                   const uint8_t *image_hash,
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
    /* leaf -> modelRoot, folding the co-path node by node straight out of its TLV
     * (no 1 KB buffer needed). */
    /* The leaf IS MCUboot's image hash. bootutil_img_validate has already computed
     * it, so it is passed in rather than recomputed -- one full-image SHA-256 pass
     * per boot instead of two. NULL is accepted for callers that have none (the
     * host cross-validation), at the cost of that extra pass. */
    if (image_hash != NULL) {
        memcpy(root, image_hash, PQ_NODE_LEN);
    } else if (pq_image_hash(read, ctx, image_len, root) != 0) {
        goto out;
    }
    {
        /* Fold the ROLE-BOUND SLOT, not the bare hash: leaf = H(0x00 || slot).
         * The slot names which co-processor this image is for, because the fold
         * alone cannot -- sorted pairs carry no direction, so a leaf's position
         * is unrecoverable and a passing fold would prove only that the founder
         * committed to SOME artifact under this modelRoot.
         *
         * `model` is MODEL_IDENTIFIER, the same value image_validate.c already
         * pins EXPECTED_MODEL_TLV against, written LITTLE-ENDIAN so its bytes
         * are the ASCII the STM copies from MODEL_INTERNAL_NAME and the signer
         * reads out of the model-id TLV. `kind` and `index` are this build's,
         * never the image's. Byte-for-byte with coproc_slot_t (STM) and
         * coproc_slot_value() (signer) -- if any of the three disagrees, the
         * folds diverge and the image simply stops verifying. */
        uint8_t slot[PQ_COPROC_SLOT_LEN];
        memset(slot, 0, sizeof(slot));
        memcpy(slot, PQ_COPROC_SLOT_TAG, 4);
        slot[4] = (uint8_t)(MODEL_IDENTIFIER & 0xFFu);
        slot[5] = (uint8_t)((MODEL_IDENTIFIER >> 8) & 0xFFu);
        slot[6] = (uint8_t)((MODEL_IDENTIFIER >> 16) & 0xFFu);
        slot[7] = (uint8_t)((MODEL_IDENTIFIER >> 24) & 0xFFu);
        slot[8] = (uint8_t)PQ_COPROC_KIND_NRF;
        slot[9] = (uint8_t)PQ_COPROC_INDEX;
        /* slot[10..11] reserved, already zero */
        memcpy(&slot[12], root, PQ_NODE_LEN); /* root holds the image hash */

        uint8_t leaf[PQ_NODE_LEN];
        static const uint8_t prefix0[] = {0x00};
        PQ_SHA_CTX sha;
        PQ_SHA_INIT(&sha);
        PQ_SHA_UPDATE(&sha, prefix0, sizeof(prefix0));
        PQ_SHA_UPDATE(&sha, slot, sizeof(slot));
        PQ_SHA_FINISH(&sha, leaf);
        PQ_SHA_DROP(&sha);
        memcpy(root, leaf, PQ_NODE_LEN);
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
