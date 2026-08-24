/*
 * Founder-tree verification for the Trezor nRF (co-processor) image.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The nRF image is a leaf in the SAME founder Merkle tree the STM boot header
 * commits to, so the ONE founder signature over modelRoot covers both MCUs --
 * there is no separate nRF signing ceremony. This module lets the nRF verify that
 * itself at boot (rather than trusting the STM to have checked at install):
 *
 *     leaf = H(0x00 || mcuboot_image_hash(image))
 *     fold leaf up through the co-path  ->  modelRoot
 *     verify the founder hybrid signature over modelRoot   (2-of-3, sigmask)
 *
 * It closes the DIRECT serial-recovery bypass: an attacker with the nRF's UART +
 * RESET/STAY_IN_BLD pins can enter MCUboot serial recovery without the STM being
 * involved at all, so the STM-side founder gate does not protect that path.
 *
 * Every hash construction here MUST match the STM
 * (trezor-firmware/core/embed/sec/image/stm32/boot_header_merkle.h) and the host
 * signer (core/tools/trezor_core_tools/nrf_tree.py) BYTE-FOR-BYTE. A mismatch is
 * silent (images simply stop verifying), so the three implementations are
 * cross-validated against shared vectors in core/tests/fw_merkle.
 */

#ifndef H_IMAGE_PQ_
#define H_IMAGE_PQ_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fault-injection hardening.
 *
 * pq_image_verify returns MCUboot's `fih_ret` and MUST be invoked through
 * FIH_CALL. That is not a style choice: with a plain int return, the caller ends
 * up writing
 *
 *     if (verify(...) != 0) { fail; }
 *     valid_signature = FIH_SUCCESS;         <-- minted locally
 *
 * where ONE glitched comparison (or one skipped branch) yields a fully valid
 * signature verdict. With fih_ret, success is a masked double-variable produced
 * INSIDE the verifier by FIH_RET, FIH_CALL seeds the result with FIH_FAILURE
 * before the call, and the CFI counter proves the function actually ran to its
 * FIH_RET. A caller can then only propagate success, never invent it.
 *
 * No host shim: the cross-validation harness supplies its own
 * mcuboot_config/mcuboot_config.h and the handful of FIH runtime symbols
 * (core/tests/fw_merkle/fih_host.c in the monorepo), so the host builds against
 * THIS header with the real macros -- double variables and the CFI counter
 * included. A stubbed-out FIH here would have made the harness prove the
 * hardening works while testing a version that has none.
 */
#include "bootutil/fault_injection_hardening.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_NODE_LEN 32 /* SHA-256 */

/*
 * Founder TLVs, in MCUboot's vendor range (0x00a0-0x00ff), continuing the
 * existing allocation (0x00A0/A1 image sigs, 0x00A2 sigmask, 0x00A3 model id).
 *
 * An ORDINARY allocation. These types used to define the leaf boundary -- the leaf
 * ran to the first one -- which made the range load-bearing and required the
 * records to be last in the unprotected area. The leaf is now MCUboot's image
 * hash, whose range MCUboot defines, so neither holds: the records may sit
 * anywhere in the unprotected area, in any order. pq_region_shape_ok still
 * requires exactly this set and nothing else.
 */
/*
 * Two of MCUboot's own TLV types, mirrored rather than included: this header is
 * also compiled by the host cross-validation, which has no bootutil/image.h.
 * _Static_asserts in image_validate.c pin both to the real definitions, so they
 * cannot drift apart unnoticed.
 */
#define IMAGE_TLV_PQ_IMAGE_HASH 0x10 /* SHA-256 of hdr+payload+prot (== leaf) */
#define IMAGE_TLV_PQ_SEC_CNT 0x50    /* security counter, rollback floor */

#define IMAGE_TLV_PQ_FIRST 0x00A4
#define IMAGE_TLV_PQ_SLH_SIG_0 0x00A4 /* SLH-DSA over modelRoot */
#define IMAGE_TLV_PQ_SLH_SIG_1 0x00A5
#define IMAGE_TLV_PQ_EC_SIG_0 0x00A6 /* Ed25519 over H(root||slh_sig) */
#define IMAGE_TLV_PQ_EC_SIG_1 0x00A7
#define IMAGE_TLV_PQ_MERKLE_PROOF 0x00A8 /* leaf -> modelRoot, 32*N bytes */
#define IMAGE_TLV_PQ_LAST 0x00A8

/*
 * Which founder keys signed. The SAME record image_validate.c calls
 * EXPECTED_SIGMASK_TLV -- identical semantics (a bitmask over the key pool), so it
 * is deliberately shared rather than duplicated at another type.
 *
 * PROTECTED, hence inside MCUboot's image hash AND inside the founder leaf: the
 * founder signature ATTESTS to the signer set instead of the verifier inferring it
 * from whichever keys happen to verify. That attestation is the whole point of
 * committing it -- it is auditable and non-repudiable, and it anchors the
 * anti-glitch check in pq_image_verify to SIGNED data.
 *
 * Being protected does NOT bind the binary to one key selection: the SIGNER stamps
 * this field (then the leaf is computed, then it signs), exactly as it stamps the
 * STM boot header's sigmask. Patching it invalidates MCUboot's image hash, so the
 * signer re-stamps TLV 0x10 too (nrf_tree.set_protected_sigmask). Rotating founder
 * keys therefore costs a re-sign, not an nRF rebuild.
 */
#define IMAGE_TLV_PQ_SIGMASK 0x00A2

/* Upper bound on the co-path, bounding untrusted TLV length arithmetic. Matches
 * NRF_OTA_MAX_PROOF_NODES on the STM side. */
#define PQ_MAX_MERKLE_PROOF_NODES 32

/* Founder signature sizes, mirroring the STM boot header
 * (BOOT_HEADER_PQ/EC_SIGNATURE_LEN): SLH-DSA (SPHINCS+-SHA2-128s) and Ed25519.
 * 2-of-3 multisig, so exactly two of each per image, selected by the sigmask. */
#define PQ_SLH_SIG_LEN 7856
#define PQ_EC_SIG_LEN 64

/*
 * Image reader. Returns 0 on success, non-zero on failure.
 *
 * Abstracts WHERE the image bytes come from: MCUboot reads through a flash_area
 * (LOAD_IMAGE_DATA), while the host cross-validation replays a flat buffer. Using
 * a callback keeps the hash/fold logic identical in both, which is the whole point
 * of the cross-validation.
 */
typedef int (*pq_read_fn)(void *ctx, uint32_t off, void *dst, uint32_t len);

/*
 * How many leading bytes of the image the founder leaf covers:
 *   founder TLVs present -> the offset of the FIRST founder record;
 *   otherwise            -> image_len (the whole image).
 *
 * ONE content-based rule, no per-model branch. A PQ-native image yields a prefix
 * (its founder material signs modelRoot, so it cannot sit inside the very leaf it
 * commits); a classic Ed25519-only image yields the whole image, which is what
 * lets the STM treat a passing fold as proof of byte-exactness for those.
 *
 * All inputs are read from the image being verified, i.e. UNTRUSTED -- but they
 * lie inside the covered range, so a lie changes the leaf and verification fails
 * closed. Bounds-checked throughout.
 *
 * Returns 0 and sets *out_len on success; non-zero if the image is malformed.
 */
/* MCUboot's own image hash -- SHA-256 over header + payload + protected TLVs,
 * the value TLV 0x10 carries -- computed by streaming through `read`.
 *
 * This IS the model-tree leaf value. bootutil_img_validate normally has it
 * already, which is why pq_image_verify takes it as a parameter; this exists for
 * callers that do not (the host cross-validation). Returns 0 on success. */
int pq_image_hash(pq_read_fn read, void *ctx, uint32_t image_len,
                  uint8_t out_hash[PQ_NODE_LEN]);

int pq_region_shape_ok(pq_read_fn read, void *ctx, uint32_t image_len,
                            bool *out_present);

/*
 * Fold `leaf` up through `count` co-path nodes to a root. Internal nodes are
 * H(0x01 || min(a,b) || max(a,b)) -- sorted pairs, so the proof carries no
 * direction bits. Shared with the STM and the host signer; a divergence here is
 * silent, so all three are cross-validated against common vectors.
 */
void pq_merkle_fold(const uint8_t leaf[PQ_NODE_LEN], const uint8_t *co_path,
                    uint32_t count, uint8_t out_root[PQ_NODE_LEN]);

/*
 * FULL founder verification: leaf -> fold -> hybrid signature over modelRoot.
 *
 * Mirrors the STM's boot_header_check_signature -- the two MCUs verify the same
 * signature bytes, so the message construction must agree, not merely be
 * equivalent:
 *   - 2 signature slots (PQ_SIG_COUNT), keys named by the protected sigmask:
 *     slot i uses the i-th LOWEST set bit, exactly PQ_SIG_COUNT bits must be
 *     set, each is consumed once, and the reconstructed set must equal the value
 *     read (the STM's sigmask/sigmask_inv check);
 *   - SLH-DSA signs modelRoot (32 bytes) directly;
 *   - Ed25519 signs SHA256(modelRoot || slh_signature) -- it therefore commits to
 *     the PQ signature too, which is what stops a PQ-signature substitution;
 *   - the Ed25519 check runs FIRST, as a cheap gate before the expensive PQ verify.
 *
 * Everything needed is read from the image: the sigmask (PROTECTED, so committed)
 * and the founder signatures + co-path (unprotected -- they commit to the leaf, so
 * the leaf cannot cover them). The shape of that unprotected region is validated
 * first (pq_region_shape_ok), so a rogue record cannot ride along.
 *
 * `pq_keys` / `ec_keys` are `key_count` public keys (32 bytes each,
 * PQ_MAX_KEYS max) supplied by the caller -- this module holds no key policy.
 *
 * Returns FIH_SUCCESS and, if `out_root` is non-NULL, the verified modelRoot.
 * Returns FIH_FAILURE on ANY failure, including an image with no founder material
 * (callers that accept classic images must check pq_region_shape_ok's
 * `present` instead of treating absence as success).
 *
 * MUST be called via FIH_CALL and the result compared with FIH_EQ/FIH_NOT_EQ
 * against FIH_SUCCESS -- see the hardening note at the top of this header. Never
 * assign a success value to a verdict variable based on this function's result;
 * propagate the returned fih_ret itself.
 */
fih_ret pq_image_verify(pq_read_fn read, void *ctx, uint32_t image_len,
                   const uint8_t *image_hash,
                   const uint8_t *const *pq_keys, const uint8_t *const *ec_keys,
                   uint32_t key_count, uint8_t *out_root);

/*
 * Read the image's security counter (IMAGE_TLV_SEC_CNT) for rollback protection.
 *
 * Searched in the PROTECTED TLV area only, which is what makes this trustworthy:
 * protected TLVs sit inside MCUboot's image hash AND inside the founder leaf (the
 * leaf covers everything up to the first PQ TLV), so the counter is already
 * covered by the founder signature -- no extra signing, and it cannot be raised
 * or forged without invalidating that signature. An unprotected copy would be
 * attacker-controlled, so one is never consulted.
 *
 * Why this exists at all: MCUboot's own MCUBOOT_HW_ROLLBACK_PROT compares
 * counters between SLOTS when deciding to swap, and updates the NV counter after
 * a swap. With CONFIG_SINGLE_APPLICATION_SLOT there is no second slot and no swap
 * decision, so neither runs, and nothing compares the image against the stored
 * counter at boot. That leaves an old-but-genuinely-signed image writable
 * straight into slot0 over serial recovery -- the one path the STM-side founder
 * gate cannot see.
 *
 * The value is the STM boot header's monotonic_version, stamped by the SIGNER --
 * ONE anti-rollback axis for the coupled release, not a counter the nRF keeps on
 * its own. Two independent axes could settle into states neither side rejects,
 * notably a forward STM paired with an nRF rolled back over serial recovery. The
 * STM enforces the same number in its boardloader against an NV monoctr.
 *
 * `*out_cnt` is set to 0 when the image carries no counter, which is a valid
 * state (an image built without imgtool's -s): any stored counter above 0 then
 * refuses it, so absence can only ever be MORE restrictive, never a bypass.
 *
 * Returns 0 on success (counter found, or validly absent), non-zero if the image
 * is malformed or the record has the wrong size.
 */
int pq_image_security_counter(pq_read_fn read, void *ctx, uint32_t image_len,
                              uint32_t *out_cnt);

/* Signature slots per image and the key-pool bound, mirroring the STM's
 * BOOT_HEADER_SIGNATURE_COUNT and its <=3 key assertion. */
#define PQ_SIG_COUNT 2
#define PQ_MAX_KEYS 3

#ifdef __cplusplus
}
#endif

#endif /* H_IMAGE_PQ_ */
