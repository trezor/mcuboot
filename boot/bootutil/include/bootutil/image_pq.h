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
 *     leaf = H(0x00 || image[0 .. pq_leaf_len))
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

#ifdef __cplusplus
extern "C" {
#endif

#define PQ_NODE_LEN 32 /* SHA-256 */

/*
 * Founder TLVs, in MCUboot's vendor range (0x00a0-0x00ff), continuing the
 * existing allocation (0x00A0/A1 image sigs, 0x00A2 sigmask, 0x00A3 model id).
 *
 * LOAD-BEARING: this contiguous range DEFINES the leaf boundary (see
 * pq_leaf_len) -- it is not merely an allocation. A founder-ish TLV placed
 * outside the range would wrongly fall INSIDE the leaf; one added inside it moves
 * the boundary. Changing the range is a leaf-format change; it must be made in
 * lockstep with the STM and the host signer.
 *
 * These records MUST be the LAST entries in the unprotected TLV area.
 */
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
int pq_leaf_len(pq_read_fn read, void *ctx, uint32_t image_len,
                     uint32_t *out_len);

/* leaf = H(0x00 || image[0 .. leaf_len)), streamed. Returns 0 on success. */
int pq_leaf_hash(pq_read_fn read, void *ctx, uint32_t leaf_len,
                      uint8_t out_leaf[PQ_NODE_LEN]);

/*
 * Fold `leaf` up through `count` co-path nodes to a root.
 * Internal node = H(0x01 || min(a,b) || max(a,b)) -- the pair is SORTED, so the
 * proof carries no direction bits.
 */
void pq_merkle_fold(const uint8_t leaf[PQ_NODE_LEN], const uint8_t *co_path,
                  uint32_t count, uint8_t out_root[PQ_NODE_LEN]);

/*
 * Validate the SHAPE of the region the leaf does NOT cover: it must be EXACTLY
 * the expected founder records and nothing else -- each expected type present
 * exactly once, each with its expected length, ending precisely at the TLV area's
 * end, with no slack and no unexpected records.
 *
 * WHY THIS EXISTS (it is not redundant with verifying the signatures): MCUboot
 * enforces a whitelist of unprotected TLV types, so a ROGUE record in the
 * uncovered region makes MCUboot reject the image -- yet it changes neither the
 * leaf, nor modelRoot, nor the founder signature, so both the Merkle fold AND a
 * full founder signature re-verify still pass. Without this check, a caller can be
 * tricked into overwriting a working nRF with an image its own MCUboot will refuse,
 * leaving no valid app at all (there is no dual slot; on a BLE-only device that is
 * the host link).
 *
 * The attacker's room is already bounded by the leaf: the unprotected TLV-area info
 * header (magic + it_tlv_tot) lies INSIDE the leaf, so the region's EXTENT is
 * founder-committed -- it cannot be grown, and bytes past tlv_end are ignored by
 * MCUboot. This check closes what is left: the fixed-size region's contents. It
 * follows that the build must emit the founder records with NO padding, or the
 * slack becomes smuggling room.
 *
 * Shared by the nRF (which verifies at boot) and the STM (which must know, before
 * it overwrites a working nRF, that MCUboot will accept the image) so both agree on
 * the expected shape by construction rather than by comment.
 *
 * `*out_present` reports whether the image carries founder material at all; a
 * classic (Ed25519-only) image has none and is reported present=false, rc=0 --
 * nothing to check, because its leaf covers the whole image anyway.
 *
 * Returns 0 if the shape is acceptable (or absent), non-zero otherwise.
 */
int pq_region_shape_ok(pq_read_fn read, void *ctx, uint32_t image_len,
                            bool *out_present);

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
 * On success returns 0 and, if `out_root` is non-NULL, the verified modelRoot.
 * Returns non-zero on ANY failure, including an image with no founder material
 * (callers that accept classic images must check pq_region_shape_ok's
 * `present` instead of treating absence as success).
 */
int pq_image_verify(pq_read_fn read, void *ctx, uint32_t image_len,
                   const uint8_t *const *pq_keys, const uint8_t *const *ec_keys,
                   uint32_t key_count, uint8_t *out_root);

/* Signature slots per image and the key-pool bound, mirroring the STM's
 * BOOT_HEADER_SIGNATURE_COUNT and its <=3 key assertion. */
#define PQ_SIG_COUNT 2
#define PQ_MAX_KEYS 3

#ifdef __cplusplus
}
#endif

#endif /* H_IMAGE_PQ_ */
