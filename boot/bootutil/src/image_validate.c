/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2017-2019 Linaro LTD
 * Copyright (c) 2016-2019 JUUL Labs
 * Copyright (c) 2019-2024 Arm Limited
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <flash_map_backend/flash_map_backend.h>

#include "bootutil/image.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/sign_key.h"
#include "bootutil/security_cnt.h"
#include "bootutil/fault_injection_hardening.h"

#include "mcuboot_config/mcuboot_config.h"

#include "bootutil/bootutil_log.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

#include "bootutil_priv.h"

/*
 * Compute SHA hash over the image.
 * (SHA384 if ECDSA-P384 is being used,
 *  SHA256 otherwise).
 */
static int
bootutil_img_hash(struct enc_key_data *enc_state, int image_index,
                  struct image_header *hdr, const struct flash_area *fap,
                  uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *hash_result,
                  uint8_t *seed, int seed_len)
{
    bootutil_sha_context sha_ctx;
    uint32_t size;
    uint16_t hdr_size;
    uint32_t blk_off;
    uint32_t tlv_off;
#if !defined(MCUBOOT_HASH_STORAGE_DIRECTLY)
    int rc;
    uint32_t off;
    uint32_t blk_sz;
#endif

#if (BOOT_IMAGE_NUMBER == 1) || !defined(MCUBOOT_ENC_IMAGES) || \
    defined(MCUBOOT_RAM_LOAD)
    (void)enc_state;
    (void)image_index;
    (void)hdr_size;
    (void)blk_off;
    (void)tlv_off;
#ifdef MCUBOOT_RAM_LOAD
    (void)blk_sz;
    (void)off;
    (void)rc;
    (void)fap;
    (void)tmp_buf;
    (void)tmp_buf_sz;
#endif
#endif

#ifdef MCUBOOT_ENC_IMAGES
    /* Encrypted images only exist in the secondary slot */
    if (MUST_DECRYPT(fap, image_index, hdr) &&
            !boot_enc_valid(enc_state, 1)) {
        return -1;
    }
#endif

    bootutil_sha_init(&sha_ctx);

    /* in some cases (split image) the hash is seeded with data from
     * the loader image */
    if (seed && (seed_len > 0)) {
        bootutil_sha_update(&sha_ctx, seed, seed_len);
    }

    /* Hash is computed over image header and image itself. */
    size = hdr_size = hdr->ih_hdr_size;
    size += hdr->ih_img_size;
    tlv_off = size;

    /* If protected TLVs are present they are also hashed. */
    size += hdr->ih_protect_tlv_size;

#ifdef MCUBOOT_HASH_STORAGE_DIRECTLY
    /* No chunk loading, storage is mapped to address space and can
     * be directly given to hashing function.
     */
    bootutil_sha_update(&sha_ctx, (void *)flash_area_get_off(fap), size);
#else /* MCUBOOT_HASH_STORAGE_DIRECTLY */
#ifdef MCUBOOT_RAM_LOAD
    bootutil_sha_update(&sha_ctx,
                        (void*)(IMAGE_RAM_BASE + hdr->ih_load_addr),
                        size);
#else
    for (off = 0; off < size; off += blk_sz) {
        blk_sz = size - off;
        if (blk_sz > tmp_buf_sz) {
            blk_sz = tmp_buf_sz;
        }
#ifdef MCUBOOT_ENC_IMAGES
        /* The only data that is encrypted in an image is the payload;
         * both header and TLVs (when protected) are not.
         */
        if ((off < hdr_size) && ((off + blk_sz) > hdr_size)) {
            /* read only the header */
            blk_sz = hdr_size - off;
        }
        if ((off < tlv_off) && ((off + blk_sz) > tlv_off)) {
            /* read only up to the end of the image payload */
            blk_sz = tlv_off - off;
        }
#endif
        rc = flash_area_read(fap, off, tmp_buf, blk_sz);
        if (rc) {
            bootutil_sha_drop(&sha_ctx);
            return rc;
        }
#ifdef MCUBOOT_ENC_IMAGES
        if (MUST_DECRYPT(fap, image_index, hdr)) {
            /* Only payload is encrypted (area between header and TLVs) */
            int slot = flash_area_id_to_multi_image_slot(image_index,
                            flash_area_get_id(fap));

            if (off >= hdr_size && off < tlv_off) {
                blk_off = (off - hdr_size) & 0xf;
                boot_enc_decrypt(enc_state, slot, off - hdr_size,
                                 blk_sz, blk_off, tmp_buf);
            }
        }
#endif
        bootutil_sha_update(&sha_ctx, tmp_buf, blk_sz);
    }
#endif /* MCUBOOT_RAM_LOAD */
#endif /* MCUBOOT_HASH_STORAGE_DIRECTLY */
    bootutil_sha_finish(&sha_ctx, hash_result);
    bootutil_sha_drop(&sha_ctx);

    return 0;
}


/*
    * The following TLVs are expected to be present in the image.
    *
    * EXPECTED_SIG_TLV contains the signature of the image.
    * EXPECTED_SIGMASK_TLV contains the bitmask of the signers that signed the image, and is
    * used to compute the public key against which the signature is verified.
    */
#define EXPECTED_SIG_TLV 0x00A0
#define EXPECTED_SIGMASK_TLV 0x00A1
#define SIG_BUF_SIZE 64
#define EXPECTED_SIG_LEN(x) ((x) == SIG_BUF_SIZE)



/**
 * Reads the value of an image's security counter.
 *
 * @param hdr           Pointer to the image header structure.
 * @param fap           Pointer to a description structure of the image's
 *                      flash area.
 * @param security_cnt  Pointer to store the security counter value.
 *
 * @return              0 on success; nonzero on failure.
 */
int32_t
bootutil_get_img_security_cnt(struct image_header *hdr,
                              const struct flash_area *fap,
                              uint32_t *img_security_cnt)
{
    struct image_tlv_iter it;
    uint32_t off;
    uint16_t len;
    int32_t rc;

    if ((hdr == NULL) ||
        (fap == NULL) ||
        (img_security_cnt == NULL)) {
        /* Invalid parameter. */
        return BOOT_EBADARGS;
    }

    /* The security counter TLV is in the protected part of the TLV area. */
    if (hdr->ih_protect_tlv_size == 0) {
        return BOOT_EBADIMAGE;
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_SEC_CNT, true);
    if (rc) {
        return rc;
    }

    /* Traverse through the protected TLV area to find
     * the security counter TLV.
     */

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0) {
        /* Security counter TLV has not been found. */
        return -1;
    }

    if (len != sizeof(*img_security_cnt)) {
        /* Security counter is not valid. */
        return BOOT_EBADIMAGE;
    }

    rc = LOAD_IMAGE_DATA(hdr, fap, off, img_security_cnt, len);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    return 0;
}



#ifndef ALLOW_ROGUE_TLVS
/*
 * The following list of TLVs are the only entries allowed in the unprotected
 * TLV section.  All other TLV entries must be in the protected section.
 */
static const uint16_t allowed_unprot_tlvs[] = {
     IMAGE_TLV_KEYHASH,
     IMAGE_TLV_PUBKEY,
     IMAGE_TLV_SHA256,
     IMAGE_TLV_SHA384,
     IMAGE_TLV_SHA512,
     IMAGE_TLV_RSA2048_PSS,
     IMAGE_TLV_ECDSA224,
     IMAGE_TLV_ECDSA_SIG,
     IMAGE_TLV_RSA3072_PSS,
     IMAGE_TLV_ED25519,
     IMAGE_TLV_ENC_RSA2048,
     IMAGE_TLV_ENC_KW,
     IMAGE_TLV_ENC_EC256,
     IMAGE_TLV_ENC_X25519,
     EXPECTED_SIG_TLV,
     EXPECTED_SIGMASK_TLV,
     /* Mark end with ANY. */
     IMAGE_TLV_ANY,
};
#endif



#include <ed25519-donna/ed25519.h>

#ifndef MCUBOOT_PRODUCTION_KEY
const uint8_t BOOTLOADER_KEY_M = 2;
const uint8_t BOOTLOADER_KEY_N = 3;
static const uint8_t * const BOOTLOADER_KEYS[] = {
  /*** DEVEL/QA KEYS  ***/
  (const uint8_t *)"\xd7\x59\x79\x3b\xbc\x13\xa2\x81\x9a\x82\x7c\x76\xad\xb6\xfb\xa8\xa4\x9a\xee\x00\x7f\x49\xf2\xd0\x99\x2d\x99\xb8\x25\xad\x2c\x48",
  (const uint8_t *)"\x63\x55\x69\x1c\x17\x8a\x8f\xf9\x10\x07\xa7\x47\x8a\xfb\x95\x5e\xf7\x35\x2c\x63\xe7\xb2\x57\x03\x98\x4c\xf7\x8b\x26\xe2\x1a\x56",
  (const uint8_t *)"\xee\x93\xa4\xf6\x6f\x8d\x16\xb8\x19\xbb\x9b\xeb\x9f\xfc\xcd\xfc\xdc\x14\x12\xe8\x7f\xee\x6a\x32\x4c\x2a\x99\xa1\xe0\xe6\x71\x48",
};
#else
#error Production keys are not defined.
#endif

/*
Function that computes a combined public key for a multi-signature (multisig) cryptographic scheme using Ed25519 elliptic curve cryptography.

The function validates parameters and combines multiple Ed25519 public keys into a single aggregate public key based on which signers participated in signing.
Parameters

 - sig_m: Minimum number of signatures required (threshold)
 - sig_n: Total number of possible signers
 - pub: Array of pointers to public keys from all possible signers
 - sigmask: Bitmask indicating which signers actually participated
 - res: Output buffer for the resulting combined public key
*/
static bool compute_pubkey(uint8_t sig_m, uint8_t sig_n,
                              const uint8_t *const *pub, uint8_t sigmask,
                              ed25519_public_key res) {
  if (0 == sig_m || 0 == sig_n) return false;
  if (sig_m > sig_n) return false;

  // discard bits higher than sig_n
  sigmask &= ((1 << sig_n) - 1);

  // remove if number of set bits in sigmask is not equal to sig_m
  if (__builtin_popcount(sigmask) != sig_m) return false;

  ed25519_public_key keys[sig_m];
  int j = 0;
  for (int i = 0; i < sig_n; i++) {
    if ((1 << i) & sigmask) {
      memcpy(keys[j], pub[i], 32);
      j++;
    }
  }

  return (0 == ed25519_cosi_combine_publickeys(res, keys, sig_m));
}


/*
 * Verify the integrity of the image.
 * Return non-zero if image could not be validated/does not validate.
 */
fih_ret
bootutil_img_validate(struct enc_key_data *enc_state, int image_index,
                      struct image_header *hdr, const struct flash_area *fap,
                      uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *seed,
                      int seed_len, uint8_t *out_hash)
{
    int rc = 0;
    bool sig_found = false;
    uint16_t sigmask = 0;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    uint32_t off;
    uint16_t len;
    uint16_t type;
    FIH_DECLARE(valid_signature, FIH_FAILURE);
    struct image_tlv_iter it;
    uint8_t buf[SIG_BUF_SIZE] = {0};
    uint8_t sig[SIG_BUF_SIZE] = {0};
    int image_hash_valid = 0;
    uint8_t hash[IMAGE_HASH_SIZE] = {0};

    rc = bootutil_img_hash(enc_state, image_index, hdr, fap, tmp_buf,
            tmp_buf_sz, hash, seed, seed_len);
    if (rc) {
        goto out;
    }

    if (out_hash) {
        memcpy(out_hash, hash, IMAGE_HASH_SIZE);
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false);
    if (rc) {
        goto out;
    }

    if (it.tlv_end > bootutil_max_image_size(fap)) {
        rc = -1;
        goto out;
    }

    /*
     * Traverse through all of the TLVs, performing any checks we know
     * and are able to do.
     */
    while (true) {
        rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
        if (rc < 0) {
            goto out;
        } else if (rc > 0) {
            break;
        }

#ifndef ALLOW_ROGUE_TLVS
        /*
         * Ensure that the non-protected TLV only has entries necessary to hold
         * the signature.  We also allow encryption related keys to be in the
         * unprotected area.
         */
        if (!bootutil_tlv_iter_is_prot(&it, off)) {
             bool found = false;
             for (const uint16_t *p = allowed_unprot_tlvs; *p != IMAGE_TLV_ANY; p++) {
                  if (type == *p) {
                       found = true;
                       break;
                  }
             }
             if (!found) {
                  FIH_SET(fih_rc, FIH_FAILURE);
                  goto out;
             }
        }
#endif
        switch(type) {
          case EXPECTED_HASH_TLV:
          {
              /* Verify the image hash. This must always be present. */
              if (len != sizeof(hash)) {
                  rc = -1;
                  goto out;
              }
              rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, sizeof(hash));
              if (rc) {
                  goto out;
              }

              FIH_CALL(boot_fih_memequal, fih_rc, hash, buf, sizeof(hash));
              if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
                  FIH_SET(fih_rc, FIH_FAILURE);
                  goto out;
              }

              image_hash_valid = 1;
              break;
          }
          case EXPECTED_SIGMASK_TLV:
            if (len != 2) {
              rc = -1;
              goto out;
            }
            rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, sizeof(hash));
            if (rc) {
              goto out;
            }
            sigmask = (buf[0] << 8) | buf[1];
            break;

          case EXPECTED_SIG_TLV:
          {
              if (!EXPECTED_SIG_LEN(len) || len > sizeof(buf)) {
                  rc = -1;
                  goto out;
              }
              rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, len);
              if (rc) {
                  goto out;
              }

              if (sig_found) {
                  /* We already found a signature, but we should only have one. */
                  rc = -1;
                  goto out;
              }

              sig_found = true;

              memcpy(sig, buf, len);
              break;
          }
        }
    }

    if (sigmask == 0 || !sig_found) {
        rc = -1;
        goto out;
    }

    ed25519_public_key pub;
    if (true != compute_pubkey(BOOTLOADER_KEY_M, BOOTLOADER_KEY_N, BOOTLOADER_KEYS, sigmask, pub))
    {
        rc = -1;
        goto out;
    } else {
        valid_signature = FIH_SUCCESS;
    }

    if (FIH_NOT_EQ(0, ed25519_sign_open(hash, sizeof(hash), pub,
                            *(const ed25519_signature *)sig))){
        rc = -1;
        goto out;
    }

    rc = !image_hash_valid;
    if (rc) {
        goto out;
    }

    FIH_SET(fih_rc, valid_signature);

out:
    if (rc) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

    FIH_RET(fih_rc);
}
