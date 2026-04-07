/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2017-2019 Linaro LTD
 * Copyright (c) 2016-2019 JUUL Labs
 * Copyright (c) 2019-2024 Arm Limited
 * Copyright (c) 2025 Nordic Semiconductor ASA
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
#include "bootutil/fault_injection_hardening.h"

#include "mcuboot_config/mcuboot_config.h"

#include "bootutil/bootutil_log.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

#include "bootutil_priv.h"

/*
    * The following TLVs are expected to be present in the image.
    *
    * EXPECTED_SIG_1_TLV contains the signature 1 of the image.
    * EXPECTED_SIG_2_TLV contains the signature 2 of the image.
    * EXPECTED_SIGMASK_TLV contains the bitmask of the signers that signed the image, and is
    * used to compute the public key against which the signature is verified.
    */
#define EXPECTED_SIG_0_TLV 0x00A0
#define EXPECTED_SIG_1_TLV 0x00A1
#define EXPECTED_SIGMASK_TLV 0x00A2
#define EXPECTED_MODEL_TLV 0x00A3
#define SIG_BUF_SIZE 64
#define EXPECTED_SIG_LEN(x) ((x) == SIG_BUF_SIZE)



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
     EXPECTED_SIG_0_TLV,
     EXPECTED_SIG_1_TLV,
     /* Mark end with ANY. */
     IMAGE_TLV_ANY,
};
#endif



#include <ed25519-donna/ed25519.h>

#ifndef MCUBOOT_PRODUCTION_KEY
const uint8_t BOOTLOADER_KEY_N = 3;
static const uint8_t * const BOOTLOADER_KEYS[] = {
  /*** DEVEL/QA KEYS  ***/
  (const uint8_t *)"\xd7\x59\x79\x3b\xbc\x13\xa2\x81\x9a\x82\x7c\x76\xad\xb6\xfb\xa8\xa4\x9a\xee\x00\x7f\x49\xf2\xd0\x99\x2d\x99\xb8\x25\xad\x2c\x48",
  (const uint8_t *)"\x63\x55\x69\x1c\x17\x8a\x8f\xf9\x10\x07\xa7\x47\x8a\xfb\x95\x5e\xf7\x35\x2c\x63\xe7\xb2\x57\x03\x98\x4c\xf7\x8b\x26\xe2\x1a\x56",
  (const uint8_t *)"\xee\x93\xa4\xf6\x6f\x8d\x16\xb8\x19\xbb\x9b\xeb\x9f\xfc\xcd\xfc\xdc\x14\x12\xe8\x7f\xee\x6a\x32\x4c\x2a\x99\xa1\xe0\xe6\x71\x48",
};
#else
const uint8_t BOOTLOADER_KEY_N = 3;
static const uint8_t * const BOOTLOADER_KEYS[] = {
    /*** PRODUCTION T3W1 KEYS  ***/
    (const uint8_t *)"\xd1\xba\xd5\xe8\xc7\x3d\xfe\x18\x3b\xa1\xbd\x54\x64\xb2\xc9\x6f\x1d\x1d\xe6\x6d\x53\xc9\x50\x26\xd1\x71\x69\x14\x8d\x09\x6f\x3e",
    (const uint8_t *)"\x58\x5f\x06\x35\xef\xc6\x51\x8c\x49\x02\x28\xa7\x2a\xe1\xf5\xd0\x80\x8e\xbe\x77\xf1\xc1\x25\x16\xeb\x6d\x52\x58\x21\xeb\x1e\x21",
    (const uint8_t *)"\x06\x5e\xe1\x9b\x0d\xe4\xee\xc3\xbe\x70\x93\x89\x35\x31\x3c\xa2\x94\x9c\xc3\x80\x8b\x2b\xf3\xad\x7e\xf0\xac\x41\x9a\x97\x41\x91"
};
#endif


/*
 * Verify the integrity of the image.
 * Return non-zero if image could not be validated/does not validate.
 */
fih_ret
bootutil_img_validate(struct boot_loader_state *state,
                      struct image_header *hdr, const struct flash_area *fap,
                      uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *seed,
                      int seed_len, uint8_t *out_hash)
{
    int rc = 0;
    bool sig_0_found = false;
    bool sig_1_found = false;
    bool model_valid = false;
    uint16_t sigmask = 0;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    uint32_t off;
    uint16_t len;
    uint16_t type;
    FIH_DECLARE(valid_signature, FIH_FAILURE);
    struct image_tlv_iter it;
    uint8_t buf[SIG_BUF_SIZE] = {0};
    uint8_t sig0[SIG_BUF_SIZE] = {0};
    uint8_t sig1[SIG_BUF_SIZE] = {0};
    int image_hash_valid = 0;
    uint8_t hash[IMAGE_HASH_SIZE] = {0};

    rc = bootutil_img_hash(state, hdr, fap, tmp_buf,
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

    if (it.tlv_end > bootutil_max_image_size(state, fap)) {
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
            if (len != 1) {
              rc = -1;
              goto out;
            }
            rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, sizeof(hash));
            if (rc) {
              goto out;
            }
            sigmask = buf[0];
            break;

          case EXPECTED_SIG_0_TLV:
          {
              if (!EXPECTED_SIG_LEN(len) || len > sizeof(buf)) {
                  rc = -1;
                  goto out;
              }
              rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, len);
              if (rc) {
                  goto out;
              }

              if (sig_0_found) {
                  /* We already found a signature, but we should only have one. */
                  rc = -1;
                  goto out;
              }

              sig_0_found = true;

              memcpy(sig0, buf, len);
              break;
          }
          case EXPECTED_SIG_1_TLV:
          {
              if (!EXPECTED_SIG_LEN(len) || len > sizeof(buf)) {
                  rc = -1;
                  goto out;
              }
              rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, len);
              if (rc) {
                  goto out;
              }

              if (sig_1_found) {
                  /* We already found a signature, but we should only have one. */
                  rc = -1;
                  goto out;
              }

              sig_1_found = true;

              memcpy(sig1, buf, len);
              break;
          }
          case EXPECTED_MODEL_TLV:
          {
              uint32_t model_identifier = 0;
              if (len != sizeof(model_identifier)) {
                  rc = -1;
                  goto out;
              }

              rc = LOAD_IMAGE_DATA(hdr, fap, off, &model_identifier, len);
              if (rc) {
                  goto out;
              }

              if (model_identifier == MODEL_IDENTIFIER) {
                  model_valid = true;
              } else {
                  rc = -1;
                  goto out;
              }

              break;
          }
        }
    }

    if (sigmask == 0 || !sig_0_found || !sig_1_found) {
        rc = -1;
        goto out;
    }

    if (!model_valid) {
        rc = -1;
        goto out;
    }

    int sig0_idx = sigmask & (1 << 0) ? 0 : 1;
    int sig1_idx = sigmask & (1 << 2) ? 2 : 1;

    if (FIH_NOT_EQ(__builtin_popcount(sigmask), 2)) {
        rc = -1;
        goto out;
    }

    if (FIH_NOT_EQ((sigmask & (~((1 << BOOTLOADER_KEY_N) - 1))), 0)){
        rc = -1;
        goto out;
    }

    // There must be two different signatures to verify
    if (FIH_EQ(sig0_idx, sig1_idx)) {
        rc = -1;
        goto out;
    } else {
        valid_signature = FIH_SUCCESS;
    }


    if (FIH_NOT_EQ(0, ed25519_sign_open(hash, sizeof(hash), BOOTLOADER_KEYS[sig0_idx],
                            *(const ed25519_signature *)sig0))){
        rc = -1;
        goto out;
    }

    if (FIH_NOT_EQ(0, ed25519_sign_open(hash, sizeof(hash), BOOTLOADER_KEYS[sig1_idx],
                            *(const ed25519_signature *)sig1))){
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
