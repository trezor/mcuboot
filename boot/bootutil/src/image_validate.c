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


// trezor crypto fault handler, force hard fault on error, as this is a security critical function
void tc_fault_handler(const char *msg) {
    (void)msg;

    /* Execute an undefined instruction (udf on Cortex-M). This raises a
     * UsageFault that escalates to a HardFault, unconditionally aborting
     * execution so control never returns to the security-critical caller. */
    __builtin_trap();

    /* Backstop: never allow the caller to continue even if the trap above is
     * somehow bypassed. */
    while (1) {}
}


/*
    * The following TLVs are expected to be present in the image.
    *
    * EXPECTED_SIG_1_TLV contains the signature 1 of the image.
    * EXPECTED_SIG_2_TLV contains the signature 2 of the image.
    * EXPECTED_SIGMASK_TLV contains the bitmask of the signers that signed the image, and is
    * used to compute the public key against which the signature is verified.
    */
#ifdef CONFIG_BOOT_PQ_SECURE_BOOT
/* Founder TLV types + sizes, needed by allowed_unprot_tlvs below. */
#include "bootutil/image_pq.h"
#ifdef CONFIG_BOOT_PQ_ROLLBACK_PROT
#include "bootutil/security_cnt.h"
#endif
#endif

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
#ifdef CONFIG_BOOT_PQ_SECURE_BOOT
     /* Founder material (signature over modelRoot + co-path). It MUST be listed
      * here or the image is rejected outright as carrying rogue TLVs -- and it has
      * to live in the unprotected area because it commits to the leaf, which
      * cannot then cover it. pq_region_shape_ok() re-checks that this region
      * contains EXACTLY these records and nothing else, since the founder leaf
      * does not cover them. */
     IMAGE_TLV_PQ_SLH_SIG_0,
     IMAGE_TLV_PQ_SLH_SIG_1,
     IMAGE_TLV_PQ_EC_SIG_0,
     IMAGE_TLV_PQ_EC_SIG_1,
     IMAGE_TLV_PQ_MERKLE_PROOF,
#endif
     /* Mark end with ANY. */
     IMAGE_TLV_ANY,
};
#endif



#include <ed25519-donna/ed25519.h>

#ifdef CONFIG_BOOT_PQ_SECURE_BOOT
/* image_pq.h mirrors this TLV type because it is also compiled by the host
 * cross-validation, which has no bootutil/image.h. Pin the two together. */
_Static_assert(IMAGE_TLV_PQ_SEC_CNT == IMAGE_TLV_SEC_CNT,
               "image_pq.h security-counter TLV drifted from bootutil/image.h");

/*
 * Founder public keys -- the SAME keys the Trezor STM boot header is verified
 * against, because both MCUs verify the SAME founder signature over modelRoot.
 * ONE key set covers ALL models. The founder ceremony signs every model in a
 * single operation, so the pool is a property of the CEREMONY, not of a model --
 * hence no per-model selection here. Model separation comes from the TREE (each
 * model has its own leaves under modelRoot) and from the model-id TLV check in
 * bootutil_img_validate, never from the key pool.
 *
 * MUST mirror ROOT_* in the STM's sec/image/inc/sec/root_keys.h (named after
 * their trezorlib counterparts), INCLUDING the dev/production split:
 *
 *     STM                          nRF
 *     BOOTLOADER_DEVEL             (default -- no MCUBOOT_PRODUCTION_KEY)
 *     !BOOTLOADER_DEVEL            CONFIG_BOOT_PRODUCTION_KEY=y
 *
 * Getting this wrong is invisible until the device refuses to boot: the signature
 * is well-formed, just made by keys this bootloader does not know. Note the DEV
 * pool has TWO keys while production has THREE, so PQ_KEY_N differs too --
 * a dev image's sigmask 0x03 names dev keys 0 and 1.
 *
 * KEY ORDER IS LOAD-BEARING: the sigmask names keys by INDEX (slot i uses the i-th
 * lowest set bit), so reordering silently invalidates every signature ever made.
 * Append only.
 *
 * This is a third copy -- unavoidable, because this repository must build
 * standalone and cannot include a monorepo header. trezorlib
 * (firmware/models.py ROOT_*) is what the signer uses and is the authority;
 * tools/trezor_core_tools/root_keys_check.py proves all three agree.
 *
 * Cross-check a signed image against a key pool on the host (much faster than a
 * flash cycle): tools/trezor_core_tools/nrf_pq_check.py.
 */
#ifndef MCUBOOT_PRODUCTION_KEY
/*** DEVEL/QA ROOT KEYS (2) -- root_keys.h ROOT_*_KEYS_DEV ***/
static const uint8_t * const PQ_SLH_KEYS[] = {
    (const uint8_t *)"\xec\x01\xe6\x02\x63\x02\x4f\x7e\x71\x72\x80\x13\xb7\x31\xf7\xba\x12\x99\xf5\x18\xc2\x7b\xa3\xed\x8f\x4a\x21\x99\x74\x12\x7c\x62",
    (const uint8_t *)"\x8a\xf8\x87\x80\x85\x94\x6e\xd8\xb1\x16\xbd\x24\xc0\xf2\xaa\xc4\x8b\x7e\x8f\x11\xbf\x06\x87\x25\xcc\xfb\xb1\x52\xab\xf7\xa4\xcd",
};
static const uint8_t * const PQ_EC_KEYS[] = {
    (const uint8_t *)"\xdb\x99\x5f\xe2\x51\x69\xd1\x41\xca\xb9\xbb\xba\x92\xba\xa0\x1f\x9f\x2e\x1e\xce\x7d\xf4\xcb\x2a\xc0\x51\x90\xf3\x7f\xcc\x1f\x9d",
    (const uint8_t *)"\x21\x52\xf8\xd1\x9b\x79\x1d\x24\x45\x32\x42\xe1\x5f\x2e\xab\x6c\xb7\xcf\xfa\x7b\x6a\x5e\xd3\x00\x97\x96\x0e\x06\x98\x81\xdb\x12",
};
#else
/*** PRODUCTION ROOT KEYS (3) -- root_keys.h ROOT_SLH_DSA_KEYS / ROOT_ED25519_KEYS ***/
static const uint8_t * const PQ_SLH_KEYS[] = {
    (const uint8_t *)"\xec\x57\xa2\x64\x3e\x55\x3c\x59\x19\x47\x3c\xd5\x79\xcd\xdd\xa6\x50\x05\x7c\x2f\xd5\x98\xa4\x47\x57\x4b\xdb\x6c\x1f\x0f\x55\x21",
    (const uint8_t *)"\xd2\x96\xd8\xcf\x9b\xe3\xe9\x23\xe1\x0a\xc0\x3f\x43\x56\x6d\x18\x9d\x11\xf6\xb5\xdd\xab\xdf\x8d\xc1\x2d\x29\xc0\x0e\x5a\x13\x6a",
    (const uint8_t *)"\xb7\x2b\xd7\x1b\xf8\xe1\x09\xd3\x77\x4d\x91\xe3\xc1\xab\xd2\xa2\xe9\xff\x6b\x57\x11\x89\x6f\x8d\x87\x3a\x3d\xf9\xb9\xbe\x98\xd1",
};
static const uint8_t * const PQ_EC_KEYS[] = {
    (const uint8_t *)"\xb0\xd7\x3e\x86\xae\x39\x2a\x26\xda\x72\x75\x99\x4e\x96\x50\x97\xae\x7e\xe8\xf8\x84\x55\x78\x8e\x8c\x53\x40\x21\xd5\xde\x18\x85",
    (const uint8_t *)"\xa8\xf1\x8b\x94\x86\x16\x7c\x97\xb0\x59\xfd\x4f\x05\x3b\xe8\x24\xf7\xd5\xb0\xcb\x87\x10\xb3\xca\x12\xd2\x6d\x2d\xda\xc3\x51\xc9",
    (const uint8_t *)"\xd2\x0f\xbd\xa4\x27\x1a\xeb\x06\xc1\x8c\x26\xc6\xf2\xad\xb6\xd6\xb0\xe3\x12\xf8\x45\xf9\x04\x41\xfd\x61\x4f\x39\x75\x54\xa8\x6e",
};
#endif
#define PQ_KEY_N (sizeof(PQ_SLH_KEYS) / sizeof(PQ_SLH_KEYS[0]))
_Static_assert(sizeof(PQ_EC_KEYS) == sizeof(PQ_SLH_KEYS),
               "founder EC and PQ key pools must pair up 1:1 (as on the STM)");
_Static_assert(PQ_KEY_N <= PQ_MAX_KEYS, "founder key pool too large");

/* Bridges pq_read_fn onto MCUboot's image access (flash_area, or a direct
 * copy under MCUBOOT_RAM_LOAD) -- which is why image_pq.c takes a callback
 * instead of a pointer: the same code is cross-validated on the host over a flat
 * buffer. */
struct pq_read_ctx {
    struct image_header *hdr;
    const struct flash_area *fap;
};

static int pq_read_image(void *ctx, uint32_t off, void *dst, uint32_t len)
{
    struct pq_read_ctx *c = (struct pq_read_ctx *)ctx;
    return LOAD_IMAGE_DATA(c->hdr, c->fap, off, dst, len);
}
#endif /* CONFIG_BOOT_PQ_SECURE_BOOT */

/* The nRF's OWN Ed25519 key pool, for the classic image-hash signatures. Not used
 * on founder-tree builds: authenticity there comes from the founder keys above,
 * over modelRoot. Compiled out so it is neither dead flash nor an unused-variable
 * warning, and so there is exactly one key pool in play per configuration. */
#ifndef CONFIG_BOOT_PQ_SECURE_BOOT
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
#endif /* !CONFIG_BOOT_PQ_SECURE_BOOT */


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
#ifndef CONFIG_BOOT_PQ_SECURE_BOOT  /* image-hash sigs: unused on founder-only models */
    bool sig_0_found = false;
    bool sig_1_found = false;
#endif
    bool model_valid = false;
#ifndef CONFIG_BOOT_PQ_SECURE_BOOT  /* sigmask: pq_image_verify reads it itself */
    uint16_t sigmask = 0;
#endif
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    uint32_t off;
    uint16_t len;
    uint16_t type;
    FIH_DECLARE(valid_signature, FIH_FAILURE);
    struct image_tlv_iter it;
    uint8_t buf[SIG_BUF_SIZE] = {0};
#ifndef CONFIG_BOOT_PQ_SECURE_BOOT  /* image-hash sigs: unused on founder-only models */
    uint8_t sig0[SIG_BUF_SIZE] = {0};
    uint8_t sig1[SIG_BUF_SIZE] = {0};
#endif
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
#ifndef CONFIG_BOOT_PQ_SECURE_BOOT  /* sigmask: pq_image_verify reads it itself */
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
#endif

#ifndef CONFIG_BOOT_PQ_SECURE_BOOT  /* image-hash sigs: unused on founder-only models */
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
#endif
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

#ifdef CONFIG_BOOT_PQ_SECURE_BOOT
    /*
     * Post-quantum-native models: authenticity comes ENTIRELY from the founder
     * tree, so the image-hash Ed25519 signatures (EXPECTED_SIG_0/1_TLV) are not
     * expected and not consulted. The founder signature is itself hybrid
     * (SLH-DSA + Ed25519 over modelRoot), so dropping them loses no classical
     * assurance while collapsing the device onto ONE trust root -- the same keys
     * and the same signature bytes the STM boot header carries.
     *
     * The image hash (EXPECTED_HASH_TLV, checked above) still provides integrity;
     * pq_image_verify() provides authenticity, and internally requires that the
     * unprotected region is exactly the expected founder records.
     *
     * The sigmask is not read HERE either: pq_image_verify fetches it itself, from
     * the PROTECTED area only (an unprotected copy would not be committed by the
     * leaf), so this function's own sigmask plumbing is unused on this path.
     */
    if (!model_valid) {
        rc = -1;
        goto out;
    }
    {
        struct pq_read_ctx fctx = { .hdr = hdr, .fap = fap };
        /* it.tlv_end is the true end of the image (hdr+img+prot+unprot), NOT the
         * slot size -- passing the slot size would make the "no founder material"
         * case cover trailing flash.
         *
         * FIH_CALL + propagate, never mint: the verdict assigned to
         * valid_signature is the fih_ret the verifier itself returned, so there is
         * no point at which a single glitched comparison here can manufacture a
         * valid signature. FIH_CALL seeds fih_rc with FIH_FAILURE and validates
         * the CFI counter, which also catches the call being skipped entirely. */
        FIH_CALL(pq_image_verify, fih_rc, pq_read_image, &fctx, it.tlv_end,
                 PQ_SLH_KEYS, PQ_EC_KEYS, PQ_KEY_N, NULL);
        if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
            rc = -1;
            goto out;
        }
        FIH_SET(valid_signature, fih_rc);

#ifdef CONFIG_BOOT_PQ_ROLLBACK_PROT
        /*
         * Rollback protection at BOOT time, which MCUboot does not otherwise do.
         * Its MCUBOOT_HW_ROLLBACK_PROT compares counters between SLOTS when
         * deciding to swap and updates the NV counter afterwards; with
         * CONFIG_SINGLE_APPLICATION_SLOT there is no second slot and no swap, so
         * neither runs and nothing checks the image already sitting in slot0.
         *
         * That gap IS the serial-recovery threat: an attacker with the nRF's UART
         * and RESET/STAY_IN_BLD pins writes an OLD but genuinely founder-signed
         * image straight into slot0. Founder verification passes -- it is a real
         * release -- and the STM is not on that path, so only a stored monotonic
         * counter can refuse it.
         *
         * The counter comes from the PROTECTED TLV area, so it sits inside the
         * founder leaf and is already covered by the founder signature: it cannot
         * be raised without breaking that signature. Checked only AFTER the
         * signature verified, so an unauthenticated image can never move it.
         *
         * The value IS the STM boot header's monotonic_version -- one axis for the
         * coupled release, stamped by the signer from the header it is signing, so
         * the two cannot disagree. This mirrors the STM boardloader exactly (read
         * the NV floor, refuse below it, then raise it), which is what keeps the
         * pair from drifting into a state neither side rejects.
         */
        {
            uint32_t img_cnt = 0;
            FIH_DECLARE(cnt_fih, FIH_FAILURE);
            fih_int nv_cnt = fih_int_encode(0);

            if (pq_image_security_counter(pq_read_image, &fctx, it.tlv_end,
                                          &img_cnt) != 0) {
                rc = -1;
                goto out;
            }

            FIH_CALL(boot_nv_security_counter_get, cnt_fih, 0, &nv_cnt);
            if (FIH_NOT_EQ(cnt_fih, FIH_SUCCESS)) {
                /*
                 * No readable counter -- the provision page has no counter
                 * collection. That is a PROVISIONING state, not a runtime one, so
                 * the response differs by build:
                 *
                 *   production: refuse. A production device without a provisioned
                 *               counter has no rollback protection at all, and
                 *               booting anyway would silently ship that.
                 *   devel:      warn and skip. Devel keys are public, so there is
                 *               no security to protect here, and failing closed
                 *               would brick every un-provisioned devkit on first
                 *               boot -- including during bring-up of this feature.
                 */
#ifdef MCUBOOT_PRODUCTION_KEY
                BOOT_LOG_ERR("no provisioned security counter; refusing to boot");
                rc = -1;
                goto out;
#else
                BOOT_LOG_WRN("no provisioned security counter; "
                             "rollback protection INACTIVE (devel build)");
#endif
            } else {
                uint32_t nv = (uint32_t)fih_int_decode(nv_cnt);

                /* Refuse anything below the floor. Equal is fine -- that is the
                 * image already in service. THIS is the security property. */
                if (img_cnt < nv) {
                    BOOT_LOG_ERR("security counter %u < stored %u: rollback refused",
                                 (unsigned)img_cnt, (unsigned)nv);
                    rc = -1;
                    goto out;
                }

                /*
                 * Raising the floor is best-effort, and deliberately NOT fatal.
                 * The counter store is a fixed array of write-once slots, so a
                 * bump can legitimately fail with -ENOMEM once they are spent;
                 * refusing to boot then would brick a device on a perfectly valid
                 * image. Losing the raise only forfeits FUTURE tightening -- the
                 * check above has already authorised this image.
                 *
                 * Only advanced on production builds. The nRF's slots are
                 * write-once and, unlike the STM's counter (secret_erase /
                 * secret_unlock_bootloader), there is no way to wind them back, so
                 * advancing on devel builds would permanently pin devkits above
                 * older releases while testing.
                 */
#ifdef MCUBOOT_PRODUCTION_KEY
                if (img_cnt > nv) {
                    if (boot_nv_security_counter_update(0, img_cnt) != 0) {
                        BOOT_LOG_WRN("could not raise security counter to %u "
                                     "(slots exhausted?); booting anyway",
                                     (unsigned)img_cnt);
                    }
                }
#else
                if (img_cnt > nv) {
                    BOOT_LOG_INF("security counter %u > stored %u; not advancing "
                                 "(devel build, slots are write-once)",
                                 (unsigned)img_cnt, (unsigned)nv);
                }
#endif
            }
        }
#endif /* CONFIG_BOOT_PQ_ROLLBACK_PROT */
    }

    rc = !image_hash_valid;
    if (rc) {
        goto out;
    }

    FIH_SET(fih_rc, valid_signature);
    goto out;
#else
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
#endif /* CONFIG_BOOT_PQ_SECURE_BOOT */

out:
    if (rc) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

    FIH_RET(fih_rc);
}
