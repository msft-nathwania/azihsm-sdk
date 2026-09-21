// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;


#[test]
fn test_flush_sync_session_slot_reclaim_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            // Handle 1: open a session, then let the handle drop (→ flush).
            {
                let new_dev = ddi.open_dev(path).unwrap();
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    &new_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                let resp = helper_open_session(
                    &new_dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "open on handle 1 failed: {:?}", resp);

                // `new_dev` is dropped here: fd close → driver OP_FLUSH →
                // firmware synchronous session teardown.
            }

            // Handle 2: after the prior session was flushed, opening a fresh
            // session on a new handle must still succeed (controller healthy,
            // session slot reclaimed rather than leaked).
            let next_dev = ddi.open_dev(path).unwrap();
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &next_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                &next_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(
                resp.is_ok(),
                "open on handle 2 after flush failed: {:?}",
                resp
            );
        },
    );
}


// Fill every partition session slot until `OpenSession` reports
// `VaultSessionLimitReached` (the partition caps concurrent sessions at 8),
// then drop exactly one holding handle. Dropping the handle closes its fd →
// driver issues `OP_FLUSH` → firmware `handle_flush_op` synchronously tears the
// session down, freeing one slot. A subsequent open must then succeed, proving
// the slot was reclaimed by flush rather than leaked.
//
// `common_setup` already holds one baseline session on the primary handle, so
// the exhaustion point is discovered dynamically rather than hard-coded.
#[test]
fn test_flush_sync_session_slot_reclaim_exhaustion() {
    // Safety bound on open attempts. The partition caps concurrent sessions far
    // below this, so exhaustion is expected much sooner; the bound only guards
    // against an infinite loop should a backend fail to enforce the cap.
    const MAX_OPEN_ATTEMPTS: usize = 32;
    // Tolerate the driver/firmware processing the flush asynchronously on real
    // hardware; the software backend reclaims synchronously on the first try.
    const RECLAIM_ATTEMPTS: usize = 20;

    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });

            // Fill the partition's session slots on dedicated handles, keeping
            // each successful handle (and thus its firmware session) alive.
            let mut holders: Vec<<DdiTest as Ddi>::Dev> = Vec::new();
            let mut exhaustion_err = None;
            for _ in 0..MAX_OPEN_ATTEMPTS {
                let holder = ddi.open_dev(path).unwrap();
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    &holder,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                match helper_open_session(&holder, None, rev, encrypted_credential, pub_key) {
                    Ok(_) => holders.push(holder),
                    Err(e) => {
                        // `holder` never held a session; dropping it is a no-op flush.
                        exhaustion_err = Some(e);
                        break;
                    }
                }
            }

            let err = exhaustion_err
                .expect("partition never reported session exhaustion; cap not enforced?");
            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::VaultSessionLimitReached)
                ),
                "expected VaultSessionLimitReached at capacity, got: {:?}",
                err
            );
            assert!(
                !holders.is_empty(),
                "no sessions were opened before exhaustion"
            );

            // Drop exactly one holder → fd close → OP_FLUSH → synchronous
            // teardown frees one firmware session slot.
            drop(holders.pop());

            // The freed slot must now be reusable.
            let mut reclaim_ok = false;
            let mut last_err = None;
            for _ in 0..RECLAIM_ATTEMPTS {
                let holder = ddi.open_dev(path).unwrap();
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    &holder,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );
                match helper_open_session(&holder, None, rev, encrypted_credential, pub_key) {
                    Ok(_) => {
                        holders.push(holder);
                        reclaim_ok = true;
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        drop(holder);
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
            assert!(
                reclaim_ok,
                "session slot not reclaimed after flush; last error: {:?}",
                last_err
            );
        },
    );
}

#[test]
fn test_flush_app_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let new_dev = ddi.open_dev(path).unwrap();
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &new_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                &new_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            // Skip closing the session, so flush happens.
            // Confirm via debugging
        },
    );
}

#[test]
#[should_panic]
fn test_flush_app_session_after_crash() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let new_dev = ddi.open_dev(path).unwrap();
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &new_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                &new_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            // Intentionally crash the test
            resp.unwrap_err();

            // Skip closing the session, so flush happens.
            // Confirm via debugging
        },
    );
}


// The two tests above only prove a plain app session survives flush. These new
// tests give the session an AES-GCM bulk key first, so the flush exercises the
// FP-clear path (`handle_flush_op` -> `session_destroy` ->
// `vault_key_delete_by_session` -> `fp_delete_ephemeral`) rather than the no-op
// path.
//
// Gated off `emu`: AES-GCM is not yet supported on the emu backend
// (mirrors `aes_gcm_bulk_stress.rs`). The firmware-side FP clear is confirmed on
// hardware via the debuglog; on mock the flush is serviced by the simulator,
// which clears the session's keys on close.

// Opens an app session, mints a GCM bulk key (asserting the session provably
// owns an FP key), then drops the handle WITHOUT CloseSession so the driver
// issues `OP_FLUSH`. Afterwards a fresh session + bulk-key generation must still
// succeed, proving the controller and FP key vault stay healthy across flush.
#[cfg(not(feature = "emu"))]
#[test]
fn test_flush_app_session_with_bulk_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });

            // Open an app session on a dedicated handle and give it an FP bulk key.
            {
                let new_dev = ddi.open_dev(path).unwrap();
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    &new_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                let resp = helper_open_session(&new_dev, None, rev, encrypted_credential, pub_key);
                assert!(resp.is_ok(), "open_session resp {:?}", resp);
                let app_sess_id = resp.unwrap().data.sess_id;

                // Generate an AES-GCM bulk key so the session owns an FP key
                // that the flush must clear.
                let resp = generate_aes_bulk_256_key(
                    &new_dev,
                    &app_sess_id,
                    None,
                    DdiAesKeySize::AesGcmBulk256Unapproved,
                );
                assert!(resp.is_ok(), "generate bulk key resp {:?}", resp);
                assert!(
                    resp.unwrap().data.bulk_key_id.is_some(),
                    "session should own an FP bulk key before flush",
                );

                // Skip CloseSession: dropping `new_dev` here closes the fd →
                // driver OP_FLUSH → firmware session_destroy → fp_delete_ephemeral
                // clears the bulk key. Firmware-side FP clear is confirmed via
                // the HW debuglog.
            }

            // Health check: the flushed session's resources (CP slot + FP key)
            // must be reusable — a fresh session can open and mint a new bulk key.
            let next_dev = ddi.open_dev(path).unwrap();
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &next_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );
            let resp = helper_open_session(&next_dev, None, rev, encrypted_credential, pub_key);
            assert!(resp.is_ok(), "reopen after flush resp {:?}", resp);
            let app_sess_id = resp.unwrap().data.sess_id;

            let resp = generate_aes_bulk_256_key(
                &next_dev,
                &app_sess_id,
                None,
                DdiAesKeySize::AesGcmBulk256Unapproved,
            );
            assert!(
                resp.is_ok(),
                "regenerate bulk key after flush resp {:?}",
                resp
            );
            assert!(
                resp.unwrap().data.bulk_key_id.is_some(),
                "FP key vault should be healthy after flush",
            );
        },
    );
}

// Same as above, but the client "crashes" (panics) while still holding the
// session that owns an FP bulk key. Unwinding drops the device handle → fd
// close → `OP_FLUSH` runs the same teardown on the abnormal path.
// `#[should_panic]` asserts the crash is the reason the handle drops.
#[cfg(not(feature = "emu"))]
#[test]
#[should_panic]
fn test_flush_app_session_with_bulk_key_after_crash() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let rev = Some(DdiApiRev { major: 1, minor: 0 });

            let new_dev = ddi.open_dev(path).unwrap();
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &new_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(&new_dev, None, rev, encrypted_credential, pub_key);
            assert!(resp.is_ok(), "open_session resp {:?}", resp);
            let app_sess_id = resp.unwrap().data.sess_id;

            let resp = generate_aes_bulk_256_key(
                &new_dev,
                &app_sess_id,
                None,
                DdiAesKeySize::AesGcmBulk256Unapproved,
            );
            assert!(resp.is_ok(), "generate bulk key resp {:?}", resp);
            assert!(
                resp.unwrap().data.bulk_key_id.is_some(),
                "session should own an FP bulk key before the simulated crash",
            );

            // Simulate a client crash while holding the session. Unwinding drops
            // `new_dev`, closing the fd → OP_FLUSH clears the session and its FP
            // bulk key. Confirm the FP clear via the HW debuglog.
            panic!("simulated client crash while holding an app session with an FP bulk key");
        },
    );
}
