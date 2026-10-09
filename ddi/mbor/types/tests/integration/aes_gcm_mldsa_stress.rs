// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware-only FP GCM stress concurrent with Admin ML-DSA-87.
//! Run alone with `--features mldsa-87 -- --test-threads=1 --nocapture`.

#![cfg(all(feature = "mldsa-87", not(any(feature = "emu", feature = "mock"))))]

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_types::TborMlDsaSignReq;
use azihsm_ddi_tbor_types::TborMlDsaVerifyReq;
use azihsm_ddi_tbor_types::ML_DSA_87_SIGNATURE_LEN;
use azihsm_ddi_tbor_types::ML_DSA_87_SIGNING_KEY_LEN;
use ml_dsa::signature::Keypair;
use ml_dsa::signature::Verifier;
use ml_dsa::MlDsa87;
use ml_dsa::Signature;
use ml_dsa::SigningKey;
use test_with_tracing::test;

use super::common::*;

const RUN_TIME: Duration = Duration::from_secs(60);
const SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_GCM_WORKERS: usize = 4;

#[derive(Debug)]
struct WorkerStats {
    cycles: usize,
    overlapping_cycles: usize,
    started: Instant,
    finished: Instant,
}

#[test]
fn test_aes_gcm_with_mldsa_concurrent_stress() {
    let ddi = DdiTest::default();
    let devices = ddi.dev_info_list();
    assert!(!devices.is_empty(), "No hardware devices found");

    for info in devices {
        // Hold the TBOR fixture lock and erase exactly once, before any worker.
        let primary = TestCtx::new_primary_with_path(&info.path);
        let mut setup_dev = ddi.open_dev(&info.path).unwrap();
        helper_common_establish_credential_no_unwrap(&mut setup_dev, TEST_CRED_ID, TEST_CRED_PIN)
            .unwrap();

        let gcm_workers = MAX_GCM_WORKERS
            .min(MAX_SESSIONS - 1)
            .min(get_device_info(&ddi, &info.path).tables as usize * 7);
        assert!(
            gcm_workers >= 2,
            "Need capacity for two GCM workers and ML-DSA"
        );
        let gcm_progress = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        let mut starts = Vec::new();
        let mut setup_errors = Vec::new();

        // Setup is serialized; channels release workers only after every session/key is ready.
        // Unlike a barrier, disconnected channels release waiters if another worker panics.
        for worker in 0..=gcm_workers {
            let path = info.path.clone();
            let progress = Arc::clone(&gcm_progress);
            let (ready_tx, ready_rx) = mpsc::channel();
            let (start_tx, start_rx) = mpsc::channel();
            workers.push(thread::spawn(move || {
                if worker == 0 {
                    run_mldsa(&path, progress, ready_tx, start_rx)
                } else {
                    run_gcm(&path, worker, progress, ready_tx, start_rx)
                }
            }));
            starts.push(start_tx);
            if let Err(error) = ready_rx.recv_timeout(SETUP_TIMEOUT) {
                setup_errors.push(format!("worker {worker} setup: {error}"));
                break;
            }
        }

        let started = Instant::now();
        if setup_errors.is_empty() {
            for (worker, start) in starts.iter().enumerate() {
                if let Err(error) = start.send(started) {
                    setup_errors.push(format!("worker {worker} start: {error}"));
                }
            }
        }
        drop(starts);
        // Join every worker, even after a failure, before erasing shared state.
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
        common_cleanup(&mut setup_dev, &ddi, &info.path, None);
        drop(primary);

        assert!(setup_errors.is_empty(), "{setup_errors:?}");
        let stats: Vec<_> = results
            .into_iter()
            .enumerate()
            .map(|(worker, result)| {
                assert!(result.is_ok(), "worker {worker} panicked: {result:?}");
                result.unwrap()
            })
            .collect();
        assert_eq!(stats.len(), gcm_workers + 1);
        for (worker, stats) in stats.iter().enumerate() {
            println!(
                "worker={worker} start={:?} end={:?} verified_cycles={} overlapping_cycles={}",
                stats.started.duration_since(started),
                stats.finished.duration_since(started),
                stats.cycles,
                stats.overlapping_cycles,
            );
            assert!(stats.cycles > 0, "worker {worker} made no progress");
            assert!(
                stats.started < started + RUN_TIME,
                "worker {worker} started too late"
            );
        }
        assert!(
            stats[0].overlapping_cycles > 0,
            "No verified GCM cycle completed during an ML-DSA sign/verify cycle",
        );
        for gcm in &stats[1..] {
            assert!(
                gcm.started < stats[0].finished && stats[0].started < gcm.finished,
                "GCM and ML-DSA worker intervals did not overlap",
            );
        }
    }
}

fn run_gcm(
    path: &str,
    worker: usize,
    progress: Arc<AtomicUsize>,
    ready: Sender<()>,
    start: Receiver<Instant>,
) -> WorkerStats {
    let dev = DdiTest::default().open_dev(path).unwrap();
    let (credential, public_key) =
        encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED);
    let session = helper_open_session(
        &dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        credential,
        public_key,
    )
    .unwrap();
    let key = generate_aes_bulk_256_key(
        &dev,
        &session.data.sess_id,
        None,
        DdiAesKeySize::AesGcmBulk256Unapproved,
    )
    .unwrap();
    let key_id = u32::from(key.data.bulk_key_id.unwrap());
    let data = vec![worker as u8; 16384];
    ready.send(()).unwrap();
    let deadline = start.recv().unwrap() + RUN_TIME;
    let started = Instant::now();
    let mut cycles = 0_u64;
    while Instant::now() < deadline {
        let mut iv = [0_u8; 12];
        iv[..8].copy_from_slice(&cycles.to_le_bytes());
        let mut params = DdiAesGcmParams {
            key_id,
            iv,
            aad: Some(vec![worker as u8; 32]),
            tag: None,
            session_id: session.data.sess_id,
            short_app_id: session.data.short_app_id,
        };
        let encrypted = dev
            .exec_op_fp_gcm(DdiAesOp::Encrypt, params.clone(), data.clone())
            .unwrap();
        assert_eq!(encrypted.data.len(), data.len());
        assert_ne!(encrypted.data, data);
        assert!(encrypted.tag.is_some(), "GCM encryption returned no tag");
        params.tag = encrypted.tag;
        let decrypted = dev
            .exec_op_fp_gcm(DdiAesOp::Decrypt, params, encrypted.data)
            .unwrap();
        assert_eq!(decrypted.data, data);
        progress.fetch_add(1, Ordering::SeqCst);
        cycles += 1;
    }
    let finished = Instant::now();
    helper_close_session(
        &dev,
        Some(session.data.sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
    )
    .unwrap();
    WorkerStats {
        cycles: usize::try_from(cycles).unwrap(),
        overlapping_cycles: 0,
        started,
        finished,
    }
}

fn run_mldsa(
    path: &str,
    progress: Arc<AtomicUsize>,
    ready: Sender<()>,
    start: Receiver<Instant>,
) -> WorkerStats {
    let ctx = TestCtx::new_with_path(path);
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let key = SigningKey::<MlDsa87>::from_seed(&[0x42_u8; 32].into());
    #[allow(deprecated)]
    let signing_key = key.expanded_key().to_expanded().to_vec();
    let verifying_key = key.verifying_key();
    assert_eq!(signing_key.len(), ML_DSA_87_SIGNING_KEY_LEN);
    ready.send(()).unwrap();
    let deadline = start.recv().unwrap() + RUN_TIME;
    let started = Instant::now();
    let mut cycles = 0_usize;
    let mut overlapping_cycles = 0;
    while Instant::now() < deadline {
        let msg = format!("Admin ML-DSA concurrent with FP GCM: {cycles}").into_bytes();
        let before_sign = progress.load(Ordering::SeqCst);
        let response = ctx
            .tbor_oob(
                &TborMlDsaSignReq {
                    session_id: session.session_id,
                    signing_key_len: ML_DSA_87_SIGNING_KEY_LEN as u32,
                    msg: msg.clone(),
                },
                &[&signing_key],
            )
            .unwrap();
        let sign_overlapped = progress.load(Ordering::SeqCst) > before_sign;
        assert_eq!(response.signature.len(), ML_DSA_87_SIGNATURE_LEN);
        let signature =
            Signature::<MlDsa87>::decode(response.signature.as_slice().try_into().unwrap())
                .unwrap();
        verifying_key.verify(&msg, &signature).unwrap();
        let before_verify = progress.load(Ordering::SeqCst);
        ctx.tbor_oob(
            &TborMlDsaVerifyReq {
                session_id: session.session_id,
                verifying_key: verifying_key.encode().to_vec(),
                signature_len: ML_DSA_87_SIGNATURE_LEN as u32,
                msg,
            },
            &[&response.signature],
        )
        .unwrap();
        overlapping_cycles +=
            usize::from(sign_overlapped || progress.load(Ordering::SeqCst) > before_verify);
        cycles += 1;
    }
    let finished = Instant::now();
    ctx.session_close(session.session_id).unwrap();
    WorkerStats {
        cycles,
        overlapping_cycles,
        started,
        finished,
    }
}
