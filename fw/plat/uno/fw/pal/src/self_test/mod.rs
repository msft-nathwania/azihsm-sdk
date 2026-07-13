// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic Algorithm Self-Tests (CAST) for the Uno HSM core.
//!
//! Implements the FIPS pre-operational and (future) periodic self-tests for
//! the HSM-core cryptographic algorithms. Each test runs a fixed known-answer
//! vector through the PAL crypto path and compares the result against the
//! expected output.
//!
//! # Memory
//!
//! All tests run on a dedicated, reserved IO slot
//! ([`crate::alloc::SELF_TEST_IO_INDEX`]) obtained via
//! [`UnoHsmIo::self_test`]. KAT operands are bump-allocated from that
//! slot's `SRAM_IO_BUF`, so the self-tests never contend with host IO or
//! partition-provisioning crypto (which uses the separate admin slot).
//!
//! # Status
//!
//! AES-256-CBC, HKDF, KBKDF, per-engine RSA-2048 mod-exp (standard and CRT),
//! ECDH-P384, ECDSA-P384, and the RNG/DRBG FW-mode KAT are implemented. The same
//! HSM-executed tests also run continuously at runtime via
//! [`UnoHsmPal::run_self_test_periodic`] (one KAT per period, round-robin),
//! excluding the state-destructive RNG KAT. Further tests are appended to both
//! [`run_pre_op`] and [`UnoHsmPal::run_self_test_periodic`] as they are added —
//! each is a direct call, with per-PKA-engine tests wrapped in a
//! `for engine in 0..PKA_ENGINES` loop.

mod aes_cbc;
mod kdf;
mod pka;
mod vectors;

use core::ops::AsyncFn;

use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_trace::tracing::error;
use azihsm_fw_uno_trace::tracing::info;
use embassy_time::Duration;
use embassy_time::Timer;

use crate::UnoHsmIo;
use crate::UnoHsmPal;

/// Runs the full pre-operational self-test suite.
///
/// Returns `Err` on the first failing test, leaving it to the caller (the boot
/// gate) to withhold the transition to the running state on failure. Mirrors
/// the reference firmware's `preops_cast` — positive known-answer tests only.
pub(crate) async fn run_pre_op(pal: &UnoHsmPal, io: &UnoHsmIo) -> HsmResult<()> {
    aes_cbc::run_aes_cbc(pal, io).await?;
    kdf::run_hkdf(pal, io).await?;
    kdf::run_kbkdf(pal, io).await?;
    for engine in 0..pka::PKA_ENGINES {
        pka::run_rsa_mod_exp_on_engine(pal, io, engine).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        pka::run_rsa_mod_exp_crt_on_engine(pal, io, engine).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        pka::run_ecdh_on_engine(pal, io, engine).await?;
    }
    for engine in 0..pka::PKA_ENGINES {
        pka::run_ecdsa_on_engine(pal, io, engine).await?;
    }
    // The DRBG FW-mode KAT is state-destructive; it saves and restores the
    // production DRBG registers internally. Run it last (matching the reference
    // `preops_cast` ordering) and before any live RNG consumer exists.
    pal.rng.self_test()?;
    Ok(())
}

/// Periodic runtime self-test cadence — one KAT per elapsed period.
///
/// Matches the reference firmware's `SELF_TEST_PERIODICITY_IN_MS`: the admin
/// CAST FSM schedules one HSM self-test every 60 seconds. In the uno refactor
/// the HSM core has no admin/simplex self-test transport, so it paces itself.
const PERIOD: Duration = Duration::from_millis(60_000);

impl UnoHsmPal {
    /// Runs the periodic runtime self-test loop forever (one KAT per [`PERIOD`]).
    ///
    /// Walks the HSM-executed CAST suite round-robin — one test per tick — and
    /// repeats the full pass indefinitely, mirroring [`run_pre_op`] minus the
    /// state-destructive RNG/DRBG KAT. RNG is excluded from the runtime path (it
    /// is pre-op only) until an IO gate exists to fence live RNG consumers; the
    /// reference likewise never schedules the DRBG KAT at runtime.
    ///
    /// Spawn this as a dedicated task once boot completes; it must run
    /// concurrently with the IPC poll loop (which emits the liveness heartbeat)
    /// and the NVIC run loop (which services crypto completion), so the awaited
    /// crypto futures make progress and the heartbeat continues while
    /// self-tests pass.
    ///
    /// # Failure
    ///
    /// On any failing test this fail-stops (see [`fail_stop`]): it spins,
    /// starving the cooperative executor so the liveness heartbeat ceases; the
    /// SP then observes the hung core and resets the module. FIPS requires a
    /// failed runtime self-test to halt the module's cryptographic operation.
    pub async fn run_self_test_periodic(&self) -> ! {
        loop {
            tick(self, aes_cbc::run_aes_cbc).await;
            tick(self, kdf::run_hkdf).await;
            tick(self, kdf::run_kbkdf).await;
            for engine in 0..pka::PKA_ENGINES {
                tick_engine(self, pka::run_rsa_mod_exp_on_engine, engine).await;
            }
            for engine in 0..pka::PKA_ENGINES {
                tick_engine(self, pka::run_rsa_mod_exp_crt_on_engine, engine).await;
            }
            for engine in 0..pka::PKA_ENGINES {
                tick_engine(self, pka::run_ecdh_on_engine, engine).await;
            }
            for engine in 0..pka::PKA_ENGINES {
                tick_engine(self, pka::run_ecdsa_on_engine, engine).await;
            }
            // RNG/DRBG is intentionally omitted (state-destructive; pre-op only).
            // TODO: Add RNG test once the IO gate exists to fence live RNG consumers.
        }
    }
}

/// Waits one [`PERIOD`], runs one whole-engine self-test, and fail-stops on error.
async fn tick<F>(pal: &UnoHsmPal, test: F)
where
    F: for<'a> AsyncFn(&'a UnoHsmPal, &'a UnoHsmIo) -> HsmResult<()>,
{
    Timer::after(PERIOD).await;
    let io = UnoHsmIo::self_test();
    if let Err(_e) = test(pal, &io).await {
        error!("selftest", _e, "periodic self-test FAILED");
        loop {
            core::hint::spin_loop();
        }
    }
}

/// Waits one [`PERIOD`], runs one per-engine self-test, and fail-stops on error.
async fn tick_engine<F>(pal: &UnoHsmPal, test: F, engine: u8)
where
    F: for<'a> AsyncFn(&'a UnoHsmPal, &'a UnoHsmIo, u8) -> HsmResult<()>,
{
    Timer::after(PERIOD).await;
    let io = UnoHsmIo::self_test();
    if let Err(_e) = test(pal, &io, engine).await {
        error!("selftest", _e, "periodic self-test FAILED");
        loop {
            core::hint::spin_loop();
        }
    }
}
