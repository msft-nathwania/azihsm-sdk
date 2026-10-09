// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Two ML-DSA-87 callers and two ECC P-256 signing workers on hardware.

#![cfg(all(feature = "mldsa-87", not(any(feature = "emu", feature = "mock"))))]

use test_with_tracing::test;

use super::crypto_mldsa_stress::run_concurrent_stress;
use super::crypto_mldsa_stress::Workload;

#[test]
fn test_ecc_with_mldsa_concurrent_stress() {
    run_concurrent_stress(Workload::Ecc);
}
