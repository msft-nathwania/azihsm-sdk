// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware-only FP GCM stress concurrent with Admin ML-DSA-87.

#![cfg(all(feature = "mldsa-87", not(any(feature = "emu", feature = "mock"))))]

use test_with_tracing::test;

use super::crypto_mldsa_stress::run_concurrent_stress;
use super::crypto_mldsa_stress::Workload;

#[test]
fn test_aes_gcm_with_mldsa_concurrent_stress() {
    run_concurrent_stress(Workload::Gcm);
}
