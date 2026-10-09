// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA-87 offload from CP1 to CP0 Admin.
//!
//! CP1 cannot run ML-DSA itself — key generation does not fit in this part's
//! RAM at any parameter set. Admin runs wolfCrypt instead, and this
//! module is the client side of that arrangement: it marshals a request into
//! the shared payload buffer, posts a descriptor, and reads the result back.
//!
//! # How a request travels
//!
//! The IPC slot is 64 bytes, so it carries only a descriptor — operation,
//! parameter set, payload length. The data itself lives at a fixed address in
//! the GSRAM reservation declared in `io_gsram`, shared by both cores.
//!
//! One buffer serves both directions: Admin writes its answer over the request.
//! That is safe because wolfCrypt imports a key into its own structure before
//! using it, and it makes the buffer `max(in, out)` rather than `in + out`.
//!
//! # Serialization and POC limitations
//!
//! A PAL mutex covers payload writes, IPC await, response reads and scrubbing.
//! The Admin POC excludes concurrent FLR/PERST/IDFU; no reset gating is implemented.
//! If an IPC future is canceled after submission, the payload is left untouched
//! and further ML-DSA requests fail until reboot. Scrubbing it while the remote
//! core is still using it would race the operation. Secrets can therefore remain
//! in this lab-only, PCIe-accessible window until reset.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;

use crate::UnoHsmPal;
use crate::ipc::IpcMessageOpCode;
use crate::pal::IpcChannel;

/// Shared payload buffer, as the CP addresses it.
const PAYLOAD: *mut u8 = (azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE
    + azihsm_fw_uno_reg_soc::io_gsram::MLDSA_PAYLOAD_OFFSET) as *mut u8;

/// Payload buffer size. The worst case is an ML-DSA-87 verify request at
/// 12 + 2592 + 4627 + msg bytes.
const PAYLOAD_LEN: usize = azihsm_fw_uno_reg_soc::io_gsram::MLDSA_PAYLOAD_SIZE as usize;

/// Descriptor opcodes, matching Admin's `mcr-ipc-message` definitions.
const OP_KEYGEN: u32 = IpcMessageOpCode::MlDsaKeyGen as u32;
const OP_SIGN: u32 = IpcMessageOpCode::MlDsaSign as u32;
const OP_VERIFY: u32 = IpcMessageOpCode::MlDsaVerify as u32;

/// `MlDsaParamSet_t`. Values are wolfCrypt's `level` argument.
const PARAM_87: u32 = 5;

/// FIPS 204 seed length.
pub const ML_DSA_SEED_LEN: usize = 32;

/// ML-DSA detail codes from Admin's C shim.
const STS_OK: u8 = 0;
const STS_BAD_REQUEST: u8 = 1;
const STS_BAD_KEY: u8 = 2;
const STS_NO_MEMORY: u8 = 3;

/// Word offsets within the 16-word reply.
///
/// The slot is `msgOp:7|resp:1`, `tag`, `sts`, `length`, then `data[]`, so the
/// status sits in byte 2 of word 0 and `MlDsaIpcResp_t` begins at word 1.
const RESP_LEN_WORD: usize = 1;
const RESP_VERIFY_WORD: usize = 2;

struct PayloadScrub<'a>(&'a core::cell::Cell<bool>);

impl Drop for PayloadScrub<'_> {
    fn drop(&mut self) {
        if self.0.get() {
            // The remote core still owns the payload. Do not wipe or reuse it.
            azihsm_fw_uno_trace::tracing::error!("mldsa", "canceled IPC; disabled until reboot");
            return;
        }
        for i in 0..PAYLOAD_LEN {
            // SAFETY: the caller holds the PAL's ML-DSA lock throughout this scrub.
            unsafe { PAYLOAD.add(i).write_volatile(0) };
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl UnoHsmPal {
    /// Writes one byte into the shared payload buffer.
    ///
    /// # Safety
    ///
    /// `off` must be within [`PAYLOAD_LEN`]; every caller below bounds-checks
    /// its whole range before starting.
    #[inline]
    fn payload_wr(off: usize, v: u8) {
        // SAFETY: bounds checked by the caller; the window is device memory
        // that is mapped at firmware boot.
        unsafe { PAYLOAD.add(off).write_volatile(v) }
    }

    /// Reads one byte from the shared payload buffer.
    #[inline]
    fn payload_rd(off: usize) -> u8 {
        // SAFETY: as `payload_wr`.
        unsafe { PAYLOAD.add(off).read_volatile() }
    }

    fn payload_wr32(off: usize, v: u32) {
        for (i, b) in v.to_le_bytes().iter().enumerate() {
            Self::payload_wr(off + i, *b);
        }
    }

    fn payload_wr_bytes(off: usize, src: &[u8]) {
        for (i, b) in src.iter().enumerate() {
            Self::payload_wr(off + i, *b);
        }
    }

    fn payload_rd_bytes(off: usize, dst: &mut [u8]) {
        for (i, b) in dst.iter_mut().enumerate() {
            *b = Self::payload_rd(off + i);
        }
    }

    /// Posts a descriptor and waits for Admin.
    ///
    /// Returns `(resp_len, verify_result)`. An ML-DSA-87 signature takes
    /// hundreds of milliseconds on Admin in the current POC, so this
    /// await is long by the standards of everything else on this core — but
    /// it is an await, not a spin, so the executor keeps running.
    async fn admin_request(&self, op: u32, payload_len: usize) -> HsmResult<(u32, u32)> {
        let msg = {
            let tag = self.mldsa_seq.get().wrapping_add(1);
            self.mldsa_seq.set(tag);
            [
                (8 << 24) | ((tag as u32) << 8) | op,
                PARAM_87,
                payload_len as u32,
            ]
        };
        let mut reply = [0u32; 16];

        // Publish the payload before the descriptor; CP caches are disabled.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        let channel = IpcChannel::AdminMlDsa;
        self.mldsa_in_flight.set(true);
        self.ipc.send(channel as u8, &msg, &mut reply).await;
        self.mldsa_in_flight.set(false);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        let sts = {
            let header_status = (reply[0] >> 16) & 0xf;
            if reply[0] & 0xffff != ((msg[0] & 0xffff) | 0x80)
                || reply[0] >> 24 != 12
                || reply[RESP_LEN_WORD] as usize > PAYLOAD_LEN
            {
                return Err(HsmError::MlDsaSignFailed);
            }
            if header_status == 0 && reply[3] != 0 {
                return Err(HsmError::MlDsaSignFailed);
            }
            if header_status != 0 {
                match reply[3] {
                    1 => STS_BAD_REQUEST,
                    2 => STS_BAD_KEY,
                    3 => STS_NO_MEMORY,
                    _ => return Err(HsmError::MlDsaSignFailed),
                }
            } else {
                STS_OK
            }
        };

        // Preserve Admin's error distinction. Collapsing everything to
        // "sign failed" told a caller with a structurally invalid key that
        // the device had broken, rather than that its key was bad.
        if sts != STS_OK {
            return Err(match sts {
                STS_BAD_KEY => HsmError::MlDsaInvalidSigningKey,
                STS_BAD_REQUEST => HsmError::InvalidArg,
                STS_NO_MEMORY => HsmError::DmaBufferAllocFailure,
                _ => HsmError::MlDsaSignFailed,
            });
        }

        Ok((reply[RESP_LEN_WORD], reply[RESP_VERIFY_WORD]))
    }

    /// Generates an ML-DSA-87 keypair on Admin from `seed`.
    ///
    /// Writes the encoded verifying key into `vk` and the encoded signing key
    /// into `sk`. Either may be empty if the caller does not want that half —
    /// the DDI returns the seed rather than the signing key, so `keygen` there
    /// asks only for the verifying key.
    async fn admin_keygen(
        &self,
        seed: &[u8; ML_DSA_SEED_LEN],
        vk: &mut [u8],
        sk: &mut [u8],
    ) -> HsmResult<()> {
        let _lock = self.mldsa_lock.lock().await;
        if self.mldsa_in_flight.get() {
            azihsm_fw_uno_trace::tracing::error!("mldsa", "service disabled; reboot required");
            return Err(HsmError::MlDsaSignFailed);
        }
        let _scrub = PayloadScrub(&self.mldsa_in_flight);
        // `MlDsaKeyGenPayload_t`: two lengths then `data[]`.
        const HDR: usize = 8;

        Self::payload_wr32(0, 0);
        Self::payload_wr32(4, 0);
        Self::payload_wr_bytes(HDR, seed);

        let (resp_len, _) = self.admin_request(OP_KEYGEN, HDR + ML_DSA_SEED_LEN).await?;

        // Admin reports what it wrote; the header says how it is divided.
        let vk_len = u32::from_le_bytes([
            Self::payload_rd(0),
            Self::payload_rd(1),
            Self::payload_rd(2),
            Self::payload_rd(3),
        ]) as usize;
        let sk_len = u32::from_le_bytes([
            Self::payload_rd(4),
            Self::payload_rd(5),
            Self::payload_rd(6),
            Self::payload_rd(7),
        ]) as usize;

        // Cross-check the two against each other before trusting either as a
        // length to copy by.
        if resp_len as usize != HDR + vk_len + sk_len
            || HDR + vk_len + sk_len > PAYLOAD_LEN
            || (!vk.is_empty() && vk.len() != vk_len)
            || (!sk.is_empty() && sk.len() != sk_len)
        {
            return Err(HsmError::MlDsaKeyGenFailed);
        }

        if !vk.is_empty() {
            Self::payload_rd_bytes(HDR, vk);
        }
        if !sk.is_empty() {
            Self::payload_rd_bytes(HDR + vk_len, sk);
        }

        Ok(())
    }

    /// Signs `msg` on Admin under the encoded signing key `sk`.
    ///
    /// Deterministic: Admin signs with `rnd = 0^32`, so this returns the same
    /// signature RustCrypto computes for the same key and message.
    async fn admin_sign(&self, sk: &[u8], msg: &[u8], sig: &mut [u8]) -> HsmResult<()> {
        let _lock = self.mldsa_lock.lock().await;
        if self.mldsa_in_flight.get() {
            azihsm_fw_uno_trace::tracing::error!("mldsa", "service disabled; reboot required");
            return Err(HsmError::MlDsaSignFailed);
        }
        let _scrub = PayloadScrub(&self.mldsa_in_flight);
        // `MlDsaSignPayload_t`: key length, message length, then `data[]`.
        const HDR: usize = 8;
        let payload_len = HDR + sk.len() + msg.len();

        // The response overwrites the request, and Admin stages the signature
        // past the end of it, so both must fit.
        if payload_len > PAYLOAD_LEN || payload_len + sig.len() > PAYLOAD_LEN {
            return Err(HsmError::InvalidArg);
        }

        Self::payload_wr32(0, sk.len() as u32);
        Self::payload_wr32(4, msg.len() as u32);
        Self::payload_wr_bytes(HDR, sk);
        Self::payload_wr_bytes(HDR + sk.len(), msg);

        let (resp_len, _) = self.admin_request(OP_SIGN, payload_len).await?;

        if resp_len as usize != sig.len() {
            return Err(HsmError::MlDsaSignFailed);
        }

        // Admin moves the signature down over the request before replying.
        Self::payload_rd_bytes(0, sig);
        Ok(())
    }

    /// Verifies `sig` over `msg` under the encoded verifying key `vk`.
    ///
    /// A signature that does not verify is a completed request with a
    /// negative answer, not a failed one, so this returns `Ok(false)` rather
    /// than an error — the caller decides which wire status that becomes.
    async fn admin_verify(&self, vk: &[u8], sig: &[u8], msg: &[u8]) -> HsmResult<bool> {
        let _lock = self.mldsa_lock.lock().await;
        if self.mldsa_in_flight.get() {
            azihsm_fw_uno_trace::tracing::error!("mldsa", "service disabled; reboot required");
            return Err(HsmError::MlDsaSignFailed);
        }
        let _scrub = PayloadScrub(&self.mldsa_in_flight);
        // `MlDsaVerifyPayload_t`: three lengths then `data[]`.
        const HDR: usize = 12;
        let payload_len = HDR + vk.len() + sig.len() + msg.len();

        if payload_len > PAYLOAD_LEN {
            return Err(HsmError::InvalidArg);
        }

        Self::payload_wr32(0, vk.len() as u32);
        Self::payload_wr32(4, sig.len() as u32);
        Self::payload_wr32(8, msg.len() as u32);
        Self::payload_wr_bytes(HDR, vk);
        Self::payload_wr_bytes(HDR + vk.len(), sig);
        Self::payload_wr_bytes(HDR + vk.len() + sig.len(), msg);

        let (_, verified) = self.admin_request(OP_VERIFY, payload_len).await?;
        Ok(verified == 1)
    }
}

impl azihsm_fw_hsm_pal_traits::HsmMlDsa for UnoHsmPal {
    /// Runs on Admin. `io` is unused: the offload addresses shared GSRAM
    /// directly rather than going through this core's DMA.
    async fn ml_dsa_keygen(
        &self,
        _io: &impl azihsm_fw_hsm_pal_traits::HsmIo,
        seed: &[u8; 32],
        vk: &mut [u8],
        sk: &mut [u8],
    ) -> HsmResult<()> {
        self.admin_keygen(seed, vk, sk).await
    }

    async fn ml_dsa_sign(
        &self,
        _io: &impl azihsm_fw_hsm_pal_traits::HsmIo,
        sk: &[u8],
        msg: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()> {
        self.admin_sign(sk, msg, sig).await
    }

    async fn ml_dsa_verify(
        &self,
        _io: &impl azihsm_fw_hsm_pal_traits::HsmIo,
        vk: &[u8],
        sig: &[u8],
        msg: &[u8],
    ) -> HsmResult<bool> {
        self.admin_verify(vk, sig, msg).await
    }
}
