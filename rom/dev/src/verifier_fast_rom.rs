/*++

Licensed under the Apache-2.0 license.

File Name:

    verifier_fast_rom.rs

Abstract:

    Image Verification support routines
    Mock ECC and LMS functionality to speed boot for verificaiton environments

--*/

#[cfg(not(feature = "fast-rom"))]
compile_error!("This file should NEVER be included except for the fast-rom feature");

use caliptra_drivers::*;
use caliptra_image_types::*;
use caliptra_image_verify::ImageVerificationEnv;
use core::ops::Range;

use crate::rom_env::RomEnv;

/// ROM Verification Environemnt
pub(crate) struct RomImageVerificationEnv<'a> {
    #[allow(dead_code)]
    pub(crate) sha256: &'a mut Sha256,
    pub(crate) sha384: &'a mut Sha384,
    pub(crate) sha384_acc: &'a mut Sha384Acc,
    pub(crate) soc_ifc: &'a mut SocIfc,
    #[allow(dead_code)]
    pub(crate) ecc384: &'a mut Ecc384,
    pub(crate) data_vault: &'a mut DataVault,
    pub(crate) pcr_bank: &'a mut PcrBank,
}

impl<'a> ImageVerificationEnv for &mut RomImageVerificationEnv<'a> {
    /// Calculate Digest using SHA-384 Accelerator
    fn sha384_digest(&mut self, offset: u32, len: u32) -> CaliptraResult<ImageDigest> {
        loop {
            if let Some(mut txn) = self.sha384_acc.try_start_operation() {
                let mut digest = Array4x12::default();
                txn.digest(len, offset, false, &mut digest)?;
                return Ok(digest.0);
            }
        }
    }

    /// ECC-384 Verification routine
    fn ecc384_verify(
        &mut self,
        _digest: &ImageDigest,
        _pub_key: &ImageEccPubKey,
        _sig: &ImageEccSignature,
    ) -> CaliptraResult<Ecc384Result> {
        // Mock verify, just always return success
        Ok(Ecc384Result::Success)
    }

    fn lms_verify(
        &mut self,
        _digest: &ImageDigest,
        _pub_key: &ImageLmsPublicKey,
        _sig: &ImageLmsSignature,
    ) -> CaliptraResult<LmsResult> {
        // Mock verify, just always return success
        Ok(LmsResult::Success)
    }

    /// Retrieve Vendor Public Key Digest
    fn vendor_pub_key_digest(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().vendor_pub_key_hash().into()
    }

    /// Retrieve Vendor ECC Public Key Revocation Bitmask
    fn vendor_ecc_pub_key_revocation(&self) -> VendorPubKeyRevocation {
        self.soc_ifc.fuse_bank().vendor_ecc_pub_key_revocation()
    }

    /// Retrieve Vendor LMS Public Key Revocation Bitmask
    fn vendor_lms_pub_key_revocation(&self) -> u32 {
        self.soc_ifc.fuse_bank().vendor_lms_pub_key_revocation()
    }

    /// Retrieve Owner Public Key Digest from fuses
    fn owner_pub_key_digest_fuses(&self) -> ImageDigest {
        self.soc_ifc.fuse_bank().owner_pub_key_hash().into()
    }

    /// Retrieve Anti-Rollback disable fuse value
    fn anti_rollback_disable(&self) -> bool {
        self.soc_ifc.fuse_bank().anti_rollback_disable()
    }

    /// Retrieve Device Lifecycle state
    fn dev_lifecycle(&self) -> Lifecycle {
        self.soc_ifc.lifecycle()
    }

    /// Get the vendor key index saved in data vault on cold boot
    fn vendor_pub_key_idx_dv(&self) -> u32 {
        self.data_vault.ecc_vendor_pk_index()
    }

    /// Get the owner public key digest saved in the dv on cold boot
    fn owner_pub_key_digest_dv(&self) -> ImageDigest {
        self.data_vault.owner_pk_hash().into()
    }

    // Get the fmc digest from the data vault on cold boot
    fn get_fmc_digest_dv(&self) -> ImageDigest {
        self.data_vault.fmc_tci().into()
    }

    // Get Fuse FMC Key Manifest SVN
    fn fmc_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().fmc_fuse_svn()
    }

    // Get Runtime fuse SVN
    fn runtime_fuse_svn(&self) -> u32 {
        self.soc_ifc.fuse_bank().runtime_fuse_svn()
    }

    fn iccm_range(&self) -> Range<u32> {
        RomEnv::ICCM_RANGE
    }

    fn lms_verify_enabled(&self) -> bool {
        self.soc_ifc.fuse_bank().lms_verify() == RomVerifyConfig::EcdsaAndLms
    }
}
