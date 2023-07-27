// Licensed under the Apache-2.0 license

use caliptra_drivers::{CaliptraError, CaliptraResult, DataVault};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature, FmcAliasCertTbs, LocalDevIdCertTbs};
use crate::{MailboxResp, MailboxRespHeader, GetLdevCsrResp, TestGetFmcAliasCertResp};

extern "C" {
    static mut LDEVID_TBS_ORG: [u8; LocalDevIdCertTbs::TBS_TEMPLATE_LEN];
    static mut FMCALIAS_TBS_ORG: [u8; FmcAliasCertTbs::TBS_TEMPLATE_LEN];
}

enum CertType {
    LDevId,
    FmcAlias,
}

/// Copy LDevID certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
#[inline(never)]
pub fn copy_ldevid_cert(dv: &DataVault, cert: &mut [u8]) -> CaliptraResult<usize> {
    cert_from_dccm(dv, cert, CertType::LDevId)
}

/// Copy FMC Alias certificate produced by ROM to `cert` buffer
///
/// Returns the number of bytes written to `cert`
#[inline(never)]
pub fn copy_fmc_alias_cert(dv: &DataVault, cert: &mut [u8]) -> CaliptraResult<usize> {
    cert_from_dccm(dv, cert, CertType::FmcAlias)
}

/// Copy a certificate from `dccm_offset`, append signature, and write the
/// output to `cert`.
fn cert_from_dccm(dv: &DataVault, cert: &mut [u8], cert_type: CertType) -> CaliptraResult<usize> {
    let (tbs, sig) = match cert_type {
        CertType::LDevId => (unsafe { &LDEVID_TBS_ORG[..] }, dv.ldev_dice_signature()),
        CertType::FmcAlias => (unsafe { &FMCALIAS_TBS_ORG[..] }, dv.fmc_dice_signature()),
    };

    // DataVault returns a different type than CertBuilder accepts
    let bldr_sig = Ecdsa384Signature {
        r: sig.r.into(),
        s: sig.s.into(),
    };
    let Some(builder) = Ecdsa384CertBuilder::new(tbs, &bldr_sig) else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    let Some(size) = builder.build(cert) else {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    };

    Ok(size)
}

/// Handle the get ldev cert message
///
/// Returns the response payload as MailboxResp
pub fn handle_get_ldevid_cert(dv: &DataVault) -> CaliptraResult<MailboxResp> {
    let mut cert = [0u8; GetLdevCsrResp::DATA_MAX_SIZE];

    let cert_size = copy_ldevid_cert(dv, &mut cert)?;

    Ok(MailboxResp::GetLdevCsr(GetLdevCsrResp {
        hdr: MailboxRespHeader::default(),
        data_size: cert_size as u32,
        data: cert,
    }))
}

/// Handle the get fmc alias cert message
///
/// Returns the response payload as MailboxResp
pub fn handle_get_fmc_alias_cert(dv: &DataVault) -> CaliptraResult<MailboxResp> {
    let mut cert = [0u8; TestGetFmcAliasCertResp::DATA_MAX_SIZE];

    let cert_size = copy_fmc_alias_cert(dv, &mut cert)?;

    Ok(MailboxResp::TestGetFmcAliasCert(TestGetFmcAliasCertResp {
        hdr: MailboxRespHeader::default(),
        data_size: cert_size as u32,
        data: cert,
    }))
}