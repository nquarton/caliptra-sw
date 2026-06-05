// Quick one-off tests to measure crypto CM sign+verify latency on FPGA.
// Not intended for commit.

use crate::common::*;
use caliptra_api::mailbox::CmKeyUsage;
use caliptra_common::mailbox_api::*;
use caliptra_hw_model::HwModel;
use zerocopy::IntoBytes;

#[test]
pub fn mldsa_sign_timing() {
    // Boot to runtime (CM is auto-initialized during reset flow)
    let mut hw = fips_test_init_to_rt(None, None);

    // --- Step 1: Import a 32-byte MLDSA seed as a CMK ---
    let seed = [0x42u8; 32];
    let mut import_req = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader::default(),
        key_usage: CmKeyUsage::Mldsa as u32,
        input_size: seed.len() as u32,
        input: {
            let mut buf = [0u8; CmImportReq::MAX_KEY_SIZE];
            buf[..seed.len()].copy_from_slice(&seed);
            buf
        },
    });
    import_req.populate_chksum().unwrap();

    let import_resp = mbx_send_and_check_resp_hdr::<_, CmImportResp>(
        &mut hw,
        u32::from(CommandId::CM_IMPORT),
        import_req.as_bytes().unwrap(),
    )
    .unwrap();

    let cmk = import_resp.cmk;

    // --- Step 2: Sign a 4096-byte message ---
    let message = [0xABu8; MAX_CMB_DATA_SIZE];

    let mut sign_req = MailboxReq::CmMldsaSign(CmMldsaSignReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        message_size: MAX_CMB_DATA_SIZE as u32,
        message,
    });
    sign_req.populate_chksum().unwrap();

    let sign_resp = mbx_send_and_check_resp_hdr::<_, CmMldsaSignResp>(
        &mut hw,
        u32::from(CommandId::CM_MLDSA_SIGN),
        sign_req.as_bytes().unwrap(),
    )
    .unwrap();

    // --- Step 3: Verify the signature ---
    let mut verify_req = MailboxReq::CmMldsaVerify(CmMldsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        cmk,
        signature: sign_resp.signature,
        message_size: MAX_CMB_DATA_SIZE as u32,
        message,
    });
    verify_req.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        &mut hw,
        u32::from(CommandId::CM_MLDSA_VERIFY),
        verify_req.as_bytes().unwrap(),
    )
    .unwrap();
}

#[test]
pub fn ecdsa_sign_timing() {
    // Boot to runtime (CM is auto-initialized during reset flow)
    let mut hw = fips_test_init_to_rt(None, None);

    // --- Step 1: Import a 48-byte ECDSA seed as a CMK ---
    let seed = [0x42u8; 48];
    let mut import_req = MailboxReq::CmImport(CmImportReq {
        hdr: MailboxReqHeader::default(),
        key_usage: CmKeyUsage::Ecdsa as u32,
        input_size: seed.len() as u32,
        input: {
            let mut buf = [0u8; CmImportReq::MAX_KEY_SIZE];
            buf[..seed.len()].copy_from_slice(&seed);
            buf
        },
    });
    import_req.populate_chksum().unwrap();

    let import_resp = mbx_send_and_check_resp_hdr::<_, CmImportResp>(
        &mut hw,
        u32::from(CommandId::CM_IMPORT),
        import_req.as_bytes().unwrap(),
    )
    .unwrap();

    let cmk = import_resp.cmk;

    // --- Step 2: Sign a 4096-byte message ---
    let message = [0xABu8; MAX_CMB_DATA_SIZE];

    let mut sign_req = MailboxReq::CmEcdsaSign(CmEcdsaSignReq {
        hdr: MailboxReqHeader::default(),
        cmk: cmk.clone(),
        message_size: MAX_CMB_DATA_SIZE as u32,
        message,
    });
    sign_req.populate_chksum().unwrap();

    let sign_resp = mbx_send_and_check_resp_hdr::<_, CmEcdsaSignResp>(
        &mut hw,
        u32::from(CommandId::CM_ECDSA_SIGN),
        sign_req.as_bytes().unwrap(),
    )
    .unwrap();

    // --- Step 3: Verify the signature ---
    let mut verify_req = MailboxReq::CmEcdsaVerify(CmEcdsaVerifyReq {
        hdr: MailboxReqHeader::default(),
        cmk,
        signature_r: sign_resp.signature_r,
        signature_s: sign_resp.signature_s,
        message_size: MAX_CMB_DATA_SIZE as u32,
        message,
    });
    verify_req.populate_chksum().unwrap();

    mbx_send_and_check_resp_hdr::<_, MailboxRespHeader>(
        &mut hw,
        u32::from(CommandId::CM_ECDSA_VERIFY),
        verify_req.as_bytes().unwrap(),
    )
    .unwrap();
}
