#![allow(non_snake_case)]
use crate::gg18_key_gen::{gg18_key_gen_1, gg18_key_gen_2, gg18_key_gen_3, gg18_key_gen_4, gg18_key_gen_5, gg18_key_gen_6};
use crate::gg18_sign::{gg18_sign1, gg18_sign2, gg18_sign3, gg18_sign4, gg18_sign5, gg18_sign6, gg18_sign7, gg18_sign8, gg18_sign9, gg18_sign10};
use sha2::{Sha256, Digest};
use curv::elliptic::curves::{p256::Secp256r1, Scalar, Point, Secp256k1, Curve};
use curv::BigInt;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::CommWitness;
use crate::gg18_refresh::{gg18_refresh1, gg18_refresh2, gg18_refresh3, gg18_refresh4};
use std::fs;

pub fn check_sig(r: &Scalar<Secp256r1>, s: &Scalar<Secp256r1>, msg: &[u8], pk: &Point<Secp256r1>) {
    use p256::ecdsa::{VerifyingKey, signature::Verifier, Signature};
    use p256::FieldBytes;

    let slice = pk.to_bytes(false);
    let mut raw_pk = Vec::new();
    if slice.len() != 65 {
        // after curv's pk_to_key_slice return 65 bytes, this can be removed
        raw_pk.insert(0, 4u8);
        raw_pk.extend(vec![0u8; 64 - slice.len()]);
        raw_pk.extend(slice.as_ref());
    } else {
        raw_pk.extend(slice.as_ref());
    }

    assert_eq!(raw_pk.len(), 65);

    let public_key : VerifyingKey = VerifyingKey::from_sec1_bytes(&raw_pk).unwrap();

    let bytes_r = &r.to_bytes()[..];
    let bytes_s = &s.to_bytes()[..];

    let signature = Signature::from_scalars(*FieldBytes::from_slice(bytes_r), *FieldBytes::from_slice(bytes_s)).unwrap();

    let is_correct = public_key.verify(msg, &signature).is_ok();
    assert!(is_correct);
}

#[test]
fn t2_of_n2() {

    // keygen1
    let (gg18_key_gen_msg1_p0, keygen_context1_p0) = gg18_key_gen_1(2, 2, 0).unwrap();
    let (gg18_key_gen_msg1_p1, keygen_context1_p1) = gg18_key_gen_1(2, 2, 1).unwrap();

    // keygen2

    let (gg18_key_gen_msg2_p0, keygen_context2_p0) = gg18_key_gen_2([gg18_key_gen_msg1_p1.clone()].to_vec(), keygen_context1_p0).unwrap();
    let (gg18_key_gen_msg2_p1, keygen_context2_p1) = gg18_key_gen_2([gg18_key_gen_msg1_p0.clone()].to_vec(), keygen_context1_p1).unwrap();

    // keygen3

    let (gg18_key_gen_msg3_p0, keygen_context3_p0) = gg18_key_gen_3([gg18_key_gen_msg2_p1.clone()].to_vec(), keygen_context2_p0).unwrap();
    let (gg18_key_gen_msg3_p1, keygen_context3_p1) = gg18_key_gen_3([gg18_key_gen_msg2_p0.clone()].to_vec(), keygen_context2_p1).unwrap();

    // keygen4

    let (gg18_key_gen_msg4_p0, keygen_context4_p0) = gg18_key_gen_4([gg18_key_gen_msg3_p1[0].clone()].to_vec(), keygen_context3_p0).unwrap();
    let (gg18_key_gen_msg4_p1, keygen_context4_p1) = gg18_key_gen_4([gg18_key_gen_msg3_p0[0].clone()].to_vec(), keygen_context3_p1).unwrap();

    // keygen5

    let (gg18_key_gen_msg5_p0, keygen_context5_p0) = gg18_key_gen_5([gg18_key_gen_msg4_p1.clone()].to_vec(), keygen_context4_p0).unwrap();
    let (gg18_key_gen_msg5_p1, keygen_context5_p1) = gg18_key_gen_5([gg18_key_gen_msg4_p0.clone()].to_vec(), keygen_context4_p1).unwrap();

    // keygen6

    let gg18_sign_context_p0 = gg18_key_gen_6([gg18_key_gen_msg5_p1.clone()].to_vec(), keygen_context5_p0).unwrap();
    let gg18_sign_context_p1 = gg18_key_gen_6([gg18_key_gen_msg5_p0.clone()].to_vec(), keygen_context5_p1).unwrap();



    let pk_p0 = gg18_sign_context_p0.pk.clone();
    let pk_p1 = gg18_sign_context_p1.pk.clone();

    // hash msg
    let mut hasher = Sha256::new();
    hasher.update(b"random message");
    let hash = hasher.finalize().to_vec();


    fs::write("data01", &serde_json::to_string(&gg18_sign_context_p0).unwrap()).expect("Unable to save setup file.");

    fs::write("data11", &serde_json::to_string(&gg18_sign_context_p1).unwrap()).expect("Unable to save setup file.");

    let (ref_msg1_p0, ref_context1_p0) = gg18_refresh1(gg18_sign_context_p0).unwrap();
    let (ref_msg1_p1, ref_context1_p1) = gg18_refresh1(gg18_sign_context_p1).unwrap();
    //send msg1
    // receive msg1 into commit5a_and_pss_vec
    // save it to zk_com_vec
    let (ref_msg2_p0, ref_context2_p0) = gg18_refresh2([ref_msg1_p1.clone()].to_vec(), ref_context1_p0).unwrap();
    let (ref_msg2_p1, ref_context2_p1) = gg18_refresh2([ref_msg1_p0.clone()].to_vec(), ref_context1_p1).unwrap();
    // send com_witness
    // receive com_witness into decommit5a_and_elgamal_and_com_wit_vec
    // save all com_witness to zk_decomm_vec
    let (ref_msg3_p0, ref_context3_p0) = gg18_refresh3([ref_msg2_p1.clone()].to_vec(), ref_context2_p0).unwrap();
    let (ref_msg3_p1, ref_context3_p1) = gg18_refresh3([ref_msg2_p0.clone()].to_vec(), ref_context2_p1).unwrap();

    let c0 = gg18_refresh4([ref_msg3_p1.clone()].to_vec(), ref_context3_p0).unwrap();
    let c1 = gg18_refresh4([ref_msg3_p0.clone()].to_vec(), ref_context3_p1).unwrap();



    fs::write("data02", &serde_json::to_string(&c0).unwrap()).expect("Unable to save setup file.");

    fs::write("data12", &serde_json::to_string(&c1).unwrap()).expect("Unable to save setup file.");


    // gg18_sign1
    let (gg18_sign_msg1_p0, gg18_sign_context1_p0) = gg18_sign1(c0, [0, 1].to_vec(), 0, hash.clone()).unwrap();
    let (gg18_sign_msg1_p1, gg18_sign_context1_p1) = gg18_sign1(c1, [0, 1].to_vec(), 1, hash.clone()).unwrap();

    // gg18_sign2
    let (gg18_sign_msg2_p0, gg18_sign_context2_p0) = gg18_sign2([gg18_sign_msg1_p1.clone()].to_vec(), gg18_sign_context1_p0).unwrap();
    let (gg18_sign_msg2_p1, gg18_sign_context2_p1) = gg18_sign2([gg18_sign_msg1_p0.clone()].to_vec(), gg18_sign_context1_p1).unwrap();


    // gg18_sign3
    let (gg18_sign_msg3_p0, gg18_sign_context3_p0) = gg18_sign3([gg18_sign_msg2_p1[0].clone()].to_vec(), gg18_sign_context2_p0).unwrap();
    let (gg18_sign_msg3_p1, gg18_sign_context3_p1) = gg18_sign3([gg18_sign_msg2_p0[0].clone()].to_vec(), gg18_sign_context2_p1).unwrap();


    // gg18_sign4
    let (gg18_sign_msg4_p0, gg18_sign_context4_p0) = gg18_sign4([gg18_sign_msg3_p1.clone()].to_vec(), gg18_sign_context3_p0).unwrap();
    let (gg18_sign_msg4_p1, gg18_sign_context4_p1) = gg18_sign4([gg18_sign_msg3_p0.clone()].to_vec(), gg18_sign_context3_p1).unwrap();

    // gg18_sign5
    let (gg18_sign_msg5_p0, gg18_sign_context5_p0) = gg18_sign5([gg18_sign_msg4_p1.clone()].to_vec(), gg18_sign_context4_p0).unwrap();
    let (gg18_sign_msg5_p1, gg18_sign_context5_p1) = gg18_sign5([gg18_sign_msg4_p0.clone()].to_vec(), gg18_sign_context4_p1).unwrap();

    // gg18_sign6
    let (gg18_sign_msg6_p0, gg18_sign_context6_p0) = gg18_sign6([gg18_sign_msg5_p1.clone()].to_vec(), gg18_sign_context5_p0).unwrap();
    let (gg18_sign_msg6_p1, gg18_sign_context6_p1) = gg18_sign6([gg18_sign_msg5_p0.clone()].to_vec(), gg18_sign_context5_p1).unwrap();

    // gg18_sign7
    let (gg18_sign_msg7_p0, gg18_sign_context7_p0) = gg18_sign7([gg18_sign_msg6_p1.clone()].to_vec(), gg18_sign_context6_p0).unwrap();
    let (gg18_sign_msg7_p1, gg18_sign_context7_p1) = gg18_sign7([gg18_sign_msg6_p0.clone()].to_vec(), gg18_sign_context6_p1).unwrap();

    // gg18_sign8
    let (gg18_sign_msg8_p0, gg18_sign_context8_p0) = gg18_sign8([gg18_sign_msg7_p1.clone()].to_vec(), gg18_sign_context7_p0).unwrap();
    let (gg18_sign_msg8_p1, gg18_sign_context8_p1) = gg18_sign8([gg18_sign_msg7_p0.clone()].to_vec(), gg18_sign_context7_p1).unwrap();

    // gg18_sign9
    let (gg18_sign_msg9_p0, gg18_sign_context9_p0) = gg18_sign9([gg18_sign_msg8_p1.clone()].to_vec(), gg18_sign_context8_p0).unwrap();
    let (gg18_sign_msg9_p1, gg18_sign_context9_p1) = gg18_sign9([gg18_sign_msg8_p0.clone()].to_vec(), gg18_sign_context8_p1).unwrap();

    // gg18_sign10
    let gg18_signature_p0 = gg18_sign10([gg18_sign_msg9_p1.clone()].to_vec(), gg18_sign_context9_p0).unwrap();
    let gg18_signature_p1 = gg18_sign10([gg18_sign_msg9_p0.clone()].to_vec(), gg18_sign_context9_p1).unwrap();

    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p0[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p0[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk_p0);


    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p1[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p1[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk_p1);


}
