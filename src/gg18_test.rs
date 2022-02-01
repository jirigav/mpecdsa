use crate::gg18_key_gen::{gg18_key_gen_1, gg18_key_gen_2, gg18_key_gen_3, gg18_key_gen_4, gg18_key_gen_5, gg18_key_gen_6};
use crate::gg18_sign::{gg18_sign1, gg18_sign2, gg18_sign3, gg18_sign4, gg18_sign5, gg18_sign6, gg18_sign7, gg18_sign8, gg18_sign9, gg18_sign10};
use sha2::{Sha256, Digest};
use curv::elliptic::curves::{p256::Secp256r1, Scalar, Point};
use curv::BigInt;
use curv::arithmetic::traits::*;



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
fn t3_of_n4() {

    // keygen1
    let (gg18_key_gen_msg1_p0, keygen_context1_p0) = gg18_key_gen_1(4, 3, 0);
    let (gg18_key_gen_msg1_p1, keygen_context1_p1) = gg18_key_gen_1(4, 3, 1);
    let (gg18_key_gen_msg1_p2, keygen_context1_p2) = gg18_key_gen_1(4, 3, 2);
    let (gg18_key_gen_msg1_p3, keygen_context1_p3) = gg18_key_gen_1(4, 3, 3);

    // keygen2

    let (gg18_key_gen_msg2_p0, keygen_context2_p0) = gg18_key_gen_2([gg18_key_gen_msg1_p1.clone(), gg18_key_gen_msg1_p2.clone(), gg18_key_gen_msg1_p3.clone()].to_vec(), keygen_context1_p0);
    let (gg18_key_gen_msg2_p1, keygen_context2_p1) = gg18_key_gen_2([gg18_key_gen_msg1_p0.clone(), gg18_key_gen_msg1_p2.clone(), gg18_key_gen_msg1_p3.clone()].to_vec(), keygen_context1_p1);
    let (gg18_key_gen_msg2_p2, keygen_context2_p2) = gg18_key_gen_2([gg18_key_gen_msg1_p0.clone(), gg18_key_gen_msg1_p1.clone(), gg18_key_gen_msg1_p3.clone()].to_vec(), keygen_context1_p2);
    let (gg18_key_gen_msg2_p3, keygen_context2_p3) = gg18_key_gen_2([gg18_key_gen_msg1_p0.clone(), gg18_key_gen_msg1_p1.clone(), gg18_key_gen_msg1_p2.clone()].to_vec(), keygen_context1_p3);


    // keygen3

    let (gg18_key_gen_msg3_p0, keygen_context3_p0) = gg18_key_gen_3([gg18_key_gen_msg2_p1.clone(), gg18_key_gen_msg2_p2.clone(), gg18_key_gen_msg2_p3.clone()].to_vec(), keygen_context2_p0);
    let (gg18_key_gen_msg3_p1, keygen_context3_p1) = gg18_key_gen_3([gg18_key_gen_msg2_p0.clone(), gg18_key_gen_msg2_p2.clone(), gg18_key_gen_msg2_p3.clone()].to_vec(), keygen_context2_p1);
    let (gg18_key_gen_msg3_p2, keygen_context3_p2) = gg18_key_gen_3([gg18_key_gen_msg2_p0.clone(), gg18_key_gen_msg2_p1.clone(), gg18_key_gen_msg2_p3.clone()].to_vec(), keygen_context2_p2);
    let (gg18_key_gen_msg3_p3, keygen_context3_p3) = gg18_key_gen_3([gg18_key_gen_msg2_p0.clone(), gg18_key_gen_msg2_p1.clone(), gg18_key_gen_msg2_p2.clone()].to_vec(), keygen_context2_p3);

    // keygen4

    let (gg18_key_gen_msg4_p0, keygen_context4_p0) = gg18_key_gen_4([gg18_key_gen_msg3_p1[0].clone(), gg18_key_gen_msg3_p2[0].clone(), gg18_key_gen_msg3_p3[0].clone()].to_vec(), keygen_context3_p0);
    let (gg18_key_gen_msg4_p1, keygen_context4_p1) = gg18_key_gen_4([gg18_key_gen_msg3_p0[0].clone(), gg18_key_gen_msg3_p2[1].clone(), gg18_key_gen_msg3_p3[1].clone()].to_vec(), keygen_context3_p1);
    let (gg18_key_gen_msg4_p2, keygen_context4_p2) = gg18_key_gen_4([gg18_key_gen_msg3_p0[1].clone(), gg18_key_gen_msg3_p1[1].clone(), gg18_key_gen_msg3_p3[2].clone()].to_vec(), keygen_context3_p2);
    let (gg18_key_gen_msg4_p3, keygen_context4_p3) = gg18_key_gen_4([gg18_key_gen_msg3_p0[2].clone(), gg18_key_gen_msg3_p1[2].clone(), gg18_key_gen_msg3_p2[2].clone()].to_vec(), keygen_context3_p3);


    // keygen5

    let (gg18_key_gen_msg5_p0, keygen_context5_p0) = gg18_key_gen_5([gg18_key_gen_msg4_p1.clone(), gg18_key_gen_msg4_p2.clone(), gg18_key_gen_msg4_p3.clone()].to_vec(), keygen_context4_p0);
    let (gg18_key_gen_msg5_p1, keygen_context5_p1) = gg18_key_gen_5([gg18_key_gen_msg4_p0.clone(), gg18_key_gen_msg4_p2.clone(), gg18_key_gen_msg4_p3.clone()].to_vec(), keygen_context4_p1);
    let (gg18_key_gen_msg5_p2, keygen_context5_p2) = gg18_key_gen_5([gg18_key_gen_msg4_p0.clone(), gg18_key_gen_msg4_p1.clone(), gg18_key_gen_msg4_p3.clone()].to_vec(), keygen_context4_p2);
    let (gg18_key_gen_msg5_p3, keygen_context5_p3) = gg18_key_gen_5([gg18_key_gen_msg4_p0.clone(), gg18_key_gen_msg4_p1.clone(), gg18_key_gen_msg4_p2.clone()].to_vec(), keygen_context4_p3);

    // keygen6

    let gg18_sign_context_p0 = gg18_key_gen_6([gg18_key_gen_msg5_p1.clone(), gg18_key_gen_msg5_p2.clone(), gg18_key_gen_msg5_p3.clone()].to_vec(), keygen_context5_p0);
    let gg18_sign_context_p1 = gg18_key_gen_6([gg18_key_gen_msg5_p0.clone(), gg18_key_gen_msg5_p2.clone(), gg18_key_gen_msg5_p3.clone()].to_vec(), keygen_context5_p1);
    let gg18_sign_context_p2 = gg18_key_gen_6([gg18_key_gen_msg5_p0.clone(), gg18_key_gen_msg5_p1.clone(), gg18_key_gen_msg5_p3.clone()].to_vec(), keygen_context5_p2);
    let gg18_sign_context_p3 = gg18_key_gen_6([gg18_key_gen_msg5_p0.clone(), gg18_key_gen_msg5_p1.clone(), gg18_key_gen_msg5_p2.clone()].to_vec(), keygen_context5_p3);



    let pk_p0 = gg18_sign_context_p0.pk.clone();
    let _pk_p1 = gg18_sign_context_p1.pk.clone();
    let pk_p2 = gg18_sign_context_p2.pk.clone();
    let _pk_p3 = gg18_sign_context_p3.pk.clone();

    // hash msg
    let mut hasher = Sha256::new();
    hasher.update(b"random message");
    let hash = hasher.finalize().to_vec();

    // gg18_sign1
    let (gg18_sign_msg1_p0, gg18_sign_context1_p0) = gg18_sign1(gg18_sign_context_p0, [2, 3, 0].to_vec(), 2, hash.clone());
    let (gg18_sign_msg1_p2, gg18_sign_context1_p2) = gg18_sign1(gg18_sign_context_p2, [2, 3, 0].to_vec(), 0, hash.clone());
    let (gg18_sign_msg1_p3, gg18_sign_context1_p3) = gg18_sign1(gg18_sign_context_p3, [2, 3, 0].to_vec(), 1, hash.clone());

    // gg18_sign2
    let (gg18_sign_msg2_p0, gg18_sign_context2_p0) = gg18_sign2([gg18_sign_msg1_p2.clone(), gg18_sign_msg1_p3.clone()].to_vec(), gg18_sign_context1_p0);
    let (gg18_sign_msg2_p2, gg18_sign_context2_p2) = gg18_sign2([gg18_sign_msg1_p3.clone(), gg18_sign_msg1_p0.clone()].to_vec(), gg18_sign_context1_p2);
    let (gg18_sign_msg2_p3, gg18_sign_context2_p3) = gg18_sign2([gg18_sign_msg1_p2.clone(), gg18_sign_msg1_p0.clone()].to_vec(), gg18_sign_context1_p3);


    // gg18_sign3
    let (gg18_sign_msg3_p0, gg18_sign_context3_p0) = gg18_sign3([gg18_sign_msg2_p2[1].clone(), gg18_sign_msg2_p3[1].clone()].to_vec(), gg18_sign_context2_p0);
    let (gg18_sign_msg3_p2, gg18_sign_context3_p2) = gg18_sign3([gg18_sign_msg2_p3[0].clone(), gg18_sign_msg2_p0[0].clone()].to_vec(), gg18_sign_context2_p2);
    let (gg18_sign_msg3_p3, gg18_sign_context3_p3) = gg18_sign3([gg18_sign_msg2_p2[0].clone(), gg18_sign_msg2_p0[1].clone()].to_vec(), gg18_sign_context2_p3);


    // gg18_sign4
    let (gg18_sign_msg4_p0, gg18_sign_context4_p0) = gg18_sign4([gg18_sign_msg3_p2.clone(), gg18_sign_msg3_p3.clone()].to_vec(), gg18_sign_context3_p0);
    let (gg18_sign_msg4_p2, gg18_sign_context4_p2) = gg18_sign4([gg18_sign_msg3_p3.clone(), gg18_sign_msg3_p0.clone()].to_vec(), gg18_sign_context3_p2);
    let (gg18_sign_msg4_p3, gg18_sign_context4_p3) = gg18_sign4([gg18_sign_msg3_p2.clone(), gg18_sign_msg3_p0.clone()].to_vec(), gg18_sign_context3_p3);

    // gg18_sign5
    let (gg18_sign_msg5_p0, gg18_sign_context5_p0) = gg18_sign5([gg18_sign_msg4_p2.clone(), gg18_sign_msg4_p3.clone()].to_vec(), gg18_sign_context4_p0);
    let (gg18_sign_msg5_p2, gg18_sign_context5_p2) = gg18_sign5([gg18_sign_msg4_p3.clone(), gg18_sign_msg4_p0.clone()].to_vec(), gg18_sign_context4_p2);
    let (gg18_sign_msg5_p3, gg18_sign_context5_p3) = gg18_sign5([gg18_sign_msg4_p2.clone(), gg18_sign_msg4_p0.clone()].to_vec(), gg18_sign_context4_p3);


    // gg18_sign6
    let (gg18_sign_msg6_p0, gg18_sign_context6_p0) = gg18_sign6([gg18_sign_msg5_p2.clone(), gg18_sign_msg5_p3.clone()].to_vec(), gg18_sign_context5_p0);
    let (gg18_sign_msg6_p2, gg18_sign_context6_p2) = gg18_sign6([gg18_sign_msg5_p3.clone(), gg18_sign_msg5_p0.clone()].to_vec(), gg18_sign_context5_p2);
    let (gg18_sign_msg6_p3, gg18_sign_context6_p3) = gg18_sign6([gg18_sign_msg5_p2.clone(), gg18_sign_msg5_p0.clone()].to_vec(), gg18_sign_context5_p3);

    // gg18_sign7
    let (gg18_sign_msg7_p0, gg18_sign_context7_p0) = gg18_sign7([gg18_sign_msg6_p2.clone(), gg18_sign_msg6_p3.clone()].to_vec(), gg18_sign_context6_p0);
    let (gg18_sign_msg7_p2, gg18_sign_context7_p2) = gg18_sign7([gg18_sign_msg6_p3.clone(), gg18_sign_msg6_p0.clone()].to_vec(), gg18_sign_context6_p2);
    let (gg18_sign_msg7_p3, gg18_sign_context7_p3) = gg18_sign7([gg18_sign_msg6_p2.clone(), gg18_sign_msg6_p0.clone()].to_vec(), gg18_sign_context6_p3);

    // gg18_sign8
    let (gg18_sign_msg8_p0, gg18_sign_context8_p0) = gg18_sign8([gg18_sign_msg7_p2.clone(), gg18_sign_msg7_p3.clone()].to_vec(), gg18_sign_context7_p0);
    let (gg18_sign_msg8_p2, gg18_sign_context8_p2) = gg18_sign8([gg18_sign_msg7_p3.clone(), gg18_sign_msg7_p0.clone()].to_vec(), gg18_sign_context7_p2);
    let (gg18_sign_msg8_p3, gg18_sign_context8_p3) = gg18_sign8([gg18_sign_msg7_p2.clone(), gg18_sign_msg7_p0.clone()].to_vec(), gg18_sign_context7_p3);

    // gg18_sign9
    let (gg18_sign_msg9_p0, gg18_sign_context9_p0) = gg18_sign9([gg18_sign_msg8_p2.clone(), gg18_sign_msg8_p3.clone()].to_vec(), gg18_sign_context8_p0);
    let (gg18_sign_msg9_p2, gg18_sign_context9_p2) = gg18_sign9([gg18_sign_msg8_p3.clone(), gg18_sign_msg8_p0.clone()].to_vec(), gg18_sign_context8_p2);
    let (gg18_sign_msg9_p3, gg18_sign_context9_p3) = gg18_sign9([gg18_sign_msg8_p2.clone(), gg18_sign_msg8_p0.clone()].to_vec(), gg18_sign_context8_p3);

    // gg18_sign10
    let gg18_signature_p0 = gg18_sign10([gg18_sign_msg9_p2.clone(), gg18_sign_msg9_p3.clone()].to_vec(), gg18_sign_context9_p0);
    let gg18_signature_p2 = gg18_sign10([gg18_sign_msg9_p3.clone(), gg18_sign_msg9_p0.clone()].to_vec(), gg18_sign_context9_p2);
    let gg18_signature_p3 = gg18_sign10([gg18_sign_msg9_p2.clone(), gg18_sign_msg9_p0.clone()].to_vec(), gg18_sign_context9_p3);

    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p0[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p0[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk_p0);


    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p2[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p2[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk_p2);


    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p3[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&gg18_signature_p3[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk_p0);

}
