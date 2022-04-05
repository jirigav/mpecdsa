use crate::li17_key_gen::{li17_key_gen1, li17_key_gen2, li17_key_gen3, li17_key_gen4};
use crate::li17_sign::{li17_sign1, li17_sign2, li17_sign3, li17_sign4};
use crate::li17_refresh::{li17_refresh1, li17_refresh2, li17_refresh3, li17_refresh4};
use sha2::{Sha256, Digest};
use curv::elliptic::curves::{p256::Secp256r1, Scalar, Point};
use curv::BigInt;
use curv::arithmetic::traits::*;
use std::fs;

pub fn check_sig(r: &Scalar<Secp256r1>, s: &Scalar<Secp256r1>, msg: &[u8], pk: &Point<Secp256r1>) {
    use p256::ecdsa::{VerifyingKey, signature::Verifier, Signature};
    use p256::FieldBytes;

    let slice = pk.to_bytes(false);
    let mut raw_pk = Vec::new();
    if slice.len() != 65 {

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

    // keygen
    let (msg1p0, context1p0) = li17_key_gen1(0).unwrap();
    let (_msg1p1, context1p1) = li17_key_gen1(1).unwrap();

    let (_msg2p0, context2p0) = li17_key_gen2(msg1p0.clone().unwrap(), context1p0).unwrap();
    let (msg2p1, context2p1) = li17_key_gen2(msg1p0.unwrap(), context1p1).unwrap();

    let (msg3p0, context3p0) = li17_key_gen3(msg2p1.clone().unwrap(), context2p0).unwrap();
    let (_msg3p1, context3p1) = li17_key_gen3(msg2p1.unwrap(), context2p1).unwrap();

    let msg3 = msg3p0.unwrap();
    let (pk1, scontext0) = li17_key_gen4(None, context3p0).unwrap();
    let (pk2, scontext1) = li17_key_gen4(Some(msg3), context3p1).unwrap();
    let pk1 = pk1.unwrap();
    let pk2 = pk2.unwrap();
    assert!(pk1 == pk2);


    // refresh

    let (msg1p0, context1p0) = li17_refresh1(scontext0).unwrap();
    let (_msg1p1, context1p1) = li17_refresh1(scontext1).unwrap();

    let (_msg2p0, context2p0) = li17_refresh2(msg1p0.clone().unwrap(), context1p0).unwrap();
    let (msg2p1, context2p1) = li17_refresh2(msg1p0.unwrap(), context1p1).unwrap();

    let (msg3p0, context3p0) = li17_refresh3(msg2p1.clone().unwrap(), context2p0).unwrap();
    let (_msg3p1, context3p1) = li17_refresh3(msg2p1.unwrap(), context2p1).unwrap();

    let scontext0 = li17_refresh4(msg3p0.clone().unwrap(), context3p0).unwrap();
    let scontext1 = li17_refresh4(msg3p0.unwrap(), context3p1).unwrap();


    // refresh 2

    let (msg1p0, context1p0) = li17_refresh1(scontext0).unwrap();
    let (_msg1p1, context1p1) = li17_refresh1(scontext1).unwrap();

    let (_msg2p0, context2p0) = li17_refresh2(msg1p0.clone().unwrap(), context1p0).unwrap();
    let (msg2p1, context2p1) = li17_refresh2(msg1p0.unwrap(), context1p1).unwrap();

    let (msg3p0, context3p0) = li17_refresh3(msg2p1.clone().unwrap(), context2p0).unwrap();
    let (_msg3p1, context3p1) = li17_refresh3(msg2p1.unwrap(), context2p1).unwrap();

    let scontext0 = li17_refresh4(msg3p0.clone().unwrap(), context3p0).unwrap();
    let scontext1 = li17_refresh4(msg3p0.unwrap(), context3p1).unwrap();

    // sign

    let mut hasher = Sha256::new();
    hasher.update(b"random message");
    let hash = hasher.finalize().to_vec();

    let (_smsg1p0, scontext1p0) = li17_sign1(scontext0, hash.clone()).unwrap();
    let (smsg1p1, scontext1p1) = li17_sign1(scontext1, hash).unwrap();

    let (smsg2p0, scontext2p0) = li17_sign2(smsg1p1.clone().unwrap(), scontext1p0).unwrap();
    let (_smsg2p1, scontext2p1) = li17_sign2(smsg1p1.unwrap(), scontext1p1).unwrap();

    let (_smsg3p0, scontext3p0) = li17_sign3(None, scontext2p0).unwrap();
    let (smsg3p1, scontext3p1) = li17_sign3(Some(smsg2p0.unwrap()), scontext2p1).unwrap();

    let sig = li17_sign4(Some(smsg3p1.unwrap()), scontext3p0).unwrap().unwrap();
    let _ = li17_sign4(None, scontext3p1).unwrap();

    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk1);



}
