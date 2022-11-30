use crate::li17_key_gen::{li17_p1_key_gen1, li17_p1_key_gen2, li17_p2_key_gen1, li17_p2_key_gen2};
use crate::li17_refresh::{li17_p1_refresh1, li17_p1_refresh2, li17_p2_refresh1, li17_p2_refresh2};
use crate::li17_sign::{li17_p1_sign1, li17_p1_sign2, li17_p2_sign1, li17_p2_sign2};
use curv::arithmetic::traits::*;
use curv::elliptic::curves::{p256::Secp256r1, Point, Scalar};
use curv::BigInt;
use sha2::{Digest, Sha256};

pub fn check_sig(r: &Scalar<Secp256r1>, s: &Scalar<Secp256r1>, msg: &[u8], pk: &Point<Secp256r1>) {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
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

    let public_key: VerifyingKey = VerifyingKey::from_sec1_bytes(&raw_pk).unwrap();

    let bytes_r = &r.to_bytes()[..];
    let bytes_s = &s.to_bytes()[..];

    let signature = Signature::from_scalars(
        *FieldBytes::from_slice(bytes_r),
        *FieldBytes::from_slice(bytes_s),
    )
    .unwrap();

    let is_correct = public_key.verify(msg, &signature).is_ok();
    assert!(is_correct);
}

#[test]
fn keygen() {
    // keygen
    let (msg1p1, context1p1) = li17_p1_key_gen1().unwrap();

    let (msg1p2, context1p2) = li17_p2_key_gen1(msg1p1).unwrap();

    let (msg2p1, _sign_context_p1) = li17_p1_key_gen2(msg1p2, context1p1).unwrap();

    let (_pk, _sign_context_p2) = li17_p2_key_gen2(msg2p1, context1p2).unwrap();
}

#[test]
fn sign() {
    // keygen
    let (msg1p1, context1p1) = li17_p1_key_gen1().unwrap();

    let (msg1p2, context1p2) = li17_p2_key_gen1(msg1p1).unwrap();

    let (msg2p1, sign_context_p1) = li17_p1_key_gen2(msg1p2, context1p1).unwrap();

    let (pk, sign_context_p2) = li17_p2_key_gen2(msg2p1, context1p2).unwrap();

    // sign

    let mut hasher = Sha256::new();
    hasher.update(b"random message");
    let hash = hasher.finalize().to_vec();

    let (smsg1p2, context1p2) = li17_p2_sign1(sign_context_p2, &hash).unwrap();

    let (smsg1p1, context1p1) = li17_p1_sign1(smsg1p2, sign_context_p1, &hash).unwrap();

    let smsg2p2 = li17_p2_sign2(smsg1p1, context1p2).unwrap();

    let sig = li17_p1_sign2(smsg2p2, context1p1).unwrap();

    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk);
}

#[test]
fn refresh_and_sign() {
    // keygen
    let (msg1p1, context1p1) = li17_p1_key_gen1().unwrap();

    let (msg1p2, context1p2) = li17_p2_key_gen1(msg1p1).unwrap();

    let (msg2p1, sign_context_p1) = li17_p1_key_gen2(msg1p2, context1p1).unwrap();

    let (pk, sign_context_p2) = li17_p2_key_gen2(msg2p1, context1p2).unwrap();

    // refresh

    let (msg1p1, context1p1) = li17_p1_refresh1(sign_context_p1).unwrap();

    let (msg1p2, context1p2) = li17_p2_refresh1(msg1p1, sign_context_p2).unwrap();

    let (msg2p1, sign_context_p1) = li17_p1_refresh2(msg1p2, context1p1).unwrap();

    let sign_context_p2 = li17_p2_refresh2(msg2p1, context1p2).unwrap();

    // sign

    let mut hasher = Sha256::new();
    hasher.update(b"random message");
    let hash = hasher.finalize().to_vec();

    let (smsg1p2, context1p2) = li17_p2_sign1(sign_context_p2, &hash).unwrap();

    let (smsg1p1, context1p1) = li17_p1_sign1(smsg1p2, sign_context_p1, &hash).unwrap();

    let smsg2p2 = li17_p2_sign2(smsg1p1, context1p2).unwrap();

    let sig = li17_p1_sign2(smsg2p2, context1p1).unwrap();

    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk);
}

#[test]
fn twice_refresh_and_sign() {
    // keygen
    let (msg1p1, context1p1) = li17_p1_key_gen1().unwrap();

    let (msg1p2, context1p2) = li17_p2_key_gen1(msg1p1).unwrap();

    let (msg2p1, sign_context_p1) = li17_p1_key_gen2(msg1p2, context1p1).unwrap();

    let (pk, sign_context_p2) = li17_p2_key_gen2(msg2p1, context1p2).unwrap();

    // refresh

    let (msg1p1, context1p1) = li17_p1_refresh1(sign_context_p1).unwrap();

    let (msg1p2, context1p2) = li17_p2_refresh1(msg1p1, sign_context_p2).unwrap();

    let (msg2p1, sign_context_p1) = li17_p1_refresh2(msg1p2, context1p1).unwrap();

    let sign_context_p2 = li17_p2_refresh2(msg2p1, context1p2).unwrap();

    // refresh 2

    let (msg1p1, context1p1) = li17_p1_refresh1(sign_context_p1).unwrap();

    let (msg1p2, context1p2) = li17_p2_refresh1(msg1p1, sign_context_p2).unwrap();

    let (msg2p1, sign_context_p1) = li17_p1_refresh2(msg1p2, context1p1).unwrap();

    let sign_context_p2 = li17_p2_refresh2(msg2p1, context1p2).unwrap();

    // sign

    let mut hasher = Sha256::new();
    hasher.update(b"random message");
    let hash = hasher.finalize().to_vec();

    let (smsg1p2, context1p2) = li17_p2_sign1(sign_context_p2, &hash).unwrap();

    let (smsg1p1, context1p1) = li17_p1_sign1(smsg1p2, sign_context_p1, &hash).unwrap();

    let smsg2p2 = li17_p2_sign2(smsg1p1, context1p2).unwrap();

    let sig = li17_p1_sign2(smsg2p2, context1p1).unwrap();

    let r = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[..32]));
    let s = Scalar::<Secp256r1>::from(&BigInt::from_bytes(&sig[32..]));
    check_sig(&r, &s, "random message".as_bytes(), &pk);
}
