use crate::li17_key_gen::{Li17SignP1Context, Li17SignP2Context};
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::BigInt;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::{p256::Secp256r1, Point};


pub struct Li17SignP2Context1 {
    pub public: Point<Secp256r1>,
    pub p2_private: party_two::Party2Private,
    pub p2_paillier_public: party_two::PaillierPublic,
    hash: BigInt,
    p2_eph_comm_witness: party_two::EphCommWitness,
    p2_eph_ec_key_pair: party_two::EphEcKeyPair,

}

pub type Li17SignP2Msg1 = party_two::EphKeyGenFirstMsg;

pub type Li17SignP2Msg2 = (party_two::PartialSig, party_two::EphKeyGenSecondMsg);

pub struct Li17SignP1Context1 {
    pub public: Point<Secp256r1>,
    pub p1_private: party_one::Party1Private,
    hash: BigInt,
    p1_eph_ec_key_pair: party_one::EphEcKeyPair,
    p1_msg1_from_p2: Li17SignP2Msg1,
}

pub type Li17SignP1Msg1 = party_one::EphKeyGenFirstMsg;


pub fn li17_p2_sign1( context: Li17SignP2Context, message_hash: &Vec<u8> ) -> Result<(Li17SignP2Msg1, Li17SignP2Context1), &'static str> {

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
                    party_two::EphKeyGenFirstMsg::create_commitments();

    let context1 = Li17SignP2Context1 {
        public: context.public,
        p2_private: context.p2_private,
        p2_paillier_public: context.p2_paillier_public,
        hash: BigInt::from_bytes(message_hash),
        p2_eph_comm_witness: eph_comm_witness,
        p2_eph_ec_key_pair: eph_ec_key_pair_party2,
    };
    Ok((eph_party_two_first_message, context1))
}

pub fn li17_p2_sign2( msg: Li17SignP1Msg1, context: Li17SignP2Context1) -> Result<Li17SignP2Msg2, &'static str> {

	let eph_party_two_second_message =
        party_two::EphKeyGenSecondMsg::verify_and_decommit(
            context.p2_eph_comm_witness,
            &msg,
        );

    if eph_party_two_second_message.is_err(){
        return Err("party1 DLog proof failed")
    }

    let partial_sig = party_two::PartialSig::compute(
        &context.p2_paillier_public.ek,
        &context.p2_paillier_public.encrypted_secret_share,
        &context.p2_private,
        &context.p2_eph_ec_key_pair,
        &msg.public_share,
        &context.hash,
    );
    Ok((partial_sig, eph_party_two_second_message.unwrap()))
}

pub fn li17_p1_sign1( msg: Li17SignP2Msg1, context: Li17SignP1Context, message_hash: &Vec<u8>)
-> Result<(Li17SignP1Msg1, Li17SignP1Context1), &'static str> {

    let (eph_party_one_first_message, eph_ec_key_pair_party1) = party_one::EphKeyGenFirstMsg::create();
    let context2 = Li17SignP1Context1 {
        public: context.public,
        p1_private: context.p1_private,
        hash: BigInt::from_bytes(message_hash),
        p1_eph_ec_key_pair: eph_ec_key_pair_party1,
        p1_msg1_from_p2: msg,

    };
    Ok((eph_party_one_first_message, context2))
}

pub fn li17_p1_sign2( msg: Li17SignP2Msg2, context: Li17SignP1Context1) -> Result<Vec<u8>, &'static str> {

    let (partial_sig, eph_party_two_second_message) = msg;

   	let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &context.p1_msg1_from_p2,
            &eph_party_two_second_message,
        );

    let sig = party_one::Signature::compute(
        &context.p1_private,
        &partial_sig.c3,
        &context.p1_eph_ec_key_pair,
        &eph_party_two_second_message.comm_witness.public_share,
    );

    if party_one::verify(&sig, &context.public, &context.hash).is_err() {
        return Err("invalid signature")
    }
    Ok([BigInt::to_bytes(&sig.r), BigInt::to_bytes(&sig.s)].concat())
}
