use crate::li17_key_gen::Li17SignContext;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::BigInt;
use curv::arithmetic::traits::*;
use curv::elliptic::curves::{p256::Secp256r1, Point};


pub struct Li17SignContext1 {
    pub index: u16,
    pub public: Point<Secp256r1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,
    hash: BigInt,
    p2_eph_comm_witness: Option<party_two::EphCommWitness>,
    p2_eph_ec_key_pair: Option<party_two::EphEcKeyPair>,

}

pub type Li17SignMsg1 = party_two::EphKeyGenFirstMsg;

pub struct Li17SignContext2 {
    pub index: u16,
    pub public: Point<Secp256r1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,
    hash: BigInt,
    p1_eph_ec_key_pair: Option<party_one::EphEcKeyPair>,
    p1_msg1_from_p2: Option<Li17SignMsg1>,
    p2_eph_comm_witness: Option<party_two::EphCommWitness>,
    p2_eph_ec_key_pair: Option<party_two::EphEcKeyPair>,

}

pub type Li17SignMsg2 = party_one::EphKeyGenFirstMsg;

pub struct Li17SignContext3 {
    pub index: u16,
    pub public: Point<Secp256r1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,
    hash: BigInt,
    p1_eph_ec_key_pair: Option<party_one::EphEcKeyPair>,
    p1_msg1_from_p2: Option<Li17SignMsg1>,
}

pub type Li17SignMsg3 = (party_two::PartialSig, party_two::EphKeyGenSecondMsg);

pub fn li17_sign1( context: Li17SignContext, message_hash: Vec<u8> ) -> Result<(Option<Li17SignMsg1>, Li17SignContext1), &'static str> {

    if context.index == 0 {
        let context1 = Li17SignContext1 {
            index: 0,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: BigInt::from_bytes(&message_hash),
            p2_eph_comm_witness: None,
            p2_eph_ec_key_pair: None,

        };
        return Ok((None, context1))
    } else {
        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
                        party_two::EphKeyGenFirstMsg::create_commitments();

        let context1 = Li17SignContext1 {
            index: 1,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: BigInt::from_bytes(&message_hash),
            p2_eph_comm_witness: Some(eph_comm_witness),
            p2_eph_ec_key_pair: Some(eph_ec_key_pair_party2),
        };
        return Ok((Some(eph_party_two_first_message), context1))
    }
}

pub fn li17_sign2( msg: Li17SignMsg1, context: Li17SignContext1) -> Result<(Option<Li17SignMsg2>, Li17SignContext2), &'static str> {

    if context.index == 0 {
        let (eph_party_one_first_message, eph_ec_key_pair_party1) = party_one::EphKeyGenFirstMsg::create();
        let context2 = Li17SignContext2 {
            index: 0,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: context.hash,
            p1_eph_ec_key_pair: Some(eph_ec_key_pair_party1),
            p1_msg1_from_p2: Some(msg),
            p2_eph_comm_witness: None,
            p2_eph_ec_key_pair: None,

        };
        return Ok((Some(eph_party_one_first_message), context2))

    } else {
        let context2 = Li17SignContext2 {
            index: 1,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: context.hash,
            p1_eph_ec_key_pair: None,
            p1_msg1_from_p2: None,
            p2_eph_comm_witness: context.p2_eph_comm_witness,
            p2_eph_ec_key_pair: context.p2_eph_ec_key_pair,

        };
        return Ok((None, context2))
    }
}

pub fn li17_sign3( msg: Option<Li17SignMsg2>, context: Li17SignContext2) -> Result<(Option<Li17SignMsg3>, Li17SignContext3), &'static str> {

    if context.index == 0 {
        let context3 = Li17SignContext3 {
            index: 0,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            hash: context.hash,
            p1_eph_ec_key_pair: context.p1_eph_ec_key_pair,
            p1_msg1_from_p2: context.p1_msg1_from_p2,
        };
        return Ok((None, context3))

    } else {

        if context.p2_eph_comm_witness.is_none() || context.p2_eph_ec_key_pair.is_none()
           || context.p2_private.is_none() || context.p2_eph_ec_key_pair.is_none() {
            return Err("invalid context");
        }
        let msg = msg.unwrap();
        let p2_paillier_public = context.p2_paillier_public.unwrap();
        let p2_private = context.p2_private.unwrap();
        let p2_eph_comm_witness = context.p2_eph_comm_witness.unwrap();
        let p2_eph_ec_key_pair = context.p2_eph_ec_key_pair.unwrap();

    	let eph_party_two_second_message =
            party_two::EphKeyGenSecondMsg::verify_and_decommit(
                p2_eph_comm_witness.clone(),
                &msg,
            );

        if eph_party_two_second_message.is_err(){
            return Err("party1 DLog proof failed")
        }

        let partial_sig = party_two::PartialSig::compute(
            &p2_paillier_public.ek,
            &p2_paillier_public.encrypted_secret_share,
            &p2_private,
            &p2_eph_ec_key_pair,
            &msg.public_share,
            &context.hash,
        );

        let context3 = Li17SignContext3 {
            index: 1,
            public: context.public,
            p1_private: context.p1_private,
            p2_private: Some(p2_private),
            p2_paillier_public: Some(p2_paillier_public),
            hash: context.hash,
            p1_eph_ec_key_pair: None,
            p1_msg1_from_p2: None,

        };
        return Ok((Some((partial_sig, eph_party_two_second_message.unwrap())), context3))
    }
}

pub fn li17_sign4( msg: Option<Li17SignMsg3>, context: Li17SignContext3) -> Result<Option<Vec<u8>>, &'static str> {

    if context.index == 0 {
        let (partial_sig, eph_party_two_second_message) = msg.unwrap();
        if context.p1_private.is_none() || context.p1_msg1_from_p2.is_none()
           || context.p1_eph_ec_key_pair.is_none() {
               return Err("invalid context")
           }

       	let _eph_party_one_second_message =
            party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
                &context.p1_msg1_from_p2.unwrap(),
                &eph_party_two_second_message,
            );

        let sig = party_one::Signature::compute(
            &context.p1_private.unwrap(),
            &partial_sig.c3,
            &context.p1_eph_ec_key_pair.unwrap(),
            &eph_party_two_second_message.comm_witness.public_share,
        );

        if party_one::verify(&sig, &context.public, &context.hash).is_err() {
            return Err("invalid signature")
        }
        return Ok(Some([sig.r.to_bytes(), sig.s.to_bytes()].concat()))

    } else {
        return Ok(None)
    }
}
