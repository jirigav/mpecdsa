use crate::li17_key_gen::Li17SignContext;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::elliptic::curves::{p256::Secp256r1, Point, Scalar};
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use sha2::Sha256;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use zk_paillier::zkproofs::CompositeDLogProof;
use zk_paillier::zkproofs::NiCorrectKeyProof;
use curv::BigInt;
use paillier::EncryptionKey;
use zk_paillier::zkproofs::SALT_STRING;

pub struct Li17RefreshContext1 {
    index: u16,
    public: Point<Secp256r1>,
    public_p1: Point<Secp256r1>,
    public_p2: Point<Secp256r1>,
    p1_private: Option<party_one::Party1Private>,
    p2_private: Option<party_two::Party2Private>,
    p2_paillier_public: Option<party_two::PaillierPublic>,
    p1_m1: Option<Scalar<Secp256r1>>,
    p1_r1: Option<Scalar<Secp256r1>>

}

pub type Li17RefreshMsg1 = coin_flip_optimal_rounds::Party1FirstMessage::<Secp256r1, Sha256>;

pub struct Li17RefreshContext2 {
    index: u16,
    public: Point<Secp256r1>,
    public_p1: Point<Secp256r1>,
    public_p2: Point<Secp256r1>,
    p1_private: Option<party_one::Party1Private>,
    p2_private: Option<party_two::Party2Private>,
    p2_paillier_public: Option<party_two::PaillierPublic>,
    p1_m1: Option<Scalar<Secp256r1>>,
    p1_r1: Option<Scalar<Secp256r1>>,
    p2_coin_flip_first_message: Option<Li17RefreshMsg2>,
    p2_msg1_from_p1: Option<coin_flip_optimal_rounds::Party1FirstMessage::<Secp256r1, Sha256>>

}

pub type Li17RefreshMsg2 = coin_flip_optimal_rounds::Party2FirstMessage::<Secp256r1>;

pub struct Li17RefreshContext3 {
    index: u16,
    public: Point<Secp256r1>,
    public_p1: Point<Secp256r1>,
    public_p2: Point<Secp256r1>,
    p1_private: Option<party_one::Party1Private>,
    p2_private: Option<party_two::Party2Private>,
    p2_paillier_public: Option<party_two::PaillierPublic>,
    p2_coin_flip_first_message: Option<Li17RefreshMsg2>,
    p2_msg1_from_p1: Option<coin_flip_optimal_rounds::Party1FirstMessage::<Secp256r1, Sha256>>
}

pub type Li17RefreshMsg3 = (coin_flip_optimal_rounds::Party1SecondMessage::<Secp256r1, Sha256>,
                            NiCorrectKeyProof, PDLwSlackStatement, PDLwSlackProof,
                            CompositeDLogProof, EncryptionKey, BigInt);

pub fn li17_refresh1( context: Li17SignContext ) -> Result<(Option<Li17RefreshMsg1>, Li17RefreshContext1), &'static str> {

    if context.index == 0 {
        let (p1_coin_flip_first_message, m1, r1) = coin_flip_optimal_rounds::Party1FirstMessage::<Secp256r1, Sha256>::commit();
        let context1 = Li17RefreshContext1 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: Some(m1),
            p1_r1: Some(r1),
        };
        return Ok((Some(p1_coin_flip_first_message), context1))

    } else {
        let context1 = Li17RefreshContext1 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: None,
            p1_r1: None,
        };
        return Ok((None, context1))
    }
}

pub fn li17_refresh2( msg: Li17RefreshMsg1,context: Li17RefreshContext1 )
-> Result<(Option<Li17RefreshMsg2>, Li17RefreshContext2), &'static str> {

    if context.index == 0 {
        let context2 = Li17RefreshContext2 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: context.p1_m1,
            p1_r1: context.p1_r1,
            p2_coin_flip_first_message: None,
            p2_msg1_from_p1: None,
        };
        return Ok((None, context2))

    } else {
        let p2_coin_flip_first_message = coin_flip_optimal_rounds::Party2FirstMessage::share(&msg.proof);
        let context2 = Li17RefreshContext2 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p1_m1: None,
            p1_r1: None,
            p2_coin_flip_first_message: Some(p2_coin_flip_first_message.clone()),
            p2_msg1_from_p1: Some(msg),
        };
        return Ok((Some(p2_coin_flip_first_message), context2))

    }
}

pub fn li17_refresh3( msg: Li17RefreshMsg2,context: Li17RefreshContext2 )
-> Result<(Option<Li17RefreshMsg3>, Li17RefreshContext3), &'static str> {

    if context.index == 0 {
        let (p1_second_message, res) = coin_flip_optimal_rounds::Party1SecondMessage::<Secp256r1, Sha256>::reveal(
                            &msg.seed, &context.p1_m1.unwrap(), &context.p1_r1.unwrap());


        let (ek_new, c_key_new, new_private, correct_key_proof,
            pdl_statement, pdl_proof, composite_dlog_proof,) =
            party_one::Party1Private::refresh_private_key(&context.p1_private.unwrap(), &res.to_bigint());

        let context3 = Li17RefreshContext3 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1 * &res,
            public_p2: context.public_p2 * &res.invert().unwrap(),
            p1_private: Some(new_private),
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p2_coin_flip_first_message: context.p2_coin_flip_first_message,
            p2_msg1_from_p1: context.p2_msg1_from_p1,
        };

        return Ok((Some((p1_second_message, correct_key_proof, pdl_statement,
                         pdl_proof, composite_dlog_proof, ek_new, c_key_new)), context3))

    } else {
        let context3 = Li17RefreshContext3 {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: None,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
            p2_coin_flip_first_message: context.p2_coin_flip_first_message,
            p2_msg1_from_p1: context.p2_msg1_from_p1,
        };
        return Ok((None, context3))

    }
}

pub fn li17_refresh4( msg: Li17RefreshMsg3,context: Li17RefreshContext3 )
-> Result<Li17SignContext, &'static str> {

    if context.index == 0 {

        let sign_context = Li17SignContext {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1,
            public_p2: context.public_p2,
            p1_private: context.p1_private,
            p2_private: context.p2_private,
            p2_paillier_public: context.p2_paillier_public,
        };

        return Ok(sign_context)

    } else {

        let res = coin_flip_optimal_rounds::finalize(
            &msg.0.proof,
            &context.p2_coin_flip_first_message.unwrap().seed,
            &context.p2_msg1_from_p1.unwrap().proof.com,
        );
        let party_two_paillier = party_two::PaillierPublic {
            ek: msg.5.clone(),
            encrypted_secret_share: msg.6.clone(),
        };

        if party_two::PaillierPublic::pdl_verify(&msg.4, &msg.2, &msg.3, &party_two_paillier,
                                                 &(context.public_p1.clone() * &res)).is_err() {
            return Err("proof failed")
        }

        if msg.1.verify(&party_two_paillier.ek, SALT_STRING).is_err() {
            return Err("proof failed")
        }

        let sign_context = Li17SignContext {
            index: context.index,
            public: context.public,
            public_p1: context.public_p1 * &res,
            public_p2: context.public_p2 * &res.invert().unwrap(),
            p1_private: None,
            p2_private: Some(party_two::Party2Private::update_private_key(
                &context.p2_private.unwrap(),
                &res.invert().unwrap().to_bigint(),
            )),
            p2_paillier_public: Some(party_two_paillier),
        };
        return Ok(sign_context)

    }
}
