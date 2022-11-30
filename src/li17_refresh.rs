use crate::li17_key_gen::{Li17SignP1Context, Li17SignP2Context};
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use curv::elliptic::curves::{p256::Secp256r1, Point, Scalar};
use curv::BigInt;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement};
use paillier::EncryptionKey;
use sha2::Sha256;
use zk_paillier::zkproofs::{CompositeDLogProof, NiCorrectKeyProof, SALT_STRING};

pub struct Li17RefreshP1Context1 {
    public: Point<Secp256r1>,
    public_p1: Point<Secp256r1>,
    public_p2: Point<Secp256r1>,
    p1_private: party_one::Party1Private,
    p1_m1: Scalar<Secp256r1>,
    p1_r1: Scalar<Secp256r1>,
}

pub type Li17RefreshP1Msg1 = coin_flip_optimal_rounds::Party1FirstMessage<Secp256r1, Sha256>;

pub type Li17RefreshP1Msg2 = (
    coin_flip_optimal_rounds::Party1SecondMessage<Secp256r1, Sha256>,
    NiCorrectKeyProof,
    PDLwSlackStatement,
    PDLwSlackProof,
    CompositeDLogProof,
    EncryptionKey,
    BigInt,
);

pub struct Li17RefreshP2Context1 {
    public: Point<Secp256r1>,
    public_p1: Point<Secp256r1>,
    public_p2: Point<Secp256r1>,
    p2_private: party_two::Party2Private,
    p2_coin_flip_first_message: Li17RefreshP2Msg1,
    p2_msg1_from_p1: coin_flip_optimal_rounds::Party1FirstMessage<Secp256r1, Sha256>,
}

pub type Li17RefreshP2Msg1 = coin_flip_optimal_rounds::Party2FirstMessage<Secp256r1>;

pub fn li17_p1_refresh1(
    context: Li17SignP1Context,
) -> Result<(Li17RefreshP1Msg1, Li17RefreshP1Context1), &'static str> {
    let (p1_coin_flip_first_message, m1, r1) =
        coin_flip_optimal_rounds::Party1FirstMessage::<Secp256r1, Sha256>::commit();

    let context1 = Li17RefreshP1Context1 {
        public: context.public,
        public_p1: context.public_p1,
        public_p2: context.public_p2,
        p1_private: context.p1_private,
        p1_m1: m1,
        p1_r1: r1,
    };
    Ok((p1_coin_flip_first_message, context1))
}

pub fn li17_p1_refresh2(
    msg: Li17RefreshP2Msg1,
    context: Li17RefreshP1Context1,
) -> Result<(Li17RefreshP1Msg2, Li17SignP1Context), &'static str> {
    let (p1_second_message, res) =
        coin_flip_optimal_rounds::Party1SecondMessage::<Secp256r1, Sha256>::reveal(
            &msg.seed,
            &context.p1_m1,
            &context.p1_r1,
        );

    let (
        ek_new,
        c_key_new,
        new_private,
        correct_key_proof,
        pdl_statement,
        pdl_proof,
        composite_dlog_proof,
    ) = party_one::Party1Private::refresh_private_key(&context.p1_private, &res.to_bigint());

    let sign_context = Li17SignP1Context {
        public: context.public,
        public_p1: context.public_p1 * &res,
        public_p2: context.public_p2 * &res.invert().unwrap(),
        p1_private: new_private,
    };

    Ok((
        (
            p1_second_message,
            correct_key_proof,
            pdl_statement,
            pdl_proof,
            composite_dlog_proof,
            ek_new,
            c_key_new,
        ),
        sign_context,
    ))
}

pub fn li17_p2_refresh1(
    msg: Li17RefreshP1Msg1,
    context: Li17SignP2Context,
) -> Result<(Li17RefreshP2Msg1, Li17RefreshP2Context1), &'static str> {
    let p2_coin_flip_first_message =
        coin_flip_optimal_rounds::Party2FirstMessage::share(&msg.proof);
    let context2 = Li17RefreshP2Context1 {
        public: context.public,
        public_p1: context.public_p1,
        public_p2: context.public_p2,
        p2_private: context.p2_private,
        p2_coin_flip_first_message: p2_coin_flip_first_message.clone(),
        p2_msg1_from_p1: msg,
    };
    Ok((p2_coin_flip_first_message, context2))
}

pub fn li17_p2_refresh2(
    msg: Li17RefreshP1Msg2,
    context: Li17RefreshP2Context1,
) -> Result<Li17SignP2Context, &'static str> {
    let res = coin_flip_optimal_rounds::finalize(
        &msg.0.proof,
        &context.p2_coin_flip_first_message.seed,
        &context.p2_msg1_from_p1.proof.com,
    );
    let party_two_paillier = party_two::PaillierPublic {
        ek: msg.5.clone(),
        encrypted_secret_share: msg.6.clone(),
    };

    if party_two::PaillierPublic::pdl_verify(
        &msg.4,
        &msg.2,
        &msg.3,
        &party_two_paillier,
        &(context.public_p1.clone() * &res),
    )
    .is_err()
    {
        return Err("proof failed");
    }

    if msg.1.verify(&party_two_paillier.ek, SALT_STRING).is_err() {
        return Err("proof failed");
    }

    let sign_context = Li17SignP2Context {
        public: context.public,
        public_p1: context.public_p1 * &res,
        public_p2: context.public_p2 * &res.invert().unwrap(),
        p2_private: party_two::Party2Private::update_private_key(
            &context.p2_private,
            &res.invert().unwrap().to_bigint(),
        ),
        p2_paillier_public: party_two_paillier,
    };
    Ok(sign_context)
}
