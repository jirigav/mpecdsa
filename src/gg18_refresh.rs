/*
Copyright 2021

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#![allow(non_snake_case)]
use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof,
        secret_sharing::feldman_vss::VerifiableSS
    },
    elliptic::curves::{p256::Secp256r1, Point, Scalar},
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2,
    Phase5DDecom2, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SharedKeys,
};
use curv::cryptographic_primitives::hashing::DigestExt;
use paillier::EncryptionKey;
use multi_party_ecdsa::utilities::mta::*;
use sha2::{Sha256, Digest};
use crate::gg18_key_gen::GG18SignContext;
use serde::{Serialize, Deserialize};
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::CommWitness;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PSSFirstMessage {
    pub k_commitment: BigInt,
    pub zk_pok_commitment: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18RefreshContext1 {
    pub threshold: u16,
    pub index: u16,
    pub party_keys: Keys,
    pub vss_scheme_vec: Vec<VerifiableSS<Secp256r1>>,
    pub shared_keys: SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub pk: Point<Secp256r1>,
    pss_first_message: PSSFirstMessage,
    com_witness: CommWitness<Secp256r1, Sha256>,
    k_i: Scalar::<Secp256r1>
}

pub type GG18RefreshMsg1 = PSSFirstMessage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18RefreshContext2 {
    pub threshold: u16,
    pub index: u16,
    pub party_keys: Keys,
    pub vss_scheme_vec: Vec<VerifiableSS<Secp256r1>>,
    pub shared_keys: SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub pk: Point<Secp256r1>,
    com_witness: CommWitness<Secp256r1, Sha256>,
    zk_comm_vec: Vec<PSSFirstMessage>,
    k_i: Scalar::<Secp256r1>
}

pub type GG18RefreshMsg2 = CommWitness<Secp256r1, Sha256>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GG18RefreshContext3 {
    pub threshold: u16,
    pub index: u16,
    pub party_keys: Keys,
    pub vss_scheme_vec: Vec<VerifiableSS<Secp256r1>>,
    pub shared_keys: SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub pk: Point<Secp256r1>,
    z_b: Scalar<Secp256r1>,
    epoch: BigInt,
    K: Point<Secp256r1>,
    d: BigInt,
    e_fe: Scalar<Secp256r1>,
}

pub type GG18RefreshMsg3= Scalar<Secp256r1>;



pub fn gg18_refresh1(context: GG18SignContext)
-> Result<(GG18RefreshMsg1, GG18RefreshContext1), &'static str> {

    //################# PSS 2: Sample new polynomial ##############

    //phase (2i)  coin toss folded with phase (3i) common k:
    let k_i = Scalar::<Secp256r1>::random();
    let G_k_i = Point::<Secp256r1>::generator()* &k_i;
    let d_log_proof = DLogProof::prove(&k_i);
    // we use hash based commitment
    let pk_commitment_blind_factor = BigInt::sample(256);
    let k_commitment = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(G_k_i.to_bytes(true).as_ref()),
        &pk_commitment_blind_factor,
    );

    let zk_pok_blind_factor = BigInt::sample(256);
    let zk_pok_commitment = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
        &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
        &zk_pok_blind_factor,
    );
    let com_witness = CommWitness {
        pk_commitment_blind_factor,
        zk_pok_blind_factor,
        public_share: G_k_i.clone(),
        d_log_proof,
    };

    let pss_first_message = PSSFirstMessage {
        k_commitment,
        zk_pok_commitment,
    };

    let context1 = GG18RefreshContext1 {
        threshold: context.threshold,
        index: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        shared_keys: context.shared_keys,
        paillier_key_vec: context.paillier_key_vec,
        pk: context.pk,
        pss_first_message,
        com_witness,
        k_i
    };
    Ok((context1.pss_first_message.clone(), context1))
}

pub fn gg18_refresh2(mut messages: Vec<GG18RefreshMsg1> ,context: GG18RefreshContext1)
-> Result<(GG18RefreshMsg2, GG18RefreshContext2), &'static str> {

    messages.insert(context.index as usize, context.pss_first_message.clone());
    let context2 = GG18RefreshContext2 {
        threshold: context.threshold,
        index: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        shared_keys: context.shared_keys,
        paillier_key_vec: context.paillier_key_vec,
        pk: context.pk,
        com_witness: context.com_witness,
        zk_comm_vec: messages,
        k_i: context.k_i,
    };
    Ok((context2.com_witness.clone(), context2))
}

pub fn gg18_refresh3(mut messages: Vec<GG18RefreshMsg2> ,context: GG18RefreshContext2)
-> Result<(GG18RefreshMsg3, GG18RefreshContext3), &'static str> {

    messages.insert(context.index as usize, context.com_witness.clone());
    let i = ((context.index + 1) % 2) as usize;
    let pk_commitment = &context.zk_comm_vec[i].k_commitment;
    let zk_pok_commitment = &context.zk_comm_vec[i].zk_pok_commitment;
    let zk_pok_blind_factor = &messages[i].zk_pok_blind_factor;
    let public_share = &messages[i].public_share;
    let pk_commitment_blind_factor = &messages[i].pk_commitment_blind_factor;
    let d_log_proof = &messages[i].d_log_proof;

    if pk_commitment
        != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(public_share.to_bytes(true).as_ref()),
            &pk_commitment_blind_factor,
        ) {
        return Err("msg");
    };
    if zk_pok_commitment
        != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(d_log_proof.pk_t_rand_commitment.to_bytes(true).as_ref()),
            &zk_pok_blind_factor,
        ) {
        return Err("msg");
    }
    let res = DLogProof::verify(&d_log_proof);
    if res.is_err() {
        return Err("error zk-dlog verify")
    }
    let d: BigInt = Sha256::new()
    .chain_bigint(&BigInt::from_bytes(messages[0].public_share.to_bytes(true).as_ref()))
    .chain_bigint(&BigInt::from_bytes(messages[1].public_share.to_bytes(true).as_ref()))
    .result_bigint();


    let K = &messages[0].public_share + &messages[1].public_share;

    let epoch = BigInt::one();

    let e: BigInt = Sha256::new()
    //.chain_bigint(&BigInt::from_bytes(R.to_bytes(true).as_ref()))
    .chain_bigint(&BigInt::from_bytes(K.to_bytes(true).as_ref()))
    .chain_bigint(&d)
    .chain_bigint(&epoch)
    .result_bigint();

    let private = PartyPrivate::set_private(context.party_keys.clone(), context.shared_keys.clone());
    let sign_keys = SignKeys::create(
        &private,
        &context.vss_scheme_vec[context.index as usize],
        context.index,
        &[0, 1],
    );
    let e_fe = Scalar::<Secp256r1>::from(&e);
    let z_b = e_fe.clone() * &sign_keys.w_i + context.k_i;


    let context3 = GG18RefreshContext3 {
        threshold: context.threshold,
        index: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        shared_keys: context.shared_keys,
        paillier_key_vec: context.paillier_key_vec,
        pk: context.pk,
        z_b,
        epoch,
        K,
        d,
        e_fe,

    };
    Ok((context3.z_b.clone(), context3))
}

pub fn gg18_refresh4(mut messages: Vec<GG18RefreshMsg3> ,context: GG18RefreshContext3)
-> Result<GG18SignContext, &'static str> {

    let z = messages[0].clone() + context.z_b.clone();


    let zG = Point::<Secp256r1>::generator() * &z;


    let e_pk = &context.shared_keys.y * &context.e_fe;
    let e_pk_K = e_pk + &context.K;
    assert_eq!(zG, e_pk_K);
    let d_fe = Scalar::<Secp256r1>::from(&context.d);
    // "ind" is the party index (one base) as it was in keygen. (signers_vec is
    // ordering indices based on time of joining, party_num_int is the number of the party
    // in the signing protocol)
    let ind = context.index;
    let ind_fe = Scalar::<Secp256r1>::from(&BigInt::from(ind as i32));

    let db = d_fe.clone() * &ind_fe;
    let li = VerifiableSS::<Secp256r1>::map_share_to_new_params(&context.vss_scheme_vec[ind as usize].parameters, ind, &[0,1]);

    let private = PartyPrivate::set_private(context.party_keys.clone(), context.shared_keys.clone());
    let mut sign_keys = SignKeys::create(
        &private,
        &context.vss_scheme_vec[context.index as usize],
        context.index,
        &[0, 1],
    );


    let db_new_param = db * &li;
    let sk_i_tag = sign_keys.w_i + &db_new_param;
    let sk_i_tag_G = Point::<Secp256r1>::generator() * &sk_i_tag;
    sign_keys.w_i = sk_i_tag;
    sign_keys.g_w_i = sk_i_tag_G;

    // g_w_j[0] is the counter party local public key: here is how we update it.
    let i = (context.index + 1) % 2;

    let refresh_point =
        Point::<Secp256r1>::generator() * &d_fe * &Scalar::<Secp256r1>::from(&BigInt::from(ind as i32));
    let refresh_point_new_param = Keys::update_commitments_to_xi(
        &refresh_point,
        &context.vss_scheme_vec[i as usize],
        i,
        &[0, 1],
    );

    messages.insert(context.index as usize, context.z_b.clone());
    let context = GG18SignContext {
        threshold: context.threshold,
        index: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        shared_keys: context.shared_keys,
        paillier_key_vec: context.paillier_key_vec,
        pk: context.pk,

    };
    Ok(context)
}
