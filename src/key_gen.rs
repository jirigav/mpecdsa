/*
Copyright 2021 Jiří Gavenda

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

use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::p256::{FE, GE},
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, SharedKeys, Parameters,
};
use paillier::EncryptionKey;

pub struct KeyGenContext1 {
    params: Parameters,
    index: u16,
    party_keys: Keys,
    bc_i: KeyGenBroadcastMessage1,
    decom_i: KeyGenDecommitMessage1
}

pub type KeyGenMsg1 = KeyGenBroadcastMessage1;

pub struct KeyGenContext2 {
    params: Parameters,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    decom_i: KeyGenDecommitMessage1

}

pub type KeyGenMsg2 = KeyGenDecommitMessage1;

pub struct KeyGenContext3 {
    params: Parameters,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    vss_scheme: VerifiableSS<GE>,
    secret_shares: Vec<FE>,
    y_sum: GE,
    point_vec: Vec<GE>,
}

pub type KeyGenMsg3 = FE;

pub struct KeyGenContext4 {
    params: Parameters,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    vss_scheme: VerifiableSS<GE>,
    y_sum: GE,
    point_vec: Vec<GE>,
    party_shares: Vec<FE>,
}

pub type KeyGenMsg4 = VerifiableSS<GE>;

pub struct KeyGenContext5 {
    params: Parameters,
    index: u16,
    party_keys: Keys,
    bc1_vec: Vec<KeyGenBroadcastMessage1>,
    vss_scheme_vec: Vec<VerifiableSS<GE>>,
    y_sum: GE,
    point_vec: Vec<GE>,
    shared_keys: SharedKeys,
    dlog_proof: DLogProof<GE>
}

pub type KeyGenMsg5 = DLogProof<GE>;

pub struct SignContext {
    threshold: u16,
    index: u16,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<GE>>,
    shared_keys: SharedKeys,
    paillier_key_vec: Vec<EncryptionKey>,
    y_sum: GE,
}

/*
Generate keys
*/

pub fn key_gen_1(parties : u16, threshold : u16, index : u16) -> (KeyGenMsg1, KeyGenContext1) {
    let params = Parameters {
        threshold: threshold - 1,
        share_count: parties,
    };

    let party_keys = Keys::create(index as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    let context1 = KeyGenContext1 {
        params: params,
        index: index,
        party_keys: party_keys,
        bc_i: bc_i.clone(),
        decom_i: decom_i,
    };
    (bc_i, context1)
}

pub fn key_gen_2(messages: Vec<KeyGenMsg1>, context: KeyGenContext1) -> (KeyGenMsg2, KeyGenContext2) {
    let (bc_i, decom_i) = (context.bc_i, context.decom_i);

    let mut bc1_vec = messages;

    bc1_vec.insert(context.index as usize, bc_i);

    let context2 = KeyGenContext2 {
        params: context.params,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: bc1_vec,
        decom_i: decom_i.clone(),
    };
    (decom_i, context2)
}


/*
Messages from this function should be sent over an encrypted channel 
*/
pub fn key_gen_3(messages: Vec<KeyGenMsg2>, context: KeyGenContext2) -> (Vec<KeyGenMsg3>, KeyGenContext3) {

    let mut j = 0;
    let mut point_vec: Vec<GE> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    for i in 0..context.params.share_count {
        if i == context.index {
            point_vec.push(context.decom_i.y_i);
            decom_vec.push(context.decom_i.clone());
        } else {
            let decom_j  = &messages[j];
            point_vec.push(decom_j.y_i);
            decom_vec.push(decom_j.clone());
            j = j + 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = context.party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &context.params, &decom_vec, &context.bc1_vec,
        )
        .expect("invalid key");

    let mut messages_output = secret_shares.clone();

    messages_output.remove(context.index as usize);

    let context3 = KeyGenContext3 {
        params: context.params,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: context.bc1_vec,
        vss_scheme: vss_scheme,
        secret_shares: secret_shares,
        y_sum: y_sum,
        point_vec: point_vec,
    };
    (messages_output, context3)
}


pub fn key_gen_4(messages: Vec<KeyGenMsg3>, context: KeyGenContext3) -> (KeyGenMsg4, KeyGenContext4) {
    let mut party_shares = messages;
    party_shares.insert(context.index as usize, context.secret_shares[context.index as usize]);

    let context4 = KeyGenContext4 {
        params: context.params,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: context.bc1_vec,
        vss_scheme: context.vss_scheme,
        y_sum: context.y_sum,
        point_vec: context.point_vec,
        party_shares: party_shares
    };

    (context4.vss_scheme.clone(), context4)
}

pub fn key_gen_5(messages: Vec<KeyGenMsg4>, context: KeyGenContext4) -> (KeyGenMsg5, KeyGenContext5) {
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = messages;
    vss_scheme_vec.insert(context.index as usize, context.vss_scheme.clone());

    let (shared_keys, dlog_proof) = context.party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &context.params,
            &context.point_vec,
            &context.party_shares,
            &vss_scheme_vec,
            context.index as usize + 1,
        )
        .expect("invalid vss");

    let context5 = KeyGenContext5 {
        params: context.params,
        index: context.index,
        party_keys: context.party_keys,
        bc1_vec: context.bc1_vec,
        vss_scheme_vec: vss_scheme_vec,
        y_sum: context.y_sum,
        point_vec: context.point_vec,
        shared_keys: shared_keys,
        dlog_proof: dlog_proof
    };

    (context5.dlog_proof.clone(), context5)
}

pub fn key_gen_6(messages: Vec<KeyGenMsg5>, context: KeyGenContext5) -> SignContext{

    let bc1_vec = context.bc1_vec;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = messages;
    dlog_proof_vec.insert(context.index as usize, context.dlog_proof.clone());

    Keys::verify_dlog_proofs(&context.params, &dlog_proof_vec, &context.point_vec).expect("bad dlog proof");

    let paillier_key_vec = (0..context.params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let sign_context = SignContext {
        threshold: context.params.threshold + 1,
        index: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        shared_keys: context.shared_keys,
        paillier_key_vec: paillier_key_vec,
        y_sum: context.y_sum,
    };
    sign_context
}
