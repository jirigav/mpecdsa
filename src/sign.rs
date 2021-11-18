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

use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof,
        secret_sharing::feldman_vss::VerifiableSS
    },
    elliptic::curves::p256::{FE, GE},
    elliptic::curves::traits::ECScalar,
    BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2, SignBroadcastPhase1, SignDecommitPhase1, SignKeys
};
use paillier::EncryptionKey;
use multi_party_ecdsa::utilities::mta::*;
use crate::key_gen::SignContext;

/*
Sign data
*/
#[allow(dead_code)]
pub struct SignContext1 {
    indices: Vec<usize>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<GE>>,
    paillier_key_vec: Vec<EncryptionKey>,
    y_sum: GE,
    sign_keys: SignKeys,
    xi_com_vec: Vec<GE>,
    com: SignBroadcastPhase1,
    decommit: SignDecommitPhase1
}

#[allow(dead_code)]
pub type SignMsg1 = (SignBroadcastPhase1, MessageA);

#[allow(dead_code)]
pub struct SignContext2 {
    indices: Vec<usize>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<GE>>,
    y_sum: GE,
    sign_keys: SignKeys,
    xi_com_vec: Vec<GE>,
    decommit: SignDecommitPhase1,
    bc1_vec: Vec<SignBroadcastPhase1>,
    beta_vec: Vec<FE>,
    ni_vec: Vec<FE>
}

#[allow(dead_code)]
pub type SignMsg2 = (MessageB, MessageB);

#[allow(dead_code)]
pub struct SignContext3 {
    indices: Vec<usize>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    y_sum: GE,
    sign_keys: SignKeys,
    decommit: SignDecommitPhase1,
    bc1_vec: Vec<SignBroadcastPhase1>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    delta_i: FE,
    sigma: FE
}

#[allow(dead_code)]
pub type SignMsg3 = FE;

#[allow(dead_code)]
pub struct SignContext4 {
    indices: Vec<usize>,
    threshold_index: usize,
    message_hash: Vec<u8>,
    threshold: u16,
    party_id: u16,
    y_sum: GE,
    sign_keys: SignKeys,
    decommit: SignDecommitPhase1,
    bc1_vec: Vec<SignBroadcastPhase1>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    sigma: FE,
    delta_inv: FE
}

#[allow(dead_code)]
pub type SignMsg4 = SignDecommitPhase1;

#[allow(dead_code)]
pub struct SignContext5 {
    indices: Vec<usize>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase5_com: Phase5Com1,
    phase_5a_decom: Phase5ADecom1,
    helgamal_proof: HomoELGamalProof<GE>,
    dlog_proof_rho: DLogProof<GE>,
    r: GE
}

#[allow(dead_code)]
pub type SignMsg5 = Phase5Com1;

#[allow(dead_code)]
pub struct SignContext6 {
    indices: Vec<usize>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase_5a_decom: Phase5ADecom1,
    helgamal_proof: HomoELGamalProof<GE>,
    dlog_proof_rho: DLogProof<GE>,
    r: GE,
    commit5a_vec: Vec<Phase5Com1>
}

#[allow(dead_code)]
pub type SignMsg6 = (Phase5ADecom1, HomoELGamalProof<GE>, DLogProof<GE>);

#[allow(dead_code)]
pub struct SignContext7 {
    indices: Vec<usize>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase_5a_decom: Phase5ADecom1,
    decommit5a_and_elgamal_and_dlog_vec_includes_i: Vec<(Phase5ADecom1, HomoELGamalProof<GE>, DLogProof<GE>)>,
    phase_5a_decomm_vec: Vec<Phase5ADecom1>,
    phase5_com2: Phase5Com2,
    phase_5d_decom2: Phase5DDecom2
}

#[allow(dead_code)]
pub type SignMsg7 = Phase5Com2;

#[allow(dead_code)]
pub struct SignContext8 {
    indices: Vec<usize>,
    threshold_index: usize,
    threshold: u16,
    party_id: u16,
    local_sig: LocalSignature,
    phase_5a_decom: Phase5ADecom1,
    decommit5a_and_elgamal_and_dlog_vec_includes_i: Vec<(Phase5ADecom1, HomoELGamalProof<GE>, DLogProof<GE>)>,
    phase_5a_decomm_vec: Vec<Phase5ADecom1>,
    phase_5d_decom2: Phase5DDecom2,
    commit5c_vec: Vec<Phase5Com2>
}

#[allow(dead_code)]
pub type SignMsg8 = Phase5DDecom2;

#[allow(dead_code)]
pub struct SignContext9 {
    threshold: u16,
    local_sig: LocalSignature
}

#[allow(dead_code)]
pub type SignMsg9 = FE;

#[allow(dead_code)]
pub fn sign1(context: SignContext, indices: Vec<usize>, threshold_index: usize, message_hash: Vec<u8>) -> (SignMsg1, SignContext1) {

    let private = PartyPrivate::set_private(context.party_keys.clone(), context.shared_keys);
    let sign_keys = SignKeys::create(
        &private,
        &context.vss_scheme_vec[context.index as usize],
        context.index as usize,
        &indices,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&context.vss_scheme_vec);
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &context.party_keys.ek);

    let context1 = SignContext1 {
        indices: indices,
        threshold_index: threshold_index,
        message_hash: message_hash,
        threshold: context.threshold,
        party_id: context.index,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        paillier_key_vec: context.paillier_key_vec,
        y_sum: context.y_sum,
        sign_keys: sign_keys,
        xi_com_vec: xi_com_vec,
        com: com,
        decommit: decommit
    };

    ((context1.com.clone(), m_a_k), context1)
}

#[allow(dead_code)]
pub fn sign2(messages: Vec<SignMsg1>, context: SignContext1) -> (Vec<SignMsg2>, SignContext2) {

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            bc1_vec.push(context.com.clone());

        } else {

            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) = messages[j].clone();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);

            j += 1;

        }
    }
    assert_eq!(context.indices.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut send_vec: Vec<(MessageB, MessageB)> = Vec::new();
    let mut beta_vec: Vec<FE> = Vec::new();
    let mut ni_vec: Vec<FE> = Vec::new();
    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) != context.threshold_index{
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &context.sign_keys.gamma_i,
                &context.paillier_key_vec[context.indices[i as usize]],
                m_a_vec[j].clone(),
            );
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &context.sign_keys.w_i,
                &context.paillier_key_vec[context.indices[i as usize]],
                m_a_vec[j].clone(),
            );
            send_vec.push((m_b_gamma, m_b_w));
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }

    let context2 = SignContext2 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        message_hash: context.message_hash,
        threshold: context.threshold,
        party_id: context.party_id,
        party_keys: context.party_keys,
        vss_scheme_vec: context.vss_scheme_vec,
        y_sum: context.y_sum,
        sign_keys: context.sign_keys,
        xi_com_vec: context.xi_com_vec,
        decommit: context.decommit,
        bc1_vec: bc1_vec,
        beta_vec: beta_vec,
        ni_vec: ni_vec
    };

    (send_vec, context2)

}

#[allow(dead_code)]
pub fn sign3(messages: Vec<SignMsg2>, context: SignContext2) -> (SignMsg3, SignContext3) {

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();
    for i in 0..(context.threshold - 1) {

        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) = messages[i as usize].clone();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);

    }
    let mut alpha_vec: Vec<FE> = Vec::new();
    let mut miu_vec: Vec<FE> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) != context.threshold_index {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&context.party_keys.dk, &context.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&context.party_keys.dk, &context.sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &context.xi_com_vec[context.indices[i as usize]],
                &context.vss_scheme_vec[context.indices[i as usize]],
                context.indices[i as usize],
                &context.indices,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }


    let delta_i = context.sign_keys.phase2_delta_i(&alpha_vec, &context.beta_vec);
    let sigma = context.sign_keys.phase2_sigma_i(&miu_vec, &context.ni_vec);

    let context3 = SignContext3 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        message_hash: context.message_hash,
        threshold: context.threshold,
        party_id: context.party_id,
        y_sum: context.y_sum,
        sign_keys: context.sign_keys,
        decommit: context.decommit,
        bc1_vec: context.bc1_vec,
        m_b_gamma_rec_vec: m_b_gamma_rec_vec,
        delta_i: delta_i,
        sigma: sigma
    };

    (delta_i, context3)
}

#[allow(dead_code)]
pub fn sign4(messages: Vec<SignMsg3>, context: SignContext3) -> (SignMsg4, SignContext4) {
    let mut delta_vec: Vec<FE> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            delta_vec.push(context.delta_i.clone());
        } else {
            delta_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    let context4 = SignContext4 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        message_hash: context.message_hash,
        threshold: context.threshold,
        party_id: context.party_id,
        y_sum: context.y_sum,
        sign_keys: context.sign_keys,
        decommit: context.decommit,
        bc1_vec: context.bc1_vec,
        m_b_gamma_rec_vec: context.m_b_gamma_rec_vec,
        sigma: context.sigma,
        delta_inv: delta_inv
    };

    (context4.decommit.clone(), context4)
}

#[allow(dead_code)]
pub fn sign5(messages: Vec<SignMsg4>, context: SignContext4) -> (SignMsg5, SignContext5) {
    let mut bc1_vec = context.bc1_vec.clone();
    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            decommit_vec.push(context.decommit.clone());
        } else {

            decommit_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let decomm_i = decommit_vec.remove(context.threshold_index);
    bc1_vec.remove(context.threshold_index);
    let b_proof_vec = (0..context.m_b_gamma_rec_vec.len())
        .map(|i| &context.m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof<GE>>>();
    let r = SignKeys::phase4(&context.delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let r = r + decomm_i.g_gamma_i * context.delta_inv;

    let message_bn = BigInt::from_bytes(&context.message_hash);
    let local_sig =
        LocalSignature::phase5_local_sig(&context.sign_keys.k_i, &message_bn, &r, &context.sigma, &context.y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    let context5 = SignContext5 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: local_sig,
        phase5_com: phase5_com,
        phase_5a_decom: phase_5a_decom,
        helgamal_proof: helgamal_proof,
        dlog_proof_rho: dlog_proof_rho,
        r: r
    };
    (context5.phase5_com.clone(), context5)

}

#[allow(dead_code)]
pub fn sign6(messages: Vec<SignMsg5>, context: SignContext5) -> (SignMsg6, SignContext6) {
    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            commit5a_vec.push(context.phase5_com.clone());
        } else {
            commit5a_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let context6 = SignContext6 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: context.local_sig,
        phase_5a_decom: context.phase_5a_decom,
        helgamal_proof: context.helgamal_proof,
        dlog_proof_rho: context.dlog_proof_rho,
        r: context.r,
        commit5a_vec: commit5a_vec

    };

    ((context6.phase_5a_decom.clone(), context6.helgamal_proof.clone(),
    context6.dlog_proof_rho.clone()), context6)

}

#[allow(dead_code)]
pub fn sign7(messages: Vec<SignMsg6>, context: SignContext6) -> (SignMsg7, SignContext7) {
    let mut commit5a_vec = context.commit5a_vec;
    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<GE>,
        DLogProof<GE>,
    )> = Vec::new();

    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            decommit5a_and_elgamal_and_dlog_vec.push((
            context.phase_5a_decom.clone(),
            context.helgamal_proof.clone(),
            context.dlog_proof_rho.clone(),
        ));
        } else {
            decommit5a_and_elgamal_and_dlog_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove(context.threshold_index);
    commit5a_vec.remove(context.threshold_index);
    let phase_5a_decomm_vec = (0..(context.threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..(context.threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof<GE>>>();
    let phase_5a_dlog_vec = (0..(context.threshold - 1))
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof<GE>>>();
    let (phase5_com2, phase_5d_decom2) = context.local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &context.phase_5a_decom.V_i,
            &context.r,
        )
        .expect("error phase5");

    let context7 = SignContext7 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: context.local_sig,
        phase_5a_decom: context.phase_5a_decom,
        decommit5a_and_elgamal_and_dlog_vec_includes_i: decommit5a_and_elgamal_and_dlog_vec_includes_i,
        phase_5a_decomm_vec: phase_5a_decomm_vec,
        phase5_com2: phase5_com2,
        phase_5d_decom2: phase_5d_decom2
    };

    (context7.phase5_com2.clone(), context7)
}

#[allow(dead_code)]
pub fn sign8(messages: Vec<SignMsg7>, context: SignContext7) -> (SignMsg8, SignContext8) {
    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            commit5c_vec.push(context.phase5_com2.clone());
        } else {
            commit5c_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let context8 = SignContext8 {
        indices: context.indices,
        threshold_index: context.threshold_index,
        threshold: context.threshold,
        party_id: context.party_id,
        local_sig: context.local_sig,
        phase_5a_decom: context.phase_5a_decom,
        decommit5a_and_elgamal_and_dlog_vec_includes_i: context.decommit5a_and_elgamal_and_dlog_vec_includes_i,
        phase_5a_decomm_vec: context.phase_5a_decomm_vec,
        phase_5d_decom2: context.phase_5d_decom2,
        commit5c_vec: commit5c_vec
    };

    (context8.phase_5d_decom2.clone(), context8)

}

#[allow(dead_code)]
pub fn sign9(messages: Vec<SignMsg8>, context: SignContext8) -> (SignMsg9, SignContext9) {
    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    let mut j = 0;
    for i in 0..context.threshold {
        if (i as usize) == context.threshold_index {
            decommit5d_vec.push(context.phase_5d_decom2.clone());
        } else {

            decommit5d_vec.push(messages[j].clone());
            j += 1;
        }
    }

    let phase_5a_decomm_vec_includes_i = (0..context.threshold)
        .map(|i| {
            context.decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = context.local_sig
        .phase5d(
            &decommit5d_vec,
            &context.commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    let context9 = SignContext9 {
        threshold: context.threshold,
        local_sig: context.local_sig
    };

    (s_i, context9)

}

#[allow(dead_code)]
pub fn sign10(messages: Vec<SignMsg9>, context: SignContext9) -> Vec<u8> {

    let mut s_i_vec: Vec<FE> = Vec::new();

    for i in 0..(context.threshold - 1) {
        s_i_vec.push(messages[i as usize].clone());
    }

    let sig = context.local_sig.output_signature(&s_i_vec).expect("verification failed");

    [sig.r.get_element().to_bytes(), sig.s.get_element().to_bytes()].concat()
}
