use curv::BigInt;
use paillier::EncryptionKey;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use zk_paillier::zkproofs::CompositeDLogProof;
use zk_paillier::zkproofs::NiCorrectKeyProof;
use curv::elliptic::curves::{p256::Secp256r1, Point};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug)]
pub struct Li17KeyGenContext1 {
    index: u16,
    p1_ec_key_pair: Option<party_one::EcKeyPair>,
    p1_comm_witness: Option<party_one::CommWitness>,
}

pub type Li17KeyGenMsg1 = party_one::KeyGenFirstMsg;

#[derive(Clone, Debug)]
pub struct Li17KeyGenContext2 {
    index: u16,
    p1_ec_key_pair: Option<party_one::EcKeyPair>,
    p1_comm_witness: Option<party_one::CommWitness>,
    p2_msg1_from_p1: Option<party_one::KeyGenFirstMsg>,
    p2_ec_key_pair: Option<party_two::EcKeyPair>,
}

pub type Li17KeyGenMsg2 = party_two::KeyGenFirstMsg;

pub struct Li17KeyGenContext3 {
    index: u16,
    p1_ec_key_pair: Option<party_one::EcKeyPair>,
    p1_paillier_key_pair: Option<party_one::PaillierKeyPair>,
    p1_public_share_p2: Option<Point<Secp256r1>>,
    p2_msg1_from_p1: Option<party_one::KeyGenFirstMsg>,
    p2_ec_key_pair: Option<party_two::EcKeyPair>,
}

pub type Li17KeyGenMsg3 = (party_one::KeyGenSecondMsg, NiCorrectKeyProof, PDLwSlackStatement,
                           PDLwSlackProof, CompositeDLogProof, EncryptionKey, BigInt);

#[derive(Serialize, Deserialize)]
pub struct Li17SignContext {
    pub index: u16,
    pub public: Point<Secp256r1>,
    pub public_p1: Point<Secp256r1>,
    pub public_p2: Point<Secp256r1>,
    pub p1_private: Option<party_one::Party1Private>,
    pub p2_private: Option<party_two::Party2Private>,
    pub p2_paillier_public: Option<party_two::PaillierPublic>,

}

pub type Li17KeyGenMsg4 = Point<Secp256r1>;


pub fn li17_key_gen1( index: u16 ) -> Result<(Option<Li17KeyGenMsg1>, Li17KeyGenContext1), &'static str> {
    if index > 1 {
        return Err("index must be 0 or 1")
    }

    if index == 0 {
        let (party1_first_message, p1_comm_witness, p1_ec_key_pair) =
                        party_one::KeyGenFirstMsg::create_commitments();
        let context1 = Li17KeyGenContext1 {
            index: 0,
            p1_ec_key_pair: Some(p1_ec_key_pair),
            p1_comm_witness: Some(p1_comm_witness),
        };
        return Ok((Some(party1_first_message), context1))
    } else {

        let context1 = Li17KeyGenContext1 {
            index: 1,
            p1_ec_key_pair: None,
            p1_comm_witness: None,
        };
        return Ok((None, context1))
    }
}

pub fn li17_key_gen2( msg: Li17KeyGenMsg1, context: Li17KeyGenContext1 )
->  Result<(Option<Li17KeyGenMsg2>, Li17KeyGenContext2), &'static str> {

    if context.index == 0 {
        let context2 = Li17KeyGenContext2 {
            index: 0,
            p1_ec_key_pair: context.p1_ec_key_pair,
            p1_comm_witness: context.p1_comm_witness,
            p2_msg1_from_p1: None,
            p2_ec_key_pair: None,
        };
        return Ok((None, context2))
    } else {
        let (p2_first_message, p2_ec_key_pair) = party_two::KeyGenFirstMsg::create();
        let context2 = Li17KeyGenContext2 {
            index: 1,
            p1_ec_key_pair: None,
            p1_comm_witness: None,
            p2_msg1_from_p1: Some(msg),
            p2_ec_key_pair: Some(p2_ec_key_pair),

        };
        return Ok((Some(p2_first_message), context2))
    }
}

pub fn li17_key_gen3( msg: Li17KeyGenMsg2, context: Li17KeyGenContext2 ) -> Result<(Option<Li17KeyGenMsg3>, Li17KeyGenContext3), &'static str> {

    if context.index == 0 {

        if context.p1_comm_witness.is_none() || context.p1_ec_key_pair.is_none() {
            return Err("invalid context")
        }
        let p1_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(context.p1_comm_witness.unwrap(), &msg.d_log_proof);

        if p1_second_message.is_err(){
            return Err("failed to verify and decommit")
        }
        let p1_second_message = p1_second_message.unwrap();
        let p1_ec_key_pair = context.p1_ec_key_pair.clone().unwrap();
        let paillier_key_pair = party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&p1_ec_key_pair);
        let party_one_private = party_one::Party1Private::set_private_key(&p1_ec_key_pair, &paillier_key_pair);

        let correct_key_proof = party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);

        let (pdl_statement, pdl_proof, composite_dlog_proof) = party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
        let ek = paillier_key_pair.ek.clone();
        let encrypted_share = paillier_key_pair.encrypted_share.clone();
        let context3 = Li17KeyGenContext3 {
            index: 0,
            p1_ec_key_pair: context.p1_ec_key_pair,
            p1_paillier_key_pair: Some(paillier_key_pair),
            p1_public_share_p2: Some(msg.public_share),
            p2_msg1_from_p1: None,
            p2_ec_key_pair: None,

        };


        return Ok((Some((p1_second_message, correct_key_proof, pdl_statement, pdl_proof, composite_dlog_proof,
                       ek, encrypted_share)), context3));


    } else {
        let context3 = Li17KeyGenContext3 {
            index: 1,
            p1_ec_key_pair: None,
            p1_paillier_key_pair: None,
            p1_public_share_p2: None,
            p2_msg1_from_p1: context.p2_msg1_from_p1,
            p2_ec_key_pair: context.p2_ec_key_pair,

        };
        return Ok((None, context3))

    }
}

pub fn li17_key_gen4( msg: Option<Li17KeyGenMsg3>, context: Li17KeyGenContext3 )
->  Result<(Option<Li17KeyGenMsg4>, Li17SignContext), &'static str> {

    if context.index == 0 {
        let party_one_private = party_one::Party1Private::set_private_key(&context.p1_ec_key_pair.clone().unwrap(),
                                                                    &context.p1_paillier_key_pair.unwrap());
        let public_key = party_one::compute_pubkey(&party_one_private, &context.p1_public_share_p2.clone().unwrap());
        let sign_context = Li17SignContext {
            index: 0,
            public: public_key.clone(),
            public_p1: context.p1_ec_key_pair.unwrap().public_share,
            public_p2: context.p1_public_share_p2.unwrap(),
            p1_private: Some(party_one_private),
            p2_private: None,
            p2_paillier_public: None,
        };

        return Ok((Some(public_key), sign_context))

    } else {
        let (party_one_second_message, correct_key_proof, pdl_statement, pdl_proof,
            composite_dlog_proof, paillier_ek, paillier_encrypted_share) = msg.unwrap();

        if context.p2_msg1_from_p1.is_none() || context.p2_ec_key_pair.is_none() {
            return Err("invalid context")
        }

        let p2_ec_key_pair = context.p2_ec_key_pair.clone().unwrap();
    	let r = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
                            &context.p2_msg1_from_p1.unwrap(),
                            &party_one_second_message,
                        );

        if r.is_err() {
            return Err("failed to verify commitments and DLog proof")
        }

        let party_two_paillier = party_two::PaillierPublic {
                        ek: paillier_ek.clone(),
                        encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        party_two::PaillierPublic::verify_ni_proof_correct_key(
                        correct_key_proof,
                        &party_two_paillier.ek,
                    )
                    .expect("bad paillier key");

        party_two::PaillierPublic::pdl_verify(
                        &composite_dlog_proof,
                        &pdl_statement,
                        &pdl_proof,
                        &party_two_paillier,
                        &party_one_second_message.comm_witness.public_share,
                    )
                    .expect("PDL error");

        let party_two_private = party_two::Party2Private::set_private_key(&p2_ec_key_pair);
        let public_key = party_two::compute_pubkey(&p2_ec_key_pair, &party_one_second_message.comm_witness.public_share);

        let sign_context = Li17SignContext {
            index: 1,
            public: public_key.clone(),
            public_p1: party_one_second_message.comm_witness.public_share,
            public_p2: context.p2_ec_key_pair.unwrap().public_share,
            p1_private: None,
            p2_private: Some(party_two_private),
            p2_paillier_public: Some(party_two_paillier)
        };

        return Ok((Some(public_key), sign_context))

    }
}
