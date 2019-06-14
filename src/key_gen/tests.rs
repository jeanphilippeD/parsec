// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
//
//
// hbbft is copyright 2018, POA Networks, Ltd.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. All files in the project
// carrying such notice may not be copied, modified, or distributed except
// according to those terms.
//
// Original copied from:
// https://raw.githubusercontent.com/poanetwork/hbbft/eafa77d5fcbdaf549e09f101d618923d408b3468/tests/sync_key_gen.rs

#![deny(unused_must_use)]
//! Tests for synchronous distributed key generation.

use std::collections::{BTreeMap, BTreeSet};

use super::{KeyGen, PartOutcome};
use crate::dev_utils::{Environment, RngChoice};
use crate::mock::PeerId;

// Alter the seed here to reproduce failures
static SEED: RngChoice = RngChoice::SeededRandom;

fn test_key_gen_with(threshold: usize, node_num: usize) {
    let mut env = Environment::new(SEED);

    // Generate individual key pairs for encryption. These are not suitable for threshold schemes.
    let peer_ids: Vec<PeerId> = (0..node_num)
        .map(|idx| unwrap!(PeerId::from_index(idx)))
        .collect();
    let pub_keys: BTreeSet<PeerId> = peer_ids.iter().cloned().collect();

    // Create the `KeyGen` instances and initial proposals.
    let mut nodes = Vec::new();
    let mut proposals = Vec::new();
    peer_ids.iter().for_each(|peer_id| {
        let (key_gen, proposal) = KeyGen::new(peer_id, pub_keys.clone(), threshold, &mut env.rng)
            .unwrap_or_else(|_err| panic!("Failed to create `KeyGen` instance {:?}", &peer_id));
        nodes.push(key_gen);
        proposals.push(proposal);
    });

    // Handle the first `threshold + 1` proposals. Those should suffice for key generation.
    let mut acks = Vec::new();
    for (sender_id, proposal) in proposals[..=threshold].iter().enumerate() {
        for (node_id, node) in nodes.iter_mut().enumerate() {
            let proposal = proposal.clone().expect("proposal");
            let ack = match node
                .handle_part(&peer_ids[node_id], &peer_ids[sender_id], proposal)
                .expect("failed to handle part")
            {
                PartOutcome::Valid(Some(ack)) => ack,
                PartOutcome::Valid(None) => panic!("missing ack message"),
                PartOutcome::Invalid(fault) => panic!("invalid proposal: {:?}", fault),
            };
            // Only the first `threshold + 1` manage to commit their `Ack`s.
            if node_id <= 2 * threshold {
                acks.push((node_id, ack));
            }
        }
    }

    // Handle the `Ack`s from `2 * threshold + 1` nodes.
    for (sender_id, ack) in acks {
        for (node_id, node) in nodes.iter_mut().enumerate() {
            assert!(!node.is_ready()); // Not enough `Ack`s yet.
            let _ = node
                .handle_ack(&peer_ids[node_id], &peer_ids[sender_id], ack.clone())
                .expect("error handling ack");
        }
    }

    // Compute the keys and test a threshold signature.
    let msg = "Help I'm trapped in a unit test factory";
    let pub_key_set = nodes[0]
        .generate()
        .expect("Failed to generate `PublicKeySet` for node #0")
        .public_key_set;
    let sig_shares: BTreeMap<_, _> = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| {
            assert!(node.is_ready());
            let dkg_result = node.generate().unwrap_or_else(|_| {
                panic!(
                    "Failed to generate `PublicKeySet` and `SecretKeyShare` for node #{}",
                    idx
                )
            });
            let sk = dkg_result.secret_key_share.expect("new secret key");
            let pks = dkg_result.public_key_set;
            assert_eq!(pks, pub_key_set);
            let sig = sk.sign(msg);
            assert!(pks.public_key_share(idx).verify(&sig, msg));
            (idx, sig)
        })
        .collect();
    let sig = pub_key_set
        .combine_signatures(sig_shares.iter().take(threshold + 1))
        .expect("signature shares match");
    assert!(pub_key_set.public_key().verify(&sig, msg));
}

fn test_key_gen(node_num: usize) {
    let threshold = (node_num - 1) / 3;
    test_key_gen_with(threshold, node_num);
}

#[test]
fn test_key_gen_1() {
    test_key_gen(1);
}

#[test]
fn test_key_gen_2() {
    test_key_gen(2);
}
#[test]
fn test_key_gen_3() {
    test_key_gen(3);
}

#[test]
fn test_key_gen_4() {
    test_key_gen(4);
}

#[test]
fn test_key_gen_8() {
    test_key_gen(8);
}

#[test]
fn test_key_gen_15() {
    test_key_gen(15);
}
