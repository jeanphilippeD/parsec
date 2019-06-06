// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::block::Block;
use crate::common_coin::CommonCoin;
use crate::dev_utils::parse_test_dot_file;
use crate::error::Error;
use crate::gossip::{Event, Graph, GraphSnapshot};
use crate::id::PublicId;
use crate::meta_voting::MetaElectionSnapshot;
use crate::mock::{self, PeerId, Transaction};
use crate::observation::Observation;
use crate::parsec::TestParsec;
use crate::peer_list::{PeerIndexSet, PeerListSnapshot, PeerState};
use rand::thread_rng;
use std::collections::BTreeSet;
use threshold_crypto::SecretKeySet;

macro_rules! assert_err {
    ($expected_error:pat, $result:expr) => {
        match $result {
            Err($expected_error) => (),
            unexpected => panic!(
                "Expected {}, but got {:?}",
                stringify!($expected_error),
                unexpected
            ),
        }
    };
}

macro_rules! btree_set {
    ($($item:expr),*) => {{
        let mut set = BTreeSet::new();
        $(
            let _ = set.insert($item);
        )*
        set
    }}
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    peer_list: PeerListSnapshot<PeerId>,
    events: GraphSnapshot,
    meta_election: MetaElectionSnapshot<PeerId>,
    consensused_blocks: Vec<Block<Transaction, PeerId>>,
}

impl Snapshot {
    fn new(parsec: &TestParsec<Transaction, PeerId>) -> Self {
        Snapshot {
            peer_list: PeerListSnapshot::new(parsec.peer_list(), parsec.graph()),
            events: GraphSnapshot::new(parsec.graph()),
            meta_election: MetaElectionSnapshot::new(
                parsec.meta_election(),
                parsec.graph(),
                parsec.peer_list(),
            ),
            consensused_blocks: parsec.consensused_blocks().cloned().collect(),
        }
    }
}

fn nth_event<P: PublicId>(graph: &Graph<P>, n: usize) -> &Event<P> {
    unwrap!(graph.iter_from(n).next()).inner()
}

#[test]
fn from_existing() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers: BTreeSet<_> = peers.into_iter().collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(peers.clone(), sks.public_keys(), None);

    let parsec = TestParsec::<Transaction, _>::from_existing(our_id.clone(), &peers, &peers, coin);

    // Existing section + us
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len() + 1);

    // Only the initial event should be in the gossip graph.
    assert_eq!(parsec.graph().len(), 1);
    let event = nth_event(parsec.graph(), 0);
    assert_eq!(*parsec.event_creator_id(&event), our_id);
    assert!(event.is_initial());
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't be empty")]
fn from_existing_requires_non_empty_genesis_group() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers: BTreeSet<_> = peers.into_iter().collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(peers.clone(), sks.public_keys(), None);

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &BTreeSet::new(), &peers, coin);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group can't already contain us")]
fn from_existing_requires_that_genesis_group_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group: BTreeSet<_> = peers.iter().cloned().collect();
    let section = peers.into_iter().skip(1).collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(genesis_group.clone(), sks.public_keys(), None);

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &genesis_group, &section, coin);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't be empty")]
fn from_existing_requires_non_empty_section() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let genesis_group: BTreeSet<_> = peers.into_iter().collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(genesis_group.clone(), sks.public_keys(), None);

    let _ =
        TestParsec::<Transaction, _>::from_existing(our_id, &genesis_group, &BTreeSet::new(), coin);
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Section can't already contain us")]
fn from_existing_requires_that_section_does_not_contain_us() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let genesis_group: BTreeSet<_> = peers.iter().skip(1).cloned().collect();
    let section = peers.into_iter().collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(genesis_group.clone(), sks.public_keys(), None);

    let _ = TestParsec::<Transaction, _>::from_existing(our_id, &genesis_group, &section, coin);
}

#[test]
fn from_genesis() {
    let peers = mock::create_ids(10);
    let our_id = unwrap!(peers.first()).clone();
    let peers: BTreeSet<_> = peers.into_iter().collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(
        peers.clone(),
        sks.public_keys(),
        Some(sks.secret_key_share(0)),
    );

    let parsec = TestParsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, coin);
    // the peer_list should contain the entire genesis group
    assert_eq!(parsec.peer_list().all_ids().count(), peers.len());
    // initial event + genesis_observation
    assert_eq!(parsec.graph().len(), 2);
    let initial_event = nth_event(parsec.graph(), 0);
    assert_eq!(*parsec.event_creator_id(&initial_event), our_id);
    assert!(initial_event.is_initial());
    let genesis_observation = nth_event(parsec.graph(), 1);
    assert_eq!(*parsec.event_creator_id(&genesis_observation), our_id);
    match parsec.event_payload(&genesis_observation) {
        Some(payload) => {
            assert_eq!(*payload, Observation::Genesis(peers));
        }
        None => panic!("Expected observation, but event carried no vote"),
    }
}

// TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
#[cfg(feature = "testing")]
#[test]
#[should_panic(expected = "Genesis group must contain us")]
fn from_genesis_requires_the_genesis_group_contains_us() {
    let mut peers = mock::create_ids(10);
    let our_id = unwrap!(peers.pop());
    let peers: BTreeSet<_> = peers.into_iter().collect();
    let sks = SecretKeySet::random(3, &mut thread_rng());
    let coin = CommonCoin::new(
        peers.clone(),
        sks.public_keys(),
        Some(sks.secret_key_share(0)),
    );

    let _ = TestParsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, coin);
}

#[test]
fn from_parsed_contents() {
    let input_file = "0.dot";
    let parsed_contents = parse_test_dot_file(input_file);
    let parsed_contents_comparison = parse_test_dot_file(input_file);
    let parsec = TestParsec::from_parsed_contents(parsed_contents);
    assert_eq!(parsed_contents_comparison.graph, *parsec.graph());
    assert_eq!(
        parsed_contents_comparison.meta_election,
        *parsec.meta_election()
    );

    let parsed_contents_other = parse_test_dot_file("1.dot");
    assert_ne!(parsed_contents_other.graph, *parsec.graph());
    assert_ne!(parsed_contents_other.meta_election, *parsec.meta_election());
}

#[test]
fn add_peer() {
    // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to add Fred is reached in D_18, so pop this event for now.
    let d_18 = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);
    let genesis_group: BTreeSet<_> = alice
        .peer_list()
        .all_ids()
        .map(|(_, id)| id.clone())
        .collect();

    let alice_id = PeerId::new("Alice");
    let dave_id = PeerId::new("Dave");
    let fred_id = PeerId::new("Fred");

    assert!(!alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == fred_id));

    let alice_snapshot = Snapshot::new(&alice);

    // Try calling `create_gossip()` for a peer which doesn't exist yet.
    assert_err!(Error::UnknownPeer, alice.create_gossip(Some(&fred_id)));
    assert_eq!(alice_snapshot, Snapshot::new(&alice));

    // Now add D_18, which should result in Alice adding Fred.
    let d_18_hash = *d_18.hash();
    unwrap!(alice.add_event(d_18));
    unwrap!(alice.create_sync_event(&dave_id, true, &PeerIndexSet::default(), Some(d_18_hash)));
    assert!(alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == fred_id));

    // Construct Fred's Parsec instance.
    let fred_coin = alice.common_coin().validator_coin();
    let mut fred = TestParsec::from_existing(fred_id, &genesis_group, &genesis_group, fred_coin);

    // Create a "naughty Carol" instance where the graph only shows four peers existing before
    // adding Fred.
    #[cfg(feature = "malice-detection")]
    {
        parsed_contents = parse_test_dot_file("carol.dot");
        let naughty_carol = TestParsec::from_parsed_contents(parsed_contents);
        let malicious_message = unwrap!(naughty_carol.create_gossip(None));
        assert_err!(
            Error::InvalidEvent,
            fred.handle_request(&alice_id, malicious_message)
        );
    }

    // Now pass a valid initial request from Alice to Fred.  The generated response would
    // normally only contain Fred's initial event, and the one recording receipt of Alice's
    // request.  However this graph doesn't represent the state it would be in if Alice were
    // actually sending such a request - it should have an event by Alice as the latest.  We
    // really only need to check here though that Fred doesn't respond with the full graph.
    let message = unwrap!(alice.create_gossip(None));
    let response = unwrap!(fred.handle_request(&alice_id, message));
    assert!(response.packed_events.len() < fred.graph().len());
}

#[test]
fn remove_peer() {
    // Generated with RNG seed: [1048220270, 1673192006, 3171321266, 2580820785].
    let mut parsed_contents = parse_test_dot_file("alice.dot");

    // The final decision to remove Eric is reached in the last event of Alice.
    let a_last = unwrap!(parsed_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(parsed_contents);

    let eric_id = PeerId::new("Eric");
    let eric_index = unwrap!(alice.peer_list().get_index(&eric_id));

    assert!(alice
        .peer_list()
        .all_ids()
        .any(|(_, peer_id)| *peer_id == eric_id));
    assert_ne!(
        alice.peer_list().peer_state(eric_index),
        PeerState::inactive()
    );

    // Add event now which shall result in Alice removing Eric.
    unwrap!(alice.add_event(a_last));
    assert_eq!(
        alice.peer_list().peer_state(eric_index),
        PeerState::inactive()
    );

    // Try calling `create_gossip()` for Eric shall result in error.
    assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&eric_id)));

    // Construct Eric's parsec instance.
    let mut section: BTreeSet<_> = alice
        .peer_list()
        .all_ids()
        .map(|(_, id)| id.clone())
        .collect();
    let _ = section.remove(&eric_id);
    let eric_coin = alice.common_coin().validator_coin();
    let mut eric =
        TestParsec::<Transaction, _>::from_existing(eric_id.clone(), &section, &section, eric_coin);

    // Peer state is (VOTE | SEND) when created from existing. Need to update the states to
    // (VOTE | SEND | RECV).
    for peer_id in &section {
        eric.change_peer_state(peer_id, PeerState::RECV);
    }

    // Eric can no longer gossip to anyone.
    assert_err!(
        Error::InvalidSelfState { .. },
        eric.create_gossip(Some(&PeerId::new("Alice")))
    );
}

#[test]
fn unpolled_and_unconsensused_observations() {
    // Generated with RNG seed: [3016139397, 1416620722, 2110786801, 3768414447], but using
    // Alice-002.dot to get the dot file where we get consensus on `Add(Eric)`.
    let mut alice_contents = parse_test_dot_file("alice.dot");
    let a_17 = unwrap!(alice_contents.remove_last_event());

    let mut alice = TestParsec::from_parsed_contents(alice_contents);

    // `Add(Eric)` should still be unconsensused since A_17 would be the first gossip event to
    // reach consensus on `Add(Eric)`, but it was removed from the graph.
    assert!(alice.has_unconsensused_observations());

    // Since we haven't called `poll()` yet, our vote for `Add(Eric)` should be returned by
    // `our_unpolled_observations()`.
    let add_eric = Observation::Add {
        peer_id: PeerId::new("Eric"),
        related_info: vec![],
    };
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should have no effect to unconsensused and unpolled
    // observations.
    assert!(alice.poll().is_none());
    assert!(alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Have Alice process A_17 to get consensus on `Add(Eric)`.
    unwrap!(alice.add_event(a_17));

    // Since we haven't call `poll()` again yet, should still return our vote for `Add(Eric)`.
    // However, `has_unconsensused_observations()` should now return false.
    assert!(!alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

    // Call `poll()` and retry - should return none.
    unwrap!(alice.poll());
    assert!(alice.poll().is_none());
    assert!(alice.our_unpolled_observations().next().is_none());

    // Vote for a new observation and check it is returned as unpolled, and that
    // `has_unconsensused_observations()` returns false again.
    let vote = Observation::OpaquePayload(Transaction::new("ABCD"));
    unwrap!(alice.vote_for(vote.clone()));

    assert!(alice.has_unconsensused_observations());
    assert_eq!(alice.our_unpolled_observations().count(), 1);
    assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), vote);

    // Reset, and re-run, this time adding Alice's vote early to check that it is returned in
    // the correct order, i.e. after `Add(Eric)` at the point where `Add(Eric)` is consensused
    // but has not been returned by `poll()`.
    alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
    unwrap!(alice.vote_for(vote.clone()));
    let mut unpolled_observations = alice.our_unpolled_observations();
    assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
    assert_eq!(*unwrap!(unpolled_observations.next()), vote);
    assert!(unpolled_observations.next().is_none());
}

#[test]
fn gossip_after_fork() {
    let alice_id = PeerId::new("Alice");
    let bob_id = PeerId::new("Bob");

    let genesis_group = btree_set![
        alice_id.clone(),
        bob_id.clone(),
        PeerId::new("Carol"),
        PeerId::new("Dave")
    ];

    let sks = SecretKeySet::random(1, &mut thread_rng());

    let alice_coin = CommonCoin::new(
        genesis_group.clone(),
        sks.public_keys(),
        Some(sks.secret_key_share(0)),
    );
    let mut alice = TestParsec::from_genesis(alice_id.clone(), &genesis_group, alice_coin);

    // Alice creates couple of valid events.
    let a_1_index = unwrap!(alice.peer_list().our_events().next());
    let a_1_hash = *unwrap!(alice.graph().get(a_1_index)).hash();

    let a_2 = unwrap!(Event::new_from_observation(
        a_1_index,
        Observation::OpaquePayload(Transaction::new("one")),
        alice.event_context_mut()
    ));
    let a_2_hash = *a_2.hash();
    let a_2_index = unwrap!(alice.add_event(a_2));

    let a_3 = unwrap!(Event::new_from_observation(
        a_2_index,
        Observation::OpaquePayload(Transaction::new("two")),
        alice.event_context_mut(),
    ));
    let a_3_hash = *a_3.hash();
    let a_3_packed = alice.pack_event(&a_3);
    unwrap!(alice.unpack_and_add_event(a_3_packed));

    let bob_coin = CommonCoin::new(
        genesis_group.clone(),
        sks.public_keys(),
        Some(sks.secret_key_share(1)),
    );
    let mut bob = TestParsec::from_genesis(bob_id.clone(), &genesis_group, bob_coin);

    // Alice sends a gossip request to Bob and receives a response back.
    let req = unwrap!(alice.create_gossip(Some(&bob_id)));
    let res = unwrap!(bob.handle_request(&alice_id, req));
    unwrap!(alice.handle_response(&bob_id, res));

    // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
    assert!(bob.graph().contains(&a_1_hash));
    assert!(bob.graph().contains(&a_2_hash));
    assert!(bob.graph().contains(&a_3_hash));

    // Alice creates a fork.
    let a_2_fork = unwrap!(Event::new_from_observation(
        a_1_index,
        Observation::OpaquePayload(Transaction::new("two-fork")),
        alice.event_context_mut(),
    ));
    let a_2_fork_hash = *a_2_fork.hash();
    unwrap!(alice.add_event(a_2_fork));

    // Alice sends another gossip request to Bob.
    let req = unwrap!(alice.create_gossip(Some(&bob_id)));
    let _ = unwrap!(bob.handle_request(&alice_id, req));

    // Verify that Bob now has the forked event.
    assert!(bob.graph().contains(&a_2_fork_hash));
}

#[cfg(feature = "malice-detection")]
mod handle_malice {
    use super::*;
    use crate::dev_utils::{parse_dot_file_with_test_name, parse_test_dot_file, ParsedContents};
    use crate::gossip::{find_event_by_short_name, Event, EventHash};
    use crate::id::SecretId;
    use crate::mock::Transaction;
    use crate::network_event::NetworkEvent;
    use crate::observation::Malice;
    use crate::peer_list::{PeerIndex, PeerList, PeerState};
    use std::collections::BTreeMap;
    use std::ops::Deref;

    // Returns iterator over all votes cast by the given node.
    fn our_votes<T: NetworkEvent, S: SecretId>(
        parsec: &TestParsec<T, S>,
    ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        parsec
            .peer_list()
            .our_events()
            .filter_map(move |index| parsec.graph().get(index))
            .filter_map(move |event| parsec.event_payload(event.inner()))
    }

    // Add the peers to the `PeerList` as the genesis group.
    fn add_genesis_group<S: SecretId>(
        peer_list: &mut PeerList<S>,
        genesis: &BTreeSet<S::PublicId>,
    ) {
        for peer_id in genesis {
            if let Some(index) = peer_list.get_index(peer_id) {
                peer_list.change_peer_state(index, PeerState::active())
            } else {
                let _ = peer_list.add_peer(peer_id.clone(), PeerState::active());
            }
        }
    }

    #[test]
    fn genesis_event_not_after_initial() {
        // Generated with RNG seed: [926181213, 2524489310, 392196615, 406869071].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents
            .peer_list
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();
        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // Simulate Dave creating unexpected genesis.
        let dave_id = PeerId::new("Dave");
        let mut dave_contents = ParsedContents::new(dave_id.clone());

        dave_contents
            .peer_list
            .change_peer_state(PeerIndex::OUR, PeerState::active());
        add_genesis_group(&mut dave_contents.peer_list, &genesis);

        let d_0 = Event::new_initial(dave_contents.event_context());
        let d_0_index = dave_contents.add_event(d_0);

        let d_1 = unwrap!(Event::new_from_observation(
            d_0_index,
            Observation::OpaquePayload(Transaction::new("dave's malicious vote")),
            dave_contents.event_context_mut()
        ));
        let d_1_index = dave_contents.add_event(d_1);

        let d_2 = unwrap!(Event::new_from_observation(
            d_1_index,
            Observation::Genesis(genesis),
            dave_contents.event_context_mut()
        ));
        let d_2_hash = *d_2.hash();
        let _ = dave_contents.add_event(d_2);

        let dave = TestParsec::from_parsed_contents(dave_contents);

        // Dave sends malicious gossip to Alice.
        let request = unwrap!(dave.create_gossip(Some(&alice_id)));
        unwrap!(alice.handle_request(&dave_id, request));

        // Verify that Alice detected the malice and accused Dave.
        let (offender, hash) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match *payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::UnexpectedGenesis(hash),
                } => Some((offender.clone(), hash)),
                _ => None,
            })
            .next());

        assert_eq!(offender, dave_id);
        assert_eq!(hash, d_2_hash);
    }

    #[test]
    fn genesis_event_creator_not_genesis_member() {
        // Generated with RNG seed: [848911612, 2362592349, 3178199135, 2458552022].
        let alice_contents = parse_test_dot_file("alice.dot");
        let alice_id = alice_contents.peer_list.our_id().clone();
        let genesis: BTreeSet<_> = alice_contents
            .peer_list
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();

        let mut alice = TestParsec::from_parsed_contents(alice_contents);

        // This is needed so the AddPeer(Eric) is consensused.
        unwrap!(alice.restart_consensus());

        // Simulate Eric creating unexpected genesis.
        let eric_id = PeerId::new("Eric");
        let mut eric_contents = ParsedContents::new(eric_id.clone());

        eric_contents
            .peer_list
            .change_peer_state(PeerIndex::OUR, PeerState::active());
        add_genesis_group(&mut eric_contents.peer_list, &genesis);

        let e_0 = Event::new_initial(eric_contents.event_context());
        let e_0_index = eric_contents.add_event(e_0);

        let e_1 = unwrap!(Event::new_from_observation(
            e_0_index,
            Observation::Genesis(genesis),
            eric_contents.event_context_mut()
        ));
        let e_1_hash = *e_1.hash();
        let _ = eric_contents.add_event(e_1);

        let eric = TestParsec::from_parsed_contents(eric_contents);

        // Eric sends malicious gossip to Alice.
        let request = unwrap!(eric.create_gossip(Some(&alice_id)));
        unwrap!(alice.handle_request(&eric_id, request));

        // Verify that Alice detected the malice and accused Eric.
        let (offender, hash) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match *payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::UnexpectedGenesis(hash),
                } => Some((offender.clone(), hash)),
                _ => None,
            })
            .next());

        assert_eq!(offender, eric_id);
        assert_eq!(hash, e_1_hash);
    }

    fn initialise_parsed_contents(
        id: PeerId,
        genesis: &BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> ParsedContents {
        let mut result = ParsedContents::new(id);
        add_genesis_group(&mut result.peer_list, genesis);

        let ev_0 = Event::new_initial(result.event_context());
        let ev_0_index = result.add_event(ev_0);
        let ev_1 = if let Some(obs_1) = second_event {
            unwrap!(Event::new_from_observation(
                ev_0_index,
                obs_1,
                result.event_context_mut()
            ))
        } else {
            unwrap!(Event::new_from_observation(
                ev_0_index,
                Observation::Genesis(genesis.clone()),
                result.event_context_mut()
            ))
        };

        let _ = result.add_event(ev_1);
        result
    }

    fn initialise_parsec(
        id: PeerId,
        genesis: &BTreeSet<PeerId>,
        second_event: Option<Observation<Transaction, PeerId>>,
    ) -> TestParsec<Transaction, PeerId> {
        let contents = initialise_parsed_contents(id, genesis, second_event);
        TestParsec::from_parsed_contents(contents)
    }

    #[test]
    fn missing_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let genesis = btree_set![alice_id.clone(), dave_id.clone()];

        // Create Alice where the first event is not a genesis event (malice)
        let alice = initialise_parsec(
            alice_id.clone(),
            &genesis,
            Some(Observation::OpaquePayload(Transaction::new("Foo"))),
        );
        let a_0_hash = *nth_event(alice.graph(), 0).hash();
        let a_1_hash = *nth_event(alice.graph(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
        assert!(!dave.graph().contains(&a_0_hash));
        assert!(!dave.graph().contains(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        unwrap!(dave.handle_request(&alice_id, message));
        assert!(dave.graph().contains(&a_0_hash));
        assert!(dave.graph().contains(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(our_votes(&dave)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::MissingGenesis(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn incorrect_genesis_event() {
        let alice_id = PeerId::new("Alice");
        let dave_id = PeerId::new("Dave");

        let genesis = btree_set![alice_id.clone(), dave_id.clone()];
        let false_genesis = btree_set![alice_id.clone(), PeerId::new("Derp")];

        // Create Alice where the first event is an incorrect genesis event (malice)
        let alice = initialise_parsec(
            alice_id.clone(),
            &genesis,
            Some(Observation::Genesis(false_genesis)),
        );
        let a_0_hash = *nth_event(alice.graph(), 0).hash();
        let a_1_hash = *nth_event(alice.graph(), 1).hash();

        // Create Dave where the first event is a genesis event containing both Alice and Dave.
        let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
        assert!(!dave.graph().contains(&a_0_hash));
        assert!(!dave.graph().contains(&a_1_hash));

        // Send gossip from Alice to Dave.
        let message = unwrap!(alice.create_gossip(Some(&dave_id)));
        // Alice's genesis should be rejected as invalid
        assert_err!(Error::InvalidEvent, dave.handle_request(&alice_id, message));
        assert!(dave.graph().contains(&a_0_hash));
        // Dave's events shouldn't contain Alice's genesis because of the rejection
        assert!(!dave.graph().contains(&a_1_hash));

        // Verify that Dave detected and accused Alice for malice.
        let (offender, hash) = unwrap!(our_votes(&dave)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::IncorrectGenesis(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(*offender, alice_id);
        assert_eq!(*hash, a_1_hash);
    }

    #[test]
    fn duplicate_votes() {
        // Generated with RNG seed: [1353978636, 426502568, 2862743769, 1583787884].
        //
        // Carol has already voted for "ABCD".  Create two new duplicate votes by Carol for this
        // opaque payload.
        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));

        let first_duplicate = unwrap!(Event::new_from_observation(
            carol.our_last_event_index(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.event_context_mut()
        ));

        let first_duplicate_clone = unwrap!(Event::new_from_observation(
            carol.our_last_event_index(),
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.event_context_mut()
        ));
        let first_duplicate_clone_packed = carol.pack_event(&first_duplicate_clone);

        let first_duplicate_hash = *first_duplicate.hash();
        let first_duplicate_index = unwrap!(carol.add_event(first_duplicate));
        let second_duplicate = unwrap!(Event::new_from_observation(
            first_duplicate_index,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.event_context_mut()
        ));
        let second_duplicate_packed = carol.pack_event(&second_duplicate);

        // Check that the first duplicate triggers an accusation by Alice, but that the
        // duplicate is still added to the graph.
        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let carols_valid_vote_hash =
            *unwrap!(find_event_by_short_name(alice.graph(), "C_4")).hash();
        unwrap!(alice.unpack_and_add_event(first_duplicate_clone_packed));

        let carol_index = unwrap!(alice.peer_list().get_index(carol.our_pub_id()));
        let expected_accusations = vec![(
            carol_index,
            Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
        )];
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&first_duplicate_hash));

        // Check that the second one doesn't trigger any further accusation, but is also added
        // to the graph.
        let second_duplicate_hash = *second_duplicate.hash();
        unwrap!(alice.unpack_and_add_event(second_duplicate_packed));
        assert_eq!(*alice.pending_accusations(), expected_accusations);
        assert!(alice.graph().contains(&second_duplicate_hash));
    }

    #[test]
    fn invalid_accusation() {
        // Generated with RNG seed: [935566334, 935694090, 88607029, 861330491].
        let mut alice_contents = parse_test_dot_file("alice.dot");

        let a_4_index =
            unwrap!(find_event_by_short_name(&alice_contents.graph, "A_4")).event_index();
        let d_1_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "D_1")).hash();

        // Create an invalid accusation from Alice
        let a_5 = unwrap!(Event::new_from_observation(
            a_4_index,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
            alice_contents.event_context_mut()
        ));
        let a_5_hash = *a_5.hash();
        let _ = alice_contents.add_event(a_5);
        let alice = TestParsec::from_parsed_contents(alice_contents);
        assert!(alice.graph().contains(&a_5_hash));

        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
        assert!(!carol.graph().contains(&a_5_hash));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(carol.our_pub_id())));

        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&a_5_hash));

        // Verify that Carol detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(our_votes(&carol)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::InvalidAccusation(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, a_5_hash);
    }

    // TODO: enable this when InvalidGossipCreator malice handlind works again
    #[ignore]
    #[test]
    fn invalid_gossip_creator() {
        // Generated with RNG seed: [753134140, 4096687351, 2912528994, 2847063513].
        //
        // Alice reports gossip to Bob from Carol that isn't in their section.
        let alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        let mut bob = TestParsec::from_parsed_contents(parse_test_dot_file("bob.dot"));

        // Verify peer lists
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let carol_id = PeerId::new("Carol");
        let mut alice_peer_list = PeerList::new(alice_id.clone());
        alice_peer_list.change_peer_state(PeerIndex::OUR, PeerState::active());
        let _ = alice_peer_list.add_peer(bob_id.clone(), PeerState::active());
        let _ = alice_peer_list.add_peer(carol_id, PeerState::active());
        assert_eq!(
            alice.peer_list().all_id_hashes().collect::<Vec<_>>(),
            alice_peer_list.all_id_hashes().collect::<Vec<_>>()
        );
        let mut bob_peer_list = PeerList::new(bob_id.clone());
        bob_peer_list.change_peer_state(PeerIndex::OUR, PeerState::active());
        let _ = bob_peer_list.add_peer(alice_id.clone(), PeerState::active());
        assert_eq!(
            bob.peer_list().all_id_hashes().collect::<Vec<_>>(),
            bob_peer_list.all_id_hashes().collect::<Vec<_>>()
        );

        // Read the dot file again so we have a set of events we can manually add to Bob instead
        // of sending gossip.
        let alice_parsed_contents = parse_test_dot_file("alice.dot");

        let c_0_index = unwrap!(find_event_by_short_name(
            &alice_parsed_contents.graph,
            "C_0"
        ))
        .event_index();

        let (a_2_index, a_2_hash) = {
            let ie = unwrap!(find_event_by_short_name(
                &alice_parsed_contents.graph,
                "A_2"
            ));
            (ie.event_index(), *ie.hash())
        };

        let b_2_index = unwrap!(find_event_by_short_name(
            &alice_parsed_contents.graph,
            "B_2"
        ))
        .event_index();

        // Carol is marked as active peer so that Bob's peer_list will accept C_0, but Carol is
        // not part of the membership_list
        let carol_id = PeerId::new("Carol");
        bob.add_peer(carol_id, PeerState::active());

        let mut alice_events: BTreeMap<_, _> = alice_parsed_contents.graph.into_iter().collect();

        let c_0 = unwrap!(alice_events.remove(&c_0_index));
        unwrap!(bob.add_event(c_0));

        // This malice is setup in two events.
        // A_2 has C_0 from Carol as other parent as Carol has gossiped to Alice. Carol is
        // however not part of the section and Alice should not have accepted it.
        let a_2 = unwrap!(alice_events.remove(&a_2_index));
        let a_2_packed = alice.pack_event(&a_2);
        unwrap!(bob.unpack_and_add_event(a_2_packed));

        // B_2 is the sync event created by Bob when he receives A_2 from Alice.
        let b_2 = unwrap!(alice_events.remove(&b_2_index));
        let b_2_packed = alice.pack_event(&b_2);
        unwrap!(bob.unpack_and_add_event(b_2_packed));

        // Bob should now have seen that Alice in A_2 incorrectly reported gossip from Carol.
        // Check that this triggers an accusation
        let alice_index = unwrap!(bob.peer_list().get_index(alice.our_pub_id()));
        let expected_accusations = (alice_index, Malice::InvalidGossipCreator(a_2_hash));
        assert!(bob.pending_accusations().contains(&expected_accusations));
        assert!(bob.graph().contains(&a_2_hash));
    }

    fn create_invalid_accusation() -> (EventHash, TestParsec<Transaction, PeerId>) {
        // Generated with RNG seed: [3932887254, 691979681, 2029125979, 3359276664]
        let mut alice_contents =
            parse_dot_file_with_test_name("alice.dot", "functional_tests_handle_malice_accomplice");

        let a_26_index =
            unwrap!(find_event_by_short_name(&alice_contents.graph, "A_26")).event_index();
        let d_1_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "D_1")).hash();

        // Create an invalid accusation from Alice
        let a_27 = unwrap!(Event::new_from_observation(
            a_26_index,
            Observation::Accusation {
                offender: PeerId::new("Dave"),
                malice: Malice::Fork(d_1_hash),
            },
            alice_contents.event_context_mut()
        ));
        let a_27_hash = *a_27.hash();
        let _ = alice_contents.add_event(a_27);
        let alice = TestParsec::from_parsed_contents(alice_contents);
        assert!(alice.graph().contains(&a_27_hash));
        (a_27_hash, alice)
    }

    fn verify_accused_accomplice(
        accuser: &TestParsec<Transaction, PeerId>,
        suspect: &PeerId,
        event_hash: &EventHash,
        malice_hash: &EventHash,
    ) {
        let (offender, hash, against) = unwrap!(our_votes(accuser)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::Accomplice(hash, against),
                } => Some((offender, hash, against)),
                _ => None,
            })
            .next());
        assert_eq!(offender, suspect);
        assert_eq!(hash, event_hash);

        let against_hash = match against.deref() {
            Malice::InvalidAccusation(hash) => Some(hash),
            _ => None,
        }
        .expect("Not all malice types supported in test for now");
        assert_eq!(against_hash, malice_hash);
    }

    #[test]
    // Carol received gossip from Bob, which should have raised an accomplice accusation against
    // Alice but didn't.
    fn accomplice() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));
        // Remove the invalid accusation event (B_31)
        unwrap!(bob.remove_last_event());

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol, with the accusation event missing. Carol will see that
        // the accusation event is missing, but is not going acuse Bob yet until she's sure.
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));
        assert!(our_votes(&carol)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    malice: Malice::Accomplice(_, _),
                    ..
                } => Some(()),
                _ => None,
            })
            .next()
            .is_none());

        // Bob adds another event which he then sends to Carol, who now becomes sure that Bob
        // didn't create the accusation he should have.
        let b_30_index = unwrap!(find_event_by_short_name(bob.graph(), "B_30")).event_index();
        let b_31_replacement = unwrap!(Event::new_from_observation(
            b_30_index,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            bob.event_context_mut(),
        ));
        let b_31_hash = *b_31_replacement.hash();
        unwrap!(bob.add_event(b_31_replacement));
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));

        // Verify that Carol detected malice and accused Alice of `InvalidAccusation` and Bob of
        // `Accomplice`.
        let mut our_accusations = our_votes(&carol).filter_map(|payload| match payload {
            Observation::Accusation {
                ref offender,
                malice: Malice::InvalidAccusation(hash),
            } => Some((offender, hash)),
            _ => None,
        });
        let (offender, hash) = unwrap!(our_accusations.next());

        assert_eq!(offender, alice.our_pub_id());
        assert_eq!(*hash, invalid_accusation);
        assert!(our_accusations.next().is_none());

        verify_accused_accomplice(&carol, bob.our_pub_id(), &b_31_hash, &invalid_accusation);
    }

    #[test]
    // Carol received `invalid_accusation` from Alice first, then received gossip from Bob,
    // which should have raised an accomplice accusation against Alice but didn't.
    fn accomplice_separate() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));
        // Remove the invalid accusation event (B_31), making Bob an accomplice.
        unwrap!(bob.remove_last_event());

        // Send gossip from Bob to Carol, with the accusation event missing. Carol will see that
        // the accusation event is missing, but is not going acuse Bob yet until she's sure.
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Accomplice(_, _),
                ..
            } => false,
            _ => true,
        }));

        // Bob adds another event which he then sends to Carol, who now becomes sure that Bob
        // didn't create the accusation he should have.
        let b_30_index = unwrap!(find_event_by_short_name(bob.graph(), "B_30")).event_index();
        let b_31_replacement = unwrap!(Event::new_from_observation(
            b_30_index,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            bob.event_context_mut(),
        ));
        let b_31_hash = *b_31_replacement.hash();
        unwrap!(bob.add_event(b_31_replacement));
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));

        // Verify that Carol detected malice and accused Bob of `Accomplice`.
        verify_accused_accomplice(&carol, bob.our_pub_id(), &b_31_hash, &invalid_accusation);
    }

    #[test]
    // Carol received `invalid_accusation` from Alice first, then receive gossip from Bob, which
    // doesn't contain the malice of Alice. Carol shall not raise accusation against Bob.
    fn accomplice_negative() {
        let (invalid_accusation, alice) = create_invalid_accusation();

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));

        let bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Bob to Carol
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(bob.our_pub_id(), message));

        // Verify that Carol didn't accuse Bob of `Accomplice`.
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Accomplice(_, _),
                ..
            } => false,
            _ => true,
        }));
    }

    #[test]
    // Alice tries to frame Bob by gossiping to Carol with Bob's InvalidAccusation removed.
    fn accomplice_framing_attempt() {
        let (invalid_accusation, mut alice) = create_invalid_accusation();

        let mut bob = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "bob.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!bob.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Bob
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
        unwrap!(bob.handle_request(alice.our_pub_id(), message));
        assert!(bob.graph().contains(&invalid_accusation));
        // ..and back to Alice
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Alice"))));
        unwrap!(alice.handle_request(bob.our_pub_id(), message));

        // Alice raises an InvalidAccusation (A_29) against Bob's InvalidAccusation (B_31), remove
        // it as we're not interested in it.
        let (_, _alice_accusation_event_against_bob) = unwrap!(alice.remove_last_event());

        // Then replace the sync event with one against B_30, effectively hiding Bob's accusation.
        let (_, _a_28) = unwrap!(alice.remove_last_event());
        let (_, _b_31) = unwrap!(alice.remove_last_event());
        let b_30_index = unwrap!(find_event_by_short_name(alice.graph(), "B_30")).event_index();
        let a_27_index = unwrap!(find_event_by_short_name(alice.graph(), "A_27")).event_index();

        let a_28_replacement = unwrap!(Event::new_from_request(
            a_27_index,
            b_30_index,
            &PeerIndexSet::default(),
            alice.event_context()
        ));

        unwrap!(alice.add_event(a_28_replacement));

        let mut carol = TestParsec::from_parsed_contents(parse_dot_file_with_test_name(
            "carol.dot",
            "functional_tests_handle_malice_accomplice",
        ));
        assert!(!carol.graph().contains(&invalid_accusation));

        // Send gossip from Alice to Carol
        let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));
        assert!(carol.graph().contains(&invalid_accusation));
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Accomplice(_, _),
                ..
            } => false,
            _ => true,
        }));

        // Bob sends his side of the story, the honest side, to Carol
        let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
        unwrap!(carol.handle_request(alice.our_pub_id(), message));

        // Verify that Carol didn't accuse Bob of `Accomplice`.
        assert!(our_votes(&carol).all(|payload| match payload {
            Observation::Accusation {
                malice: Malice::Accomplice(_, _),
                ..
            } => false,
            _ => true,
        }));
    }

    #[test]
    fn handle_fork() {
        // In this scenario, Alice creates two descendants of A_3 and sends one of them to Bob,
        // and the other one to Dave. When Bob gossips to Dave afterwards, Dave is made aware of
        // both sides of the fork and should raise an accusation.
        let bob_contents = parse_test_dot_file("bob.dot");
        let dave_contents = parse_test_dot_file("dave.dot");
        let a_3_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "A_3")).hash();
        // Bob and Dave have different notions of which event is the fourth one by Alice - here
        // we save the hashes of these two events that could be considered A_4.
        let a_4_bob_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "A_4")).hash();
        let a_4_dave_hash = *unwrap!(find_event_by_short_name(&dave_contents.graph, "A_4")).hash();

        let bob = TestParsec::from_parsed_contents(bob_contents);
        let mut dave = TestParsec::from_parsed_contents(dave_contents);
        assert!(bob.graph().contains(&a_3_hash));
        assert!(dave.graph().contains(&a_3_hash));
        // Bob doesn't know Dave's A_4, and Dave doesn't know Bob's
        assert!(!bob.graph().contains(&a_4_dave_hash));
        assert!(!dave.graph().contains(&a_4_bob_hash));

        // Send gossip from Bob to Dave
        let message = unwrap!(bob.create_gossip(Some(dave.our_pub_id())));
        unwrap!(dave.handle_request(bob.our_pub_id(), message));
        // Dave should now become aware of the other branch of the fork
        assert!(dave.graph().contains(&a_4_bob_hash));

        // Verify that Dave detected malice and accused Alice of it.
        let (offender, hash) = unwrap!(our_votes(&dave)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::Fork(hash),
                } => Some((offender, hash)),
                _ => None,
            })
            .next());
        assert_eq!(offender, &PeerId::new("Alice"));
        assert_eq!(*hash, a_3_hash);
    }

    #[test]
    fn self_parent_by_different_creator() {
        // Generated with RNG seed: [856368386, 135728199, 764559083, 3829746197].
        let mut carol = TestParsec::from_parsed_contents(parse_test_dot_file("carol.dot"));

        // Carol creates an event with one of Bob's as the self-parent.
        let b_2_index = unwrap!(find_event_by_short_name(carol.graph(), "B_2")).event_index();
        let c_4 = unwrap!(Event::new_from_observation(
            b_2_index,
            Observation::OpaquePayload(Transaction::new("ABCD")),
            carol.event_context_mut()
        ));
        let c_4_hash = *c_4.hash();
        let c_4_packed = carol.pack_event(&c_4);

        let mut alice = TestParsec::from_parsed_contents(parse_test_dot_file("alice.dot"));

        // Try to add the event.
        assert_err!(
            Error::InvalidEvent,
            alice.unpack_and_add_event(c_4_packed.clone())
        );

        // The invalid event should trigger an accusation vote to be raised immediately, and the
        // invalid event should not be added to the graph.
        let a_2 = unwrap!(find_event_by_short_name(alice.graph(), "A_2"));
        let expected_observation = Observation::Accusation {
            offender: carol.our_pub_id().clone(),
            malice: Malice::SelfParentByDifferentCreator(Box::new(c_4_packed)),
        };

        assert_eq!(*unwrap!(alice.event_payload(&a_2)), expected_observation);
        assert!(!alice.graph().contains(&c_4_hash));
    }

    #[test]
    fn other_parent_by_same_creator() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");
        let genesis = btree_set![alice_id.clone(), bob_id.clone()];

        let mut alice = initialise_parsec(alice_id, &genesis, None);
        let mut bob_contents = initialise_parsed_contents(bob_id.clone(), &genesis, None);

        let (b_0_packed, b_0_index, b_0_hash) = {
            let e = unwrap!(find_event_by_short_name(&bob_contents.graph, "b_0"));
            let packed = unwrap!(e.pack(bob_contents.event_context()));
            (packed, e.event_index(), *e.hash())
        };

        let (b_1_packed, b_1_index, b_1_hash) = {
            let e = unwrap!(find_event_by_short_name(&bob_contents.graph, "b_1"));
            let packed = unwrap!(e.pack(bob_contents.event_context()));
            (packed, e.event_index(), *e.hash())
        };

        let b_2 = unwrap!(Event::new_from_request(
            b_1_index,
            b_0_index,
            &PeerIndexSet::default(),
            bob_contents.event_context()
        ));
        let b_2_hash = *b_2.hash();
        let b_2_packed = unwrap!(b_2.pack(bob_contents.event_context()));

        let b_1 = unwrap!(bob_contents.remove_last_event());
        assert_eq!(*b_1.hash(), b_1_hash);

        let b_0 = unwrap!(bob_contents.remove_last_event());
        assert_eq!(*b_0.hash(), b_0_hash);

        unwrap!(alice.unpack_and_add_event(b_0_packed));
        unwrap!(alice.unpack_and_add_event(b_1_packed));

        // This should fail, as B_2 has other-parent by the same creator.
        assert_err!(Error::InvalidEvent, alice.unpack_and_add_event(b_2_packed));

        // Alice should raise accusation against Bob
        let (offender, event) = unwrap!(our_votes(&alice)
            .filter_map(|payload| match payload {
                Observation::Accusation {
                    ref offender,
                    malice: Malice::OtherParentBySameCreator(event),
                } => Some((offender, event)),
                _ => None,
            })
            .next());

        assert_eq!(*offender, bob_id);
        assert_eq!(event.compute_hash(), b_2_hash);

        // B_2 should not have been inserted into Alice's graph
        assert!(!alice.graph().contains(&b_2_hash));
    }

    #[test]
    fn premature_gossip() {
        // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
        // Copied from add_peer
        let mut parsed_contents = parse_test_dot_file("alice.dot");

        // The final decision to add Frank is reached in D_18, so we remove this event.
        let _d_18 = unwrap!(parsed_contents.remove_last_event());

        let mut alice = TestParsec::from_parsed_contents(parsed_contents);
        let genesis_group: BTreeSet<_> = alice
            .peer_list()
            .all_ids()
            .map(|(_, id)| id.clone())
            .collect();

        let alice_id = PeerId::new("Alice");
        let fred_id = PeerId::new("Fred");
        assert!(!alice
            .peer_list()
            .all_ids()
            .any(|(_, peer_id)| *peer_id == fred_id));

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_err!(Error::UnknownPeer, alice.create_gossip(Some(&fred_id)));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // We'll modify Alice's peer list to allow her to create gossip for Fred
        alice.add_peer(fred_id.clone(), PeerState::RECV | PeerState::VOTE);

        // Construct Fred's Parsec instance.
        let mut fred = TestParsec::from_existing(fred_id.clone(), &genesis_group, &genesis_group);

        // Check that Fred has no events that Alice has
        assert!(alice
            .graph()
            .iter()
            .all(|ev| !fred.graph().contains(ev.inner().hash())));

        // Now Alice will prematurely gossip to Fred
        let request = unwrap!(alice.create_gossip(Some(&fred_id)));
        let result = fred.handle_request(&alice_id, request);

        // check that Fred detected premature gossip
        assert_err!(Error::PrematureGossip, result);

        // Check that Fred has all the events that Alice has
        assert!(alice
            .graph()
            .iter()
            .all(|ev| fred.graph().contains(ev.inner().hash())));
    }
}
