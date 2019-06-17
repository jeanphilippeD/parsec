// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! A basic example of running some nodes which reach consensus on the order of some random events.

#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences
)]

#[macro_use]
extern crate clap;
#[macro_use]
extern crate unwrap;

use clap::{App, Arg, ArgMatches};
use maidsafe_utilities::{log, SeededRng};
use parsec::{
    mock::{PeerId, Transaction},
    Block, ConsensusMode, Parsec, Request,
};
use rand::Rng;
use std::{
    cmp,
    collections::BTreeSet,
    fmt::{self, Debug, Formatter},
    process, usize,
};

// When we are down to 3 peers, if we attempt to remove one peer, and it becomes unresponsive
// (which happens in the code), consensus can never be reached as this one inactive peer isn't
// `< N/3` participants.
// See https://github.com/maidsafe/parsec/issues/313 for details
const MIN_PEER_COUNT: usize = 3;
const MAX_EVENT_COUNT: usize = 1000;
const GENESIS_PEERS_ARG_LONG_NAME: &str = "initial-peers";
const GENESIS_PEERS_ARG_SHORT_NAME: &str = "i";
const ADD_PEER_EVENTS_ARG_LONG_NAME: &str = "add-peers";
const ADD_PEER_EVENTS_ARG_SHORT_NAME: &str = "a";
const REMOVE_PEER_EVENTS_ARG_LONG_NAME: &str = "remove-peers";
const REMOVE_PEER_EVENTS_ARG_SHORT_NAME: &str = "r";
const MAX_PEER_COUNT_ARG_LONG_NAME: &str = "max-peers";
const MAX_PEER_COUNT_ARG_SHORT_NAME: &str = "m";
const OPAQUE_EVENTS_ARG_LONG_NAME: &str = "opaque";
const OPAQUE_EVENTS_ARG_SHORT_NAME: &str = "o";
const MAX_ROUNDS_ARG_LONG_NAME: &str = "max-rounds";
const SEED_ARG_LONG_NAME: &str = "seed";
const SEED_ARG_SHORT_NAME: &str = "s";
// We generate an Opaque observation in a given round with 1 in `OPAQUE_CHANCE` odds.
const OPAQUE_CHANCE: u32 = 3;
// We generate an Add observation in a given round with 1 in `ADD_PEER_CHANCE` odds.
const ADD_PEER_CHANCE: u32 = 2;
// We generate Remove observation(s) in a given round with 1 in `REMOVE_PEERS_CHANCE` odds.
const REMOVE_PEERS_CHANCE: u32 = 5;

type Seed = [u32; 4];
type Observation = parsec::Observation<Transaction, PeerId>;
type BlockPayload = parsec::BlockPayload<Transaction, PeerId>;

struct Peer {
    id: PeerId,
    parsec: Parsec<Transaction, PeerId>,
    // The random network events which this node has voted for, held in the order in which the votes
    // were made.
    observations: Vec<Observation>,
    // The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    blocks: Vec<Block<Transaction, PeerId>>,
}

impl Peer {
    fn from_genesis(our_id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        Self {
            id: our_id.clone(),
            parsec: Parsec::from_genesis(
                our_id,
                genesis_group,
                vec![],
                ConsensusMode::Supermajority,
            ),
            observations: vec![],
            blocks: vec![],
        }
    }

    fn from_existing(
        our_id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        section: &BTreeSet<PeerId>,
    ) -> Self {
        Self {
            id: our_id.clone(),
            parsec: Parsec::from_existing(
                our_id,
                genesis_group,
                section,
                ConsensusMode::Supermajority,
            ),
            observations: vec![],
            blocks: vec![],
        }
    }

    fn vote_for_first_not_already_voted_for(&mut self, observations: &[Observation]) {
        if !self.parsec.can_vote() {
            return;
        }
        for observation in observations {
            if !self.observations.iter().any(|o| o == observation) {
                unwrap!(self.parsec.vote_for(observation.clone()));
                self.observations.push(observation.clone());
                break;
            }
        }
    }

    fn vote_to_add(&mut self, peer_id: &PeerId) {
        let add = vec![parsec::Observation::Add {
            peer_id: peer_id.clone(),
            related_info: vec![],
        }];
        self.vote_for_first_not_already_voted_for(&add);
    }

    fn vote_to_remove(&mut self, peer_id: &PeerId) {
        let remove = vec![parsec::Observation::Remove {
            peer_id: peer_id.clone(),
            related_info: vec![],
        }];
        self.vote_for_first_not_already_voted_for(&remove);
    }

    fn poll(&mut self) {
        while let Some(block) = self.parsec.poll() {
            self.blocks.push(block);
        }
    }

    fn has_added(&self, added_id: &PeerId) -> bool {
        self.blocks.iter().any(|block| match block.payload() {
            parsec::BlockPayload::InputObservation(parsec::InputObservation::Add {
                peer_id,
                ..
            }) => peer_id == added_id,
            _ => false,
        })
    }

    fn has_removed(&self, removed_id: &PeerId) -> bool {
        self.blocks.iter().any(|block| match block.payload() {
            parsec::BlockPayload::InputObservation(parsec::InputObservation::Remove {
                peer_id,
                ..
            }) => peer_id == removed_id,
            _ => false,
        })
    }

    fn blocks_payloads(&self) -> Vec<&BlockPayload> {
        self.blocks.iter().map(Block::payload).collect::<Vec<_>>()
    }

    fn display_id(&self) -> String {
        format!("{:?}: ", self.id)
    }

    fn completed(&self, params: &Params) -> bool {
        self.blocks.len() == params.total_observations()
    }
}

impl Debug for Peer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Peer{{ {:?} }}", self.id)
    }
}

#[derive(Default)]
struct Params {
    max_peer_count: usize,
    genesis_peer_count: usize,
    add_peers_count: usize,
    remove_peers_count: usize,
    opaque_event_count: usize,
    max_rounds: usize,
    seed: Option<Seed>,
}

impl Params {
    fn new() -> Params {
        let max_peers_info = format!(
            "must be a value greater than or equal to {}.",
            MIN_PEER_COUNT
        );
        let events_info = format!("must be a value less than or equal to {}.", MAX_EVENT_COUNT);
        let genesis_peers_info = format!(
            "must be a value between {} and that specified by '{}' inclusive.",
            MIN_PEER_COUNT, MAX_PEER_COUNT_ARG_LONG_NAME
        );
        let seed_info = format!(
            "should be quoted and in the form of four unsigned integers e.g. --{}=\"1, 2, 3, 4\".",
            SEED_ARG_LONG_NAME
        );
        let matches = App::new("Parsec basic example")
        .version(crate_version!())
        .about(
            "This example creates a mock network of peers, each running the Parsec protocol to \
             reach consensus on a number of random network events.  To dump each node's gossip \
             graph in dot format to a file in your system temp dir, build the example with \
             `--features=dump-graphs`.  If you have `dot` (from graphviz) available in your path, \
             each dot file will have a corresponding SVG file created for it.  Otherwise you can \
             copy the contents of a generated dot file into an online converter (e.g. \
             http://viz-js.com) to view the gossip graph.",
        ).set_term_width(100)
        .arg(
            Arg::with_name(MAX_PEER_COUNT_ARG_LONG_NAME)
                .short(MAX_PEER_COUNT_ARG_SHORT_NAME)
                .long(MAX_PEER_COUNT_ARG_LONG_NAME)
                .default_value("20")
                .value_name("COUNT")
                .help(&format!(
                    "Max. number of peers at any given time in the network; {}",
                    max_peers_info
                )).takes_value(true),
        ).arg(
            Arg::with_name(GENESIS_PEERS_ARG_LONG_NAME)
                .short(GENESIS_PEERS_ARG_SHORT_NAME)
                .long(GENESIS_PEERS_ARG_LONG_NAME)
                .default_value("4")
                .value_name("COUNT")
                .help(&format!(
                    "Number of initial peers in the network; {}",
                    genesis_peers_info
                )).takes_value(true),
        ).arg(
            Arg::with_name(ADD_PEER_EVENTS_ARG_LONG_NAME)
                .short(ADD_PEER_EVENTS_ARG_SHORT_NAME)
                .long(ADD_PEER_EVENTS_ARG_LONG_NAME)
                .default_value("1")
                .value_name("COUNT")
                .help(&format!(
                    "Number of peers to add to the network while running.  Regardless of the value \
                     passed here, the total number of peers will not be allowed to exceed the \
                     value specified by '{}' at any time.",
                    MAX_PEER_COUNT_ARG_LONG_NAME
                )).takes_value(true),
        ).arg(
            Arg::with_name(REMOVE_PEER_EVENTS_ARG_LONG_NAME)
                .short(REMOVE_PEER_EVENTS_ARG_SHORT_NAME)
                .long(REMOVE_PEER_EVENTS_ARG_LONG_NAME)
                .default_value("1")
                .value_name("COUNT")
                .help(&format!(
                    "Number of peers to remove from the network while running.  Regardless of the \
                     value passed here, the total number of peers will not be allowed to fall \
                     below {}",
                    MIN_PEER_COUNT
                )).takes_value(true),
        ).arg(
            Arg::with_name(OPAQUE_EVENTS_ARG_LONG_NAME)
                .short(OPAQUE_EVENTS_ARG_SHORT_NAME)
                .long(OPAQUE_EVENTS_ARG_LONG_NAME)
                .default_value("3")
                .value_name("COUNT")
                .help(&format!(
                    "Number of random opaque network events to reach consensus on; {}",
                    events_info
                )).takes_value(true),
        ).arg(
            Arg::with_name(MAX_ROUNDS_ARG_LONG_NAME)
                .long(MAX_ROUNDS_ARG_LONG_NAME)
                .default_value("1000")
                .value_name("COUNT")
                .help(
                    "Max. number of rounds of gossip between peers in the network.  If consensus \
                     on all events is achieved by all peers in fewer rounds than this, the example \
                     will exit.",
                ).takes_value(true),
        ).arg(
            Arg::with_name(SEED_ARG_LONG_NAME)
                .short(SEED_ARG_SHORT_NAME)
                .long(SEED_ARG_LONG_NAME)
                .value_name("VALUE")
                .help(&format!(
                    "Seed used to initialise the random number generator; {}",
                    seed_info
                )).takes_value(true),
        ).get_matches();

        let mut params = Params::default();
        match value_t!(matches.value_of(MAX_PEER_COUNT_ARG_LONG_NAME), usize) {
            Ok(count) if count >= MIN_PEER_COUNT => params.max_peer_count = count,
            _ => {
                println!("'{}' {}", MAX_PEER_COUNT_ARG_LONG_NAME, max_peers_info);
                process::exit(1);
            }
        }
        match value_t!(matches.value_of(GENESIS_PEERS_ARG_LONG_NAME), usize) {
            Ok(count) if count >= MIN_PEER_COUNT && count <= params.max_peer_count => {
                params.genesis_peer_count = count
            }
            _ => {
                println!("'{}' {}", GENESIS_PEERS_ARG_LONG_NAME, genesis_peers_info);
                process::exit(2);
            }
        }
        params.add_peers_count = parse_usize(&matches, ADD_PEER_EVENTS_ARG_LONG_NAME);
        params.remove_peers_count = parse_usize(&matches, REMOVE_PEER_EVENTS_ARG_LONG_NAME);

        println!("Running example with:");
        println!("  max peer count: {}", params.max_peer_count);
        println!("  initial peers: {}", params.genesis_peer_count);
        println!("  peers to be added: {}", params.add_peers_count);
        println!("  peers to be removed: {}", params.remove_peers_count);
        println!("  random network events: {}", params.opaque_event_count);

        if params.genesis_peer_count + params.add_peers_count
            < params.remove_peers_count + MIN_PEER_COUNT
        {
            println!(
                "Can't remove that many peers and still retain at least {} peers in the network.",
                MIN_PEER_COUNT
            );
            println!(
                "Max value for '{}' with these args is {}.",
                REMOVE_PEER_EVENTS_ARG_LONG_NAME,
                params.genesis_peer_count + params.add_peers_count - MIN_PEER_COUNT
            );
            process::exit(3);
        }

        if params.genesis_peer_count + params.add_peers_count
            > params.remove_peers_count + params.max_peer_count
        {
            println!(
                "Can't add that many peers and not exceed {} peers in the network.",
                params.max_peer_count
            );
            println!(
                "Max value for '{}' with these args is {}.",
                ADD_PEER_EVENTS_ARG_LONG_NAME,
                params.max_peer_count + params.remove_peers_count - params.genesis_peer_count
            );
            process::exit(4);
        }

        match value_t!(matches.value_of(OPAQUE_EVENTS_ARG_LONG_NAME), usize) {
            Ok(count) if count <= MAX_EVENT_COUNT => params.opaque_event_count = count,
            _ => {
                println!("'{}' {}", OPAQUE_EVENTS_ARG_LONG_NAME, events_info);
                process::exit(5);
            }
        }
        params.max_rounds = parse_usize(&matches, MAX_ROUNDS_ARG_LONG_NAME);
        params.seed =
            matches
                .value_of(SEED_ARG_LONG_NAME)
                .map(|seed_str| match parse_seed(seed_str) {
                    Ok(seed) => seed,
                    Err(()) => {
                        println!("'{}' {}", SEED_ARG_LONG_NAME, seed_info);
                        process::exit(6);
                    }
                });

        params
    }

    fn total_observations(&self) -> usize {
        // Expect + 1 for the genesis block.
        self.add_peers_count + self.remove_peers_count + self.opaque_event_count + 1
    }
}

fn parse_usize(matches: &ArgMatches, arg: &str) -> usize {
    match value_t!(matches.value_of(arg), usize) {
        Ok(count) => count,
        _ => {
            println!("Failed to parse '{}' as a positive integer.", arg);
            process::exit(7);
        }
    }
}

fn parse_seed(seed_str: &str) -> Result<Seed, ()> {
    let parts = seed_str
        .split(',')
        .map(ToString::to_string)
        .collect::<Vec<String>>();
    if parts.len() != 4 {
        return Err(());
    }
    let mut seed = [0; 4];
    for (index, part) in parts.iter().enumerate() {
        seed[index] = part
            .trim_matches(|c: char| !c.is_digit(10))
            .parse::<u32>()
            .map_err(|_| ())?;
    }
    Ok(seed)
}

struct Environment {
    params: Params,
    rng: SeededRng,
    genesis_group: BTreeSet<PeerId>,
    peers: Vec<Peer>,
    opaque_observations: Vec<Observation>,
    peers_added_count: usize,
    peers_removed_count: usize,
    current_remove_peers: Vec<PeerId>,
    current_new_peer: Option<PeerId>,
    current_round: usize,
    pretty_id_count: usize,
}

impl Environment {
    fn new() -> Self {
        let params = Params::new();

        let rng = params
            .seed
            .map_or_else(SeededRng::new, SeededRng::from_seed);
        println!("Using {:?}", rng);

        let mut env = Environment {
            params,
            rng,
            genesis_group: BTreeSet::new(),
            peers: vec![],
            opaque_observations: vec![],
            peers_added_count: 0,
            peers_removed_count: 0,
            current_remove_peers: vec![],
            current_new_peer: None,
            current_round: 0,
            pretty_id_count: 0,
        };

        // Set up the requested number of peers and random network events.
        env.genesis_group = (0..env.params.genesis_peer_count)
            .map(|_| env.new_peer_id())
            .collect();

        env.peers = env
            .genesis_group
            .iter()
            .map(|id| Peer::from_genesis(id.clone(), &env.genesis_group))
            .collect();

        env.opaque_observations = (0..env.params.opaque_event_count)
            .map(|_| parsec::Observation::OpaquePayload(env.rng.gen()))
            .collect();

        env
    }

    // Returns a randomly created new `PeerId`.
    fn new_peer_id(&mut self) -> PeerId {
        let peer = PeerId::from_index(self.pretty_id_count).unwrap_or_else(|| {
            PeerId::new_with_random_keypair(
                self.rng
                    .gen_ascii_chars()
                    .take(6)
                    .collect::<String>()
                    .as_str(),
            )
        });
        self.pretty_id_count += 1;
        peer
    }

    // Returns a random number of peers which can be dropped so that we don't lose consensus, and so
    // that we retain at least 2 peers at all times.
    fn num_to_drop(&mut self) -> usize {
        if self.peers.len() > MIN_PEER_COUNT
            && self.params.remove_peers_count != self.peers_removed_count
            && self.rng.gen_weighted_bool(REMOVE_PEERS_CHANCE)
        {
            assert!(self.peers_removed_count < self.params.remove_peers_count);
            let respect_remove_peers_count =
                self.params.remove_peers_count - self.peers_removed_count;
            let strictly_less_than_a_third_plus_one = (self.peers.len() + 2) / 3;
            let max_peers_to_remove = cmp::min(
                respect_remove_peers_count,
                strictly_less_than_a_third_plus_one,
            );
            if max_peers_to_remove == 1 {
                // gen_range(1, 1) would panic as the range must contain a strictly positive
                // number of elements
                1
            } else {
                self.rng.gen_range(1, max_peers_to_remove)
            }
        } else {
            0
        }
    }

    // Sets `self.new_peer` to a new `PeerId` with a random chance, if we still haven't created
    // `add_peers_count`.
    fn try_new_peer(&mut self) {
        self.current_new_peer = if self.peers.len() < self.params.max_peer_count
            && self.params.add_peers_count != self.peers_added_count
            && self.rng.gen_weighted_bool(ADD_PEER_CHANCE)
        {
            Some(self.new_peer_id())
        } else {
            None
        };
    }

    fn prepare_next_phase(&mut self) {
        println!("\nStarting next phase\n===================");
        let mut num_to_drop = self.num_to_drop();
        self.try_new_peer();
        self.peers_removed_count += num_to_drop;
        self.current_remove_peers.clear();
        while num_to_drop > 0 {
            self.rng.shuffle(&mut self.peers);
            let dropped = unwrap!(self.peers.pop());
            println!("Dropping {:?}", dropped.id);
            self.current_remove_peers.push(dropped.id);
            num_to_drop -= 1;
        }
        if let Some(ref new_peer_id) = self.current_new_peer {
            self.peers_added_count += 1;
            println!("Adding {:?}", new_peer_id);
            let section = self.peers.iter().map(|peer| peer.id.clone()).collect();
            let new_peer = Peer::from_existing(new_peer_id.clone(), &self.genesis_group, &section);
            self.peers.push(new_peer);
        }
    }

    fn vote_for_non_opaques(&mut self) {
        for peer in &mut self.peers {
            if let Some(ref new_peer_id) = self.current_new_peer {
                peer.vote_to_add(new_peer_id);
            }

            for peer_to_remove in &self.current_remove_peers {
                peer.vote_to_remove(peer_to_remove);
            }
        }
    }

    fn phase_complete(&self) -> bool {
        self.current_round >= self.params.max_rounds
            || self.peers.iter().all(|peer| {
                if let Some(ref new_peer_id) = self.current_new_peer {
                    if !peer.has_added(new_peer_id) {
                        return false;
                    }
                }

                for removed_peer_id in &self.current_remove_peers {
                    if !peer.has_removed(removed_peer_id) {
                        return false;
                    }
                }

                true
            })
    }

    fn get_receiver_and_message(
        &mut self,
        sender_index: usize,
    ) -> (usize, Request<Transaction, PeerId>) {
        let mut receiver_index = (sender_index + 1) % self.peers.len();

        loop {
            let receiver_id = self.peers[receiver_index].id.clone();
            match self.peers[sender_index].parsec.create_gossip(&receiver_id) {
                Ok(request) => {
                    return (receiver_index, request);
                }
                Err(_) => {
                    receiver_index += 1;
                    if receiver_index >= self.peers.len() {
                        receiver_index = 0;
                    }
                    if receiver_index == (sender_index + 1) % self.peers.len() {
                        panic!("No suitable peer to gossip to.");
                    }
                }
            }
        }
    }

    fn execute_round(&mut self) {
        println!("\nGossip Round {:03}\n================", self.current_round);
        self.current_round += 1;

        self.rng.shuffle(&mut self.peers);

        // Each peer will send a request and handle the corresponding response.  For each peer,
        // there is also a chance that they will vote for one of the observations if they haven't
        // already done so.
        for sender_index in 0..self.peers.len() {
            if !self.peers[sender_index].parsec.can_vote() {
                self.peers[sender_index].poll();
                continue;
            }

            let (receiver_index, request) = self.get_receiver_and_message(sender_index);

            let receiver_id = self.peers[receiver_index].id.clone();
            let sender_id = self.peers[sender_index].id.clone();

            if let Ok(response) = self.peers[receiver_index]
                .parsec
                .handle_request(&sender_id, request)
            {
                unwrap!(self.peers[sender_index]
                    .parsec
                    .handle_response(&receiver_id, response));
            }

            let peer = &mut self.peers[sender_index];
            if peer.observations.len() < self.params.total_observations()
                && self.rng.gen_weighted_bool(OPAQUE_CHANCE)
            {
                self.rng.shuffle(&mut self.opaque_observations);
                peer.vote_for_first_not_already_voted_for(&self.opaque_observations);
            }

            peer.poll();
        }
    }

    fn print_summary(&mut self) {
        self.peers.sort_by_key(|peer| peer.id.clone());
        println!("Votes:");
        let max_width = unwrap!(self.peers.iter().map(|peer| peer.display_id().len()).max());
        for peer in &self.peers {
            println!(
                "  {:2$}{:?}",
                peer.display_id(),
                peer.observations,
                max_width
            );
        }
        println!("Stable Blocks:");
        for peer in &self.peers {
            println!(
                "  {:2$}{:?}",
                peer.display_id(),
                peer.blocks_payloads(),
                max_width
            );
        }
        println!();
    }

    fn validate_blocks_order(&mut self) {
        self.peers
            .sort_by_key(|peer| usize::MAX - peer.blocks.len());
        let mut payloads = self.peers[0].blocks_payloads();
        for peer in self.peers.iter().skip(1) {
            payloads.truncate(peer.blocks.len());
            if peer.blocks_payloads() != payloads {
                println!(
                    "\n!!! {:?} and {:?} have failed to agree on stable block order !!!",
                    self.peers[0].id, peer.id
                );
                process::exit(8);
            }
        }
    }

    fn completed(&self) -> bool {
        if self.peers.iter().all(|peer| peer.completed(&self.params)) {
            return true;
        } else if self.current_round >= self.params.max_rounds {
            println!(
                "\n!!! Failed to reach consensus within {} rounds of gossip... giving up !!!",
                self.params.max_rounds
            );
            process::exit(9);
        }
        false
    }
}

fn main() {
    unwrap!(log::init(false));

    let mut env = Environment::new();

    while !env.completed() {
        env.prepare_next_phase();
        loop {
            env.vote_for_non_opaques();
            env.execute_round();
            env.print_summary();
            env.validate_blocks_order();
            if env.phase_complete() {
                break;
            }
        }
    }
}
