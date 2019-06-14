// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Environment, Observation, PeerStatus, PeerStatuses};
#[cfg(feature = "dump-graphs")]
use crate::dump_graph::DIR;
use crate::{
    mock::{PeerId, Transaction, NAMES},
    observation::{ConsensusMode, Observation as ParsecObservation},
};
use itertools::Itertools;
use rand::{seq, Rng};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, iter, mem,
};
#[cfg(feature = "dump-graphs")]
use std::{fs::File, io::Write};

/// This struct holds the data necessary to make a simulated request when a node executes a local
/// step.
#[derive(Clone, Debug)]
pub struct Request {
    /// The recipient of the request - it will then respond back to the sender
    pub recipient: PeerId,
    /// The delay, in steps, between sending and reception of the request
    pub req_delay: usize,
    /// The delay, in steps, between sending and reception of the response
    pub resp_delay: usize,
}

#[derive(Clone, Debug)]
pub struct Genesis {
    ids_of_good_peers: BTreeSet<PeerId>,
    ids_of_malicious_peers: BTreeSet<PeerId>,
}

impl Genesis {
    pub fn new(ids_of_good_peers: BTreeSet<PeerId>) -> Self {
        Self {
            ids_of_good_peers,
            ids_of_malicious_peers: BTreeSet::new(),
        }
    }

    pub fn new_with_malicious(
        ids_of_good_peers: BTreeSet<PeerId>,
        ids_of_malicious_peers: BTreeSet<PeerId>,
    ) -> Self {
        assert!(
            ids_of_good_peers.is_disjoint(&ids_of_malicious_peers),
            "{:?} cannot be good *and* malicious",
            ids_of_good_peers
                .intersection(&ids_of_malicious_peers)
                .collect_vec()
        );
        Self {
            ids_of_good_peers,
            ids_of_malicious_peers,
        }
    }

    fn from_all_ids(mut peer_ids: BTreeSet<PeerId>, malicious_count: usize) -> Self {
        assert!(malicious_count <= peer_ids.len());
        if malicious_count == 0 {
            return Self {
                ids_of_good_peers: peer_ids,
                ids_of_malicious_peers: BTreeSet::new(),
            };
        }

        let split_off_at_id = unwrap!(peer_ids.iter().rev().nth(malicious_count - 1)).clone();
        let ids_of_malicious_peers = peer_ids.split_off(&split_off_at_id);
        Self {
            ids_of_good_peers: peer_ids,
            ids_of_malicious_peers,
        }
    }

    pub fn ids_of_good_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.ids_of_good_peers.iter()
    }

    pub fn ids_of_malicious_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.ids_of_malicious_peers.iter()
    }

    pub fn all_ids(&self) -> BTreeSet<PeerId> {
        self.ids_of_good_peers()
            .chain(self.ids_of_malicious_peers())
            .cloned()
            .collect()
    }
}

/// Represents an event the network is supposed to simulate.
/// The simulation proceeds in steps. During every global step, every node has some probability
/// of being scheduled to perform a local step, consisting of receiving messages that reached it
/// by this time, generating appropriate responses and optionally sending a gossip request.
#[derive(Clone, Debug)]
pub enum ScheduleEvent {
    /// Event storing the names of the initial nodes
    Genesis(Genesis),
    /// This event variant represents a scheduled slot to execute a local step for all active peers.
    /// It contains a global step number.
    LocalStep(usize),
    /// This event causes the node with the given ID to stop responding. All further events
    /// concerning that node will be ignored.
    Fail(PeerId),
    /// This event makes a node vote on the given observation.
    VoteFor(PeerId, Observation),
    /// Adds a peer to the network (this is separate from nodes voting to add the peer)
    AddPeer(PeerId),
    /// Removes a peer from the network (this is separate from nodes voting to remove the peer)
    /// It is similar to Fail in that the peer will stop responding; however, this will also
    /// cause the other peers to vote for removal
    RemovePeer(PeerId),
    /// Start Dkg process: place-holder for Dkg participant to avoid clippy::large_enum_variant
    StartDkg(BTreeSet<PeerId>),
}

impl ScheduleEvent {
    pub fn fail(&self) -> Option<&PeerId> {
        if let ScheduleEvent::Fail(ref peer) = self {
            Some(peer)
        } else {
            None
        }
    }

    pub fn get_peer(&self) -> &PeerId {
        match *self {
            ScheduleEvent::LocalStep(_) => panic!("ScheduleEvent::get_peer called on LocalStep!"),
            ScheduleEvent::Fail(ref peer) => peer,
            ScheduleEvent::VoteFor(ref peer, _) => peer,
            ScheduleEvent::AddPeer(ref peer) => peer,
            ScheduleEvent::RemovePeer(ref peer) => peer,
            ScheduleEvent::Genesis(_) => panic!("ScheduleEvent::get_peer called on Genesis!"),
            ScheduleEvent::StartDkg(_) => panic!("ScheduleEvent::get_peer called on StartDkg!"),
        }
    }
}

/// Stores pending observations per node, so that nodes only vote for each observation once.
pub struct PendingObservations {
    min_delay: usize,
    max_delay: usize,
    p_delay: f64,
    queues: BTreeMap<PeerId, BTreeMap<usize, Vec<Observation>>>,
    opaque_vote_counts: BTreeMap<PeerId, usize>,
}

impl PendingObservations {
    pub fn new(opts: &ScheduleOptions) -> PendingObservations {
        PendingObservations {
            min_delay: opts.min_observation_delay,
            max_delay: opts.max_observation_delay,
            p_delay: opts.p_observation_delay,
            queues: BTreeMap::new(),
            opaque_vote_counts: BTreeMap::new(),
        }
    }

    /// Add the observation to peers' queues at a random step after the event happened
    pub fn peers_make_observation<'a, R: Rng, I: IntoIterator<Item = &'a PeerId>>(
        &mut self,
        rng: &mut R,
        peers: I,
        strategy: Sampling,
        step: usize,
        observation: &Observation,
    ) {
        let peers: Vec<_> = peers.into_iter().collect();
        let peers = sample(rng, &peers, strategy);
        for peer in peers {
            let observations = self
                .queues
                .entry(peer.clone())
                .or_insert_with(BTreeMap::new);
            let tgt_step = step
                + self.min_delay
                + binomial(rng, self.max_delay - self.min_delay, self.p_delay);
            let step_observations = observations.entry(tgt_step).or_insert_with(Vec::new);
            step_observations.push(observation.clone());

            if observation.is_opaque() {
                *self.opaque_vote_counts.entry(peer.clone()).or_insert(0) += 1
            }
        }
    }

    /// Pops all the observations that should be made at `step` at the latest
    pub fn pop_at_step(&mut self, peer: &PeerId, step: usize) -> Vec<Observation> {
        let mut result = vec![];
        if let Some(queue) = self.queues.get_mut(peer) {
            let to_leave = queue.split_off(&(step + 1));
            let popped = mem::replace(queue, to_leave);
            for (_, observations) in popped {
                result.extend(observations.into_iter());
            }
            result
        } else {
            vec![]
        }
    }

    /// Returns true if no more peers have pending observations
    pub fn queues_empty<'a, I: Iterator<Item = &'a PeerId>>(&self, mut peers: I) -> bool {
        peers.all(|id| self.queues.get(id).map_or(true, BTreeMap::is_empty))
    }

    /// Number of `OpaquePayload` observations scheduled to be made by the given peer.
    pub fn num_opaque_observations(&self, peer: &PeerId) -> usize {
        self.opaque_vote_counts.get(peer).cloned().unwrap_or(0)
    }
}

/// Available options for the distribution of message delays
#[derive(Clone, Copy, Debug)]
pub enum DelayDistribution {
    Poisson(f64),
    Constant(usize),
}

/// A struct aggregating the options controlling schedule generation
#[derive(Clone, Debug)]
pub struct ScheduleOptions {
    /// Size of the genesis group
    pub genesis_size: usize,
    /// Number of malicious peers included in the genesis group
    pub malicious_genesis_count: usize,
    /// Probability per step that a random node will fail
    pub prob_failure: f64,
    /// Probability that a vote will get repeated
    pub prob_vote_duplication: f64,
    /// A map: step number → num of nodes to fail
    pub deterministic_failures: BTreeMap<usize, usize>,
    /// The distribution of message delays
    pub delay_distr: DelayDistribution,
    /// The probability that a node will gossip during its local step
    pub prob_gossip: f64,
    /// When true, nodes will first insert all votes into the graph, then start gossiping
    pub votes_before_gossip: bool,
    /// Number of opaque observations to make
    pub opaque_to_add: usize,
    /// Probability per global step that a node will make a vote
    pub prob_opaque: f64,
    /// The number of peers to be added during the simulation
    pub peers_to_add: usize,
    /// Probability per step that a peer will get added
    pub prob_add: f64,
    /// The number of peers to be removed during the simulation
    pub peers_to_remove: usize,
    /// Probability per step that a peer will get removed
    pub prob_remove: f64,
    /// Minimum number of non-failed peers
    pub min_peers: usize,
    /// Maximum number of peers
    pub max_peers: usize,
    /// Minimum delay between an event and its observation
    pub min_observation_delay: usize,
    /// Maximum delay between an event and its observation
    pub max_observation_delay: usize,
    /// The binomial distribution p coefficient for observation delay
    pub p_observation_delay: f64,
    /// Number of peers that vote on opaque payloads
    pub opaque_voters: Sampling,
    /// Number of peers that vote on transparent payloads (Add, Remove, ...)
    pub transparent_voters: Sampling,
    /// Intermediate consistency checks (Raise error closer to the source)
    pub intermediate_consistency_checks: bool,
    /// The only genesis members that will compute consensus if provided. All if none.
    pub genesis_restrict_consensus_to: Option<BTreeSet<PeerId>>,
}

impl ScheduleOptions {
    /// Generates a delay according to the delay distribution
    pub fn gen_delay<R: Rng>(&self, rng: &mut R) -> usize {
        match self.delay_distr {
            DelayDistribution::Poisson(lambda) => poisson(rng, lambda),
            DelayDistribution::Constant(x) => x,
        }
    }
}

impl Default for ScheduleOptions {
    fn default() -> ScheduleOptions {
        ScheduleOptions {
            // default genesis of 4 peers
            genesis_size: 4,
            // no malicious genesis peers
            malicious_genesis_count: 0,
            // no randomised failures
            prob_failure: 0.0,
            // no vote duplication
            prob_vote_duplication: 0.0,
            // no deterministic failures
            deterministic_failures: BTreeMap::new(),
            // randomised delays, 4 steps on average
            delay_distr: DelayDistribution::Poisson(4.0),
            // gossip every so often
            prob_gossip: 0.05,
            // vote while gossiping
            votes_before_gossip: false,
            // add 5 opaque observations
            opaque_to_add: 5,
            // vote for an opaque observation every ~20 steps
            prob_opaque: 0.05,
            // no adds
            peers_to_add: 0,
            // add a node every 50 steps, on average
            prob_add: 0.02,
            // no removes
            peers_to_remove: 0,
            // remove a node every 50 steps, on average
            prob_remove: 0.02,
            // always keep at least 3 active peers
            min_peers: 3,
            // allow at most as many peers as we have names
            max_peers: NAMES.len(),
            // observation delay between 1
            min_observation_delay: 1,
            // ...and 100
            max_observation_delay: 100,
            // with binomial p coefficient 0.45
            p_observation_delay: 0.45,
            opaque_voters: Sampling::Fraction(1.0, 1.0),
            transparent_voters: Sampling::Fraction(1.0, 1.0),
            intermediate_consistency_checks: true,
            genesis_restrict_consensus_to: None,
        }
    }
}

#[derive(Debug)]
pub enum ObservationEvent {
    Opaque(Transaction),
    AddPeer(PeerId),
    RemovePeer(PeerId),
    Fail(PeerId),
    StartDkg,
}

impl ObservationEvent {
    pub fn is_opaque(&self) -> bool {
        match *self {
            ObservationEvent::Opaque(_) => true,
            _ => false,
        }
    }

    pub fn get_opaque(self) -> Option<Observation> {
        match self {
            ObservationEvent::Opaque(t) => Some(ParsecObservation::OpaquePayload(t)),
            _ => None,
        }
    }
}

pub struct ObservationSchedule {
    pub genesis: Genesis,
    /// A `Vec` of pairs (step number, event), carrying information about what events happen at
    /// which steps
    pub schedule: Vec<(usize, ObservationEvent)>,
}

impl ObservationSchedule {
    fn gen<R: Rng>(rng: &mut R, options: &ScheduleOptions) -> ObservationSchedule {
        let mut schedule = vec![];
        let mut names_iter = NAMES
            .iter()
            .map(ToString::to_string)
            // Generate numbered names skipping the ones in NAMES.
            .chain((10..).map(|num| num.to_string()));

        // a counter for peer adds/removes and opaque transactions
        // (so not counting genesis and failures)
        let mut num_observations: usize = 0;
        let mut added_peers: usize = 0;
        let mut removed_peers: usize = 0;
        let mut opaque_count: usize = 0;

        // schedule genesis first
        let genesis_ids = names_iter
            .by_ref()
            .take(options.genesis_size)
            .map(|s| PeerId::new(&s))
            .collect();
        let mut peers = PeerStatuses::new(&genesis_ids);

        let mut step: usize = 1;
        while num_observations
            < options.opaque_to_add + options.peers_to_add + options.peers_to_remove
        {
            if opaque_count < options.opaque_to_add && rng.gen::<f64>() < options.prob_opaque {
                schedule.push((
                    step,
                    ObservationEvent::Opaque(Transaction::new(opaque_count.to_string())),
                ));
                num_observations += 1;
                opaque_count += 1;
            }
            if added_peers < options.peers_to_add && rng.gen::<f64>() < options.prob_add {
                let next_id = PeerId::new(&unwrap!(names_iter.next()));
                peers.add_peer(next_id.clone());
                schedule.push((step, ObservationEvent::AddPeer(next_id)));
                num_observations += 1;
                added_peers += 1;
            }
            if removed_peers < options.peers_to_remove && rng.gen::<f64>() < options.prob_remove {
                if let Some(id) = peers.remove_random_peer(rng, options.min_peers) {
                    schedule.push((step, ObservationEvent::RemovePeer(id)));
                    num_observations += 1;
                    removed_peers += 1;
                }
            }

            // generate a random failure
            if rng.gen::<f64>() < options.prob_failure {
                if let Some(id) = peers.fail_random_peer(rng, options.min_peers) {
                    schedule.push((step, ObservationEvent::Fail(id)));
                }
            }
            // then handle deterministic failures
            let num_deterministic_fails = options
                .deterministic_failures
                .get(&step)
                .cloned()
                .unwrap_or(0);

            for _ in 0..num_deterministic_fails {
                if let Some(id) = peers.fail_random_peer(rng, options.min_peers) {
                    schedule.push((step, ObservationEvent::Fail(id)));
                }
            }

            step += 1;
        }

        ObservationSchedule {
            genesis: Genesis::from_all_ids(genesis_ids, options.malicious_genesis_count),
            schedule,
        }
    }

    fn extract_opaque(&mut self) -> Vec<Observation> {
        let schedule = mem::replace(&mut self.schedule, vec![]);
        let (opaque, rest): (Vec<_>, _) = schedule
            .into_iter()
            .partition(|&(_, ref observation)| observation.is_opaque());
        self.schedule = rest;
        opaque
            .into_iter()
            .filter_map(|(_, o)| o.get_opaque())
            .collect()
    }

    fn count_observations(&self) -> usize {
        self.schedule
            .iter()
            .filter(|&(_, ref event)| match *event {
                ObservationEvent::Fail(_) => false,
                _ => true,
            })
            .count()
    }

    fn count_expected_accusations(&self) -> usize {
        if cfg!(feature = "malice-detection") {
            // One accusation per malicious peer as currently the malicious peers commit only one
            // malice each.
            self.genesis.ids_of_malicious_peers.len()
        } else {
            0
        }
    }
}

pub struct StepObservationSchedule {
    /// A `sorted Vec` of pairs (step number, event), carrying information about what events happen at
    /// which steps
    schedule: Vec<(usize, ObservationEvent)>,
}

impl StepObservationSchedule {
    fn new(mut schedule: Vec<(usize, ObservationEvent)>) -> Self {
        schedule.sort_by_key(|(step, _)| *step);
        Self { schedule }
    }
}

/// Stores the list of network events to be simulated.
#[derive(Clone)]
pub struct Schedule {
    pub peers: BTreeMap<PeerId, PeerStatus>,
    pub min_observations: usize,
    pub max_observations: usize,
    pub events: Vec<ScheduleEvent>,
    pub additional_steps: std::ops::Range<usize>,
    pub options: ScheduleOptions,
}

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "----------------------------")?;
        writeln!(f, " Schedule:")?;
        for event in &self.events {
            writeln!(f, "- {:?}", event)?;
        }
        writeln!(f, "----------------------------")
    }
}

impl Schedule {
    #[cfg(feature = "dump-graphs")]
    fn save(&self, options: &ScheduleOptions) {
        let path = DIR.with(|dir| dir.join("schedule.txt"));
        if let Ok(mut file) = File::create(&path) {
            unwrap!(writeln!(
                file,
                "Generating a schedule with options: {:?}",
                options
            ));
            unwrap!(write!(file, "{:?}", self));
        } else {
            println!("Failed to create {:?}", path);
        }
    }

    fn perform_step(
        step: usize,
        peers: &mut PeerStatuses,
        // mut required to be able to use the inner reference in a loop
        mut pending: Option<&mut PendingObservations>,
        schedule: &mut Vec<ScheduleEvent>,
    ) {
        // First let the peers vote for scheduled observations...
        if let Some(pending) = pending.as_mut() {
            for peer in peers.all_peers() {
                for observation in pending.pop_at_step(peer, step) {
                    schedule.push(ScheduleEvent::VoteFor(peer.clone(), observation));
                }
            }
        }

        // ...then perform the local step.
        schedule.push(ScheduleEvent::LocalStep(step));
    }

    pub fn new(env: &mut Environment, options: &ScheduleOptions) -> Schedule {
        let obs_schedule = ObservationSchedule::gen(&mut env.rng, options);
        Self::from_observation_schedule(env, options, obs_schedule)
    }

    /// Creates a new pseudo-random schedule based on the given options
    ///
    /// The `let_and_return` clippy lint is allowed since it is actually necessary to create the
    /// `result` variable so the result can be saved when the `dump-graphs` feature is used.
    #[allow(clippy::let_and_return)]
    pub fn from_observation_schedule(
        env: &mut Environment,
        options: &ScheduleOptions,
        mut obs_schedule: ObservationSchedule,
    ) -> Schedule {
        let mut pending = PendingObservations::new(options);

        // the +1 below is to account for genesis
        let max_observations =
            obs_schedule.count_observations() + obs_schedule.count_expected_accusations() + 1;

        let mut peers = PeerStatuses::new(&obs_schedule.genesis.all_ids());
        let mut step = 0;

        // genesis has to be first
        let mut schedule = vec![ScheduleEvent::Genesis(obs_schedule.genesis.clone())];
        let mut observations_made = vec![];

        // if votes before gossip enabled, insert all votes
        if options.votes_before_gossip {
            let opaque_transactions = obs_schedule.extract_opaque();
            let sampling = match env.network.consensus_mode() {
                ConsensusMode::Single => Sampling::Constant(1),
                ConsensusMode::Supermajority => options.opaque_voters,
            };

            for obs in opaque_transactions {
                pending.peers_make_observation(
                    &mut env.rng,
                    peers.all_peers(),
                    sampling,
                    step,
                    &obs,
                );
                observations_made.push(obs);
            }
        }

        let step_obs_schedule = StepObservationSchedule::new(obs_schedule.schedule);
        let schedule_by_step = step_obs_schedule
            .schedule
            .into_iter()
            .group_by(|(step, _)| *step);

        for (_, observations) in schedule_by_step.into_iter() {
            for (_, observation) in observations {
                match observation {
                    ObservationEvent::AddPeer(new_peer) => {
                        let observation = ParsecObservation::Add {
                            peer_id: new_peer.clone(),
                            related_info: vec![],
                        };

                        peers.add_peer(new_peer.clone());
                        pending.peers_make_observation(
                            &mut env.rng,
                            peers.all_peers(),
                            options.transparent_voters,
                            step,
                            &observation,
                        );
                        schedule.push(ScheduleEvent::AddPeer(new_peer.clone()));

                        // vote for all observations that were made before this peer joined
                        // this prevents situations in which peers joining reach consensus before
                        // some other observations they haven't seen, which cause those
                        // observations to no longer have a supermajority of votes and never get
                        // consensused; this is something that can validly happen in a real
                        // network, but causes problems with evaluating test results
                        for obs in &observations_made {
                            let sampling = if obs.is_opaque() {
                                // No need to mirror opaques if we are in the single-vote mode.
                                if env.network.consensus_mode() == ConsensusMode::Single {
                                    continue;
                                }

                                options.opaque_voters
                            } else {
                                options.transparent_voters
                            };

                            pending.peers_make_observation(
                                &mut env.rng,
                                iter::once(&new_peer),
                                sampling,
                                step,
                                obs,
                            );
                        }

                        observations_made.push(observation);
                    }
                    ObservationEvent::RemovePeer(peer) => {
                        let observation = ParsecObservation::Remove {
                            peer_id: peer.clone(),
                            related_info: vec![],
                        };

                        peers.remove_peer(&peer);
                        pending.peers_make_observation(
                            &mut env.rng,
                            peers.all_peers(),
                            options.transparent_voters,
                            step,
                            &observation,
                        );
                        schedule.push(ScheduleEvent::RemovePeer(peer));

                        observations_made.push(observation);
                    }
                    ObservationEvent::Opaque(payload) => {
                        let observation = ParsecObservation::OpaquePayload(payload);
                        let sampling = match env.network.consensus_mode() {
                            ConsensusMode::Single => Sampling::Constant(1),
                            ConsensusMode::Supermajority => options.opaque_voters,
                        };

                        pending.peers_make_observation(
                            &mut env.rng,
                            peers.all_peers(),
                            sampling,
                            step,
                            &observation,
                        );
                        observations_made.push(observation);
                    }
                    ObservationEvent::Fail(peer) => {
                        peers.fail_peer(&peer);
                        schedule.push(ScheduleEvent::Fail(peer));
                    }
                    ObservationEvent::StartDkg => {
                        schedule.push(ScheduleEvent::StartDkg(Default::default()));
                    }
                }
            }
            Self::perform_step(step, &mut peers, Some(&mut pending), &mut schedule);
            step += 1;
        }

        while !pending.queues_empty(peers.all_peers()) {
            Self::perform_step(step, &mut peers, Some(&mut pending), &mut schedule);
            step += 1;
        }

        // Gossip should theoretically complete in O(log N) steps
        // The constant (adjustment_coeff) is for making the number big enough.
        let n = peers.present_peers().count() as f64;
        let adjustment_coeff = 250.0 / options.prob_gossip;
        let additional_steps = (adjustment_coeff * n.ln()) as usize;

        // Peers scheduled for removal / failure might not get a chance to vote for their scheduled
        // observations.
        let min_observations = if env.network.consensus_mode() == ConsensusMode::Single {
            max_observations
                - peers
                    .inactive_peers()
                    .map(|peer| pending.num_opaque_observations(peer))
                    .sum::<usize>()
        } else {
            max_observations
        };

        let result = Schedule {
            peers: peers.into(),
            min_observations,
            max_observations,
            events: schedule,
            additional_steps: step..(step + additional_steps),
            options: options.clone(),
        };
        #[cfg(feature = "dump-graphs")]
        result.save(options);
        result
    }
}

// A function generating a Poisson-distributed random number.
fn poisson<R: Rng>(rng: &mut R, lambda: f64) -> usize {
    let mut result = 0;
    let mut p = 1.0;
    let l = (-lambda).exp();
    loop {
        p *= rng.gen::<f64>();
        if p <= l {
            break;
        }
        result += 1;
    }
    result
}

fn binomial<R: Rng>(rng: &mut R, n: usize, p: f64) -> usize {
    let mut successes = 0;
    for _ in 0..n {
        if rng.gen::<f64>() < p {
            successes += 1;
        }
    }
    successes
}

#[derive(Clone, Copy, Debug)]
pub enum Sampling {
    // Sample the given amount of items.
    Constant(usize),
    // Fraction of all items, where the fraction is randomly selected from the given closed
    // interval.
    Fraction(f64, f64),
}

/// Return a random subset of `items` according to the given sampling strategy.
fn sample<T: Clone, R: Rng>(rng: &mut R, items: &[T], strategy: Sampling) -> Vec<T> {
    let amount = match strategy {
        Sampling::Constant(amount) => amount,
        Sampling::Fraction(min, max) => {
            let min = (items.len() as f64 * min).ceil() as usize;
            let max = (items.len() as f64 * max).floor() as usize + 1;
            rng.gen_range(min, max)
        }
    };

    seq::sample_slice(rng, items, amount)
}
