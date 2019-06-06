// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "testing")]
use super::parse_test_dot_file;
use super::peer::{Peer, PeerStatus};
use super::schedule::{Schedule, ScheduleEvent, ScheduleOptions};
use super::Observation;
use crate::block::Block;
use crate::common_coin::CommonCoin;
use crate::error::Error;
use crate::gossip::{Request, Response};
use crate::mock::{PeerId, Transaction};
use crate::observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation as ParsecObservation,
};
use rand::{seq::SliceRandom, thread_rng, Rng};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use threshold_crypto::{PublicKeySet, SecretKeySet};

enum Message {
    Request(Request<Transaction, PeerId>, usize),
    Response(Response<Transaction, PeerId>),
}

struct QueueEntry {
    pub sender: PeerId,
    pub message: Message,
    pub deliver_after: usize,
}

pub struct Network {
    pub peers: BTreeMap<PeerId, Peer>,
    genesis: BTreeSet<PeerId>,
    genesis_coin_keys: PublicKeySet,
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
    consensus_mode: ConsensusMode,
}

#[derive(Debug)]
pub struct BlocksOrder {
    peer: PeerId,
    order: Vec<Observation>,
}

#[derive(Debug)]
pub enum ConsensusError {
    DifferingBlocksOrder {
        order_1: BlocksOrder,
        order_2: BlocksOrder,
    },
    WrongBlocksNumber {
        expected_min: usize,
        expected_max: usize,
        got: usize,
    },
    WrongPeers {
        expected: BTreeMap<PeerId, PeerStatus>,
        got: BTreeMap<PeerId, PeerStatus>,
    },
    InvalidSignatory {
        observation: Observation,
        signatory: PeerId,
    },
    TooFewSignatures {
        observation: Observation,
        signatures: BTreeSet<PeerId>,
    },
    UnexpectedAccusation {
        accuser: PeerId,
        accused: PeerId,
        malice: Malice<Transaction, PeerId>,
    },
}

fn peers_from_ids<R: Rng>(
    ids: &BTreeSet<PeerId>,
    consensus_mode: ConsensusMode,
    rng: &mut R,
) -> (BTreeMap<PeerId, Peer>, PublicKeySet) {
    let sks = SecretKeySet::random(ids.len() / 3, rng);
    (
        ids.iter()
            .enumerate()
            .map(|(index, id)| {
                let coin = CommonCoin::new(
                    ids.clone(),
                    sks.public_keys(),
                    Some(sks.secret_key_share(index)),
                );
                (
                    id.clone(),
                    Peer::from_genesis(id.clone(), &ids, consensus_mode, coin),
                )
            })
            .collect(),
        sks.public_keys(),
    )
}

impl Network {
    /// Create an empty test network
    pub fn new(consensus_mode: ConsensusMode) -> Self {
        // a dummy SecretKeySet to put a value in genesis_coin_keys - will be replaced anyway when
        // the network processes the Genesis event
        let sks = SecretKeySet::random(1, &mut thread_rng());
        Network {
            peers: BTreeMap::new(),
            genesis: BTreeSet::new(),
            genesis_coin_keys: sks.public_keys(),
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    /// Create a test network with initial peers constructed from the given IDs
    pub fn with_peers<I: IntoIterator<Item = PeerId>, R: Rng>(
        all_ids: I,
        consensus_mode: ConsensusMode,
        rng: &mut R,
    ) -> Self {
        let genesis_group = all_ids.into_iter().collect::<BTreeSet<_>>();
        let (peers, genesis_coin_keys) = peers_from_ids(&genesis_group, consensus_mode, rng);
        Network {
            genesis: genesis_group,
            genesis_coin_keys,
            peers,
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    #[cfg(feature = "testing")]
    pub fn from_graphs<I: IntoIterator<Item = &'static str>>(
        consensus_mode: ConsensusMode,
        genesis: BTreeSet<PeerId>,
        names: I,
    ) -> Self {
        let mut peers = BTreeMap::new();
        for name in names {
            let filename = format!("{}.dot", name.to_lowercase());
            let parsed_contents = parse_test_dot_file(&filename);
            let id = parsed_contents.our_id.clone();
            let _ = peers.insert(id, Peer::from_parsed_contents(parsed_contents));
        }
        // TODO: get the coin from graphs
        let sks = SecretKeySet::random(peers.len() / 3, &mut thread_rng());
        Network {
            peers,
            genesis,
            genesis_coin_keys: sks.public_keys(),
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    pub fn consensus_mode(&self) -> ConsensusMode {
        self.consensus_mode
    }

    fn peers_with_status(&self, status: PeerStatus) -> impl Iterator<Item = &Peer> {
        self.peers
            .values()
            .filter(move |&peer| peer.status == status)
    }

    fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers_with_status(PeerStatus::Active)
    }

    fn present_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(move |&peer| {
            peer.status == PeerStatus::Active || peer.status == PeerStatus::Pending
        })
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    fn blocks_all_in_sequence(&self) -> Result<(), ConsensusError> {
        let first_peer = unwrap!(self.active_peers().next());
        let payloads = first_peer.blocks_payloads();
        if let Some(peer) = self
            .active_peers()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err(ConsensusError::DifferingBlocksOrder {
                order_1: BlocksOrder {
                    peer: first_peer.id.clone(),
                    order: payloads.into_iter().cloned().collect(),
                },
                order_2: BlocksOrder {
                    peer: peer.id.clone(),
                    order: peer.blocks_payloads().into_iter().cloned().collect(),
                },
            })
        } else {
            Ok(())
        }
    }

    fn peer(&self, id: &PeerId) -> &Peer {
        unwrap!(self.peers.get(id))
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Peer {
        unwrap!(self.peers.get_mut(id))
    }

    fn send_message(&mut self, src: PeerId, dst: &PeerId, message: Message, deliver_after: usize) {
        if self.peer(dst).status != PeerStatus::Active
            && self.peer(dst).status != PeerStatus::Pending
        {
            return;
        }
        self.msg_queue
            .entry(dst.clone())
            .or_insert_with(Vec::new)
            .push(QueueEntry {
                sender: src,
                message,
                deliver_after,
            });
    }

    /// Handles incoming requests and responses
    fn handle_messages(&mut self, peer: &PeerId, step: usize) {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer.clone(), rest);
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => match self
                        .peer_mut(peer)
                        .parsec
                        .handle_request(&entry.sender, req)
                    {
                        Ok(response) => {
                            self.send_message(
                                peer.clone(),
                                &entry.sender,
                                Message::Response(response),
                                step + resp_delay,
                            );
                        }
                        Err(Error::UnknownPeer) | Err(Error::InvalidPeerState { .. }) => (),
                        Err(e) => panic!("{:?}", e),
                    },
                    Message::Response(resp) => unwrap!(self
                        .peer_mut(peer)
                        .parsec
                        .handle_response(&entry.sender, resp)),
                }
            }
        }
    }

    fn send_gossip<R: Rng>(
        &mut self,
        rng: &mut R,
        options: &ScheduleOptions,
        sender: &PeerId,
        present_peers: &[PeerId],
        step: usize,
    ) {
        let recipient = loop {
            let recipient = unwrap!(present_peers.choose(rng));
            if recipient != sender {
                break recipient;
            }
        };
        let valid = self
            .peer(sender)
            .parsec
            .gossip_recipients()
            .any(|valid_recipient| valid_recipient == recipient);
        let result = self.peer(sender).parsec.create_gossip(Some(recipient));

        if valid {
            // Recipient is valid. `create_gossip` must have succeeded.
            let request = unwrap!(result);
            let req_delay = options.gen_delay(rng);
            let resp_delay = options.gen_delay(rng);
            self.send_message(
                sender.clone(),
                recipient,
                Message::Request(request, resp_delay),
                step + req_delay,
            );
        } else {
            // Recipient is not valid. `create_gossip` must have failed.
            match result {
                Err(Error::InvalidSelfState { .. })
                | Err(Error::InvalidPeerState { .. })
                | Err(Error::UnknownPeer) => (),
                x => panic!("Unexpected {:?}", x),
            }
        }
    }

    fn check_consensus_broken(&self) -> Result<(), ConsensusError> {
        let mut block_order = BTreeMap::new();
        for peer in self.active_peers() {
            for (index, block) in peer.blocks().iter().enumerate() {
                let key = self.block_key(block);

                if let Some((old_peer, old_index)) = block_order.insert(key, (peer, index)) {
                    if old_index != index {
                        // old index exists and isn't equal to the new one
                        return Err(ConsensusError::DifferingBlocksOrder {
                            order_1: BlocksOrder {
                                peer: peer.id.clone(),
                                order: peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                            order_2: BlocksOrder {
                                peer: old_peer.id.clone(),
                                order: old_peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn block_key<'a>(
        &self,
        block: &'a Block<Transaction, PeerId>,
    ) -> (&'a Observation, Option<&'a PeerId>) {
        let peer_id = if block.payload().is_opaque() {
            if self.consensus_mode == ConsensusMode::Single {
                Some(&unwrap!(block.proofs().iter().next()).public_id)
            } else {
                None
            }
        } else {
            None
        };

        (block.payload(), peer_id)
    }

    fn consensus_complete(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> bool {
        self.check_consensus(
            expected_peers,
            num_expected_observations,
            num_expected_observations,
        )
        .is_ok()
    }

    /// Checks whether there is a right number of blocks and the blocks are in an agreeing order
    fn check_consensus(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        min_expected_observations: usize,
        max_expected_observations: usize,
    ) -> Result<(), ConsensusError> {
        // Check the number of consensused blocks.
        let got = unwrap!(self.active_peers().next()).blocks_payloads().len();
        if got < min_expected_observations || got > max_expected_observations {
            return Err(ConsensusError::WrongBlocksNumber {
                expected_min: min_expected_observations,
                expected_max: max_expected_observations,
                got,
            });
        }

        // Check peers.
        let got = self
            .peers
            .values()
            .map(|peer| (peer.id.clone(), peer.status))
            .collect();
        if *expected_peers != got {
            return Err(ConsensusError::WrongPeers {
                expected: expected_peers.clone(),
                got,
            });
        }

        // Check everybody has the same blocks in the same order.
        self.blocks_all_in_sequence()
    }

    fn check_block_signatories(
        &self,
        block: &Block<Transaction, PeerId>,
        section: &BTreeSet<PeerId>,
    ) -> Result<(), ConsensusError> {
        let signatories: BTreeSet<_> = block
            .proofs()
            .iter()
            .map(|proof| proof.public_id().clone())
            .collect();
        if let Some(pub_id) = signatories.difference(section).next() {
            return Err(ConsensusError::InvalidSignatory {
                observation: block.payload().clone(),
                signatory: pub_id.clone(),
            });
        }

        let consensus_mode = if block.payload().is_opaque() {
            self.consensus_mode
        } else if let ParsecObservation::DkgMessage(_) = block.payload() {
            ConsensusMode::Single
        } else {
            ConsensusMode::Supermajority
        };
        let correct_signatories = match consensus_mode {
            ConsensusMode::Single => !signatories.is_empty(),
            ConsensusMode::Supermajority => {
                is_more_than_two_thirds(signatories.len(), section.len())
            }
        };
        if !correct_signatories {
            return Err(ConsensusError::TooFewSignatures {
                observation: block.payload().clone(),
                signatures: signatories,
            });
        }
        Ok(())
    }

    /// Checks if the blocks are only signed by valid voters
    fn check_blocks_signatories(&self) -> Result<(), ConsensusError> {
        let blocks = self.active_peers().next().unwrap().blocks();
        let mut valid_voters = BTreeSet::new();
        for block in blocks {
            match *block.payload() {
                ParsecObservation::Genesis(ref g) => {
                    // explicitly don't check signatories - the list of valid voters
                    // should be empty at this point
                    valid_voters = g.clone();
                }
                ParsecObservation::Add { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.insert(peer_id.clone());
                }
                ParsecObservation::Remove { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.remove(peer_id);
                }
                _ => {
                    self.check_block_signatories(block, &valid_voters)?;
                }
            }
        }
        Ok(())
    }

    /// Check that no node has been accused of malice.
    fn check_unexpected_accusations(&self, peer_id: &PeerId) -> Result<(), ConsensusError> {
        let peer = self.peer(peer_id);
        let accusation = peer
            .unpolled_accusations()
            .find(|(_, malice)| malice.is_provable());
        if let Some((offender, malice)) = accusation {
            return Err(ConsensusError::UnexpectedAccusation {
                accuser: peer.id.clone(),
                accused: offender.clone(),
                malice: malice.clone(),
            });
        } else {
            Ok(())
        }
    }

    /// Simulates the network according to the given schedule
    pub fn execute_schedule<R: Rng>(
        &mut self,
        rng: &mut R,
        schedule: Schedule,
        options: &ScheduleOptions,
    ) -> Result<(), ConsensusError> {
        let Schedule {
            peers,
            min_observations,
            max_observations,
            events,
        } = schedule;
        let mut peer_removal_guard = PeerRemovalGuard::default();
        let mut queue: VecDeque<_> = events.into_iter().collect();
        let mut retry = Vec::new();

        while let Some(event) = queue.pop_front() {
            if self.execute_event(rng, options, event.clone(), &mut peer_removal_guard)? {
                for event in retry.drain(..).rev() {
                    queue.push_front(event)
                }

                self.check_consensus_broken()?;
                if self.consensus_complete(&peers, max_observations) {
                    break;
                }
            } else {
                retry.push(event);
            }
        }

        self.check_consensus(&peers, min_observations, max_observations)?;
        self.check_blocks_signatories()
    }

    // Returns 'Ok(true)' when event got executed, or 'Ok(false)' when the event needs to be delayed
    // due to the parsec membership status.
    fn execute_event<R: Rng>(
        &mut self,
        rng: &mut R,
        options: &ScheduleOptions,
        event: ScheduleEvent,
        peer_removal_guard: &mut PeerRemovalGuard,
    ) -> Result<bool, ConsensusError> {
        match event {
            ScheduleEvent::Genesis(genesis_group) => {
                if !self.peers.is_empty() {
                    // if the peers are already initialised, we won't initialise them again
                    return Ok(true);
                }
                let (peers, public_keys) = peers_from_ids(&genesis_group, self.consensus_mode, rng);
                for node in &genesis_group {
                    peer_removal_guard.add_genesis_peer(node.clone());
                }
                self.peers = peers;
                self.genesis = genesis_group;
                self.genesis_coin_keys = public_keys;
                // do a full reset while we're at it
                self.msg_queue.clear();
            }
            ScheduleEvent::AddPeer(peer) => {
                let current_peers = self.active_peers().map(|peer| peer.id.clone()).collect();
                let coin =
                    CommonCoin::new(self.genesis.clone(), self.genesis_coin_keys.clone(), None);
                let _ = self.peers.insert(
                    peer.clone(),
                    Peer::from_existing(
                        peer.clone(),
                        &self.genesis,
                        &current_peers,
                        self.consensus_mode,
                        coin,
                    ),
                );

                peer_removal_guard.add_peer(peer);
            }
            ScheduleEvent::RemovePeer(peer) => {
                if peer_removal_guard.attempt_to_remove_peer(&peer) {
                    (*self.peer_mut(&peer)).status = PeerStatus::Removed;
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::Fail(peer) => {
                if peer_removal_guard.attempt_to_remove_peer(&peer) {
                    (*self.peer_mut(&peer)).status = PeerStatus::Failed;
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::LocalStep(step) => {
                let present_peers: Vec<PeerId> =
                    self.present_peers().map(|peer| peer.id.clone()).collect();
                for peer in &present_peers {
                    self.peer_mut(&peer).make_votes();
                    self.handle_messages(&peer, step);
                    let first_block = self.peer_mut(&peer).poll();
                    self.check_unexpected_accusations(&peer)?;

                    for block in &self.peer(&peer).blocks()[first_block..] {
                        match *block.payload() {
                            ParsecObservation::Remove { ref peer_id, .. } => {
                                peer_removal_guard.record_consensus_on_remove_peer(peer, peer_id);
                            }
                            ParsecObservation::Add { ref peer_id, .. } => {
                                peer_removal_guard.record_consensus_on_add_peer(peer, peer_id);
                            }
                            _ => (),
                        }
                    }

                    if rng.gen::<f64>() < options.prob_gossip {
                        self.send_gossip(rng, options, peer, &present_peers, step);
                    }
                }
            }
            ScheduleEvent::VoteFor(peer, observation) => {
                // Skip voting by removed/failed peers.
                match self.peer(&peer).status {
                    PeerStatus::Active | PeerStatus::Pending => (),
                    PeerStatus::Removed | PeerStatus::Failed => return Ok(true),
                }

                if let ParsecObservation::Remove { ref peer_id, .. } = observation {
                    if !peer_removal_guard.attempt_to_remove_peer(&peer_id) {
                        return Ok(false);
                    }
                }

                self.peer_mut(&peer).vote_for(&observation);
            }
        }
        Ok(true)
    }
}

// Helper struct that protects the test network from losing too many nodes.
#[derive(Default)]
struct PeerRemovalGuard {
    states: BTreeMap<PeerId, PeerRemovalState>,
}

#[derive(Debug)]
enum PeerRemovalState {
    // Peer is being added. The `usize` is the number of peers that consensused the add.
    Adding(usize),
    // Peer was added by at least the supermajority of the section.
    Added,
    // Peer is being removed. The `usize` is the number of peers that consensused the remove.
    Removing(usize),
    // Peer was removed by at least the supermajority of the section.
    Removed,
}

impl PeerRemovalState {
    fn is_active(&self) -> bool {
        match *self {
            PeerRemovalState::Added | PeerRemovalState::Removing(..) => true,
            PeerRemovalState::Adding(..) | PeerRemovalState::Removed => false,
        }
    }
}

impl PeerRemovalGuard {
    fn num_active(&self) -> usize {
        self.states
            .values()
            .filter(|state| state.is_active())
            .count()
    }

    fn num_removing(&self) -> usize {
        self.states
            .values()
            .filter(|state| {
                if let PeerRemovalState::Removing(..) = *state {
                    true
                } else {
                    false
                }
            })
            .count()
    }

    fn add_genesis_peer(&mut self, peer_id: PeerId) {
        let _ = self.states.insert(peer_id, PeerRemovalState::Added);
    }

    fn add_peer(&mut self, peer_id: PeerId) {
        let _ = self.states.insert(peer_id, PeerRemovalState::Adding(0));
    }

    fn record_consensus_on_add_peer(&mut self, recorder_id: &PeerId, added_peer_id: &PeerId) {
        if !unwrap!(self.states.get(recorder_id)).is_active() {
            return;
        }

        let active = self.num_active();
        let state = unwrap!(
            self.states.get_mut(added_peer_id),
            "record consensus on add {:?} failed: unknown peer",
            added_peer_id
        );
        let add = if let PeerRemovalState::Adding(ref mut count) = *state {
            *count += 1;
            is_more_than_two_thirds(*count, active)
        } else {
            false
        };

        if add {
            *state = PeerRemovalState::Added;
        }
    }

    fn record_consensus_on_remove_peer(&mut self, recorder_id: &PeerId, removed_peer_id: &PeerId) {
        if !unwrap!(self.states.get(recorder_id)).is_active() {
            return;
        }

        let active = self.num_active();

        let state = unwrap!(
            self.states.get_mut(removed_peer_id),
            "record consensus on remove {:?} failed: unknown peer",
            removed_peer_id
        );
        let remove = match *state {
            PeerRemovalState::Adding(..) | PeerRemovalState::Added => panic!(
                "record consensus on remove {:?} failed: not scheduled for removal",
                removed_peer_id
            ),
            PeerRemovalState::Removing(ref mut count) => {
                *count += 1;
                is_more_than_two_thirds(*count, active)
            }
            PeerRemovalState::Removed => false,
        };

        if remove {
            *state = PeerRemovalState::Removed;
        }
    }

    fn attempt_to_remove_peer(&mut self, peer_id: &PeerId) -> bool {
        let active = self.num_active();
        let removing = self.num_removing();
        let remaining = active - removing - 1;

        if let Some(state) = self.states.get_mut(peer_id) {
            match *state {
                PeerRemovalState::Adding(..) => false,
                PeerRemovalState::Added => {
                    if is_more_than_two_thirds(remaining, active) {
                        *state = PeerRemovalState::Removing(0);
                        true
                    } else {
                        false
                    }
                }
                PeerRemovalState::Removing(..) | PeerRemovalState::Removed => true,
            }
        } else {
            panic!("attempt to remove {:?} failed: unknown peer", peer_id)
        }
    }
}
