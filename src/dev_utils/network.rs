// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{
    peer::{NetworkView, Peer, PeerStatus},
    schedule::{Schedule, ScheduleEvent, ScheduleOptions},
    Observation,
};
use crate::{
    block::Block,
    error::Error,
    gossip::{Request, Response},
    mock::{PeerId, Transaction},
    observation::{
        is_more_than_two_thirds, ConsensusMode, Malice, Observation as ParsecObservation,
    },
};
use itertools::Itertools;
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

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
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
    consensus_mode: ConsensusMode,
}

#[derive(Debug)]
pub struct BlocksOrder {
    peer: PeerId,
    order: Vec<Observation>,
}

pub struct DifferingBlocksOrder {
    order_1: BlocksOrder,
    order_2: BlocksOrder,
}

impl fmt::Debug for DifferingBlocksOrder {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        writeln!(formatter, "{{")?;
        writeln!(
            formatter,
            "  peers: {:?} / {:?}",
            self.order_1.peer, self.order_2.peer
        )?;
        writeln!(formatter, "  order:")?;
        for (i, (block1, block2)) in self
            .order_1
            .order
            .iter()
            .zip(self.order_2.order.iter())
            .enumerate()
        {
            writeln!(formatter, "  {}. {:?} / {:?}", i + 1, block1, block2)?;
        }
        write!(formatter, "}}")
    }
}

#[derive(Debug)]
pub enum ConsensusError {
    DifferingBlocksOrder(DifferingBlocksOrder),
    WrongBlocksNumber {
        expected_min: usize,
        expected_max: usize,
        got_min: usize,
        got_max: usize,
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

impl Network {
    /// Create an empty test network.
    pub fn new(consensus_mode: ConsensusMode) -> Self {
        Network {
            peers: BTreeMap::new(),
            genesis: BTreeSet::new(),
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    pub fn consensus_mode(&self) -> ConsensusMode {
        self.consensus_mode
    }

    fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers
            .values()
            .filter(|peer| peer.status() == PeerStatus::Active && !peer.ignore_process_events())
    }

    pub fn active_non_malicious_peers(&self) -> impl Iterator<Item = &Peer> {
        self.active_peers().filter(|peer| !peer.is_malicious())
    }

    /// Returns the IDs of peers which consider themselves to be still running correctly, i.e. those
    /// for which `is_running()` is true.
    fn running_peers_ids(&self) -> Vec<PeerId> {
        self.peers
            .values()
            .filter_map(|peer| {
                if peer.is_running() {
                    Some(peer.id().clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the number of peers for which the network has the given view of their state.
    fn num_with_network_view(&self, network_view: NetworkView) -> usize {
        self.peers
            .values()
            .filter(|peer| peer.network_view() == network_view)
            .count()
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    fn check_blocks_all_in_sequence(&self) -> Result<(), ConsensusError> {
        let first_peer = unwrap!(self.active_non_malicious_peers().next());
        let payloads = first_peer.blocks_payloads();
        if let Some(peer) = self
            .active_non_malicious_peers()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err(ConsensusError::DifferingBlocksOrder(DifferingBlocksOrder {
                order_1: BlocksOrder {
                    peer: first_peer.id().clone(),
                    order: payloads.into_iter().cloned().collect(),
                },
                order_2: BlocksOrder {
                    peer: peer.id().clone(),
                    order: peer.blocks_payloads().into_iter().cloned().collect(),
                },
            }))
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
        if !self.peer(dst).is_running() {
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

    /// Handles incoming requests and responses.
    fn handle_messages(&mut self, peer: &PeerId, step: usize) {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer.clone(), rest);
            // If this is a malicious peer which has already created a fork, ignore all incoming
            // messages.
            if self.peer(peer).has_misbehaved() {
                return;
            }
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => {
                        match self.peer_mut(peer).handle_request(&entry.sender, req) {
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
                        }
                    }
                    Message::Response(resp) => {
                        unwrap!(self.peer_mut(peer).handle_response(&entry.sender, resp))
                    }
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
        if present_peers.len() == 1 && present_peers.contains(sender) {
            return;
        }

        let recipient = loop {
            let recipient = unwrap!(rng.choose(present_peers));
            if recipient != sender {
                break recipient;
            }
        };
        let valid = self
            .peer(sender)
            .gossip_recipients()
            .any(|valid_recipient| valid_recipient == recipient);
        let result = if self.peer(sender).is_malicious() && !self.peer(sender).has_misbehaved() {
            self.peer_mut(sender)
                .create_gossip_with_fork(recipient, rng)
        } else {
            self.peer_mut(sender).create_gossip(recipient)
        };

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
        for peer in self.active_non_malicious_peers() {
            for (index, block) in peer.blocks().enumerate() {
                let key = self.block_key(block);

                if let Some((old_peer, old_index)) = block_order.insert(key, (peer, index)) {
                    if old_index != index {
                        // old index exists and isn't equal to the new one
                        return Err(ConsensusError::DifferingBlocksOrder(DifferingBlocksOrder {
                            order_1: BlocksOrder {
                                peer: peer.id().clone(),
                                order: peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                            order_2: BlocksOrder {
                                peer: old_peer.id().clone(),
                                order: old_peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                        }));
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

    /// Checks whether there is a right number of blocks and the blocks are in an agreeing order.
    fn check_consensus(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        min_expected_observations: usize,
        max_expected_observations: usize,
    ) -> Result<(), ConsensusError> {
        // Check the number of consensused blocks.
        let (got_min, got_max) = unwrap!(self
            .active_non_malicious_peers()
            .map(|peer| peer.blocks_payloads().len())
            .minmax()
            .into_option());
        if got_min < min_expected_observations || got_max > max_expected_observations {
            return Err(ConsensusError::WrongBlocksNumber {
                expected_min: min_expected_observations,
                expected_max: max_expected_observations,
                got_min,
                got_max,
            });
        }

        // Check peers.
        let got = self
            .peers
            .values()
            .map(|peer| (peer.id().clone(), peer.status()))
            .collect();
        if *expected_peers != got {
            return Err(ConsensusError::WrongPeers {
                expected: expected_peers.clone(),
                got,
            });
        }

        // Check everybody has the same blocks in the same order.
        self.check_blocks_all_in_sequence()
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

    /// Checks if the blocks are only signed by valid voters.
    fn check_blocks_signatories(&self) -> Result<(), ConsensusError> {
        let block_groups = unwrap!(self.active_non_malicious_peers().next()).grouped_blocks();
        let mut valid_voters = BTreeSet::new();

        for block_group in block_groups {
            for block in block_group {
                if let ParsecObservation::Genesis { ref group, .. } = *block.payload() {
                    valid_voters = group.clone();
                }

                if block.payload().is_dkg_result() {
                    // DKG blocks do not have signatures
                    continue;
                }

                self.check_block_signatories(block, &valid_voters)?;
            }

            for block in block_group {
                match *block.payload() {
                    ParsecObservation::Genesis { .. } => (),
                    ParsecObservation::Add { ref peer_id, .. } => {
                        let _ = valid_voters.insert(peer_id.clone());
                    }
                    ParsecObservation::Remove { ref peer_id, .. } => {
                        let _ = valid_voters.remove(peer_id);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Check that no well-behaved peer has been accused of malice.
    fn check_unexpected_accusations(&self, peer_id: &PeerId) -> Result<(), ConsensusError> {
        let accusation = self
            .peer(peer_id)
            .unpolled_accusations()
            .find(|(offender, malice)| match malice {
                Malice::Fork(..) => !self.peer(offender).has_misbehaved(),
                _ => true,
            });

        if let Some((offender, malice)) = accusation {
            Err(ConsensusError::UnexpectedAccusation {
                accuser: peer_id.clone(),
                accused: offender.clone(),
                malice: malice.clone(),
            })
        } else {
            Ok(())
        }
    }

    /// Simulates the network according to the given schedule.
    pub fn execute_schedule<R: Rng>(
        &mut self,
        rng: &mut R,
        schedule: Schedule,
    ) -> Result<(), ConsensusError> {
        let Schedule {
            peers,
            min_observations,
            max_observations,
            events,
            additional_steps,
            options,
        } = schedule;
        let mut queue: VecDeque<_> = events.into_iter().collect();
        let mut retry = Vec::new();
        let mut additional_steps = additional_steps;
        let mut additional_step = || additional_steps.next().map(ScheduleEvent::LocalStep);

        while let Some(event) = queue.pop_front().or_else(&mut additional_step) {
            if self.execute_event(rng, &options, event.clone())? {
                for event in retry.drain(..).rev() {
                    queue.push_front(event)
                }

                if options.intermediate_consistency_checks {
                    self.check_consensus_broken()?;
                }

                if self.consensus_complete(&peers, max_observations) {
                    break;
                }
            } else {
                retry.push(event);
            }
        }

        for peer_id in self.running_peers_ids() {
            self.check_unexpected_accusations(&peer_id)?;
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
    ) -> Result<bool, ConsensusError> {
        match event {
            ScheduleEvent::Genesis(genesis) => {
                if !self.peers.is_empty() {
                    // If the peers are already initialised, we won't initialise them again.
                    return Ok(true);
                }

                let genesis_ids = genesis.all_ids();
                let good_peers = genesis
                    .ids_of_good_peers()
                    .map(|id| Peer::from_genesis(id.clone(), &genesis_ids, self.consensus_mode));
                let malicious_peers = genesis.ids_of_malicious_peers().map(|id| {
                    Peer::malicious_from_genesis(id.clone(), &genesis_ids, self.consensus_mode)
                });

                self.peers = good_peers
                    .chain(malicious_peers)
                    .map(|peer| (peer.id().clone(), peer))
                    .collect();

                if let Some(keep_consensus) = &options.genesis_restrict_consensus_to {
                    assert!(
                        !keep_consensus.is_empty() && keep_consensus.iter().all(|id| genesis_ids.contains(id)),
                        "genesis_restrict_consensus_to must be None or not empty and contain only ids from the genesis group.: {:?} - {:?}", keep_consensus, genesis_ids);

                    self.peers
                        .iter_mut()
                        .filter(|(id, _)| !keep_consensus.contains(id))
                        .for_each(|(_, peer)| peer.set_ignore_process_events());
                }

                self.genesis = genesis_ids;
                // Do a full reset while we're at it.
                self.msg_queue.clear();
            }
            ScheduleEvent::AddPeer(peer_id) => {
                if !self.allow_addition_of_peer() {
                    return Ok(false);
                }
                let current_peers = self.active_peers().map(|peer| peer.id().clone()).collect();
                let _ = self.peers.insert(
                    peer_id.clone(),
                    Peer::from_existing(
                        peer_id.clone(),
                        &self.genesis,
                        &current_peers,
                        self.consensus_mode,
                    ),
                );
            }
            ScheduleEvent::RemovePeer(peer_id) => {
                if self.allow_removal_of_peer(&peer_id) {
                    (*self.peer_mut(&peer_id)).mark_as_removed();
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::Fail(peer_id) => {
                if self.allow_removal_of_peer(&peer_id) {
                    (*self.peer_mut(&peer_id)).mark_as_failed();
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::LocalStep(step) => {
                for peer_id in self.running_peers_ids() {
                    self.peer_mut(&peer_id).make_votes();
                    self.handle_messages(&peer_id, step);
                    self.peer_mut(&peer_id).poll_all();
                    if options.intermediate_consistency_checks {
                        self.check_unexpected_accusations(&peer_id)?;
                    }
                }
                Peer::update_network_views(&mut self.peers);
                let running_peers_ids = self.running_peers_ids();
                for peer_id in &running_peers_ids {
                    if rng.gen::<f64>() < options.prob_gossip {
                        self.send_gossip(rng, options, peer_id, &running_peers_ids, step);
                    }
                }
            }
            ScheduleEvent::VoteFor(voting_peer_id, observation) => {
                if let Some(voter) = self.peers.get(&voting_peer_id) {
                    // Skip voting by removed/failed peers.
                    if !voter.is_running() {
                        return Ok(true);
                    }
                } else {
                    // Retry voting once the voting peer has been added.
                    return Ok(false);
                }

                match observation {
                    ParsecObservation::Remove { ref peer_id, .. } => {
                        if self.allow_removal_of_peer(&peer_id) {
                            (*self.peer_mut(&peer_id)).mark_network_view_as_leaving();
                        } else {
                            return Ok(false);
                        }
                    }
                    ParsecObservation::Add { ref peer_id, .. } => {
                        // If the peer to be added hasn't yet been inserted into `self.peers`, it
                        // means we should postpone voting for its addition until it is inserted.
                        if !self.peers.contains_key(peer_id) {
                            return Ok(false);
                        }
                    }
                    _ => (),
                }

                self.peer_mut(&voting_peer_id).vote_for(&observation);
            }
            ScheduleEvent::StartDkg(_) => {
                // For test purpose: simulate starting DKG on all nodes at the same time.
                for peer_id in self.running_peers_ids() {
                    self.peer_mut(&peer_id).dkg_start_consensus(rng)
                }
            }
        }
        Ok(true)
    }

    fn allow_removal_of_peer(&self, peer_id: &PeerId) -> bool {
        match self.peers.get(peer_id).map(Peer::network_view) {
            None | Some(NetworkView::Joining) => false,
            Some(NetworkView::Joined) => {
                let joined_count = self.num_with_network_view(NetworkView::Joined);
                let leaving_count = self.num_with_network_view(NetworkView::Leaving);
                let current_count = joined_count + leaving_count;
                is_more_than_two_thirds(joined_count - 1, current_count)
            }
            Some(NetworkView::Leaving) | Some(NetworkView::Left) => true,
        }
    }

    fn allow_addition_of_peer(&self) -> bool {
        // For sections of size 3 or more, we only allow new node to join if the currently joined
        // ones would still form a supermajority event after all the joining one including the new
        // node become joined. This is to prevent the situation where too many nodes join so the
        // votes to add more nodes no longer have supermajority.
        //
        // Section of size 1 or 2 need special handling, otherwise they would never be allowed to
        // grow.
        let joined_count = self.num_with_network_view(NetworkView::Joined);
        let joining_count = self.num_with_network_view(NetworkView::Joining);

        (joined_count < 3 && joining_count == 0)
            || is_more_than_two_thirds(joined_count, joined_count + joining_count + 1)
    }
}
