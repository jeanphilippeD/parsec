// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::block::Block;
use crate::common_coin::CommonCoin;
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use crate::dev_utils::ParsedContents;
use crate::dump_graph;
use crate::error::{Error, Result};
#[cfg(all(test, feature = "mock"))]
use crate::gossip::EventHash;
use crate::gossip::{
    Event, EventContextMut, EventContextRef, EventIndex, Graph, IndexedEventRef, PackedEvent,
    Request, Response, UnpackedEvent,
};
use crate::id::{PublicId, SecretId};
use crate::key_gen::{message::DkgMessage, Ack, AckOutcome, KeyGen, Part, PartOutcome};
use crate::meta_voting::{MetaElection, MetaEvent, MetaEventBuilder, MetaVote, Step};
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use crate::mock::{PeerId, Transaction};
use crate::network_event::NetworkEvent;
#[cfg(feature = "malice-detection")]
use crate::observation::UnprovableMalice;
use crate::observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation, ObservationHash, ObservationKey,
    ObservationStore,
};
use crate::peer_list::{PeerIndex, PeerIndexSet, PeerList, PeerState};
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
#[cfg(all(test, feature = "mock"))]
use std::ops::{Deref, DerefMut};
use std::usize;

pub(crate) type BlockNumber = usize;

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused [Block](struct.Block.html)s by applying the PARSEC
/// algorithm. A `Block`'s payload, described by the [Observation](enum.Observation.html) type, is
/// called an "observation" or a "transaction".
///
/// The struct is generic with regards to two type arguments: one that represents a network event,
/// and one that represents a peer ID on the network. This allows the consumer to customise both
/// what constitutes a transaction that can get consensus, and the way peers are identified. The
/// types have to implement [NetworkEvent](trait.NetworkEvent.html) and
/// [SecretId](trait.SecretId.html) traits, respectively.
///
/// The `Parsec` struct exposes two constructors:
///
/// * [from_genesis](struct.Parsec.html#method.from_genesis), if the owning peer is a part of the
/// genesis group, i.e. the initial group of peers that participate in the network startup
/// * [from_existing](struct.Parsec.html#method.from_existing), if the owning peer is trying to
/// join an already functioning network
///
/// Once the peer becomes a full member of the section,
/// [gossip_recipients](struct.Parsec.html#method.gossip_recipients) will start to return potential
/// partners for gossip. In order to initiate gossip exchange with a partner,
/// [create_gossip](struct.Parsec.html#method.create_gossip) should be called.
///
/// Any messages of type [Request](struct.Request.html) or [Response](struct.Response.html)
/// received by the network layer should be passed to
/// [handle_request](struct.Parsec.html#method.handle_request) and
/// [handle_response](struct.Parsec.html#method.handle_response), respectively.
///
/// If the owning peer needs to propose something to be consensused, it has to call the
/// [vote_for](struct.Parsec.html#method.vote_for) method.
///
/// The [poll](struct.Parsec.html#method.poll) method is used to get the observations in the
/// consensused order.
///
/// Most public methods return an error if called after the owning peer has been removed from the
/// section, i.e. a block with payload `Observation::Remove(our_id)` has been made stable.
///
/// For more details, see the descriptions of methods below.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // The historical index of the first block in consensused_blocks
    first_consensused_block_number: BlockNumber,
    // the next block to be applied when keygen finishes
    next_block_number: BlockNumber,
    // A distributed key generation based common coin mechanism.
    key_gen: BTreeMap<BlockNumber, KeyGen<S>>,
    // Everything needed to flip a common coin as many times as required with a given set of voters
    common_coin: CommonCoin<S::PublicId>,
    // The Gossip graph.
    graph: Graph<S::PublicId>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: ObservationStore<T, S::PublicId>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_election: MetaElection,
    consensus_mode: ConsensusMode,
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: Accusations<T, S::PublicId>,
    pending_dkg_msgs: Vec<DkgMessage>,
    // map of DkgMessage -> Observation containing it
    dkg_msg_map: BTreeMap<DkgMessage, EventIndex>,
    // Peers we accused of unprovable malice.
    #[cfg(feature = "malice-detection")]
    unprovable_offenders: PeerIndexSet,
    rng: OsRng,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    ///
    /// * `our_id` is the value that will identify the owning peer in the network.
    /// * `genesis_group` is the set of public IDs of the peers that are present at the network
    /// startup.
    /// * `consensus_mode` determines how many votes are needed for an observation to become a
    /// candidate for consensus. For more details, see [ConsensusMode](enum.ConsensusMode.html)
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
        common_coin: CommonCoin<S::PublicId>,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut peer_list = PeerList::new(our_id);
        let genesis_indices: PeerIndexSet = genesis_group
            .iter()
            .map(|peer_id| {
                if peer_id == peer_list.our_pub_id() {
                    let peer_index = PeerIndex::OUR;
                    peer_list.change_peer_state(peer_index, PeerState::active());
                    peer_index
                } else {
                    peer_list.add_peer(peer_id.clone(), PeerState::active())
                }
            })
            .collect();

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode, common_coin);
        parsec
            .meta_election
            .initialise_round_hashes(parsec.peer_list.all_ids());

        // Add initial event.
        let event = Event::new_initial(parsec.event_context());
        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let event = parsec.our_last_event_index().and_then(|self_parent| {
            Event::new_from_observation(
                self_parent,
                genesis_observation,
                parsec.event_context_mut(),
            )
        });
        if let Err(error) = event.and_then(|event| parsec.add_event(event)) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    ///
    /// * `our_id` is the value that will identify the owning peer in the network.
    /// * `genesis_group` is the set of public IDs of the peers that were present at the section
    /// startup.
    /// * `section` is the set of public IDs of the peers that constitute the section at the time
    /// of joining. They are the peers this `Parsec` instance will accept gossip from.
    /// * `consensus_mode` determines how many votes are needed for an observation to become a
    /// candidate for consensus. For more details, see [ConsensusMode](enum.ConsensusMode.html)
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        consensus_mode: ConsensusMode,
        common_coin: CommonCoin<S::PublicId>,
    ) -> Self {
        if genesis_group.is_empty() {
            log_or_panic!("Genesis group can't be empty");
        }

        if genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group can't already contain us");
        }

        if section.is_empty() {
            log_or_panic!("Section can't be empty");
        }

        if section.contains(our_id.public_id()) {
            log_or_panic!("Section can't already contain us");
        }

        let mut peer_list = PeerList::new(our_id);

        // Add ourselves
        peer_list.change_peer_state(PeerIndex::OUR, PeerState::RECV);

        // Add the genesis group.
        let genesis_indices: PeerIndexSet = genesis_group
            .iter()
            .map(|peer_id| peer_list.add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND))
            .collect();

        // Add the current section members.
        for peer_id in section {
            if peer_list.contains(peer_id) {
                continue;
            }
            let _ = peer_list.add_peer(peer_id.clone(), PeerState::SEND);
        }

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode, common_coin);

        parsec
            .meta_election
            .initialise_round_hashes(parsec.peer_list.all_ids());

        let initial_event = Event::new_initial(parsec.event_context());
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        parsec
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        peer_list: PeerList<S>,
        genesis_group: PeerIndexSet,
        consensus_mode: ConsensusMode,
        common_coin: CommonCoin<S::PublicId>,
    ) -> Self {
        dump_graph::init();

        let rng = OsRng::new().expect("Could not open OS random number generator.");

        Self {
            peer_list,
            first_consensused_block_number: 0,
            next_block_number: 0,
            key_gen: BTreeMap::new(),
            common_coin,
            graph: Graph::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_election: MetaElection::new(genesis_group),
            consensus_mode,
            pending_accusations: vec![],
            pending_dkg_msgs: vec![],
            dkg_msg_map: BTreeMap::new(),
            #[cfg(feature = "malice-detection")]
            unprovable_offenders: PeerIndexSet::default(),
            rng,
        }
    }

    /// Returns our public ID
    pub fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    /// Inserts the owning peer's vote for `observation` into the gossip graph. The subsequent
    /// gossip messages will spread the vote to other peers, eventually making it a candidate for
    /// the next consensused block.
    ///
    /// Returns an error if the owning peer is not a full member of the section yet, if it has
    /// already voted for this `observation`, or if adding a gossip event containing the vote to
    /// the gossip graph failed.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let self_parent = self.our_last_event_index()?;
        let event =
            Event::new_from_observation(self_parent, observation, self.event_context_mut())?;

        let _ = self.add_event(event)?;
        Ok(())
    }

    /// Returns an iterator with the IDs of peers who the owning peer can send gossip messages to.
    /// Calling `create_gossip` with a peer ID returned by this method is guaranteed to succeed
    /// (assuming no section mutation happened in between).
    pub fn gossip_recipients(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peer_list
            .gossip_recipients()
            .map(|(_, peer)| peer.id())
    }

    /// Creates a new message to be gossipped to a peer, containing all gossip events this peer
    /// thinks that peer needs. If `peer_id` is `None`, a message containing all known gossip
    /// events is returned. If `peer_id` is `Some` and the given peer is not an active node, an
    /// error is returned.
    ///
    /// * `peer_id`: the intended recipient of the gossip message
    /// * returns a `Request` to be sent to the intended recipient
    pub fn create_gossip(&self, peer_id: Option<&S::PublicId>) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(peer_id) = peer_id {
            let peer_index = self.get_peer_index(peer_id)?;
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
            // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
            // adding them to the section so we shouldn't contact them yet.
            self.confirm_peer_state(peer_index, PeerState::VOTE | PeerState::RECV)?;

            if self.peer_list.last_event(peer_index).is_some() {
                debug!(
                    "{:?} creating gossip request for {:?}",
                    self.our_pub_id(),
                    peer_id
                );

                let events = self.events_to_gossip_to_peer(peer_index)?;
                return self.pack_events(events).map(Request::new);
            }
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        self.pack_events(self.graph.iter().map(|e| e.inner()))
            .map(Request::new)
    }

    /// Handles a `Request` the owning peer received from the `src` peer.  Returns a `Response` to
    /// be sent back to `src`, or `Err` if the request was not valid or if `src` has been removed
    /// from the section already.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        let src_index = self.get_peer_index(src)?;

        let other_parent = req.hash_of_last_event_created_by(src)?;
        let other_parent = other_parent.and_then(|hash| self.graph.get_index(&hash));

        let forking_peers = self.unpack_and_add_events(src_index, req.packed_events)?;
        self.create_sync_event(src_index, true, &forking_peers, other_parent)?;
        self.create_accusation_events()?;
        self.create_coin_shares_event()?;
        self.create_dkg_events()?;

        let events = self.events_to_gossip_to_peer(src_index)?;
        self.pack_events(events).map(Response::new)
    }

    /// Handles a `Response` the owning peer received from the `src` peer. Returns `Err` if the
    /// response was not valid or if `src` has been removed from the section already.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<()> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        let src_index = self.get_peer_index(src)?;

        let other_parent = resp.hash_of_last_event_created_by(src)?;
        let other_parent = other_parent.and_then(|hash| self.graph.get_index(&hash));

        let forking_peers = self.unpack_and_add_events(src_index, resp.packed_events)?;
        self.create_sync_event(src_index, false, &forking_peers, other_parent)?;
        self.create_accusation_events()?;
        self.create_coin_shares_event()?;
        self.create_dkg_events()
    }

    /// Returns the next stable block, if any. The method might need to be called more than once
    /// for the caller to get all the blocks that have been consensused. A `None` value means that
    /// all the blocks consensused so far have already been returned.
    ///
    /// Once the owning peer has been removed from the section (i.e. a block with payload
    /// `Observation::Remove(our_id)` has been made stable), then no further blocks will be
    /// enqueued. So, once `poll()` returns such a block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        if self.first_consensused_block_number < self.next_block_number {
            self.first_consensused_block_number += 1;
            self.consensused_blocks.pop_front()
        } else {
            None
        }
    }

    /// Check if the owning peer can vote (that is, it has reached a consensus on itself being a
    /// full member of the section).
    pub fn can_vote(&self) -> bool {
        self.peer_list.our_state().can_vote()
    }

    /// Checks if the given `observation` has already been voted for by the owning peer.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        let hash = ObservationHash::from(observation);
        let key = ObservationKey::new(hash, PeerIndex::OUR, self.consensus_mode.of(observation));
        self.observations
            .get(&key)
            .map(|info| info.created_by_us)
            .unwrap_or(false)
    }

    /// Check if there are any observations that have been voted for but not yet consensused - i.e.
    /// if there is a gossip event containing a vote for a payload that is not yet a part of a
    /// stable block.
    pub fn has_unconsensused_observations(&self) -> bool {
        self.observations.values().any(|info| !info.consensused)
    }

    /// Returns observations voted for by the owning peer which haven't been returned as a stable
    /// block by `poll` yet.
    /// This includes observations that are either not yet consensused or that are already
    /// consensused, but not yet popped out of the consensus queue.
    ///
    /// The observations are sorted first by the consensus order, then by the vote order.
    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.our_consensused_observations()
            .chain(self.our_unconsensused_observations())
    }

    fn our_consensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(move |info| {
            if info.created_by_us
                && info.consensused
                && self
                    .consensused_blocks
                    .iter()
                    .any(|block| block.payload() == &info.observation)
            {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    fn our_unconsensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(|info| {
            if info.created_by_us && !info.consensused {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_index: EventIndex) -> Result<IndexedEventRef<S::PublicId>> {
        get_known_event(self.our_pub_id(), &self.graph, event_index)
    }

    fn confirm_peer_state(&self, peer_index: PeerIndex, required: PeerState) -> Result<()> {
        let actual = self.peer_list.peer_state(peer_index);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_index,
                required,
                actual,
            );
            Err(Error::InvalidPeerState { required, actual })
        }
    }

    fn confirm_self_state(&self, required: PeerState) -> Result<()> {
        let actual = self.peer_list.our_state();
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} has invalid state (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                required,
                actual,
            );
            Err(Error::InvalidSelfState { required, actual })
        }
    }

    fn get_peer_index(&self, peer_id: &S::PublicId) -> Result<PeerIndex> {
        self.peer_list.get_index(peer_id).ok_or(Error::UnknownPeer)
    }

    fn our_last_event_index(&self) -> Result<EventIndex> {
        self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!(
                "{:?} has no last event.\n{:?}\n",
                self.our_pub_id(),
                self.peer_list
            );
            Error::Logic
        })
    }

    fn is_observer(&self, builder: &MetaEventBuilder<S::PublicId>) -> bool {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.
        let voter_count = self.voter_count();

        if !is_more_than_two_thirds(builder.observee_count(), voter_count) {
            return false;
        }

        let self_parent_index = if let Some(index) = builder.event().self_parent() {
            index
        } else {
            log_or_panic!(
                "{:?} has event {:?} with observations, but not self-parent",
                self.our_pub_id(),
                *builder.event()
            );
            return false;
        };

        let self_parent = if let Ok(event) = self.get_known_event(self_parent_index) {
            event
        } else {
            return false;
        };

        // If self-parent is initial, we don't have to check it's meta-event, as we already know it
        // can not have any observations. Also, we don't assign meta-events to initial events anyway.
        if self_parent.is_initial() {
            return true;
        }

        // If self-parent is earlier in history than the start of the meta-election, it won't have
        // a meta-event; but it also means that it wasn't an observer, so this event is
        if self.start_index() > self_parent.topological_index() {
            return true;
        }

        if let Some(meta_parent) = self.meta_election.meta_event(self_parent_index) {
            !is_more_than_two_thirds(meta_parent.observees.len(), voter_count)
        } else {
            log_or_panic!(
                "{:?} doesn't have meta-event for event {:?} (self-parent of {:?})",
                self.our_pub_id(),
                *self_parent,
                builder.event().hash(),
            );

            false
        }
    }

    fn pack_events<'a, I>(&self, events: I) -> Result<Vec<PackedEvent<T, S::PublicId>>>
    where
        I: IntoIterator<Item = &'a Event<S::PublicId>>,
        S::PublicId: 'a,
    {
        events
            .into_iter()
            .map(|event| event.pack(self.event_context()))
            .collect()
    }

    fn unpack_and_add_events(
        &mut self,
        src_index: PeerIndex,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<PeerIndexSet> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src_index, PeerState::SEND)?;

        let mut forking_peers = PeerIndexSet::default();
        let mut known = Vec::new();

        for packed_event in packed_events {
            match Event::unpack(packed_event, &forking_peers, self.event_context_mut())? {
                UnpackedEvent::New(event) => {
                    if self
                        .peer_list
                        .events_by_index(event.creator(), event.index_by_creator())
                        .next()
                        .is_some()
                    {
                        let _ = forking_peers.insert(event.creator());
                    }

                    let event_creator = event.creator();
                    let event_index = self.add_event(event)?;

                    // We have received an event of a peer in the message. The peer can now receive
                    // gossips from us as well.
                    self.peer_list
                        .change_peer_state(event_creator, PeerState::RECV);
                    self.peer_list
                        .record_gossiped_event_by(src_index, event_index);

                    #[cfg(feature = "malice-detection")]
                    self.detect_accomplice(event_index)?;
                }
                UnpackedEvent::Known(index) => {
                    known.push(index);
                }
            }
        }

        #[cfg(feature = "malice-detection")]
        {
            self.detect_premature_gossip()?;

            for event_index in known {
                self.detect_spam(src_index, event_index);
            }
        }

        Ok(forking_peers)
    }

    fn add_event(&mut self, event: Event<S::PublicId>) -> Result<EventIndex> {
        let our = event.creator() == PeerIndex::OUR;
        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_before_process(&event)?;
        }

        self.peer_list.confirm_can_add_event(&event)?;

        let has_unconsensused_payload = if let Some(info) = event
            .payload_key()
            .and_then(|key| self.observations.get_mut(key))
        {
            if our {
                info.created_by_us = true;
            }
            !info.consensused
        } else {
            false
        };

        let is_initial = event.is_initial();
        let event_index = {
            let event = self.graph.insert(event);
            self.peer_list.add_event(event);
            event.event_index()
        };

        if has_unconsensused_payload {
            self.meta_election.add_unconsensused_event(event_index);
        }

        if is_initial {
            return Ok(event_index);
        }

        // Cache the index for DkgMessages
        // Do it before process_events so that the cached indices are already available
        if let Some(Observation::DkgMessage(ref msg)) = self
            .graph
            .get(event_index)
            .map(|idxref| idxref.inner())
            .and_then(|ev| ev.payload_key())
            .and_then(|key| self.observations.get(key))
            .map(|info| &info.observation)
        {
            let _ = self.dkg_msg_map.insert(msg.clone(), event_index);
        }

        self.process_events(event_index.topological_index())?;

        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_after_process(event_index);
        }

        Ok(event_index)
    }

    fn process_events(&mut self, mut start_index: usize) -> Result<()> {
        'outer: loop {
            for event_index in self.graph.indices_from(start_index) {
                match self.process_event(event_index)? {
                    PostProcessAction::Restart(new_start_index)
                        if new_start_index <= event_index.topological_index() =>
                    {
                        start_index = new_start_index;
                        continue 'outer;
                    }
                    PostProcessAction::Restart(_) | PostProcessAction::Continue => (),
                }
            }

            break;
        }

        Ok(())
    }

    fn process_event(&mut self, event_index: EventIndex) -> Result<PostProcessAction> {
        if self.peer_list.our_state() == PeerState::inactive() {
            return Ok(PostProcessAction::Continue);
        }

        self.create_meta_event(event_index)?;

        if let Some(payload_key) = self.compute_consensus(event_index) {
            self.output_consensus_info(&payload_key);

            match self.create_block(&payload_key) {
                Ok(block) => self.consensused_blocks.push_back(block),
                Err(Error::MissingVotes) => (),
                Err(error) => return Err(error),
            }

            self.mark_observation_as_consensused(&payload_key);

            let block_index =
                self.consensused_blocks.len() - 1 + self.first_consensused_block_number;
            self.handle_consensus(&payload_key, block_index)?;

            // Calculate new unconsensused events here, because `MetaElections` doesn't have access
            // to the actual payloads, so can't tell which ones are consensused.
            let unconsensused_events = self.collect_unconsensused_events(&payload_key);
            self.meta_election.new_election(
                payload_key,
                self.peer_list.voter_indices().collect(),
                unconsensused_events,
            );

            // Trigger reprocess.
            self.meta_election
                .initialise_round_hashes(self.peer_list.all_ids());
            let start_index = self.start_index();
            return Ok(PostProcessAction::Restart(start_index));
        }

        Ok(PostProcessAction::Continue)
    }

    fn output_consensus_info(&self, payload_key: &ObservationKey) {
        dump_graph::to_file(
            self.our_pub_id(),
            &self.graph,
            &self.meta_election,
            &self.peer_list,
            &self.common_coin,
            &self.observations,
        );

        let payload = self
            .observations
            .get(payload_key)
            .map(|info| &info.observation);
        info!(
            "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
            self.our_pub_id(),
            self.meta_election.consensus_history().len(),
            payload,
            payload_key.hash()
        )
    }

    fn mark_observation_as_consensused(&mut self, payload_key: &ObservationKey) {
        if let Some(info) = self.observations.get_mut(payload_key) {
            info.consensused = true;
        } else {
            log_or_panic!(
                "{:?} doesn't know about observation with hash {:?}",
                self.peer_list.our_pub_id(),
                payload_key.hash()
            );
        }
    }

    /// Handles consensus reached by us.
    fn handle_consensus(
        &mut self,
        payload_key: &ObservationKey,
        block_index: BlockNumber,
    ) -> Result<()> {
        match self
            .observations
            .get(payload_key)
            .map(|info| info.observation.clone())
        {
            Some(Observation::Add { .. }) | Some(Observation::Remove { .. }) => {
                self.handle_mutation_consensus(block_index)?;
            }
            Some(Observation::Accusation {
                ref offender,
                ref malice,
            }) => {
                info!(
                    "{:?} removing {:?} due to consensus on accusation of malice {:?}",
                    self.our_pub_id(),
                    offender,
                    malice
                );

                self.handle_mutation_consensus(block_index)?;
            }
            Some(Observation::DkgMessage(msg)) => {
                let dkg_result = self.handle_dkg_message(msg);
                if let Err(err) = dkg_result {
                    log_or_panic!("Failed to handle DKG message: {}", err);
                    return Err(err);
                }
            }

            Some(Observation::Genesis(_)) | Some(Observation::OpaquePayload(_)) => (),
            None => {
                log_or_panic!("Failed to get observation from hash.");
            }
        };
        self.move_next_block_number();
        Ok(())
    }

    fn move_next_block_number(&mut self) {
        self.next_block_number =
            self.key_gen.keys().next().cloned().unwrap_or_else(|| {
                self.consensused_blocks.len() + self.first_consensused_block_number
            });
    }

    fn get_dkg_msg_event(&self, msg: &DkgMessage) -> Option<&Event<S::PublicId>> {
        self.dkg_msg_map
            .get(&msg)
            .and_then(|idx| self.graph.get(*idx))
            .map(|idxref| idxref.inner())
    }

    fn handle_dkg_message(&mut self, msg: DkgMessage) -> Result<()> {
        let creator_id = self
            .get_dkg_msg_event(&msg)
            .map(|ev| ev.creator())
            .and_then(|peer_idx| self.peer_list.get(peer_idx))
            .map(|peer| peer.id())
            .ok_or(Error::DkgCacheMiss)?
            .clone();
        match msg {
            DkgMessage::Part { block_number, part } => {
                self.handle_dkg_message_part(&creator_id, block_number, part)
            }
            DkgMessage::Ack { block_number, ack } => {
                self.handle_dkg_message_ack(&creator_id, block_number, ack)
            }
        }
    }

    fn handle_dkg_message_part(
        &mut self,
        creator_id: &S::PublicId,
        block_number: BlockNumber,
        part: Part,
    ) -> Result<()> {
        if block_number < self.next_block_number {
            return Ok(());
        }
        // TODO: accuse of malice if we don't have the right key_gen?
        let key_gen = &mut self.key_gen.get_mut(&block_number).unwrap();
        let part_result = key_gen.handle_part(
            &self.peer_list.our_id(),
            creator_id,
            part.clone(),
            &mut self.rng,
        )?;

        match part_result {
            PartOutcome::Valid(Some(ack)) => {
                self.add_dkg_msg_to_queue(DkgMessage::Ack { block_number, ack });
            }
            PartOutcome::Valid(None) => (),
            PartOutcome::Invalid(fault) => {
                warn!("An invalid Part was detected from {:?}", creator_id);
                let event_hash = self
                    .get_dkg_msg_event(&DkgMessage::Part { block_number, part })
                    .ok_or(Error::DkgCacheMiss)?
                    .hash();
                let creator_idx = self
                    .peer_list
                    .get_index(creator_id)
                    .ok_or(Error::UnknownPeer)?;
                let accusation = (creator_idx, Malice::InvalidDkgPart(*event_hash, fault));
                self.pending_accusations.push(accusation);
            }
        }

        Ok(())
    }

    fn handle_dkg_message_ack(
        &mut self,
        creator_id: &S::PublicId,
        block_number: BlockNumber,
        ack: Ack,
    ) -> Result<()> {
        if block_number < self.next_block_number {
            return Ok(());
        }
        // TODO: accuse of malice if we don't have the right key_gen?
        let key_gen = &mut self.key_gen.get_mut(&block_number).unwrap();
        let ack_result = key_gen.handle_ack(&self.peer_list.our_id(), creator_id, ack.clone())?;
        match ack_result {
            AckOutcome::Valid => {
                if key_gen.is_ready() {
                    trace!(
                        "{:?}: key_gen for block number {} is ready.",
                        self.peer_list.our_pub_id(),
                        block_number
                    );
                    let (public_key_set, secret_key_share) = key_gen.generate()?;
                    self.common_coin = CommonCoin::new(
                        key_gen.public_keys().clone(),
                        public_key_set,
                        secret_key_share,
                    );

                    // Actually handle peer adds and removes
                    for block in self
                        .consensused_blocks
                        .clone() // TODO: optimise this
                        .iter()
                        .skip(self.next_block_number - self.first_consensused_block_number)
                        .take(block_number + 1 - self.next_block_number)
                    {
                        trace!(
                            "{:?}: Acting upon block {:?}",
                            self.peer_list.our_pub_id(),
                            block.payload()
                        );
                        match block.payload() {
                            Observation::Add { peer_id, .. } => self.finalise_add_peer(peer_id),
                            Observation::Remove { peer_id, .. } => {
                                self.finalise_remove_peer(peer_id)
                            }
                            Observation::Accusation { offender, .. } => {
                                self.finalise_remove_peer(offender)
                            }
                            _ => (),
                        }
                    }

                    trace!("{:?}: dropping old key_gens", self.peer_list.our_pub_id());

                    // drop old keygens
                    let key_gens = mem::replace(&mut self.key_gen, BTreeMap::new());
                    self.key_gen = key_gens
                        .into_iter()
                        .filter(|&(bn, _)| bn >= block_number + 1)
                        .collect();

                    self.move_next_block_number();
                }
            }
            AckOutcome::Invalid(fault) => {
                warn!("An invalid Ack was detected from {:?}", creator_id);
                let event_hash = self
                    .get_dkg_msg_event(&DkgMessage::Ack { block_number, ack })
                    .ok_or(Error::DkgCacheMiss)?
                    .hash();
                let creator_idx = self
                    .peer_list
                    .get_index(creator_id)
                    .ok_or(Error::UnknownPeer)?;
                let accusation = (creator_idx, Malice::InvalidDkgAck(*event_hash, fault));
                self.pending_accusations.push(accusation);
            }
        }
        Ok(())
    }

    /// This calculates the set of active voters after a given block is applied
    fn voters_at_block(&self, block_number: BlockNumber) -> BTreeSet<S::PublicId> {
        let mut peers: BTreeSet<S::PublicId> = self
            .peer_list
            .voters()
            .map(|(_, p)| p.id().clone())
            .collect();
        for block in self
            .consensused_blocks
            .iter()
            .skip(self.next_block_number - self.first_consensused_block_number)
            .take(block_number + 1 - self.next_block_number)
        {
            match block.payload() {
                Observation::Add { peer_id, .. } => {
                    let _ = peers.insert(peer_id.clone());
                }
                Observation::Remove { peer_id, .. } => {
                    let _ = peers.remove(peer_id);
                }
                Observation::Accusation { offender, .. } => {
                    let _ = peers.remove(offender);
                }
                _ => (),
            }
        }
        peers
    }

    fn handle_mutation_consensus(&mut self, block_number: BlockNumber) -> Result<()> {
        let voters = self.voters_at_block(block_number);
        let (key_gen, part) = KeyGen::from_peer_list(self.our_pub_id(), &voters)?;
        if let Some(part) = part {
            self.add_dkg_msg_to_queue(DkgMessage::Part { block_number, part });
        }
        let _ = self.key_gen.insert(block_number, key_gen);
        Ok(())
    }

    fn finalise_add_peer(&mut self, peer_id: &S::PublicId) {
        // - If we are already full member of the section, we can start sending gossips to
        //   the new peer from this moment.
        // - If we are the new peer, we must wait for the other members to send gossips to
        //   us first.
        //
        // To distinguish between the two, we check whether everyone we reached consensus on
        // adding also reached consensus on adding us.
        let recv = self
            .peer_list
            .iter()
            .filter(|(peer_index, peer)| {
                // Peers that can vote, which means we got consensus on adding them.
                peer.state().can_vote() &&
                        // Excluding us.
                        *peer_index != PeerIndex::OUR &&
                        // Excluding the peer being added.
                        peer.id() != peer_id
            })
            .all(|(_, peer)| {
                // Peers that can receive, which implies they've already sent us at least
                // one message which implies they've already reached consensus on adding us.
                peer.state().can_recv()
            });

        let state = if recv {
            PeerState::VOTE | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::VOTE | PeerState::SEND
        };

        if let Some(peer_index) = self.peer_list.get_index(peer_id) {
            self.peer_list.change_peer_state(peer_index, state);
        } else {
            let _ = self.peer_list.add_peer(peer_id.clone(), state);
        }
    }

    fn finalise_remove_peer(&mut self, peer_id: &S::PublicId) {
        if let Some(peer_index) = self.peer_list.get_index(peer_id) {
            self.peer_list.remove_peer(peer_index);
        }
    }

    fn create_meta_event(&mut self, event_index: EventIndex) -> Result<()> {
        let event = get_known_event(self.our_pub_id(), &self.graph, event_index)?;

        let mut builder =
            if let Some(meta_event) = self.meta_election.remove_meta_event(event_index) {
                meta_event.rebuild(event)
            } else {
                MetaEvent::build(event)
            };

        trace!(
            "{:?} creating a meta-event for event {:?}",
            self.our_pub_id(),
            event
        );

        self.set_interesting_content(&mut builder);
        self.set_observees(&mut builder);
        self.set_meta_votes(&mut builder)?;

        let meta_event = builder.finish();

        self.meta_election
            .add_meta_event(event_index, event.creator(), meta_event);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        if self.reuse_previous_interesting_content(builder) {
            return;
        }

        let peers_that_can_vote = self.voters();
        let start_index = self.start_index();

        let mut payloads: Vec<_> = self
            .unconsensused_events()
            .map(|event| event.inner())
            .filter(|event| builder.event().sees(event))
            .filter_map(|event| event.payload_key().map(|key| (event, key)))
            .filter(|(_, payload_key)| {
                !self
                    .meta_election
                    .is_already_interesting_content(builder.event().creator(), payload_key)
            })
            .filter(|(event, payload_key)| {
                self.is_interesting_payload(builder, &peers_that_can_vote, payload_key)
                    || event.sees_fork()
                        && self.has_interesting_ancestor(builder, payload_key, start_index)
            })
            .map(|(event, payload_key)| {
                (
                    if event.creator() == builder.event().creator() {
                        event.index_by_creator()
                    } else {
                        usize::MAX
                    },
                    payload_key,
                )
            })
            .collect();

        // First, remove duplicates (preferring payloads voted for by the creator)...
        payloads
            .sort_by(|(l_index, l_key), (r_index, r_key)| (l_key, l_index).cmp(&(r_key, r_index)));
        payloads.dedup_by(|(_, l_key), (_, r_key)| l_key == r_key);

        // ...then sort the payloads in the order the creator voted for them, followed by the ones
        // not voted for by the creator (if any).
        payloads.sort();

        let payloads = payloads.into_iter().map(|(_, key)| key).cloned().collect();
        builder.set_interesting_content(payloads);
    }

    // Try to reuse interesting content of the given event from the previous meta-election.
    fn reuse_previous_interesting_content(
        &self,
        builder: &mut MetaEventBuilder<S::PublicId>,
    ) -> bool {
        // Can't reuse interesting content of new meta-events.
        if builder.is_new() {
            return false;
        }

        let last_consensus = if let Some(payload_key) = self.meta_election.consensus_history.last()
        {
            payload_key
        } else {
            // This is the first meta-election. Nothing to reuse.
            return false;
        };

        // If membership change occurred in the last meta-election, we can't reuse the interesting
        // content.
        let payload = self
            .observations
            .get(last_consensus)
            .map(|info| &info.observation);
        match payload {
            Some(&Observation::Add { .. })
            | Some(&Observation::Remove { .. })
            | Some(&Observation::Accusation { .. }) => return false,
            _ => (),
        }

        let creator = builder.event().creator();
        builder.reuse_interesting_content(|payload_key| {
            payload_key != last_consensus
                && !self
                    .meta_election
                    .is_already_interesting_content(creator, payload_key)
        });

        true
    }

    // Returns true if `builder.event()` has an ancestor by a different creator that has `payload`
    // in interesting content
    fn has_interesting_ancestor(
        &self,
        builder: &MetaEventBuilder<S::PublicId>,
        payload_key: &ObservationKey,
        start_index: usize,
    ) -> bool {
        self.graph
            .ancestors(builder.event())
            .take_while(|that_event| that_event.topological_index() >= start_index)
            .filter(|that_event| that_event.creator() != builder.event().creator())
            .any(|that_event| {
                self.meta_election
                    .meta_event(that_event.event_index())
                    .map(|meta_event| meta_event.interesting_content.contains(payload_key))
                    .unwrap_or(false)
            })
    }

    // Returns true if enough of `valid_voters` have voted for the indicated payload from the
    // perspective of `builder.event()`.
    fn is_interesting_payload(
        &self,
        builder: &MetaEventBuilder<S::PublicId>,
        peers_that_can_vote: &PeerIndexSet,
        payload_key: &ObservationKey,
    ) -> bool {
        let num_peers_that_did_vote = self.num_creators_of_ancestors_carrying_payload(
            peers_that_can_vote,
            &*builder.event(),
            payload_key,
        );

        match payload_key.consensus_mode() {
            ConsensusMode::Single => {
                let num_ancestor_peers =
                    self.num_creators_of_ancestors(peers_that_can_vote, &*builder.event());
                is_more_than_two_thirds(num_ancestor_peers, peers_that_can_vote.len())
                    && num_peers_that_did_vote > 0
            }
            ConsensusMode::Supermajority => {
                is_more_than_two_thirds(num_peers_that_did_vote, peers_that_can_vote.len())
            }
        }
    }

    // Number of unique peers that created at least one ancestor of the given event.
    fn num_creators_of_ancestors(
        &self,
        peers_that_can_vote: &PeerIndexSet,
        event: &Event<S::PublicId>,
    ) -> usize {
        event
            .last_ancestors()
            .keys()
            .filter(|peer_index| peers_that_can_vote.contains(*peer_index))
            .count()
    }

    // Number of unique peers that created at least one ancestor of the given event that carries the
    // given payload.
    fn num_creators_of_ancestors_carrying_payload(
        &self,
        peers_that_can_vote: &PeerIndexSet,
        event: &Event<S::PublicId>,
        payload_key: &ObservationKey,
    ) -> usize {
        peers_that_can_vote
            .iter()
            .filter(|peer_index| {
                self.unconsensused_events()
                    .map(|that_event| that_event.inner())
                    .filter(|that_event| that_event.creator() == *peer_index)
                    .filter_map(|that_event| that_event.payload_key().map(|key| (that_event, key)))
                    .any(|(that_event, that_payload_key)| {
                        payload_key == that_payload_key && event.sees(that_event)
                    })
            })
            .count()
    }

    fn set_observees(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        let observees = self
            .meta_election
            .interesting_events()
            .filter_map(|(peer_index, event_indices)| {
                let event_index = event_indices.front()?;
                let event = self.get_known_event(*event_index).ok()?;
                if self.strongly_sees(builder.event(), event) {
                    Some(peer_index)
                } else {
                    None
                }
            })
            .collect();
        builder.set_observees(observees);
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<S::PublicId>) -> Result<()> {
        let voters = self.voters();

        let parent_meta_votes = builder
            .event()
            .self_parent()
            .and_then(|parent_hash| self.meta_election.meta_votes(parent_hash))
            .and_then(|parent_meta_votes| {
                if !parent_meta_votes.is_empty() {
                    Some(parent_meta_votes)
                } else {
                    None
                }
            });

        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        if let Some(parent_meta_votes) = parent_meta_votes {
            for (peer_index, parent_event_votes) in parent_meta_votes {
                let new_meta_votes = {
                    let other_votes =
                        self.collect_other_meta_votes(&voters, peer_index, &*builder.event());
                    let coin_tosses =
                        self.toss_coins(&voters, peer_index, &parent_event_votes, builder.event())?;
                    MetaVote::next(
                        &parent_event_votes,
                        &other_votes,
                        &coin_tosses,
                        voters.len(),
                        voters.contains(builder.event().creator()),
                    )
                };

                builder.add_meta_votes(peer_index, new_meta_votes);
            }
        } else if self.is_observer(builder) {
            // For the case that event's creator is not a voter, the initial estimation shall not be
            // created.
            let is_voter = voters.contains(builder.event().creator());

            // Start meta votes for this event.
            for peer_index in voters {
                let other_votes =
                    self.collect_other_meta_votes(&voters, peer_index, &*builder.event());
                let initial_estimate = builder.has_observee(peer_index);

                builder.add_meta_votes(
                    peer_index,
                    MetaVote::new(initial_estimate, &other_votes, voters.len(), is_voter),
                );
            }
        };

        trace!(
            "{:?} has set the meta votes for {:?}",
            self.our_pub_id(),
            *builder.event(),
        );

        Ok(())
    }

    fn toss_coins(
        &self,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        parent_votes: &[MetaVote],
        event: IndexedEventRef<S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(voters, peer_index, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        parent_vote: &MetaVote,
        event: IndexedEventRef<S::PublicId>,
    ) -> Result<Option<bool>> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                if voters.contains(event.creator()) {
                    // This should never happen as estimates get cleared only in increase step when the
                    // step is Step::GenuineFlip and the round gets incremented.
                    log_or_panic!(
                        "{:?} missing parent vote estimates at round 0.",
                        self.our_pub_id()
                    );
                    return Err(Error::Logic);
                } else {
                    return Ok(None);
                }
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash = if let Some(hashes) = self.meta_election.round_hashes(peer_index) {
            hashes[round]
        } else {
            log_or_panic!("{:?} missing round hash.", self.our_pub_id());
            return Err(Error::Logic);
        };

        let start_index = self.meta_election.start_index().unwrap_or(0);
        let shares_with_creators = self
            .graph
            .ancestors(event)
            .take_while(|idxref| idxref.topological_index() >= start_index)
            .filter_map(|idxref| {
                idxref
                    .inner()
                    .coin_shares()
                    .and_then(|shares| shares.get(&round_hash))
                    .and_then(|share| {
                        self.peer_list
                            .get(idxref.inner().creator())
                            .map(|peer| (peer.id().clone(), share.clone()))
                    })
            });

        let valid_shares = shares_with_creators
            .filter(|(peer_id, share)| {
                self.common_coin
                    .verify_share(&round_hash, peer_id.clone(), share)
            })
            .collect();

        Ok(self.common_coin.get_value(&round_hash, valid_shares))
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.  Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        creator: PeerIndex,
        creator_event_index: usize,
        peer_index: PeerIndex,
        round: usize,
        step: Step,
    ) -> impl Iterator<Item = &MetaVote> {
        let mut events = self.peer_list.events_by_index(creator, creator_event_index);
        let event = events.next().and_then(|event| {
            if events.next().is_some() {
                // Fork
                None
            } else {
                Some(event)
            }
        });

        event
            .and_then(|event| self.meta_election.meta_votes(event))
            .and_then(|meta_votes| meta_votes.get(peer_index))
            .into_iter()
            .flat_map(|meta_votes| meta_votes)
            .filter(move |meta_vote| {
                meta_vote.round > round || meta_vote.round == round && meta_vote.step >= step
            })
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by the peer at `peer_index`.
    fn collect_other_meta_votes(
        &self,
        voters: &PeerIndexSet,
        peer_index: PeerIndex,
        event: &Event<S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        voters
            .iter()
            .filter(|voter_index| *voter_index != event.creator())
            .filter_map(|creator| {
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            creator,
                            *creator_event_index,
                            peer_index,
                            0,
                            Step::ForcedTrue,
                        )
                        .cloned()
                        .collect()
                    })
            })
            .collect()
    }

    // List of voters for the given meta-election.
    fn voters(&self) -> &PeerIndexSet {
        self.meta_election.voters()
    }

    // Number of voters for the given meta-election.
    fn voter_count(&self) -> usize {
        self.meta_election.voters().len()
    }

    fn unconsensused_events(&self) -> impl Iterator<Item = IndexedEventRef<S::PublicId>> {
        self.meta_election
            .unconsensused_events()
            .filter_map(move |index| self.get_known_event(index).ok())
    }

    fn start_index(&self) -> usize {
        self.meta_election
            .start_index()
            .unwrap_or_else(|| self.graph.len())
    }

    fn compute_consensus(&self, event_index: EventIndex) -> Option<ObservationKey> {
        let last_meta_votes = self.meta_election.meta_votes(event_index)?;

        let decided_meta_votes = last_meta_votes
            .iter()
            .filter_map(|(peer_index, event_votes)| {
                event_votes
                    .last()
                    .and_then(|v| v.decision)
                    .map(|v| (peer_index, v))
            });

        if decided_meta_votes.clone().count() < self.voter_count() {
            return None;
        }

        self.compute_payload_for_consensus(decided_meta_votes)
    }

    fn compute_payload_for_consensus<I>(&self, decided_meta_votes: I) -> Option<ObservationKey>
    where
        I: IntoIterator<Item = (PeerIndex, bool)>,
    {
        let mut payloads: Vec<_> = decided_meta_votes
            .into_iter()
            .filter_map(|(peer_index, decision)| {
                if decision {
                    self.meta_election
                        .first_interesting_content_by(peer_index)
                        .cloned()
                } else {
                    None
                }
            })
            .collect();

        // IMPORTANT: We must sort this in consistent order, so when the tie breaking rule kicks in,
        // the outcome is the same for everyone.
        payloads.sort_by(|a, b| a.hash().cmp(b.hash()));

        payloads
            .iter()
            .max_by(|lhs_payload, rhs_payload| {
                let lhs_count = payloads
                    .iter()
                    .filter(|payload_carried| lhs_payload == payload_carried)
                    .count();
                let rhs_count = payloads
                    .iter()
                    .filter(|payload_carried| rhs_payload == payload_carried)
                    .count();
                lhs_count.cmp(&rhs_count)
            })
            .cloned()
    }

    fn create_block(&self, payload_key: &ObservationKey) -> Result<Block<T, S::PublicId>> {
        let voters = self.voters();
        let votes = self
            .graph
            .iter()
            .map(|event| event.inner())
            .filter(|event| voters.contains(event.creator()))
            .filter_map(|event| {
                let (vote, key) = event.vote_and_payload_key(&self.observations)?;
                let creator_id = self.peer_list.get(event.creator()).map(|peer| peer.id())?;
                Some((key, vote, creator_id))
            })
            .filter(|(key, _, _)| payload_key == key)
            .map(|(_, vote, creator_id)| (creator_id.clone(), vote.clone()))
            .collect();

        Block::new(&votes)
    }

    // Collects still unconsensused event from the current meta-election.
    fn collect_unconsensused_events(&self, decided_key: &ObservationKey) -> BTreeSet<EventIndex> {
        self.meta_election
            .unconsensused_events()
            .filter(|event_index| {
                self.get_known_event(*event_index)
                    .ok()
                    .and_then(|event| event.inner().payload_key())
                    .map(|payload_key| payload_key != decided_key)
                    .unwrap_or(false)
            })
            .collect()
    }

    // Returns the number of peers that created events which are seen by event X (descendant) and
    // see event Y (ancestor). This means number of peers through which there is a directed path
    // between x and y, excluding peers contains fork.
    fn num_peers_created_events_seen_by_x_that_can_see_y(
        &self,
        x: &Event<S::PublicId>,
        y: &Event<S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_index, &event_index)| {
                for event_hash in self.peer_list.events_by_index(*peer_index, event_index) {
                    if let Ok(event) = self.get_known_event(event_hash) {
                        if x.sees(event) && event.sees(y) {
                            return true;
                        }
                    }
                }
                false
            })
            .count()
    }

    // Returns whether event X can strongly see the event Y during the evaluation of the given
    // election.
    fn strongly_sees<A, B>(&self, x: A, y: B) -> bool
    where
        A: AsRef<Event<S::PublicId>>,
        B: AsRef<Event<S::PublicId>>,
    {
        is_more_than_two_thirds(
            self.num_peers_created_events_seen_by_x_that_can_see_y(x.as_ref(), y.as_ref()),
            self.voter_count(),
        )
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    //
    // `opt_other_parent` will contain the other-parent this new sync event should use, unless the
    // gossip message from the peer was empty, in which case this will be `None` and we'll just use
    // `src`'s most recent event we know of.
    fn create_sync_event(
        &mut self,
        src_index: PeerIndex,
        is_request: bool,
        forking_peers: &PeerIndexSet,
        opt_other_parent: Option<EventIndex>,
    ) -> Result<()> {
        let self_parent = self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
            Error::Logic
        })?;

        let other_parent = match opt_other_parent {
            Some(index) => index,
            None => self.peer_list.last_event(src_index).ok_or_else(|| {
                log_or_panic!(
                    "{:?} missing last event hash of {:?}.",
                    self.our_pub_id(),
                    src_index
                );
                Error::Logic
            })?,
        };

        let sync_event = if is_request {
            Event::new_from_request(
                self_parent,
                other_parent,
                forking_peers,
                self.event_context(),
            )?
        } else {
            Event::new_from_response(
                self_parent,
                other_parent,
                forking_peers,
                self.event_context(),
            )?
        };

        let _ = self.add_event(sync_event)?;
        Ok(())
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(&self, peer_index: PeerIndex) -> Result<Vec<&Event<S::PublicId>>> {
        let last_event = if let Some(event_index) = self.peer_list.last_event(peer_index) {
            self.get_known_event(event_index)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_index);
            return Err(Error::Logic);
        };

        // Events to include in the result. Initially start with including everything...
        let mut inclusion_list = vec![true; self.graph.len()];

        // ...then exclude events that are ancestors of `last_event`, because the peer already has
        // them.
        for event in self.graph.ancestors(last_event) {
            inclusion_list[event.topological_index()] = false;
        }

        Ok(self
            .graph
            .iter()
            .filter(|event| inclusion_list[event.topological_index()])
            .map(|event| event.inner())
            .collect())
    }

    fn create_accusation_event(
        &mut self,
        offender: PeerIndex,
        malice: Malice<T, S::PublicId>,
    ) -> Result<()> {
        let offender = self.peer_list.get_known(offender)?.id().clone();
        let event = Event::new_from_observation(
            self.our_last_event_index()?,
            Observation::Accusation { offender, malice },
            self.event_context_mut(),
        )?;

        let _ = self.add_event(event)?;
        Ok(())
    }

    fn create_accusation_events(&mut self) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice)?;
        }

        Ok(())
    }

    fn add_dkg_msg_to_queue(&mut self, msg: DkgMessage) {
        self.pending_dkg_msgs.push(msg);
    }

    fn create_coin_shares_event(&mut self) -> Result<()> {
        let last_sync_event_idxref = if let Some(event) = self
            .peer_list
            .our_events()
            .rev()
            .filter_map(|ev_idx| self.graph.get(ev_idx))
            .find(|idxref| idxref.inner().is_request() || idxref.inner().is_response())
        {
            event
        } else {
            return Ok(());
        };
        let last_sync_event_parent = last_sync_event_idxref
            .inner()
            .self_parent()
            .and_then(|idx| self.graph.get(idx))
            .ok_or(Error::Logic)?;
        let last_meta_event = self
            .meta_election
            .meta_event(last_sync_event_idxref.event_index());
        let parent_meta_event = self
            .meta_election
            .meta_event(last_sync_event_parent.event_index());

        // we are only interested in situations where both meta events exist
        if let (Some(last_meta_event), Some(parent_meta_event)) =
            (last_meta_event, parent_meta_event)
        {
            let shares: BTreeMap<_, _> = last_meta_event
                .meta_votes
                .iter()
                .filter(|&(peer_idx, meta_votes)| {
                    // only get the meta votes for which the last one is at genuine flip step, and
                    // there is a corresponding vec of meta votes in the parent meta event, for
                    // which the last meta vote is not at the genuine flip step
                    meta_votes
                        .last()
                        .map(|mv| mv.step == Step::GenuineFlip)
                        .unwrap_or(false)
                        && parent_meta_event
                            .meta_votes
                            .get(peer_idx)
                            .and_then(|mvs| mvs.last())
                            .map(|mv| mv.step != Step::GenuineFlip)
                            .unwrap_or(false)
                })
                .filter_map(|(peer_idx, _)| {
                    self.meta_election
                        .round_hashes(peer_idx)
                        .and_then(|round_hashes| round_hashes.last())
                })
                .filter_map(|round_hash| {
                    self.common_coin
                        .sign_round_hash(round_hash)
                        .map(|sig_share| (round_hash.clone(), sig_share))
                })
                .collect();
            if !shares.is_empty() {
                let coin_shares_event = Event::new_from_coin_shares(
                    self.our_last_event_index()?,
                    shares,
                    self.event_context_mut(),
                )?;
                let _ = self.add_event(coin_shares_event)?;
            }
        }

        Ok(())
    }

    fn create_dkg_events(&mut self) -> Result<()> {
        for msg in mem::replace(&mut self.pending_dkg_msgs, vec![]) {
            self.publish_dkg_msg(msg)?;
        }
        Ok(())
    }

    fn publish_dkg_msg(&mut self, msg: DkgMessage) -> Result<()> {
        let event = Event::new_from_observation(
            self.our_last_event_index()?,
            Observation::DkgMessage(msg),
            self.event_context_mut(),
        )?;
        let _ = self.add_event(event)?;
        Ok(())
    }

    fn event_context(&self) -> EventContextRef<T, S> {
        EventContextRef {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &self.observations,
        }
    }

    fn event_context_mut(&mut self) -> EventContextMut<T, S> {
        EventContextMut {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &mut self.observations,
            consensus_mode: self.consensus_mode,
        }
    }

    #[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
    fn event_payload<'a>(
        &'a self,
        event: &Event<S::PublicId>,
    ) -> Option<&'a Observation<T, S::PublicId>> {
        event
            .payload_key()
            .and_then(|key| self.observations.get(key))
            .map(|info| &info.observation)
    }

    #[cfg(any(all(test, feature = "mock"), feature = "malice-detection"))]
    fn event_creator_id<'a>(&'a self, event: &Event<S::PublicId>) -> Result<&'a S::PublicId> {
        self.peer_list
            .get(event.creator())
            .map(|peer| peer.id())
            .ok_or_else(|| {
                log_or_panic!(
                    "{:?} doesn't know the creator of {:?}",
                    self.our_pub_id(),
                    event
                );
                Error::Logic
            })
    }
}

#[cfg(feature = "malice-detection")]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    fn detect_malice_before_process(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        // NOTE: `detect_incorrect_genesis` must come first.
        self.detect_incorrect_genesis(event)?;

        self.detect_other_parent_by_same_creator(event)?;
        self.detect_self_parent_by_different_creator(event)?;

        self.detect_unexpected_genesis(event);
        self.detect_missing_genesis(event);
        self.detect_duplicate_vote(event);
        self.detect_fork(event);
        self.detect_invalid_accusation(event);
        self.detect_invalid_coin_shares(event)?;

        // TODO: detect other forms of malice here

        Ok(())
    }

    fn detect_malice_after_process(&mut self, event_index: EventIndex) {
        self.detect_invalid_gossip_creator(event_index);
    }

    // Detect if the event carries an `Observation::Genesis` that doesn't match what we'd expect.
    fn detect_incorrect_genesis(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        let (offender, malice) =
            if let Some(Observation::Genesis(ref group)) = self.event_payload(event) {
                if group.iter().collect::<BTreeSet<_>>() != self.genesis_group() {
                    (event.creator(), Malice::IncorrectGenesis(*event.hash()))
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            };

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        self.create_accusation_event(offender, malice)?;
        Err(Error::InvalidEvent)
    }

    // Detect if the event's other_parent has the same creator as this event.
    fn detect_other_parent_by_same_creator(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        if let Some(other_parent) = self.graph.other_parent(event) {
            if other_parent.creator() != event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        let packed_event = event.pack(self.event_context())?;
        self.create_accusation_event(
            event.creator(),
            Malice::OtherParentBySameCreator(Box::new(packed_event)),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect if the event's self_parent has the different creator as this event.
    fn detect_self_parent_by_different_creator(
        &mut self,
        event: &Event<S::PublicId>,
    ) -> Result<()> {
        if let Some(self_parent) = self.graph.self_parent(event) {
            if self_parent.creator() == event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        let packed_event = event.pack(self.event_context())?;
        self.create_accusation_event(
            event.creator(),
            Malice::SelfParentByDifferentCreator(Box::new(packed_event)),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&mut self, event: &Event<S::PublicId>) {
        let accuse = {
            let payload = if let Some(payload) = self.event_payload(event) {
                payload
            } else {
                return;
            };

            let genesis_group = if let Observation::Genesis(ref group) = *payload {
                group
            } else {
                return;
            };

            let creator_id = if let Ok(id) = self.event_creator_id(event) {
                id
            } else {
                return;
            };

            // - the creator is not member of the genesis group, or
            // - the self-parent of the event is not initial event
            !genesis_group.contains(creator_id)
                || self
                    .graph
                    .self_parent(event)
                    .map_or(true, |self_parent| !self_parent.is_initial())
        };

        if accuse {
            self.accuse(event.creator(), Malice::UnexpectedGenesis(*event.hash()));
        }
    }

    // Detect when the first event by a peer belonging to genesis doesn't carry genesis
    fn detect_missing_genesis(&mut self, event: &Event<S::PublicId>) {
        if event.index_by_creator() != 1 {
            return;
        }

        if let Some(&Observation::Genesis(_)) = self.event_payload(event) {
            return;
        }

        let accuse = {
            let creator_id = if let Ok(id) = self.event_creator_id(event) {
                id
            } else {
                return;
            };

            self.genesis_group().contains(creator_id)
        };

        if accuse {
            self.accuse(event.creator(), Malice::MissingGenesis(*event.hash()));
        }
    }

    // Detect that if the event carries a vote, there is already one or more votes with the same
    // observation by the same creator.
    fn detect_duplicate_vote(&mut self, event: &Event<S::PublicId>) {
        let other_hash = {
            let payload = if let Some(payload) = self.event_payload(event) {
                payload
            } else {
                return;
            };

            let mut duplicates = self
                .peer_list
                .peer_events(event.creator())
                .rev()
                .filter_map(|index| self.get_known_event(index).ok())
                .filter(|event| {
                    self.event_payload(event)
                        .map_or(false, |event_payload| event_payload == payload)
                })
                .map(|event| *event.hash())
                .take(2);

            let hash = if let Some(hash) = duplicates.next() {
                // One duplicate found - raise the accusation.
                hash
            } else {
                // No duplicates found - do not raise the accusation.
                return;
            };

            if duplicates.next().is_some() {
                // More than one duplicate found - the accusation should have already been raised,
                // so don't raise it again.
                return;
            }

            hash
        };

        self.accuse(
            event.creator(),
            Malice::DuplicateVote(other_hash, *event.hash()),
        );
    }

    // Detect whether the event incurs a fork.
    fn detect_fork(&mut self, event: &Event<S::PublicId>) {
        if self.peer_list.last_event(event.creator()) != event.self_parent() {
            if let Some(self_parent_hash) = self.graph.self_parent(event).map(|event| *event.hash())
            {
                self.accuse(event.creator(), Malice::Fork(self_parent_hash));
            }
        }
    }

    fn detect_invalid_accusation(&mut self, event: &Event<S::PublicId>) {
        {
            let their_accusation = match self.event_payload(event) {
                Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) => {
                    if !malice.is_provable() {
                        return;
                    }

                    let offender = if let Some(index) = self.peer_list.get_index(offender) {
                        index
                    } else {
                        return;
                    };

                    (offender, malice)
                }
                _ => return,
            };

            // First try to find the same accusation in our pending accusations...
            let found = self
                .pending_accusations
                .iter()
                .any(|&(our_offender, ref our_malice)| {
                    their_accusation == (our_offender, our_malice)
                });
            if found {
                return;
            }

            // ...then in our events...
            let found = self
                .peer_list
                .our_events()
                .rev()
                .filter_map(|hash| self.get_known_event(hash).ok())
                .filter_map(|event| {
                    if let Some(&Observation::Accusation {
                        ref offender,
                        ref malice,
                    }) = self.event_payload(event.inner())
                    {
                        Some((offender, malice))
                    } else {
                        None
                    }
                })
                .filter_map(|(offender_id, malice)| {
                    self.peer_list
                        .get_index(offender_id)
                        .map(|index| (index, malice))
                })
                .any(|our_accusation| their_accusation == our_accusation);
            if found {
                return;
            }
        }

        // ..if not found, their accusation is invalid.
        self.accuse(event.creator(), Malice::InvalidAccusation(*event.hash()))
    }

    fn detect_invalid_coin_shares(&mut self, event: &Event<S::PublicId>) -> Result<()> {
        let creator_id = self
            .peer_list
            .get(event.creator())
            .ok_or(Error::UnknownPeer)?
            .id();
        if let Some(shares) = event.coin_shares() {
            for (round_hash, share) in shares {
                if !self
                    .common_coin
                    .verify_share(round_hash, creator_id.clone(), share)
                {
                    self.pending_accusations.push((
                        event.creator(),
                        Malice::InvalidCoinShare(*event.hash(), round_hash.value().clone()),
                    ));
                }
            }
        }
        Ok(())
    }

    fn detect_invalid_gossip_creator(&mut self, _event_index: EventIndex) {
        /* TODO: bring this back somehow
        let accusation = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            let other_parent = if let Some(parent) = self.graph.other_parent(event) {
                parent
            } else {
                return;
            };

            let membership_list = if let Some(list) = self
                .peer_list
                .peer_membership_list_snapshot_excluding_last_remove(
                    event.creator(),
                    event.index_by_creator(),
                ) {
                list
            } else {
                // The membership list is not yet initialised - skip the detection.
                return;
            };

            if membership_list.contains(other_parent.creator()) {
                None
            } else {
                Some((event.creator(), *event.hash()))
            }
        };

        if let Some((offender, event_hash)) = accusation {
            self.accuse(offender, Malice::InvalidGossipCreator(event_hash))
        }
        */
    }

    fn detect_premature_gossip(&self) -> Result<()> {
        self.confirm_self_state(PeerState::VOTE)
            .map_err(|_| Error::PrematureGossip)
    }

    fn detect_spam(&mut self, src_index: PeerIndex, known_event_index: EventIndex) {
        if self.unprovable_offenders.contains(src_index) {
            // Already accused.
            return;
        }

        let spam = {
            let their_event = self
                .peer_list
                .last_gossiped_event_by(src_index)
                .and_then(|index| self.get_known_event(index).ok())
                .and_then(|event| self.last_ancestor_by(event, src_index));
            let their_event = if let Some(their_event) = their_event {
                their_event
            } else {
                return;
            };

            let known_event = if let Ok(event) = self.get_known_event(known_event_index) {
                event
            } else {
                return;
            };

            self.last_ancestor_by(their_event, PeerIndex::OUR)
                .map(|our_event| self.graph.is_descendant(our_event, known_event))
                .unwrap_or(false)
        };

        if spam {
            let _ = self.unprovable_offenders.insert(src_index);
            self.accuse(src_index, Malice::Unprovable(UnprovableMalice::Spam));
        }
    }

    fn accuse(&mut self, offender: PeerIndex, malice: Malice<T, S::PublicId>) {
        self.pending_accusations.push((offender, malice));
    }

    fn accusations_by_peer_since(
        &self,
        peer_index: PeerIndex,
        oldest_event: Option<EventIndex>,
    ) -> Accusations<T, S::PublicId> {
        self.graph
            .iter_from(oldest_event.map(|e| e.topological_index()).unwrap_or(0))
            .filter(|event| event.creator() == peer_index)
            .filter_map(|event| match self.event_payload(event.inner()) {
                Some(Observation::Accusation { offender, malice }) => Some((offender, malice)),
                _ => None,
            })
            .filter_map(|(offender, malice)| {
                self.peer_list
                    .get_index(offender)
                    .map(|offender| (offender, malice.clone()))
            })
            .collect()
    }

    fn malicious_event_is_ancestor_of_this_event(
        &self,
        malice: &Malice<T, S::PublicId>,
        event: EventIndex,
    ) -> bool {
        let event = if let Some(event) = self.graph.get(event) {
            event
        } else {
            return false;
        };

        match malice {
            Malice::UnexpectedGenesis(hash)
            | Malice::MissingGenesis(hash)
            | Malice::IncorrectGenesis(hash)
            | Malice::InvalidAccusation(hash)
            | Malice::InvalidGossipCreator(hash)
            | Malice::Accomplice(hash, _)
            | Malice::InvalidDkgPart(hash, _)
            | Malice::InvalidDkgAck(hash, _)
            | Malice::InvalidCoinShare(hash, _) => self
                .graph
                .get_index(hash)
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| self.graph.is_descendant(event, malicious_event))
                .unwrap_or(false),

            Malice::DuplicateVote(hash0, hash1) => {
                self.graph
                    .get_index(hash0)
                    .and_then(|index| self.graph.get(index))
                    .map(|malicious_event0| self.graph.is_descendant(event, malicious_event0))
                    .unwrap_or(false)
                    && self
                        .graph
                        .get_index(hash1)
                        .and_then(|index| self.graph.get(index))
                        .map(|malicious_event1| self.graph.is_descendant(event, malicious_event1))
                        .unwrap_or(false)
            }
            Malice::Fork(hash) => self
                .graph
                .get_index(hash)
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| {
                    self.graph.is_descendant(event, malicious_event)
                        && event.is_forking_peer(malicious_event.creator())
                })
                .unwrap_or(false),
            Malice::OtherParentBySameCreator(packed_event)
            | Malice::SelfParentByDifferentCreator(packed_event) => self
                .graph
                .get_index(&packed_event.compute_hash())
                .and_then(|index| self.graph.get(index))
                .map(|malicious_event| self.graph.is_descendant(event, malicious_event))
                .unwrap_or(false),
            Malice::Unprovable(_) => false,
        }
    }

    fn detect_accomplice(&mut self, event: EventIndex) -> Result<()> {
        let (event_hash, creator) = {
            let event = self.get_known_event(event)?;
            let is_accusation = self
                .event_payload(&event)
                .map(|payload| match payload {
                    Observation::Accusation { .. } => true,
                    _ => false,
                })
                .unwrap_or(false);

            // If this is a Request or an accusation for another malice then the peer might not
            // have raised the accusation yet.
            if event.is_request() || is_accusation {
                return Ok(());
            }

            (*event.hash(), event.creator())
        };

        let starting_index = self.peer_list.accomplice_event_checkpoint_by(creator);
        for (_, malice) in self.detect_accomplice_for_our_accusations(event, starting_index)? {
            self.accuse(creator, Malice::Accomplice(event_hash, Box::new(malice)));
        }

        // Updating the event checkpoint for the next event when it will be used as starting index,
        // purely as an optimisation
        let last_malice_event_accused_by_peer = self
            .accusations_by_peer_since(creator, starting_index)
            .iter()
            .filter_map(|(_, malice)| malice.single_hash().and_then(|h| self.graph.get_index(&h)))
            .max_by_key(|event_index| event_index.topological_index());
        if let Some(index) = last_malice_event_accused_by_peer {
            self.peer_list
                .update_accomplice_event_checkpoint_by(creator, index);
        }

        Ok(())
    }

    fn detect_accomplice_for_our_accusations(
        &self,
        event: EventIndex,
        starting_event: Option<EventIndex>,
    ) -> Result<Accusations<T, S::PublicId>> {
        let creator = self.get_known_event(event)?.creator();
        let our_accusations = self.accusations_by_peer_since(PeerIndex::OUR, starting_event);
        let accusations_by_peer_since_starter_event =
            self.accusations_by_peer_since(creator, starting_event);

        Ok(self
            .pending_accusations
            .iter()
            .chain(our_accusations.iter())
            .filter(|(offender, _)| offender != &creator)
            .filter(|(_, malice)| self.malicious_event_is_ancestor_of_this_event(&malice, event))
            .filter(|(offender, malice)| {
                !accusations_by_peer_since_starter_event
                    .iter()
                    .any(|(off, mal)| (off, mal) == (offender, &malice))
            })
            .cloned()
            .collect())
    }

    fn genesis_group(&self) -> BTreeSet<&S::PublicId> {
        self.graph
            .iter()
            .filter_map(|event| {
                let observation = self.event_payload(&*event)?;
                if let Observation::Genesis(ref gen) = *observation {
                    Some(gen.iter().collect())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_else(|| self.peer_list.voters().map(|(_, peer)| peer.id()).collect())
    }

    // Returns the last ancestor of the given event created by the given peer, if any.
    fn last_ancestor_by<'a>(
        &'a self,
        event: IndexedEventRef<'a, S::PublicId>,
        creator: PeerIndex,
    ) -> Option<IndexedEventRef<'a, S::PublicId>> {
        use crate::gossip::LastAncestor;

        match event.last_ancestor_by(creator) {
            LastAncestor::Some(index) => self
                .peer_list
                .events_by_index(creator, index)
                .next()
                .and_then(|index| self.get_known_event(index).ok()),
            LastAncestor::None => None,
            LastAncestor::Fork => self
                .graph
                .ancestors(event)
                .find(|ancestor| ancestor.creator() == creator),
        }
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.graph,
                &self.meta_election,
                &self.peer_list,
                &self.common_coin,
                &self.observations,
            );
        }
    }
}

fn get_known_event<'a, P: PublicId>(
    our_pub_id: &P,
    graph: &'a Graph<P>,
    event_index: EventIndex,
) -> Result<IndexedEventRef<'a, P>> {
    graph.get(event_index).ok_or_else(|| {
        log_or_panic!("{:?} doesn't have event {:?}", our_pub_id, event_index);
        Error::Logic
    })
}

// What to do after processing the current event.
enum PostProcessAction {
    // Continue with the next event (if any)
    Continue,
    // Restart processing events from the given index.
    Restart(usize),
}

type Accusations<T, P> = Vec<(PeerIndex, Malice<T, P>)>;

#[cfg(any(feature = "testing", all(test, feature = "mock")))]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(mut parsed_contents: ParsedContents) -> Self {
        let peer_list = PeerList::new(parsed_contents.our_id);
        let mut parsec = Parsec::empty(
            peer_list,
            PeerIndexSet::default(),
            ConsensusMode::Supermajority,
            parsed_contents.common_coin,
        );

        for event in &parsed_contents.graph {
            if let Some(payload_key) = event.payload_key() {
                if let Some(info) = parsed_contents.observations.get_mut(payload_key) {
                    if event.creator() == PeerIndex::OUR {
                        info.created_by_us = true;
                    }
                }
            }
        }

        for consensused in parsed_contents.meta_election.consensus_history() {
            let _ = parsed_contents
                .observations
                .get_mut(consensused)
                .map(|info| info.consensused = true);
        }

        parsec.graph = parsed_contents.graph;
        parsec.meta_election = parsed_contents.meta_election;
        parsec.peer_list = parsed_contents.peer_list;
        parsec.observations = parsed_contents.observations;
        parsec
    }
}

/// Wrapper around `Parsec` that exposes additional functionality useful for testing.
#[cfg(all(test, feature = "mock"))]
pub(crate) struct TestParsec<T: NetworkEvent, S: SecretId>(Parsec<T, S>);

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> TestParsec<T, S> {
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        common_coin: CommonCoin<S::PublicId>,
    ) -> Self {
        TestParsec(Parsec::from_genesis(
            our_id,
            genesis_group,
            ConsensusMode::Supermajority,
            common_coin,
        ))
    }

    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        common_coin: CommonCoin<S::PublicId>,
    ) -> Self {
        TestParsec(Parsec::from_existing(
            our_id,
            genesis_group,
            section,
            ConsensusMode::Supermajority,
            common_coin,
        ))
    }

    pub fn graph(&self) -> &Graph<S::PublicId> {
        &self.0.graph
    }

    pub fn peer_list(&self) -> &PeerList<S> {
        &self.0.peer_list
    }

    pub fn common_coin(&self) -> &CommonCoin<S::PublicId> {
        &self.0.common_coin
    }

    pub fn meta_election(&self) -> &MetaElection {
        &self.meta_election
    }

    pub fn consensused_blocks(&self) -> impl Iterator<Item = &Block<T, S::PublicId>> {
        self.0.consensused_blocks.iter()
    }

    pub fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &PeerIndexSet,
        other_parent: Option<EventHash>,
    ) -> Result<()> {
        let src_index = unwrap!(self.0.peer_list.get_index(src));
        let other_parent = other_parent
            .as_ref()
            .map(|hash| unwrap!(self.0.graph.get_index(hash)));
        self.0
            .create_sync_event(src_index, is_request, forking_peers, other_parent)
    }

    pub fn change_peer_state(&mut self, peer_id: &S::PublicId, state: PeerState) {
        let peer_index = unwrap!(self.0.peer_list.get_index(peer_id));
        self.0.peer_list.change_peer_state(peer_index, state)
    }

    pub fn pack_event(&self, event: &Event<S::PublicId>) -> PackedEvent<T, S::PublicId> {
        unwrap!(event.pack(self.0.event_context()))
    }

    pub fn unpack_and_add_event(
        &mut self,
        event: PackedEvent<T, S::PublicId>,
    ) -> Result<EventIndex> {
        match Event::unpack(event, &PeerIndexSet::default(), self.0.event_context_mut())? {
            UnpackedEvent::New(event) => self.0.add_event(event),
            UnpackedEvent::Known(index) => Ok(index),
        }
    }

    // Warning: only add events created using this instance of `Parsec`. Adding an event from other
    // instance is not detectable and might lead to incorrect test results. To add event from other
    // instance, first `pack_event` it using that other instance, then add it using
    // `unpack_and_add_event`.
    pub fn add_event(&mut self, event: Event<S::PublicId>) -> Result<EventIndex> {
        self.0.add_event(event)
    }

    #[cfg(feature = "malice-detection")]
    pub fn our_last_event_index(&self) -> EventIndex {
        unwrap!(self.0.our_last_event_index())
    }

    #[cfg(feature = "malice-detection")]
    pub fn remove_last_event(&mut self) -> Option<(EventIndex, Event<S::PublicId>)> {
        let (event_index, event) = self.graph.remove_last()?;
        let _ = self
            .0
            .meta_election
            .unconsensused_events
            .remove(&event_index);

        Some((event_index, event))
    }

    #[cfg(feature = "malice-detection")]
    pub fn pending_accusations(&self) -> &Accusations<T, S::PublicId> {
        &self.0.pending_accusations
    }

    #[cfg(feature = "malice-detection")]
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) {
        let _ = self.0.peer_list.add_peer(peer_id, state);
    }

    #[cfg(feature = "malice-detection")]
    pub fn restart_consensus(&mut self) -> Result<()> {
        self.0.process_events(0)
    }

    pub fn event_payload(
        &self,
        event: &Event<S::PublicId>,
    ) -> Option<&Observation<T, S::PublicId>> {
        self.0.event_payload(event)
    }

    pub fn event_creator_id(&self, event: &Event<S::PublicId>) -> &S::PublicId {
        unwrap!(self.0.event_creator_id(event))
    }

    #[cfg(feature = "malice-detection")]
    pub fn event_context(&self) -> EventContextRef<T, S> {
        self.0.event_context()
    }

    pub fn event_context_mut(&mut self) -> EventContextMut<T, S> {
        self.0.event_context_mut()
    }
}

#[cfg(all(test, feature = "mock"))]
impl TestParsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        TestParsec(Parsec::from_parsed_contents(parsed_contents))
    }
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> Deref for TestParsec<T, S> {
    type Target = Parsec<T, S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> DerefMut for TestParsec<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Assert that the two parsec instances have the same events modulo their insertion order.
#[cfg(all(test, feature = "testing"))]
pub(crate) fn assert_same_events<T: NetworkEvent, S: SecretId>(a: &Parsec<T, S>, b: &Parsec<T, S>) {
    use crate::gossip::GraphSnapshot;

    let a = GraphSnapshot::new(&a.graph);
    let b = GraphSnapshot::new(&b.graph);

    assert_eq!(a, b)
}
