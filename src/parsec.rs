// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::block::{Block, BlockGroup};
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use crate::dev_utils::ParsedContents;
use crate::dump_graph;
use crate::error::{Error, Result};
#[cfg(all(test, feature = "mock"))]
use crate::gossip::EventHash;
#[cfg(all(test, feature = "testing"))]
use crate::gossip::GraphSnapshot;
use crate::gossip::{
    Event, EventContextRef, EventIndex, Graph, IndexedEventRef, PackedEvent, Request, Response,
};
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use crate::hash::Hash;
use crate::id::{PublicId, SecretId};
use crate::meta_voting::{MetaElection, MetaEvent, MetaEventBuilder, MetaVote, Observer, Step};
#[cfg(any(feature = "testing", all(test, feature = "mock")))]
use crate::mock::{PeerId, Transaction};
use crate::network_event::NetworkEvent;
use crate::observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation, ObservationHash, ObservationKey,
    ObservationStore,
};
use crate::parsec_helpers::find_interesting_content_for_event;
use crate::peer_list::{
    PeerIndex, PeerIndexMap, PeerIndexSet, PeerList, PeerListChange, PeerState,
};
use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
#[cfg(all(test, feature = "mock"))]
use std::ops::{Deref, DerefMut};
use std::usize;

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
    // The Gossip graph.
    graph: Graph<S::PublicId>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: ObservationStore<T, S::PublicId>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<BlockGroup<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_election: MetaElection,
    consensus_mode: ConsensusMode,
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: Accusations<T, S::PublicId>,
    // Events to be inserted into the gossip graph when this node becomes voter.
    pending_events: Vec<PendingEvent<T, S::PublicId>>,
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

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode);
        parsec
            .meta_election
            .initialise_round_hashes(parsec.peer_list.all_ids());

        // Add initial event.
        parsec.add_initial_event();

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let event = parsec.our_last_event_index().and_then(|self_parent| {
            parsec.new_event_from_observation(self_parent, genesis_observation)
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

        let mut parsec = Self::empty(peer_list, genesis_indices, consensus_mode);
        parsec
            .meta_election
            .initialise_round_hashes(parsec.peer_list.all_ids());
        parsec
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        peer_list: PeerList<S>,
        genesis_group: PeerIndexSet,
        consensus_mode: ConsensusMode,
    ) -> Self {
        dump_graph::init();

        Self {
            peer_list,
            graph: Graph::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_election: MetaElection::new(genesis_group),
            consensus_mode,
            pending_accusations: vec![],
            pending_events: vec![],
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

        self.flush_pending_events()?;

        let self_parent = self.our_last_event_index()?;
        let event = self.new_event_from_observation(self_parent, observation)?;

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

    /// Creates a new message to be gossiped to a peer, containing all gossip events this peer
    /// thinks that peer needs.  If the given peer is not an active node, an error is returned.
    ///
    /// * `peer_id`: the intended recipient of the gossip message
    /// * returns a `Request` to be sent to the intended recipient
    pub fn create_gossip(&mut self, peer_id: &S::PublicId) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        let peer_index = self.get_peer_index(peer_id)?;
        // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
        // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
        // adding them to the section so we shouldn't contact them yet.
        self.confirm_peer_state(peer_index, PeerState::VOTE | PeerState::RECV)?;

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        let self_parent = self.peer_list.last_event(PeerIndex::OUR).ok_or_else(|| {
            log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
            Error::Logic
        })?;
        let forking_peers = PeerIndexSet::default();
        let sync_event =
            Event::new_from_requesting(self_parent, peer_id, &forking_peers, self.event_context())?;
        let _ = self.add_event(sync_event)?;

        let events = if self.peer_list.last_event(peer_index).is_some() {
            self.events_to_gossip_to_peer(peer_index)?
        } else {
            self.graph.iter().map(|e| e.inner()).collect()
        };
        self.pack_events(events).map(Request::new)
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
        self.create_sync_event(src_index, true, forking_peers, other_parent)?;
        self.create_accusation_events()?;
        self.flush_pending_events()?;

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
        self.create_sync_event(src_index, false, forking_peers, other_parent)?;
        self.create_accusation_events()?;
        self.flush_pending_events()
    }

    /// Returns the next stable block, if any. The method might need to be called more than once
    /// for the caller to get all the blocks that have been consensused. A `None` value means that
    /// all the blocks consensused so far have already been returned.
    ///
    /// Once the owning peer has been removed from the section (i.e. a block with payload
    /// `Observation::Remove(our_id)` has been made stable), then no further blocks will be
    /// enqueued. So, once `poll()` returns such a block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<BlockGroup<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
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
                    .flatten()
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
        for packed_event in packed_events {
            if let Some(event) = self.unpack(packed_event, &forking_peers)? {
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
        }

        #[cfg(feature = "malice-detection")]
        self.detect_premature_gossip()?;

        Ok(forking_peers)
    }

    fn unpack(
        &mut self,
        packed_event: PackedEvent<T, S::PublicId>,
        forking_peers: &PeerIndexSet,
    ) -> Result<Option<Event<S::PublicId>>> {
        if let Some(unpacked_event) =
            Event::unpack(packed_event, &forking_peers, &self.event_context())?
        {
            if let Some((payload_key, observation_info)) = unpacked_event.observation_for_store {
                let _ = self
                    .observations
                    .entry(payload_key)
                    .or_insert_with(|| observation_info);
            }
            Ok(Some(unpacked_event.event))
        } else {
            Ok(None)
        }
    }

    fn new_event_from_observation(
        &mut self,
        self_parent: EventIndex,
        observation: Observation<T, S::PublicId>,
    ) -> Result<Event<S::PublicId>> {
        let (event, observation_for_store) =
            Event::new_from_observation(self_parent, observation, &self.event_context())?;

        if let Some((payload_key, observation_info)) = observation_for_store {
            let _ = self
                .observations
                .entry(payload_key)
                .or_insert_with(|| observation_info);
        }

        Ok(event)
    }

    fn add_event(&mut self, event: Event<S::PublicId>) -> Result<EventIndex> {
        let our = event.creator() == PeerIndex::OUR;
        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_before_process(&event)?;
        }

        self.peer_list.confirm_can_add_event(&event)?;

        if our && event.is_initial() {
            log_or_panic!(
                "{:?} attempted to add initial event with add_event. It must be added with add_initial_event instead.",
                self.our_pub_id(),
            );
            return Err(Error::InvalidEvent);
        }

        let unconsensused_payload_key = event
            .payload_key()
            .and_then(|key| self.observations.get_mut(key).map(|info| (key, info)))
            .and_then(|(key, info)| {
                if our {
                    info.created_by_us = true;
                }
                if info.consensused {
                    None
                } else {
                    Some(*key)
                }
            });

        let event_index = self.insert_event(event);

        let _ = unconsensused_payload_key.map(|payload_key| {
            self.meta_election
                .add_unconsensused_event(event_index, payload_key);
        });

        self.process_events(event_index.topological_index())?;

        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_after_process(event_index);
        }

        Ok(event_index)
    }

    // Create initial event for this node and insert it into the graph. This must be called when
    // this node becomes voter.
    fn add_initial_event(&mut self) {
        let event = Event::new_initial(self.event_context());
        let _ = self.insert_event(event);
    }

    fn insert_event(&mut self, event: Event<S::PublicId>) -> EventIndex {
        let event = self.graph.insert(event);
        self.peer_list.add_event(event);
        event.event_index()
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

        let payload_keys = self.compute_consensus(event_index);
        if payload_keys.is_empty() {
            return Ok(PostProcessAction::Continue);
        }

        self.output_consensus_info(&payload_keys);

        let blocks = self.create_blocks(&payload_keys)?;
        if !blocks.is_empty() {
            self.consensused_blocks.push_back(blocks);
        }

        self.mark_observations_as_consensused(&payload_keys);

        let peer_list_changes = payload_keys
            .iter()
            .filter_map(|payload_key| self.handle_consensus(payload_key))
            .collect();

        self.meta_election
            .new_election(&self.graph, payload_keys, peer_list_changes);
        self.meta_election
            .initialise_round_hashes(self.peer_list.all_ids());

        // Trigger reprocess.
        let start_index = self.meta_election.continue_consensus_start_index();
        Ok(PostProcessAction::Restart(start_index))
    }

    fn output_consensus_info(&self, payload_keys: &[ObservationKey]) {
        dump_graph::to_file(
            self.our_pub_id(),
            &self.graph,
            &self.meta_election,
            &self.peer_list,
            &self.observations,
            &dump_graph::DumpGraphContext::ConsensusReached,
        );

        for payload_key in payload_keys {
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
    }

    fn mark_observations_as_consensused(&mut self, payload_keys: &[ObservationKey]) {
        for payload_key in payload_keys {
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
    }

    /// Handles consensus reached by us.
    fn handle_consensus(&mut self, payload_key: &ObservationKey) -> Option<PeerListChange> {
        match self
            .observations
            .get(payload_key)
            .map(|info| info.observation.clone())
        {
            Some(Observation::Add { ref peer_id, .. }) => self.handle_add_peer(peer_id).into(),
            Some(Observation::Remove { ref peer_id, .. }) => self.handle_remove_peer(peer_id),
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

                self.handle_remove_peer(offender)
            }
            Some(Observation::Genesis(_)) | Some(Observation::OpaquePayload(_)) => None,
            None => {
                log_or_panic!("Failed to get observation from hash.");
                None
            }
        }
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) -> PeerListChange {
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

        let peer_index = if let Some(peer_index) = self.peer_list.get_index(peer_id) {
            self.peer_list.change_peer_state(peer_index, state);
            peer_index
        } else {
            self.peer_list.add_peer(peer_id.clone(), state)
        };

        if peer_index == PeerIndex::OUR && self.peer_list.our_events().next().is_none() {
            self.add_initial_event();
        }

        PeerListChange::Add(peer_index)
    }

    fn handle_remove_peer(&mut self, peer_id: &S::PublicId) -> Option<PeerListChange> {
        self.peer_list.get_index(peer_id).map(|peer_index| {
            self.peer_list.remove_peer(peer_index);
            PeerListChange::Remove(peer_index)
        })
    }

    fn create_meta_event(&mut self, event_index: EventIndex) -> Result<()> {
        let event = get_known_event(self.our_pub_id(), &self.graph, event_index)?;

        trace!(
            "{:?} creating a meta-event for event {:?}",
            self.our_pub_id(),
            event
        );

        let mut builder =
            if let Some(meta_event) = self.meta_election.remove_meta_event(event_index) {
                meta_event.rebuild(event)
            } else {
                MetaEvent::build(event)
            };

        self.set_interesting_content(&mut builder);
        self.set_observer(&mut builder);
        self.set_meta_votes(&mut builder)?;

        self.meta_election.add_meta_event(builder);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        if !builder.is_new() {
            return;
        }

        let peers_that_can_vote = self.voters();

        let is_already_interesting_content = |payload_key: &ObservationKey| {
            self.meta_election
                .is_already_interesting_content(builder.event().creator(), payload_key)
        };

        let is_interesting_payload = |payload_key: &ObservationKey| {
            self.is_interesting_payload(builder, &peers_that_can_vote, payload_key)
        };

        let has_interesting_ancestor =
            |payload_key: &ObservationKey| self.has_interesting_ancestor(builder, payload_key);

        let payloads = find_interesting_content_for_event(
            builder.event().as_ref(),
            self.unconsensused_events(None).map(|event| event.inner()),
            is_already_interesting_content,
            is_interesting_payload,
            has_interesting_ancestor,
        );

        builder.set_interesting_content(payloads);
    }

    // Returns true if `builder.event()` has an ancestor by a different creator that has `payload`
    // in interesting content
    fn has_interesting_ancestor(
        &self,
        builder: &MetaEventBuilder<S::PublicId>,
        payload_key: &ObservationKey,
    ) -> bool {
        let start_index = self.meta_election.new_consensus_start_index();

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
        let num_peers_that_did_vote = || {
            self.num_creators_of_ancestors_carrying_payload(
                peers_that_can_vote,
                &*builder.event(),
                payload_key,
            )
        };

        match payload_key.consensus_mode() {
            ConsensusMode::Single => {
                let num_ancestor_peers =
                    self.num_creators_of_ancestors(peers_that_can_vote, &*builder.event());
                is_more_than_two_thirds(num_ancestor_peers, peers_that_can_vote.len())
                    && num_peers_that_did_vote() > 0
            }
            ConsensusMode::Supermajority => {
                is_more_than_two_thirds(num_peers_that_did_vote(), peers_that_can_vote.len())
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
        let unconsensused_events = self
            .unconsensused_events(Some(payload_key))
            .map(|that_event| that_event.inner())
            .collect_vec();

        peers_that_can_vote
            .iter()
            .filter(|peer_index| {
                unconsensused_events
                    .iter()
                    .any(|that_event| that_event.creator() == *peer_index && event.sees(that_event))
            })
            .count()
    }

    fn set_observer(&self, builder: &mut MetaEventBuilder<S::PublicId>) {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.

        if self.is_descendant_of_observer(builder.event()) {
            builder.set_observer(Observer::Ancestor);
            return;
        }

        let voter_count = self.voter_count();
        let observees: PeerIndexSet = self
            .meta_election
            .interesting_events()
            .filter_map(|(peer_index, event_indices)| {
                let event_index = event_indices.first()?;
                let event = self.get_known_event(*event_index).ok()?;
                if self.strongly_sees(builder.event(), event) {
                    Some(peer_index)
                } else {
                    None
                }
            })
            .collect();

        if is_more_than_two_thirds(observees.len(), voter_count) {
            builder.set_observer(Observer::This(observees));
        } else {
            builder.set_observer(Observer::None);
        }
    }

    fn is_descendant_of_observer(&self, event: IndexedEventRef<S::PublicId>) -> bool {
        self.graph
            .self_parent(event)
            .and_then(|self_parent| self.meta_election.meta_event(self_parent.event_index()))
            .map(|meta_parent| meta_parent.is_observer() || meta_parent.has_ancestor_observer())
            .unwrap_or(false)
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<S::PublicId>) -> Result<()> {
        let parent_meta_votes = builder
            .event()
            .self_parent()
            .and_then(|parent_hash| self.meta_election.populated_meta_votes(parent_hash));

        if parent_meta_votes.is_none() && !builder.is_observer() {
            // No meta votes to set for this event
            return Ok(());
        }

        let voters = self.voters();
        let is_voter = voters.contains(builder.event().creator());
        let ancestors_meta_votes =
            self.other_voting_ancestors_meta_votes(&voters, &builder.event());

        if let Some(parent_meta_votes) = parent_meta_votes {
            // Parent has meta votes: Derive this event's meta votes from them.
            for (peer_index, parent_event_votes) in parent_meta_votes {
                let new_meta_votes = {
                    let other_votes = Self::peer_meta_votes(&ancestors_meta_votes, peer_index);
                    let coin_tosses =
                        self.toss_coins(&voters, peer_index, &parent_event_votes, builder.event())?;
                    MetaVote::next(
                        &parent_event_votes,
                        &other_votes,
                        &coin_tosses,
                        voters.len(),
                        is_voter,
                    )
                };

                builder.add_meta_votes(peer_index, new_meta_votes);
            }
        } else {
            // Start meta votes for this observer event.
            for peer_index in voters {
                let new_meta_votes = {
                    let other_votes = Self::peer_meta_votes(&ancestors_meta_votes, peer_index);
                    let initial_estimate = builder.has_observee(peer_index);

                    MetaVote::new(initial_estimate, &other_votes, voters.len(), is_voter)
                };

                builder.add_meta_votes(peer_index, new_meta_votes);
            }
        }

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
            hashes[round].value()
        } else {
            log_or_panic!("{:?} missing round hash.", self.our_pub_id());
            return Err(Error::Logic);
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes: Vec<_> = self
            .peer_list
            .all_id_hashes()
            .filter(|(peer_index, _)| voters.contains(*peer_index))
            .collect();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.1, &rhs.1));

        // Try to get the "most-leader"'s aux value.
        let creator = peer_id_hashes[0].0;
        if let Some(creator_event_index) = event.last_ancestors().get(creator) {
            if let Some(aux_value) =
                self.aux_value(creator, *creator_event_index, peer_index, round)
            {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(round, event) {
            for (creator, _) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(*creator) {
                    if let Some(aux_value) =
                        self.aux_value(*creator, *creator_event_index, peer_index, round)
                    {
                        return Ok(Some(aux_value));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // the genuine flip step.
    fn aux_value(
        &self,
        creator: PeerIndex,
        creator_event_index: usize,
        peer_index: PeerIndex,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_by_creator(creator, creator_event_index)
            .and_then(|meta_votes| meta_votes.get(peer_index))
            .and_then(|votes| {
                votes
                    .iter()
                    .find(|meta_vote| meta_vote.round_and_step() >= (round, Step::GenuineFlip))
            })
            .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through events created by the peer until passed `responsiveness_threshold`
    // response events and sees if the peer had its `aux_value` set at this round.  If so, returns
    // `true`.
    fn stop_waiting(&self, round: usize, event: IndexedEventRef<S::PublicId>) -> bool {
        let mut event_index = Some(event.event_index());
        let mut response_count = 0;
        let responsiveness_threshold = self.responsiveness_threshold();

        loop {
            if let Some(event) = event_index.and_then(|index| self.get_known_event(index).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == responsiveness_threshold {
                        break;
                    }
                }
                event_index = event.self_parent();
            } else {
                return false;
            }
        }
        let event_index = match event_index {
            Some(index) => index,
            None => {
                log_or_panic!("{:?} event_index was None.", self.our_pub_id());
                return false;
            }
        };
        self.meta_election
            .populated_meta_votes(event_index)
            .and_then(|meta_votes| meta_votes.get(event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes created by `creator`.
    fn meta_votes_by_creator(
        &self,
        creator: PeerIndex,
        creator_event_index: usize,
    ) -> Option<&PeerIndexMap<Vec<MetaVote>>> {
        let (event, fork_event) = {
            let mut events = self.peer_list.events_by_index(creator, creator_event_index);
            (events.next(), events.next())
        };

        if fork_event.is_none() {
            // Not a fork
            if let Some(event) = event {
                return self.meta_election.populated_meta_votes(event);
            }
        }
        None
    }

    // Returns all the meta votes from the event's voting ancestors except the event's creator.
    fn other_voting_ancestors_meta_votes(
        &self,
        voters: &PeerIndexSet,
        event: &Event<S::PublicId>,
    ) -> Vec<&PeerIndexMap<Vec<MetaVote>>> {
        voters
            .iter()
            .filter(|voter_index| *voter_index != event.creator())
            .filter_map(|creator| {
                event
                    .last_ancestors()
                    .get(creator)
                    .and_then(|creator_event_index| {
                        self.meta_votes_by_creator(creator, *creator_event_index)
                    })
            })
            .collect()
    }

    // Collect the vectors of meta votes for the peer
    fn peer_meta_votes<'a>(
        meta_votes_maps: &'a [&PeerIndexMap<Vec<MetaVote>>],
        peer_index: PeerIndex,
    ) -> Vec<&'a [MetaVote]> {
        meta_votes_maps
            .iter()
            .filter_map(|meta_votes| meta_votes.get(peer_index))
            .map(|meta_votes| meta_votes.as_slice())
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

    fn unconsensused_events(
        &self,
        filter_key: Option<&ObservationKey>,
    ) -> impl Iterator<Item = IndexedEventRef<S::PublicId>> {
        self.meta_election
            .unconsensused_events(filter_key)
            .filter_map(move |index| self.get_known_event(index).ok())
    }

    fn compute_consensus(&self, event_index: EventIndex) -> Vec<ObservationKey> {
        let last_meta_votes = match self.meta_election.populated_meta_votes(event_index) {
            Some(meta_votes) => meta_votes,
            None => return Vec::new(),
        };

        let decided_meta_votes = last_meta_votes
            .iter()
            .filter_map(|(peer_index, event_votes)| {
                event_votes
                    .last()
                    .and_then(|v| v.decision)
                    .map(|v| (peer_index, v))
            });

        if decided_meta_votes.clone().count() < self.voter_count() {
            return Vec::new();
        }

        self.compute_payloads_for_consensus(decided_meta_votes)
    }

    fn compute_payloads_for_consensus<I>(&self, decided_meta_votes: I) -> Vec<ObservationKey>
    where
        I: IntoIterator<Item = (PeerIndex, bool)>,
    {
        use fnv::FnvHashSet;

        let mut payload_iters = decided_meta_votes
            .into_iter()
            .filter_map(|(peer_index, decision)| {
                if decision {
                    self.meta_election.interesting_content_by(peer_index)
                } else {
                    None
                }
            })
            .map(|payload_keys| payload_keys.iter())
            .collect_vec();

        let mut all_payloads = Vec::new();
        let mut all_payload_lookup: FnvHashSet<&ObservationKey> = FnvHashSet::default();
        loop {
            let payloads_counts = payload_iters
                .iter_mut()
                .filter_map(|iter| iter.find(|key| !all_payload_lookup.contains(key)))
                .fold(BTreeMap::new(), |mut map, payload_key| {
                    *map.entry(payload_key).or_insert(0) += 1;
                    map
                });

            if payloads_counts.is_empty()
            {
                break;
            }

            let new_payloads = payloads_counts
                .into_iter()
                .sorted_by(|(lhs_key, lhs_count), (rhs_key, rhs_count)| {
                    lhs_count
                        .cmp(rhs_count)
                        .reverse()
                        .then_with(|| lhs_key.consistent_cmp(rhs_key, &self.peer_list))
                })
                .map(|(key, _)| key)
                .collect_vec();
            all_payloads.extend(new_payloads.iter().cloned());
            all_payload_lookup.extend(new_payloads.iter());
        }

        all_payloads
    }

    fn create_blocks(&self, payload_keys: &[ObservationKey]) -> Result<BlockGroup<T, S::PublicId>> {
        let voters = self.voters();
        let blocks: Result<Vec<_>> = payload_keys
            .iter()
            .map(|payload_key| {
                let votes = self
                    .graph
                    .iter()
                    .map(|event| event.inner())
                    .filter(|event| voters.contains(event.creator()))
                    .filter(|event| event.payload_key() == Some(payload_key))
                    .filter_map(|event| {
                        let (vote, key) = event.vote_and_payload_key(&self.observations)?;
                        let creator_id =
                            self.peer_list.get(event.creator()).map(|peer| peer.id())?;
                        Some((key, vote, creator_id))
                    })
                    .map(|(_, vote, creator_id)| (creator_id.clone(), vote.clone()))
                    .collect();

                Block::new(&votes)
            })
            .filter(|block| match block {
                Err(Error::MissingVotes) => false,
                Err(_) | Ok(_) => true,
            })
            .collect();

        Ok(BlockGroup(blocks?))
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
        forking_peers: PeerIndexSet,
        opt_other_parent: Option<EventIndex>,
    ) -> Result<()> {
        let other_parent = self.other_parent_for_sync_event(src_index, opt_other_parent)?;

        if self.peer_list.last_event(PeerIndex::OUR).is_none() {
            self.pending_events.push(PendingEvent::Sync {
                is_request,
                other_parent,
                forking_peers,
            });
            return Ok(());
        };

        self.add_sync_event(is_request, other_parent, &forking_peers)
    }

    fn add_sync_event(
        &mut self,
        is_request: bool,
        other_parent: EventIndex,
        forking_peers: &PeerIndexSet,
    ) -> Result<()> {
        let self_parent = self.our_last_event_index()?;
        let event = if is_request {
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

        let _ = self.add_event(event)?;
        Ok(())
    }

    fn other_parent_for_sync_event(
        &self,
        src_index: PeerIndex,
        opt_other_parent: Option<EventIndex>,
    ) -> Result<EventIndex> {
        match opt_other_parent {
            Some(index) => Ok(index),
            None => self.peer_list.last_event(src_index).ok_or_else(|| {
                log_or_panic!(
                    "{:?} missing last event index of {:?}.",
                    self.our_pub_id(),
                    src_index
                );
                Error::Logic
            }),
        }
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

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self) -> usize {
        (self.voter_count() as f64).log2().ceil() as usize
    }

    fn create_accusation_events(&mut self) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice)?;
        }

        Ok(())
    }

    fn create_accusation_event(
        &mut self,
        offender: PeerIndex,
        malice: Malice<T, S::PublicId>,
    ) -> Result<()> {
        if self.peer_list.last_event(PeerIndex::OUR).is_none() {
            self.pending_events
                .push(PendingEvent::Accusation { offender, malice });
            return Ok(());
        }

        self.add_accusation_event(offender, malice)
    }

    fn add_accusation_event(
        &mut self,
        offender: PeerIndex,
        malice: Malice<T, S::PublicId>,
    ) -> Result<()> {
        let offender = self.peer_list.get_known(offender)?.id().clone();
        let event = self.new_event_from_observation(
            self.our_last_event_index()?,
            Observation::Accusation { offender, malice },
        )?;

        let _ = self.add_event(event)?;
        Ok(())
    }

    fn flush_pending_events(&mut self) -> Result<()> {
        // Insert the pending events only if we already have the initial event, which means we are
        // voter.
        if self.peer_list.our_events().next().is_none() {
            return Ok(());
        }

        for event in mem::replace(&mut self.pending_events, vec![]) {
            match event {
                PendingEvent::Sync {
                    is_request,
                    other_parent,
                    forking_peers,
                } => self.add_sync_event(is_request, other_parent, &forking_peers)?,
                PendingEvent::Accusation { offender, malice } => {
                    self.add_accusation_event(offender, malice)?
                }
            }
        }

        Ok(())
    }

    fn event_context(&self) -> EventContextRef<T, S> {
        EventContextRef {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &self.observations,
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
        if self.is_first_fork(event) {
            if let Some(self_parent_hash) = self.graph.self_parent(event).map(|event| *event.hash())
            {
                self.accuse(event.creator(), Malice::Fork(self_parent_hash));
            }
        }
    }

    fn is_first_fork(&self, event: &Event<S::PublicId>) -> bool {
        let same_index_events = self
            .peer_list
            .events_by_index(event.creator(), event.index_by_creator());
        // Having no event with the same index means no fork, meanwhile multiple and having the same
        // self_parent means already cast forking accusation.
        same_index_events
            .filter_map(|other_event| self.graph.get(other_event))
            .filter(|other_event| other_event.inner().self_parent() == event.self_parent())
            .count()
            == 1
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
            | Malice::Accomplice(hash, _) => self
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
            .filter(|(_, malice)| {
                !self.pending_accusations.iter().any(|(off, mal)| match mal {
                    Malice::Accomplice(_, ori_mal) => off == &creator && &**ori_mal == malice,
                    _ => false,
                })
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
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        dump_graph::to_file(
            self.our_pub_id(),
            &self.graph,
            &self.meta_election,
            &self.peer_list,
            &self.observations,
            &dump_graph::DumpGraphContext::DroppingParsec,
        );
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

enum PendingEvent<T: NetworkEvent, P: PublicId> {
    Sync {
        is_request: bool,
        other_parent: EventIndex,
        forking_peers: PeerIndexSet,
    },
    Accusation {
        offender: PeerIndex,
        malice: Malice<T, P>,
    },
}

#[cfg(any(feature = "testing", all(test, feature = "mock")))]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(mut parsed_contents: ParsedContents) -> Self {
        let peer_list = PeerList::new(parsed_contents.our_id);
        let mut parsec = Parsec::empty(
            peer_list,
            PeerIndexSet::default(),
            ConsensusMode::Supermajority,
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

    /// The consensus history hashes in order of consensus (for testing)
    pub fn meta_election_consensus_history_hash(&self) -> Vec<Hash> {
        self.meta_election
            .consensus_history
            .iter()
            .map(|observation| observation.hash().0)
            .collect()
    }
}

/// Wrapper around `Parsec` that exposes additional functionality useful for testing.
#[cfg(all(test, feature = "mock"))]
pub(crate) struct TestParsec<T: NetworkEvent, S: SecretId>(Parsec<T, S>);

#[cfg(all(test, feature = "mock"))]
impl<T: NetworkEvent, S: SecretId> TestParsec<T, S> {
    pub fn from_genesis(our_id: S, genesis_group: &BTreeSet<S::PublicId>) -> Self {
        TestParsec(Parsec::from_genesis(
            our_id,
            genesis_group,
            ConsensusMode::Supermajority,
        ))
    }

    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
    ) -> Self {
        TestParsec(Parsec::from_existing(
            our_id,
            genesis_group,
            section,
            ConsensusMode::Supermajority,
        ))
    }

    pub fn graph(&self) -> &Graph<S::PublicId> {
        &self.0.graph
    }

    pub fn peer_list(&self) -> &PeerList<S> {
        &self.0.peer_list
    }

    pub fn meta_election(&self) -> &MetaElection {
        &self.meta_election
    }

    pub fn consensused_blocks(&self) -> impl Iterator<Item = &Block<T, S::PublicId>> {
        self.0.consensused_blocks.iter().flatten()
    }

    pub fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: PeerIndexSet,
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
        packed_event: PackedEvent<T, S::PublicId>,
    ) -> Result<EventIndex> {
        match self.0.unpack(packed_event, &PeerIndexSet::default())? {
            Some(event) => self.0.add_event(event),
            None => Err(Error::Logic),
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
        assert_eq!(
            event_index,
            unwrap!(self.peer_list.remove_last_event(event.creator()))
        );

        if let Some(payload_key) = event.payload_key() {
            let _ = self
                .0
                .meta_election
                .unconsensused_events
                .ordered_indices
                .remove(&event_index);
            let _ = self
                .0
                .meta_election
                .unconsensused_events
                .indices_by_key
                .get_mut(payload_key)
                .map(|indices| indices.remove(&event_index));
        }

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

    pub fn new_event_from_observation(
        &mut self,
        self_parent: EventIndex,
        observation: Observation<T, S::PublicId>,
    ) -> Result<Event<S::PublicId>> {
        self.0.new_event_from_observation(self_parent, observation)
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

/// Get the parsec graph snapshot with inserted events out of order.
#[cfg(all(test, feature = "testing"))]
pub(crate) fn get_graph_snapshot<T: NetworkEvent, S: SecretId>(
    parsec: &Parsec<T, S>,
    ignore_last_events: usize,
) -> GraphSnapshot {
    GraphSnapshot::new_with_ignore(&parsec.graph, ignore_last_events)
}
