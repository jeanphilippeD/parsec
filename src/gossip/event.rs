// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
use super::graph::IndexedEventRef;
use super::{
    cause::{other_parent_hash, self_parent_hash, Cause},
    content::Content,
    event_context::EventContextRef,
    event_hash::EventHash,
    graph::{EventIndex, Graph},
    packed_event::PackedEvent,
};
use crate::error::Error;
use crate::hash::Hash;
use crate::id::{PublicId, SecretId};
#[cfg(any(test, feature = "testing"))]
use crate::mock::{PeerId, Transaction};
use crate::network_event::NetworkEvent;
use crate::observation::{Observation, ObservationForStore, ObservationKey, ObservationStore};
use crate::peer_list::{PeerIndex, PeerIndexMap, PeerIndexSet, PeerList};
use crate::serialise;
use crate::vote::{Vote, VoteKey};
use std::cmp;
#[cfg(any(test, feature = "testing"))]
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Display, Formatter};

/// Provide a small interface to Event not dependent on PublicId. Serves as a test seam.
pub(crate) trait AbstractEvent {
    /// Returns whether this event can see `other`, i.e. whether there's a directed path from `other`
    /// to `self` in the graph, and no two events created by `other`'s creator are ancestors to
    /// `self` (fork).
    fn sees<E: AsRef<Self>>(&self, other: E) -> bool
    where
        Self: Sized;

    /// The vote payload_key for an Observation event
    fn payload_key(&self) -> Option<&ObservationKey>
    where
        Self: Sized;

    /// The PeerIndex for this event creator
    fn creator(&self) -> PeerIndex
    where
        Self: Sized;

    /// Whether we have seen any forking peers
    fn sees_fork(&self) -> bool
    where
        Self: Sized;

    // Index of this event relative to other events by the same creator.
    fn index_by_creator(&self) -> usize
    where
        Self: Sized;
}

pub(crate) struct Event<P: PublicId> {
    content: Content<VoteKey<P>, EventIndex, PeerIndex>,
    // Creator's signature of `content`.
    signature: P::Signature,
    cache: Cache,
}

impl<P: PublicId> Event<P> {
    // Creates a new event as the result of receiving a gossip request message.
    pub fn new_from_request<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        other_parent: EventIndex,
        forking_peers: &PeerIndexSet,
        ctx: EventContextRef<T, S>,
    ) -> Result<Self, Error> {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Request {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                other_parent: other_parent_hash(ctx.graph, other_parent)?,
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());

        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Request {
                self_parent,
                other_parent,
            },
        };

        Ok(Self::new(
            hash,
            signature,
            content,
            ctx.graph,
            ctx.peer_list,
            forking_peers,
        ))
    }

    // Creates a new event as the result of receiving a gossip response message.
    pub fn new_from_response<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        other_parent: EventIndex,
        forking_peers: &PeerIndexSet,
        ctx: EventContextRef<T, S>,
    ) -> Result<Self, Error> {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Response {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                other_parent: other_parent_hash(ctx.graph, other_parent)?,
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());

        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Response {
                self_parent,
                other_parent,
            },
        };

        Ok(Self::new(
            hash,
            signature,
            content,
            ctx.graph,
            ctx.peer_list,
            forking_peers,
        ))
    }

    // Creates a new event as the result of observing a network event.
    pub fn new_from_observation<T: NetworkEvent, S: SecretId<PublicId = P>>(
        self_parent: EventIndex,
        observation: Observation<T, P>,
        ctx: &EventContextRef<T, S>,
    ) -> Result<(Self, ObservationForStore<T, P>), Error> {
        // Compute event hash + signature.
        let vote = Vote::new(ctx.peer_list.our_id(), observation);
        let content = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Observation {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                vote,
            },
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());
        let graph = ctx.graph;
        let peer_list = ctx.peer_list;
        let (content, observation_for_store) = Content::unpack(content, ctx)?;

        Ok((
            Self::new(
                hash,
                signature,
                content,
                graph,
                peer_list,
                &PeerIndexSet::default(),
            ),
            observation_for_store,
        ))
    }

    // Creates an initial event.  This is the first event by its creator in the graph.
    pub fn new_initial<T: NetworkEvent, S: SecretId<PublicId = P>>(
        ctx: EventContextRef<T, S>,
    ) -> Self {
        let content: Content<Vote<T, _>, _, _> = Content {
            creator: ctx.peer_list.our_pub_id().clone(),
            cause: Cause::Initial,
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, ctx.peer_list.our_id());

        let content = Content {
            creator: PeerIndex::OUR,
            cause: Cause::Initial,
        };

        Self::new(
            hash,
            signature,
            content,
            ctx.graph,
            ctx.peer_list,
            &PeerIndexSet::default(),
        )
    }

    fn new<S: SecretId<PublicId = P>>(
        hash: EventHash,
        signature: P::Signature,
        content: Content<VoteKey<P>, EventIndex, PeerIndex>,
        graph: &Graph<P>,
        peer_list: &PeerList<S>,
        forking_peers: &PeerIndexSet,
    ) -> Self {
        let cache = Cache::new(hash, &content, graph, peer_list, forking_peers);
        Self {
            content,
            signature,
            cache,
        }
    }

    // Creates an event from a `PackedEvent`.
    //
    // Returns:
    //   - `Ok(None)` if the event already exists
    //   - `Err(Error::SignatureFailure)` if signature validation fails
    //   - `Err(Error::UnknownParent)` if the event indicates it should have an ancestor, but the
    //     ancestor isn't in `events`.
    pub(crate) fn unpack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        packed_event: PackedEvent<T, P>,
        forking_peers: &PeerIndexSet,
        ctx: &EventContextRef<T, S>,
    ) -> Result<UnpackedEvent<T, P>, Error> {
        let hash = compute_event_hash_and_verify_signature(
            &packed_event.content,
            &packed_event.signature,
        )?;

        if let Some(index) = ctx.graph.get_index(&hash) {
            return Ok(UnpackedEvent::Known(index));
        }

        let graph = ctx.graph;
        let peer_list = ctx.peer_list;
        let (content, observation_for_store) = Content::unpack(packed_event.content, ctx)?;
        let cache = Cache::new(hash, &content, graph, peer_list, forking_peers);

        Ok(UnpackedEvent::New(
            Self {
                content,
                signature: packed_event.signature,
                cache,
            },
            observation_for_store,
        ))
    }

    // Creates a `PackedEvent` from this `Event`.
    pub(crate) fn pack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        &self,
        ctx: EventContextRef<T, S>,
    ) -> Result<PackedEvent<T, P>, Error> {
        Ok(PackedEvent {
            content: self.content.pack(ctx)?,
            signature: self.signature.clone(),
        })
    }

    // Returns whether this event can see `other`, i.e. whether there's a directed path from `other`
    // to `self` in the graph, and no two events created by `other`'s creator are ancestors to
    // `self` (fork).
    pub fn sees<E: AsRef<Event<P>>>(&self, other: E) -> bool {
        self.is_descendant_of(other).unwrap_or(false)
    }

    // Returns whether this event is descendant of `other`. If there are forks between this event
    // and `other` the answer cannot be determined from the events themselves and graph traversal
    // is required. `None` is returned in that case. Otherwise returns `Some` with the correct
    // answer.
    pub fn is_descendant_of<E: AsRef<Event<P>>>(&self, other: E) -> Option<bool> {
        match self.last_ancestor_by(other.as_ref().creator()) {
            LastAncestor::Some(last_index) => Some(last_index >= other.as_ref().index_by_creator()),
            LastAncestor::None => Some(false),
            LastAncestor::Fork => None,
        }
    }

    // Returns the index-by-creator of the last ancestor of this event created by the given peer.
    pub fn last_ancestor_by(&self, peer_index: PeerIndex) -> LastAncestor {
        if self.is_forking_peer(peer_index) {
            LastAncestor::Fork
        } else {
            self.cache
                .last_ancestors
                .get(peer_index)
                .map(|last_index| LastAncestor::Some(*last_index))
                .unwrap_or(LastAncestor::None)
        }
    }

    pub(crate) fn is_forking_peer(&self, peer_index: PeerIndex) -> bool {
        self.cache.forking_peers.contains(peer_index)
    }

    pub fn payload_key(&self) -> Option<&ObservationKey> {
        match self.content.cause {
            Cause::Observation { ref vote, .. } => Some(vote.payload_key()),
            _ => None,
        }
    }

    pub fn vote_and_payload_key<T: NetworkEvent>(
        &self,
        observations: &ObservationStore<T, P>,
    ) -> Option<(Vote<T, P>, ObservationKey)> {
        match self.content.cause {
            Cause::Observation { ref vote, .. } => {
                let key = *vote.payload_key();
                let vote = vote.resolve(observations).ok()?;

                Some((vote, key))
            }
            _ => None,
        }
    }

    pub fn creator(&self) -> PeerIndex {
        self.content.creator
    }

    pub fn self_parent(&self) -> Option<EventIndex> {
        self.content.self_parent().cloned()
    }

    pub fn other_parent(&self) -> Option<EventIndex> {
        self.content.other_parent().cloned()
    }

    pub fn hash(&self) -> &EventHash {
        &self.cache.hash
    }

    // Index of this event relative to other events by the same creator.
    pub fn index_by_creator(&self) -> usize {
        self.cache.index_by_creator
    }

    pub fn last_ancestors(&self) -> &PeerIndexMap<usize> {
        &self.cache.last_ancestors
    }

    pub fn is_request(&self) -> bool {
        if let Cause::Request { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn is_response(&self) -> bool {
        if let Cause::Response { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn is_initial(&self) -> bool {
        if let Cause::Initial = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn sees_fork(&self) -> bool {
        !self.cache.forking_peers.is_empty()
    }

    /// Returns the first char of the creator's ID, followed by an underscore and the event's index.
    #[cfg(any(test, feature = "testing"))]
    pub fn short_name(&self) -> ShortName {
        ShortName {
            creator_initial: self.cache.creator_initial,
            index_by_creator: self.cache.index_by_creator,
        }
    }

    #[cfg(feature = "dump-graphs")]
    pub fn cause(&self) -> &Cause<VoteKey<P>, EventIndex> {
        &self.content.cause
    }
}

impl<P: PublicId> AbstractEvent for Event<P> {
    fn sees<E: AsRef<Self>>(&self, other: E) -> bool {
        self.sees(other)
    }

    fn payload_key(&self) -> Option<&ObservationKey> {
        self.payload_key()
    }

    fn creator(&self) -> PeerIndex {
        self.creator()
    }

    fn sees_fork(&self) -> bool {
        self.sees_fork()
    }

    fn index_by_creator(&self) -> usize {
        self.index_by_creator()
    }
}

impl<P: PublicId> PartialEq for Event<P> {
    fn eq(&self, other: &Self) -> bool {
        self.content == other.content && self.signature == other.signature
    }
}

impl<P: PublicId> Eq for Event<P> {}

impl<P: PublicId> Debug for Event<P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Event{{")?;

        #[cfg(any(test, feature = "testing"))]
        write!(formatter, " {}", self.short_name())?;

        write!(formatter, " {:?}", self.hash())?;
        write!(formatter, ", {:?}", self.content.cause)?;
        write!(
            formatter,
            ", self_parent: {:?}, other_parent: {:?}",
            self.content.self_parent(),
            self.content.other_parent()
        )?;
        write!(
            formatter,
            ", last_ancestors: {:?}",
            self.cache.last_ancestors
        )?;
        write!(formatter, " }}")
    }
}

impl<P: PublicId> AsRef<Self> for Event<P> {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[cfg(any(test, feature = "testing"))]
impl Event<PeerId> {
    // Creates a new event using the input parameters directly.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_from_dot_input(
        creator: &PeerId,
        cause: CauseInput,
        self_parent: Option<(EventIndex, EventHash)>,
        other_parent: Option<(EventIndex, EventHash)>,
        index_by_creator: usize,
        last_ancestors: BTreeMap<PeerId, usize>,
        peer_list: &PeerList<PeerId>,
        observations: &mut ObservationStore<Transaction, PeerId>,
    ) -> Self {
        let cause = Cause::new_from_dot_input(
            cause,
            creator,
            self_parent.map(|(_, h)| h),
            other_parent.map(|(_, h)| h),
        );
        let content = Content {
            creator: creator.clone(),
            cause,
        };
        let (hash, signature) = compute_event_hash_and_signature(&content, creator);

        let creator = unwrap!(peer_list.get_index(creator));
        let cause = Cause::unpack_from_dot_input(
            content.cause,
            creator,
            self_parent.map(|(i, _)| i),
            other_parent.map(|(i, _)| i),
            observations,
        );
        let content = Content { creator, cause };

        let last_ancestors = last_ancestors
            .into_iter()
            .map(|(peer_id, index_by_creator)| {
                (unwrap!(peer_list.get_index(&peer_id)), index_by_creator)
            })
            .collect();

        let cache = Cache {
            hash,
            index_by_creator,
            last_ancestors,
            forking_peers: PeerIndexSet::default(),
            creator_initial: get_creator_initial(peer_list, creator),
        };

        Self {
            content,
            signature,
            cache,
        }
    }
}

#[derive(Debug)]
pub(crate) enum UnpackedEvent<T: NetworkEvent, P: PublicId> {
    // Event is already in our gossip graph
    Known(EventIndex),
    // Event is not yet in our gossip graph
    New(Event<P>, ObservationForStore<T, P>),
}

impl<T: NetworkEvent, P: PublicId> UnpackedEvent<T, P> {
    pub fn take_observation(&mut self) -> ObservationForStore<T, P> {
        match self {
            UnpackedEvent::New(_, observation) => observation.take(),
            UnpackedEvent::Known(_) => None,
        }
    }
}

pub(crate) enum LastAncestor {
    // There are no forks and the ancestor exists.
    Some(usize),
    // Ancestor doesn't exist.
    None,
    // Fork detected. Ancestor cannot be determined from the events only. Graph traversal required.
    Fork,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub(crate) enum CauseInput {
    Initial,
    Request,
    Response,
    Observation(Observation<Transaction, PeerId>),
}

// Properties of `Event` that can be computed from its `Content`.
struct Cache {
    // Hash of `Event`s `Content`.
    hash: EventHash,
    // Index of this event relative to other events by the same creator.
    index_by_creator: usize,
    // Index of each peer's latest event that is an ancestor of this event.
    last_ancestors: PeerIndexMap<usize>,
    // Peers with a fork having both sides seen by this event.
    forking_peers: PeerIndexSet,
    // First leter of the creator name.
    #[cfg(any(test, feature = "testing"))]
    creator_initial: char,
}

impl Cache {
    fn new<S: SecretId>(
        hash: EventHash,
        content: &Content<VoteKey<S::PublicId>, EventIndex, PeerIndex>,
        graph: &Graph<S::PublicId>,
        peer_list: &PeerList<S>,
        forking_peers: &PeerIndexSet,
    ) -> Self {
        let self_parent = content.self_parent().and_then(|index| graph.get(*index));
        let other_parent = content.other_parent().and_then(|index| graph.get(*index));

        let (index_by_creator, last_ancestors) = index_by_creator_and_last_ancestors(
            content.creator,
            self_parent.map(|e| e.inner()),
            other_parent.map(|e| e.inner()),
            peer_list,
        );
        let forking_peers = join_forking_peers(
            self_parent.map(|e| e.inner()),
            other_parent.map(|e| e.inner()),
            forking_peers,
        );

        Self {
            hash,
            index_by_creator,
            last_ancestors,
            forking_peers,
            #[cfg(any(test, feature = "testing"))]
            creator_initial: get_creator_initial(peer_list, content.creator),
        }
    }
}

fn index_by_creator_and_last_ancestors<S: SecretId>(
    creator: PeerIndex,
    self_parent: Option<&Event<S::PublicId>>,
    other_parent: Option<&Event<S::PublicId>>,
    peer_list: &PeerList<S>,
) -> (usize, PeerIndexMap<usize>) {
    let (index_by_creator, mut last_ancestors) = if let Some(self_parent) = self_parent {
        (
            self_parent.index_by_creator() + 1,
            self_parent.last_ancestors().clone(),
        )
    } else {
        // Initial event
        (0, PeerIndexMap::default())
    };

    if let Some(other_parent) = other_parent {
        for (peer_index, _) in peer_list.iter() {
            if let Some(other_index) = other_parent.last_ancestors().get(peer_index) {
                let existing_index = last_ancestors.entry(peer_index).or_insert(*other_index);
                *existing_index = cmp::max(*existing_index, *other_index);
            }
        }
    }

    let _ = last_ancestors.insert(creator, index_by_creator);

    (index_by_creator, last_ancestors)
}

// An event's forking_peers list is a union inherited from its self_parent and other_parent.
// The event shall only put forking peer into the list when have direct path to both sides of
// the fork.
fn join_forking_peers<P: PublicId>(
    self_parent: Option<&Event<P>>,
    other_parent: Option<&Event<P>>,
    prev_forking_peers: &PeerIndexSet,
) -> PeerIndexSet {
    let mut forking_peers = PeerIndexSet::default();
    forking_peers.extend(
        self_parent
            .into_iter()
            .flat_map(|parent| parent.cache.forking_peers.iter()),
    );
    forking_peers.extend(
        other_parent
            .into_iter()
            .flat_map(|parent| parent.cache.forking_peers.iter()),
    );
    forking_peers.extend(prev_forking_peers.iter());
    forking_peers
}

fn compute_event_hash_and_signature<T: NetworkEvent, S: SecretId>(
    content: &Content<Vote<T, S::PublicId>, EventHash, S::PublicId>,
    our_id: &S,
) -> (EventHash, <S::PublicId as PublicId>::Signature) {
    let serialised_content = serialise(&content);
    let hash = EventHash(Hash::from(serialised_content.as_slice()));
    let signature = our_id.sign_detached(&serialised_content);

    (hash, signature)
}

fn compute_event_hash_and_verify_signature<T: NetworkEvent, P: PublicId>(
    content: &Content<Vote<T, P>, EventHash, P>,
    signature: &P::Signature,
) -> Result<EventHash, Error> {
    let serialised_content = serialise(content);
    if content
        .creator
        .verify_signature(signature, &serialised_content)
    {
        Ok(EventHash(Hash::from(serialised_content.as_slice())))
    } else {
        Err(Error::SignatureFailure)
    }
}

/// Finds the first event which has the `short_name` provided.
#[cfg(test)]
pub(crate) fn find_event_by_short_name<'a, I, P>(
    events: I,
    short_name: &str,
) -> Option<IndexedEventRef<'a, P>>
where
    I: IntoIterator<Item = IndexedEventRef<'a, P>>,
    P: PublicId,
{
    let short_name = short_name.to_uppercase();
    events
        .into_iter()
        .find(|event| event.short_name().to_string() == short_name)
}

#[cfg(any(test, feature = "testing"))]
fn get_creator_initial<S: SecretId>(peer_list: &PeerList<S>, creator: PeerIndex) -> char {
    peer_list
        .get(creator)
        .and_then(|peer| {
            let name = format!("{:?}", peer.id());
            name.chars().next().map(|c| c.to_ascii_uppercase())
        })
        .unwrap_or('?')
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct ShortName {
    creator_initial: char,
    index_by_creator: usize,
}

impl Display for ShortName {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}_{}", self.creator_initial, self.index_by_creator)
    }
}

impl Debug for ShortName {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::gossip::{
        cause::Cause,
        event::Event,
        event_hash::EventHash,
        graph::{EventIndex, Graph},
    };
    use crate::id::SecretId;
    use crate::mock::{PeerId, Transaction};
    use crate::observation::ConsensusMode;
    use crate::observation::Observation;
    use crate::peer_list::{PeerList, PeerState};

    struct Context {
        graph: Graph<PeerId>,
        peer_list: PeerList<PeerId>,
        observations: ObservationStore<Transaction, PeerId>,
        consensus_mode: ConsensusMode,
    }

    impl Context {
        fn new(our_id: &str) -> Self {
            let our_id = PeerId::new(our_id);
            let peer_list = PeerList::new(our_id);

            Self {
                graph: Graph::new(),
                peer_list,
                observations: ObservationStore::new(),
                consensus_mode: ConsensusMode::Supermajority,
            }
        }

        fn as_ref(&self) -> EventContextRef<Transaction, PeerId> {
            EventContextRef {
                graph: &self.graph,
                peer_list: &self.peer_list,
                observations: &self.observations,
                consensus_mode: self.consensus_mode,
            }
        }
    }

    fn create_event_with_single_peer(id: &str) -> (Context, Event<PeerId>) {
        let context = Context::new(id);
        let event = Event::new_initial(context.as_ref());

        (context, event)
    }

    fn insert_into_gossip_graph(
        initial_event: Event<PeerId>,
        graph: &mut Graph<PeerId>,
    ) -> (EventIndex, EventHash) {
        let hash = *initial_event.hash();
        assert!(!graph.contains(&hash));
        (graph.insert(initial_event).event_index(), hash)
    }

    fn create_two_events(id0: &str, id1: &str) -> (Context, Event<PeerId>, Context, Event<PeerId>) {
        let mut context0 = Context::new(id0);
        let mut context1 = Context::new(id1);

        let _ = context0.peer_list.add_peer(
            context1.peer_list.our_pub_id().clone(),
            PeerState::VOTE | PeerState::SEND | PeerState::RECV,
        );
        let _ = context1.peer_list.add_peer(
            context0.peer_list.our_pub_id().clone(),
            PeerState::VOTE | PeerState::SEND | PeerState::RECV,
        );

        let event0 = Event::new_initial(context0.as_ref());
        let event1 = Event::new_initial(context1.as_ref());

        (context0, event0, context1, event1)
    }

    fn convert_event(
        event: &Event<PeerId>,
        src: EventContextRef<Transaction, PeerId>,
        dst: EventContextRef<Transaction, PeerId>,
    ) -> Event<PeerId> {
        let e = unwrap!(event.pack(src));
        match unwrap!(Event::unpack(e, &PeerIndexSet::default(), &dst)) {
            UnpackedEvent::New(e, _) => e,
            UnpackedEvent::Known(_) => panic!("Unexpected known event"),
        }
    }

    #[test]
    fn event_construction_initial() {
        let initial = create_event_with_single_peer("Alice").1;
        assert!(initial.is_initial());
        assert!(!initial.is_response());
        assert!(initial.self_parent().is_none());
        assert!(initial.other_parent().is_none());
        assert_eq!(initial.index_by_creator(), 0);
    }

    #[test]
    fn event_construction_from_observation() {
        let (mut alice, a_0) = create_event_with_single_peer("Alice");
        let (initial_event_index, initial_event_hash) =
            insert_into_gossip_graph(a_0, &mut alice.graph);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let (event_from_observation, observation_for_store) = unwrap!(Event::new_from_observation(
            initial_event_index,
            net_event.clone(),
            &alice.as_ref(),
        ));

        let (key, observation_info) = unwrap!(observation_for_store);
        let _ = alice.observations.insert(key, observation_info);

        let packed_event_from_observation = unwrap!(event_from_observation.pack(alice.as_ref()));

        assert_eq!(
            packed_event_from_observation.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        match &packed_event_from_observation.content.cause {
            Cause::Observation { self_parent, vote } => {
                assert_eq!(self_parent, &initial_event_hash);
                assert_eq!(*vote.payload(), net_event);
            }
            _ => panic!(
                "Expected Observation, got {:?}",
                event_from_observation.content.cause
            ),
        }
        assert_eq!(event_from_observation.index_by_creator(), 1);
        assert!(!event_from_observation.is_initial());
        assert!(!event_from_observation.is_response());
        assert_eq!(
            event_from_observation.self_parent(),
            Some(initial_event_index)
        );
        assert!(event_from_observation.other_parent().is_none());
    }

    #[test]
    #[cfg(feature = "testing")]
    fn event_construction_from_observation_with_phony_self_parent() {
        let alice = Context::new("Alice");
        let self_parent_index = EventIndex::PHONY;
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        match Event::new_from_observation(self_parent_index, net_event.clone(), &alice.as_ref()) {
            Err(Error::UnknownSelfParent) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    #[test]
    fn event_construction_from_request() {
        let (mut alice, a_0, bob, b_0) = create_two_events("Alice", "Bob");
        let b_0 = convert_event(&b_0, bob.as_ref(), alice.as_ref());
        let a_0_index = alice.graph.insert(a_0).event_index();
        let b_0_index = alice.graph.insert(b_0).event_index();

        // Alice receives request from Bob
        let event_from_request = unwrap!(Event::new_from_request(
            a_0_index,
            b_0_index,
            &PeerIndexSet::default(),
            alice.as_ref()
        ));

        let packed_event_from_request = unwrap!(event_from_request.pack(alice.as_ref()));

        assert_eq!(
            packed_event_from_request.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_request.index_by_creator(), 1);
        assert!(!event_from_request.is_initial());
        assert!(!event_from_request.is_response());
        assert_eq!(event_from_request.self_parent(), Some(a_0_index));
        assert_eq!(event_from_request.other_parent(), Some(b_0_index));
    }

    #[test]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_self_parent_event_in_graph() {
        let (mut alice, _, bob, b_0) = create_two_events("Alice", "Bob");
        let b_0 = convert_event(&b_0, bob.as_ref(), alice.as_ref());
        let b_0_index = alice.graph.insert(b_0).event_index();

        match Event::new_from_request(
            EventIndex::PHONY,
            b_0_index,
            &PeerIndexSet::default(),
            alice.as_ref(),
        ) {
            Err(Error::UnknownSelfParent) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    #[test]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_other_parent_event_in_graph() {
        let (mut alice, a_0, _, _) = create_two_events("Alice", "Bob");
        let a_0_index = alice.graph.insert(a_0).event_index();

        match Event::new_from_request(
            a_0_index,
            EventIndex::PHONY,
            &PeerIndexSet::default(),
            alice.as_ref(),
        ) {
            Err(Error::UnknownOtherParent) => (),
            x => panic!("Unexpected {:?}", x),
        }
    }

    #[test]
    fn event_construction_from_response() {
        let (mut alice, a_0, bob, b_0) = create_two_events("Alice", "Bob");
        let b_0 = convert_event(&b_0, bob.as_ref(), alice.as_ref());
        let a_0_index = alice.graph.insert(a_0).event_index();
        let b_0_index = alice.graph.insert(b_0).event_index();

        let event_from_response = unwrap!(Event::new_from_response(
            a_0_index,
            b_0_index,
            &PeerIndexSet::default(),
            alice.as_ref()
        ));
        let packed_event_from_response = unwrap!(event_from_response.pack(alice.as_ref()));

        assert_eq!(
            packed_event_from_response.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_response.index_by_creator(), 1);
        assert!(!event_from_response.is_initial());
        assert!(event_from_response.is_response());
        assert_eq!(event_from_response.self_parent(), Some(a_0_index));
        assert_eq!(event_from_response.other_parent(), Some(b_0_index));
    }

    #[test]
    fn event_construction_unpack() {
        let (mut alice, a_0) = create_event_with_single_peer("Alice");
        let a_0_index = alice.graph.insert(a_0).event_index();

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let (event_from_observation, observation_for_store) = unwrap!(Event::new_from_observation(
            a_0_index,
            net_event,
            &alice.as_ref()
        ));

        let (key, observation_info) = unwrap!(observation_for_store);
        let _ = alice.observations.insert(key, observation_info);

        let packed_event = unwrap!(event_from_observation.pack(alice.as_ref()));
        let unpacked_event = match unwrap!(Event::unpack(
            packed_event.clone(),
            &PeerIndexSet::default(),
            &alice.as_ref()
        )) {
            UnpackedEvent::New(event, _) => event,
            UnpackedEvent::Known(_) => panic!("Unexpected known event"),
        };

        assert_eq!(event_from_observation, unpacked_event);
        assert!(!alice.graph.contains(unpacked_event.hash()));

        let _ = alice.graph.insert(unpacked_event);

        match unwrap!(Event::unpack(
            packed_event,
            &PeerIndexSet::default(),
            &alice.as_ref()
        )) {
            UnpackedEvent::New(_, _) => panic!("Unexpected new event"),
            UnpackedEvent::Known(_) => (),
        }
    }

    #[test]
    fn event_construction_unpack_fail_with_wrong_signature() {
        let (mut alice, a_0) = create_event_with_single_peer("Alice");
        let a_0_index = alice.graph.insert(a_0).event_index();

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let (event_from_observation, observation_for_store) = unwrap!(Event::new_from_observation(
            a_0_index,
            net_event,
            &alice.as_ref()
        ));

        let (key, observation_info) = unwrap!(observation_for_store);
        let _ = alice.observations.insert(key, observation_info);

        let mut packed_event = unwrap!(event_from_observation.pack(alice.as_ref()));
        packed_event.signature = alice.peer_list.our_id().sign_detached(&[123]);

        let error = unwrap_err!(Event::unpack(
            packed_event,
            &PeerIndexSet::default(),
            &alice.as_ref()
        ));
        if let Error::SignatureFailure = error {
        } else {
            panic!("Expected SignatureFailure, but got {:?}", error);
        }
    }
}
