// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_event::{MetaEvent, MetaEventBuilder};
use super::meta_vote::MetaVote;
use crate::gossip::{EventIndex, Graph};
use crate::id::PublicId;
use crate::observation::{ObservationHash, ObservationKey};
use crate::peer_list::{PeerIndex, PeerIndexMap, PeerIndexSet, PeerListChange};
use crate::round_hash::RoundHash;
use fnv::{FnvHashMap, FnvHashSet};
use std::collections::BTreeSet;
use std::{cmp, usize};

lazy_static! {
    static ref EMPTY_BTREESET_EVENT_INDEX: BTreeSet<EventIndex> = BTreeSet::new();
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct UnconsensusedEvents {
    // Set of all events that carry a payload that hasn't yet been consensused.
    pub(crate) ordered_indices: BTreeSet<EventIndex>,
    // Same events grouped by ObservationKey for lookup performance,
    pub(crate) indices_by_key: FnvHashMap<ObservationKey, BTreeSet<EventIndex>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetaElection {
    // Set of meta-events corresponding to the events in the gossip graph.
    pub(crate) meta_events: FnvHashMap<EventIndex, MetaEvent>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    pub(crate) round_hashes: PeerIndexMap<Vec<RoundHash>>,
    // Set of peers participating in this meta-election, i.e. all voters at the time the current
    // meta-election was started.
    pub(crate) voters: PeerIndexSet,
    // The indices of events for each peer that have a non-empty set of `interesting_content`.
    // The second element allow fast lookup for existing interesting_content.
    pub(crate) interesting_events: PeerIndexMap<(Vec<EventIndex>, FnvHashSet<ObservationKey>)>,
    // All events that carry a payload that hasn't yet been consensused.
    pub(crate) unconsensused_events: UnconsensusedEvents,
    // Keys of the consensused blocks' payloads in the order they were consensused.
    pub(crate) consensus_history: Vec<ObservationKey>,
    // Topological index of the first unconsensused payload-carrying event or of the first observer
    // event, whichever is the greater.
    pub(crate) continue_consensus_start_index: usize,
    // Topological index of the first unconsensused payload-carrying event.
    pub(crate) new_consensus_start_index: usize,
}

impl MetaElection {
    pub fn new(voters: PeerIndexSet) -> Self {
        MetaElection {
            meta_events: FnvHashMap::default(),
            round_hashes: PeerIndexMap::default(),
            voters,
            interesting_events: PeerIndexMap::default(),
            unconsensused_events: UnconsensusedEvents::default(),
            consensus_history: Vec::new(),
            continue_consensus_start_index: 0,
            new_consensus_start_index: 0,
        }
    }

    pub fn add_meta_event<P: PublicId>(&mut self, builder: MetaEventBuilder<P>) {
        let event_index = builder.event().event_index();
        let creator = builder.event().creator();
        let meta_event = builder.finish();

        // Update round hashes.
        for (peer_index, event_votes) in &meta_event.meta_votes {
            let hashes = if let Some(hashes) = self.round_hashes.get_mut(peer_index) {
                hashes
            } else {
                continue;
            };

            for meta_vote in event_votes {
                while hashes.len() < meta_vote.round + 1 {
                    let next_round_hash = hashes[hashes.len() - 1].increment_round();
                    hashes.push(next_round_hash);
                }
            }
        }

        // Update interesting events.
        if !meta_event.interesting_content.is_empty() {
            self.add_interesting_event(creator, event_index, &meta_event.interesting_content);
        }

        // Insert the meta-event itself.
        let _ = self.meta_events.insert(event_index, meta_event);
    }

    pub fn remove_meta_event(&mut self, event_index: EventIndex) -> Option<MetaEvent> {
        self.meta_events.remove(&event_index)
    }

    pub fn meta_event(&self, event_index: EventIndex) -> Option<&MetaEvent> {
        self.meta_events.get(&event_index)
    }

    /// The event meta votes if available
    pub fn populated_meta_votes(
        &self,
        event_index: EventIndex,
    ) -> Option<&PeerIndexMap<Vec<MetaVote>>> {
        self.meta_events
            .get(&event_index)
            .map(|meta_event| &meta_event.meta_votes)
            .filter(|meta_votes| !meta_votes.is_empty())
    }

    pub fn round_hashes(&self, peer_index: PeerIndex) -> Option<&Vec<RoundHash>> {
        self.round_hashes.get(peer_index)
    }

    /// List of voters participating in the current meta-election.
    pub fn voters(&self) -> &PeerIndexSet {
        &self.voters
    }

    pub fn consensus_history(&self) -> &[ObservationKey] {
        &self.consensus_history
    }

    pub fn interesting_events(&self) -> impl Iterator<Item = (PeerIndex, &[EventIndex])> {
        self.interesting_events
            .iter()
            .map(|(peer_index, (event_indices, _))| (peer_index, &event_indices[..]))
    }

    pub fn interesting_content_by(&self, creator: PeerIndex) -> Option<&Vec<ObservationKey>> {
        self.interesting_events
            .get(creator)
            .and_then(|(indices, _)| indices.first())
            .and_then(|event_index| self.meta_events.get(event_index))
            .map(|meta_event| &meta_event.interesting_content)
    }

    pub fn is_already_interesting_content(
        &self,
        creator: PeerIndex,
        payload_key: &ObservationKey,
    ) -> bool {
        self.interesting_events
            .get(creator)
            .map_or(false, |(_, contents)| contents.contains(payload_key))
    }

    pub fn continue_consensus_start_index(&self) -> usize {
        self.continue_consensus_start_index
    }

    pub fn new_consensus_start_index(&self) -> usize {
        self.new_consensus_start_index
    }

    /// Starts new election.
    pub fn new_election<P: PublicId>(
        &mut self,
        graph: &Graph<P>,
        decided_keys: Vec<ObservationKey>,
        peer_list_changes: Vec<PeerListChange>,
    ) {
        let peer_list_changed = !peer_list_changes.is_empty();

        self.update_voters(peer_list_changes);
        self.update_unconsensused_events(&decided_keys);
        self.update_new_consensus_start_index();
        self.update_continue_consensus_start_index(peer_list_changed);
        self.update_meta_events(&decided_keys, peer_list_changed);
        self.update_interesting_content(graph);

        self.round_hashes.clear();
        self.consensus_history.extend(decided_keys);
    }

    pub fn initialise_round_hashes<'a, I, P>(&mut self, peer_ids: I)
    where
        I: IntoIterator<Item = (PeerIndex, &'a P)>,
        P: PublicId + 'a,
    {
        let hash = self
            .consensus_history
            .last()
            .map(|key| *key.hash())
            .unwrap_or(ObservationHash::ZERO);

        self.round_hashes = peer_ids
            .into_iter()
            .map(|(index, id)| {
                let round_hash = RoundHash::new(id, hash);
                (index, vec![round_hash])
            })
            .collect();
    }

    #[cfg(feature = "dump-graphs")]
    pub fn meta_events(&self) -> &FnvHashMap<EventIndex, MetaEvent> {
        &self.meta_events
    }

    pub fn add_unconsensused_event(&mut self, event_index: EventIndex, key: ObservationKey) {
        let _ = self
            .unconsensused_events
            .ordered_indices
            .insert(event_index);
        let _ = self
            .unconsensused_events
            .indices_by_key
            .entry(key)
            .or_insert_with(BTreeSet::new)
            .insert(event_index);
    }

    pub fn unconsensused_events<'a>(
        &'a self,
        filter_key: Option<&ObservationKey>,
    ) -> impl Iterator<Item = EventIndex> + 'a {
        let indices = if let Some(filter_key) = filter_key {
            self.unconsensused_events
                .indices_by_key
                .get(filter_key)
                .unwrap_or(&*EMPTY_BTREESET_EVENT_INDEX)
        } else {
            &self.unconsensused_events.ordered_indices
        };

        indices.iter().cloned()
    }

    fn add_interesting_event(
        &mut self,
        creator: PeerIndex,
        event_index: EventIndex,
        interesting_content: &[ObservationKey],
    ) {
        let (indices, contents) = self
            .interesting_events
            .entry(creator)
            .or_insert_with(|| (Vec::new(), FnvHashSet::default()));
        indices.push(event_index);
        contents.extend(interesting_content);
    }

    // Updates unconsensused_events by removing those that became consensused.
    fn update_unconsensused_events(&mut self, decided_keys: &[ObservationKey]) {
        for key in decided_keys {
            if let Some(remove) = self.unconsensused_events.indices_by_key.remove(key) {
                for event_index in remove {
                    let _ = self
                        .unconsensused_events
                        .ordered_indices
                        .remove(&event_index);
                }
            }
        }
    }

    fn update_voters(&mut self, peer_list_changes: Vec<PeerListChange>) {
        for peer_list_change in peer_list_changes {
            match peer_list_change {
                PeerListChange::Add(peer_index) => {
                    if !self.voters.insert(peer_index) {
                        log_or_panic!("Meta election already contains {:?}", peer_index);
                    }
                }
                PeerListChange::Remove(peer_index) => {
                    if !self.voters.remove(peer_index) {
                        log_or_panic!("Meta election doesn't contain {:?}", peer_index);
                    }
                }
            }
        }
    }

    fn update_new_consensus_start_index(&mut self) {
        self.new_consensus_start_index = self
            .unconsensused_events
            .ordered_indices
            .iter()
            .next()
            .map(|event_index| event_index.topological_index())
            .unwrap_or(usize::MAX);
    }

    fn update_continue_consensus_start_index(&mut self, peer_list_changed: bool) {
        self.continue_consensus_start_index = if peer_list_changed {
            self.new_consensus_start_index
        } else {
            cmp::max(
                self.meta_events
                    .iter()
                    .filter(|(_, meta_event)| meta_event.is_observer())
                    .map(|(event_index, _)| event_index.topological_index())
                    .min()
                    .unwrap_or(self.new_consensus_start_index),
                self.new_consensus_start_index,
            )
        };
    }

    fn update_meta_events(&mut self, decided_keys: &[ObservationKey], peer_list_changed: bool) {
        if peer_list_changed {
            self.meta_events.clear();
        } else {
            let new_consensus_start_index = self.new_consensus_start_index;
            self.meta_events.retain(|event_index, _| {
                event_index.topological_index() >= new_consensus_start_index
            });
            let decided_keys_lookup: FnvHashSet<_> = decided_keys.iter().collect();
            for meta_event in self.meta_events.values_mut() {
                meta_event
                    .interesting_content
                    .retain(|payload_key| !decided_keys_lookup.contains(payload_key));
            }
        }
    }

    fn update_interesting_content<P: PublicId>(&mut self, graph: &Graph<P>) {
        self.interesting_events.clear();

        let continue_consensus_start_index = self.continue_consensus_start_index;
        for event in graph
            .iter_from(self.new_consensus_start_index)
            .take_while(|event| event.topological_index() < continue_consensus_start_index)
        {
            let interesting = self
                .meta_events
                .get(&event.event_index())
                .map(|meta_event| &meta_event.interesting_content)
                .filter(|interesting_content| !interesting_content.is_empty())
                .cloned();
            if let Some(interesting) = interesting {
                self.add_interesting_event(event.creator(), event.event_index(), &interesting)
            }
        }
    }
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::super::meta_event::snapshot::MetaEventSnapshot;
    use super::*;
    use crate::gossip::{EventHash, Graph};
    use crate::id::SecretId;
    use crate::peer_list::PeerList;
    use std::collections::BTreeMap;

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) struct MetaElectionSnapshot<P: PublicId> {
        meta_events: BTreeMap<EventHash, MetaEventSnapshot<P>>,
        round_hashes: BTreeMap<P, Vec<RoundHash>>,
        voters: BTreeSet<P>,
        interesting_events: BTreeMap<P, Vec<EventHash>>,
    }

    impl<P: PublicId> MetaElectionSnapshot<P> {
        pub fn new<S>(
            meta_election: &MetaElection,
            graph: &Graph<P>,
            peer_list: &PeerList<S>,
        ) -> Self
        where
            S: SecretId<PublicId = P>,
        {
            let meta_events = meta_election
                .meta_events
                .iter()
                .filter_map(|(index, meta_event)| {
                    graph
                        .get(*index)
                        .map(|event| *event.hash())
                        .map(|hash| (hash, MetaEventSnapshot::new(meta_event, peer_list)))
                })
                .collect();

            let interesting_events = meta_election
                .interesting_events
                .iter()
                .filter_map(|(peer_index, event_indices)| {
                    peer_list
                        .get(peer_index)
                        .map(|peer| (peer.id(), event_indices))
                })
                .map(|(peer_id, (indices, _))| {
                    let hashes = indices
                        .iter()
                        .filter_map(|index| graph.get(*index).map(|event| *event.hash()))
                        .collect();
                    (peer_id.clone(), hashes)
                })
                .collect();

            MetaElectionSnapshot {
                meta_events,
                round_hashes: meta_election
                    .round_hashes
                    .iter()
                    .filter_map(|(peer_index, hashes)| {
                        peer_list
                            .get(peer_index)
                            .map(|peer| (peer.id().clone(), hashes.clone()))
                    })
                    .collect(),
                voters: meta_election
                    .voters
                    .iter()
                    .filter_map(|index| peer_list.get(index).map(|peer| peer.id().clone()))
                    .collect(),
                interesting_events,
            }
        }
    }
}
