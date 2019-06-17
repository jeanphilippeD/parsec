// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(all(test, feature = "malice-detection", feature = "mock"))]
use crate::error::Error;
#[cfg(any(all(test, feature = "mock"), feature = "testing"))]
use crate::gossip::EventContextRef;
use crate::{
    gossip::{CauseInput, Event, EventIndex, Graph, IndexedEventRef},
    hash::{Hash, HASH_LEN},
    meta_voting::{
        BoolSet, MetaElection, MetaEvent, MetaVote, Observer, Step, UnconsensusedEvents,
    },
    mock::{PeerId, Transaction},
    observation::{
        ConsensusMode, Malice, MaliceInput, Observation, ObservationHash, ObservationInfo,
        ObservationKey, ObservationStore,
    },
    peer_list::{PeerIndex, PeerIndexMap, PeerIndexSet, PeerList, PeerState},
};
use fnv::{FnvHashMap, FnvHashSet};
use itertools::Itertools;
use pom::{
    char_class::{alphanum, digit, hex_digit, multispace, space},
    parser::*,
    DataInput, Parser, Result as PomResult,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read},
    path::Path,
    rc::Rc,
    str::FromStr,
};

pub const HEX_DIGITS_PER_BYTE: usize = 2;

type ObservationMap = Vec<(ObservationKey, Observation<Transaction, PeerId>)>;

type PeerParsedEvents = BTreeMap<PeerEventKey, (String, ParsedEvent)>;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
struct PeerEventKey {
    index_by_creator: u32,
    fork_index: u32,
}

fn newline() -> Parser<u8, ()> {
    (seq(b"\n") | seq(b"\r\n")).discard()
}

fn next_line() -> Parser<u8, ()> {
    none_of(b"\r\n").repeat(0..) * newline()
}

// Skip spaces or tabs.
fn spaces() -> Parser<u8, ()> {
    is_a(space).repeat(0..).discard()
}

// Skip any whitespace including newlines.
fn whitespace() -> Parser<u8, ()> {
    is_a(multispace).repeat(0..).discard()
}

fn comment_prefix() -> Parser<u8, ()> {
    seq(b"///") * spaces()
}

#[derive(Debug)]
struct ParsedFile {
    our_id: PeerId,
    peer_list: ParsedPeerList,
    consensus_mode: ConsensusMode,
    graph: ParsedGraph,
    meta_election: ParsedMetaElection,
}

struct ParserCtx {
    peer_ids: RefCell<BTreeMap<String, PeerId>>,
}

impl ParserCtx {
    fn new_rc() -> Rc<Self> {
        Rc::new(ParserCtx {
            peer_ids: RefCell::new(BTreeMap::new()),
        })
    }

    fn populate_peer_ids(&self, peer_list: &ParsedPeerList) {
        *self.peer_ids.borrow_mut() = peer_list
            .0
            .keys()
            .map(|id| (id.id().to_string(), id.clone()))
            .collect();
    }

    fn peer_id_from_short_name(&self, short_name: &str) -> PeerId {
        use std::ops::Bound::{Included, Unbounded};

        let peer_ids = self.peer_ids.borrow();

        // The full name will be the first greater or equal full name
        let mut range = peer_ids.range::<str, _>((Included(short_name), Unbounded));
        if let Some((_name, peer_id)) = range.next() {
            return peer_id.clone();
        }

        panic!(
            "cannot find a name starts with {:?} within {:?}",
            short_name, peer_ids
        )
    }
}

fn parse_file(ctx: &Rc<ParserCtx>) -> Parser<u8, ParsedFile> {
    (parse_our_id()
        + parse_peer_list(ctx)
        + parse_consensus_mode()
        + parse_graph()
        + parse_meta_election(ctx)
        - parse_end())
    .map(
        |((((our_id, peer_list), consensus_mode), graph), meta_election)| ParsedFile {
            our_id,
            peer_list,
            consensus_mode,
            graph,
            meta_election,
        },
    )
}

fn parse_peer_id() -> Parser<u8, PeerId> {
    is_a(alphanum)
        .repeat(1..)
        .collect()
        .convert(String::from_utf8)
        .map(|s| PeerId::new(&s))
}

fn parse_our_id() -> Parser<u8, PeerId> {
    comment_prefix() * seq(b"our_id: ") * parse_peer_id() - next_line()
}

#[derive(Debug)]
struct ParsedPeerList(BTreeMap<PeerId, PeerState>);

fn parse_peer_list(ctx: &Rc<ParserCtx>) -> Parser<u8, ParsedPeerList> {
    let list_defs =
        comment_prefix() * seq(b"peer_list: {") * next_line() * parse_peer().repeat(0..)
            - comment_prefix()
            - sym(b'}') * next_line();

    let ctx = Rc::clone(ctx);
    list_defs.map(move |defs| {
        let peer_list = ParsedPeerList(defs.into_iter().collect());
        ctx.populate_peer_ids(&peer_list);
        peer_list
    })
}

fn parse_peer() -> Parser<u8, (PeerId, PeerState)> {
    comment_prefix() * parse_peer_id() - seq(b": ") + parse_peer_state() - next_line()
}

fn parse_peer_state() -> Parser<u8, PeerState> {
    let state = seq(b"PeerState(") * list(parse_single_state(), sym(b'|')) - sym(b')');
    state.map(|states| {
        states
            .into_iter()
            .fold(PeerState::inactive(), |s1, s2| s1 | s2)
    })
}

fn parse_single_state() -> Parser<u8, PeerState> {
    seq(b"VOTE").map(|_| PeerState::VOTE)
        | seq(b"SEND").map(|_| PeerState::SEND)
        | seq(b"RECV").map(|_| PeerState::RECV)
}

fn parse_peers() -> Parser<u8, BTreeSet<PeerId>> {
    (sym(b'{') * list(parse_peer_id(), seq(b", ")) - sym(b'}')).map(|v| v.into_iter().collect())
}

fn parse_consensus_mode() -> Parser<u8, ConsensusMode> {
    let parser = seq(b"Single").map(|_| ConsensusMode::Single)
        | seq(b"Supermajority").map(|_| ConsensusMode::Supermajority);
    let parser = comment_prefix() * seq(b"consensus_mode: ") * parser - next_line();
    parser
        .opt()
        .map(|mode| mode.unwrap_or(ConsensusMode::Supermajority))
}

#[derive(Debug)]
struct ParsedGraph {
    graph: BTreeMap<String, ParsedEvent>,
    event_details: BTreeMap<String, EventDetails>,
}

#[derive(Debug)]
struct ParsedEvent {
    creator: PeerId,
    self_parent: Option<String>,
    other_parent: Option<String>,
}

const SKIP_DIGRAPH_INITIAL_PROPS: usize = 4;
const SKIP_STYLE_INVIS: usize = 3;

fn parse_graph() -> Parser<u8, ParsedGraph> {
    let subgraphs = seq(b"digraph GossipGraph")
        * next_line().repeat(SKIP_DIGRAPH_INITIAL_PROPS)
        * parse_subgraph().repeat(1..)
        - (none_of(b"}").repeat(0..) * one_of(b"}"))
        - next_line().repeat(SKIP_STYLE_INVIS)
        + parse_event_details()
        - seq(b"}")
        - next_line().repeat(2);
    subgraphs.map(|(graphs, details)| {
        let mut graph = BTreeMap::new();
        for subgraph in graphs {
            for event in subgraph.events {
                let self_parent = subgraph.self_parents.get(&event).cloned();
                let other_parent = subgraph.other_parents.get(&event).cloned();
                let _ = graph.insert(
                    event.clone(),
                    ParsedEvent {
                        creator: subgraph.creator.clone(),
                        self_parent,
                        other_parent,
                    },
                );
            }
        }
        ParsedGraph {
            graph,
            event_details: details,
        }
    })
}

#[derive(Debug)]
struct ParsedEdge {
    start: String,
    end: String,
}

#[derive(Debug)]
struct ParsedSubgraph {
    creator: PeerId,
    events: Vec<String>,
    self_parents: BTreeMap<String, String>,
    other_parents: BTreeMap<String, String>,
}

const SKIP_AFTER_SUBGRAPH: usize = 3;

fn parse_subgraph() -> Parser<u8, ParsedSubgraph> {
    let id = whitespace()
        * seq(b"style=invis")
        * whitespace()
        * seq(b"subgraph cluster_")
        * parse_peer_id();

    let self_parents = whitespace()
        * sym(b'{')
        * next_line().repeat(SKIP_AFTER_SUBGRAPH)
        * parse_edge().repeat(0..)
        - whitespace()
        - sym(b'}');
    let other_parents = whitespace() * parse_edge().repeat(0..);

    // `self_parents` will contain the creator's line - we are only interested in the set of events at the
    // end of edges
    (id + self_parents + other_parents).map(|((id, self_parents), other_parents)| {
        let events = self_parents.iter().map(|edge| edge.end.clone()).collect();
        ParsedSubgraph {
            creator: id,
            events,
            self_parents: self_parents
                .into_iter()
                .skip(1)    // skip the edge creator_id -> initial_event
                .map(|edge| (edge.end, edge.start))
                .collect(),
            other_parents: other_parents
                .into_iter()
                .map(|edge| (edge.end, edge.start))
                .collect(),
        }
    })
}

fn parse_edge() -> Parser<u8, ParsedEdge> {
    (spaces() * sym(b'"') * parse_event_id() - seq(b"\" -> \"") + parse_event_id() - next_line())
        .map(|(id1, id2)| ParsedEdge {
            start: id1,
            end: id2,
        })
}

fn parse_event_id() -> Parser<u8, String> {
    is_a(|c| alphanum(c) || c == b'_' || c == b',')
        .repeat(1..)
        .convert(String::from_utf8)
}

fn parse_event_details() -> Parser<u8, BTreeMap<String, EventDetails>> {
    seq(b"/// ===== details of events")
        * next_line()
        * parse_single_event_detail()
            .repeat(1..)
            .map(|details| details.into_iter().collect())
}

#[derive(Debug)]
struct EventDetails {
    cause: CauseInput,
    last_ancestors: BTreeMap<PeerId, usize>,
}

fn skip_brackets() -> Parser<u8, ()> {
    sym(b'[') * (none_of(b"[]").discard() | call(skip_brackets)).repeat(0..) * sym(b']').discard()
}

fn parse_single_event_detail() -> Parser<u8, (String, EventDetails)> {
    (spaces() * sym(b'"') * parse_event_id() - seq(b"\" ") - skip_brackets() - next_line()
        + parse_cause()
        + parse_last_ancestors()
        - next_line())
    .map(|((id, cause), last_ancestors)| {
        (
            id,
            EventDetails {
                cause,
                last_ancestors,
            },
        )
    })
}

fn parse_cause() -> Parser<u8, CauseInput> {
    let prefix = comment_prefix() * seq(b"cause: ");
    let initial = seq(b"Initial").map(|_| CauseInput::Initial);
    let requesting =
        (seq(b"Requesting(") * parse_peer_id() - sym(b')')).map(CauseInput::Requesting);
    let request = seq(b"Request").map(|_| CauseInput::Request);
    let response = seq(b"Response").map(|_| CauseInput::Response);
    let observation =
        (seq(b"Observation(") * parse_observation() - sym(b')')).map(CauseInput::Observation);
    let malice = (seq(b"Observation(") * parse_accusation() - sym(b')'))
        .map(|(offender, malice_input)| CauseInput::Malice(offender, malice_input));

    prefix * (initial | requesting | request | response | observation | malice) - newline()
}

fn parse_last_ancestors() -> Parser<u8, BTreeMap<PeerId, usize>> {
    (comment_prefix()
        * seq(b"last_ancestors: {")
        * list(
            parse_peer_id() - seq(b": ")
                + is_a(digit)
                    .repeat(1..)
                    .convert(String::from_utf8)
                    .convert(|s| usize::from_str(&s)),
            seq(b", "),
        )
        - next_line())
    .map(|v| v.into_iter().collect())
}

fn parse_consensus_history() -> Parser<u8, Vec<ObservationKey>> {
    let hash_line = comment_prefix()
        * (parse_hash()).map(|hash| ObservationKey::Supermajority(ObservationHash(hash)))
        - next_line();
    comment_prefix() * seq(b"consensus_history:") * next_line() * hash_line.repeat(0..)
}

fn parse_hash() -> Parser<u8, Hash> {
    is_a(hex_digit)
        .repeat(HEX_DIGITS_PER_BYTE)
        .convert(String::from_utf8)
        .convert(|s| u8::from_str_radix(&s, 16))
        .repeat(HASH_LEN)
        .map(|v| {
            let mut bytes = [0; HASH_LEN];
            for (i, byte) in v.into_iter().enumerate() {
                bytes[i] = byte;
            }
            Hash::from_bytes(bytes)
        })
}

#[derive(Debug)]
struct ParsedMetaElection {
    interesting_events: BTreeMap<PeerId, Vec<String>>,
    voters: BTreeSet<PeerId>,
    payload: Option<Observation<Transaction, PeerId>>,
    unconsensused_events: BTreeSet<String>,
    observation_map: BTreeMap<ObservationKey, Observation<Transaction, PeerId>>,
    meta_events: BTreeMap<String, ParsedMetaEvent>,
    consensus_history: Vec<ObservationKey>,
}

#[derive(Debug)]
struct ParsedMetaEvent {
    observees: BTreeSet<PeerId>,
    interesting_content: Vec<ObservationKey>,
    meta_votes: BTreeMap<PeerId, Vec<MetaVote>>,
}

fn parse_meta_election(ctx: &Rc<ParserCtx>) -> Parser<u8, ParsedMetaElection> {
    seq(b"/// ===== meta-elections =====")
        * next_line()
        * (parse_consensus_history() - next_line()
            + parse_interesting_events()
            + parse_voters()
            + parse_payload().opt()
            + parse_unconsensused_events()
            + parse_meta_events(ctx))
        .map(
            |(
                (
                    (((consensus_history, interesting_events), voters), payload),
                    unconsensused_events,
                ),
                observation_map_and_meta_events,
            )| {
                let mut observation_map = BTreeMap::new();
                let mut meta_events = BTreeMap::new();
                for (id, (obs, m_ev)) in observation_map_and_meta_events {
                    observation_map.extend(obs);
                    let _ = meta_events.insert(id, m_ev);
                }

                ParsedMetaElection {
                    interesting_events,
                    voters,
                    payload,
                    unconsensused_events,
                    observation_map,
                    meta_events,
                    consensus_history,
                }
            },
        )
}

fn parse_usize() -> Parser<u8, usize> {
    is_a(digit)
        .repeat(1..)
        .convert(String::from_utf8)
        .convert(|s| usize::from_str(&s))
}

fn parse_interesting_events() -> Parser<u8, BTreeMap<PeerId, Vec<String>>> {
    (comment_prefix()
        * seq(b"interesting_events: {")
        * next_line()
        * parse_interesting_events_for_peer().repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line())
    .map(|v| v.into_iter().collect())
}

fn parse_interesting_events_for_peer() -> Parser<u8, (PeerId, Vec<String>)> {
    comment_prefix() * parse_peer_id() - seq(b" -> [")
        + list(sym(b'"') * parse_event_id() - sym(b'"'), seq(b", "))
        - seq(b"]")
        - next_line()
}

fn parse_voters() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"all_voters: ") * parse_peers() - next_line()
}

fn parse_payload() -> Parser<u8, Observation<Transaction, PeerId>> {
    comment_prefix() * seq(b"payload: ") * parse_observation() - next_line()
}

fn parse_unconsensused_events() -> Parser<u8, BTreeSet<String>> {
    let line = comment_prefix()
        * seq(b"unconsensused_events: {")
        * list(sym(b'"') * parse_event_id() - sym(b'"'), seq(b", "))
        - seq(b"}")
        - next_line();
    line.opt()
        .map(|ids| ids.into_iter().flat_map(|ids| ids).collect())
}

fn parse_observation() -> Parser<u8, Observation<Transaction, PeerId>> {
    parse_genesis() | parse_add() | parse_remove() | parse_opaque()
}

fn parse_accusation() -> Parser<u8, (PeerId, MaliceInput)> {
    seq(b"Accusation") * parse_offender_and_malice()
}

fn parse_offender_and_malice() -> Parser<u8, (PeerId, MaliceInput)> {
    let peer_id = parse_peer_id();
    let malice = parse_malice();

    spaces() * sym(b'{') * spaces() * peer_id - spaces() - sym(b',') - spaces() + malice
        - spaces()
        - sym(b'}')
}

fn parse_malice() -> Parser<u8, MaliceInput> {
    parse_fork() | parse_invalid()
}

fn parse_fork() -> Parser<u8, MaliceInput> {
    (seq(b"Fork(") * parse_event_id() - seq(b")")).map(MaliceInput::Fork)
}

fn parse_invalid() -> Parser<u8, MaliceInput> {
    (seq(b"InvalidAccusation(") * parse_event_id() - seq(b")")).map(MaliceInput::InvalidAccusation)
}

fn parse_genesis() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"Genesis(") * parse_peers() - seq(b")")).map(|group| Observation::Genesis {
        group,
        related_info: vec![],
    })
}

fn parse_add() -> Parser<u8, Observation<Transaction, PeerId>> {
    seq(b"Add")
        * parse_add_or_remove().map(|(peer_id, related_info)| Observation::Add {
            peer_id,
            related_info,
        })
}

fn parse_remove() -> Parser<u8, Observation<Transaction, PeerId>> {
    seq(b"Remove")
        * parse_add_or_remove().map(|(peer_id, related_info)| Observation::Remove {
            peer_id,
            related_info,
        })
}

fn parse_add_or_remove() -> Parser<u8, (PeerId, Vec<u8>)> {
    parse_add_or_remove_with_related_info() | parse_add_or_remove_without_related_info()
}

fn parse_add_or_remove_with_related_info() -> Parser<u8, (PeerId, Vec<u8>)> {
    let peer_id = seq(b"peer_id:") * spaces() * parse_peer_id();
    let related_info =
        seq(b"related_info:") * spaces() * sym(b'[') * none_of(b"]").repeat(0..) - sym(b']');

    spaces() * sym(b'{') * spaces() * peer_id - spaces() - sym(b',') - spaces() + related_info
        - spaces()
        - sym(b'}')
}

fn parse_add_or_remove_without_related_info() -> Parser<u8, (PeerId, Vec<u8>)> {
    (spaces() * sym(b'(') * spaces() * parse_peer_id() - spaces() - sym(b')'))
        .map(|peer_id| (peer_id, vec![]))
}

fn parse_opaque() -> Parser<u8, Observation<Transaction, PeerId>> {
    (seq(b"OpaquePayload(") * parse_transaction() - seq(b")"))
        .map(Transaction::new)
        .map(Observation::OpaquePayload)
}

fn parse_transaction() -> Parser<u8, String> {
    is_a(alphanum).repeat(1..).convert(String::from_utf8)
}

fn parse_meta_events(
    ctx: &Rc<ParserCtx>,
) -> Parser<u8, BTreeMap<String, (ObservationMap, ParsedMetaEvent)>> {
    (comment_prefix()
        * seq(b"meta_events: {")
        * next_line()
        * parse_single_meta_event(ctx).repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line())
    .map(|v| v.into_iter().collect())
}

fn parse_single_meta_event(
    ctx: &Rc<ParserCtx>,
) -> Parser<u8, (String, (ObservationMap, ParsedMetaEvent))> {
    comment_prefix() * parse_event_id() - seq(b" -> {") - next_line()
        + parse_meta_event_content(ctx)
        - comment_prefix()
        - sym(b'}')
        - next_line()
}

fn parse_meta_event_content(ctx: &Rc<ParserCtx>) -> Parser<u8, (ObservationMap, ParsedMetaEvent)> {
    (parse_observees() + parse_interesting_content() + parse_meta_votes(ctx).opt()).map(
        |((observees, observation_map), meta_votes)| {
            let interesting_content = observation_map.iter().map(|(key, _)| *key).collect();
            (
                observation_map,
                ParsedMetaEvent {
                    observees,
                    interesting_content,
                    meta_votes: meta_votes.unwrap_or_else(BTreeMap::new),
                },
            )
        },
    )
}

fn parse_observees() -> Parser<u8, BTreeSet<PeerId>> {
    comment_prefix() * seq(b"observees: ") * parse_peers() - next_line()
}

fn parse_interesting_content() -> Parser<u8, ObservationMap> {
    (comment_prefix() * seq(b"interesting_content: [") * list(parse_observation(), seq(b", "))
        - next_line())
    .map(|observations| {
        observations
            .into_iter()
            .map(|payload| {
                (
                    ObservationKey::Supermajority(ObservationHash::from(&payload.as_ref())),
                    payload,
                )
            })
            .collect()
    })
}

fn parse_meta_votes(ctx: &Rc<ParserCtx>) -> Parser<u8, BTreeMap<PeerId, Vec<MetaVote>>> {
    (comment_prefix()
        * seq(b"meta_votes: {")
        * next_line()
        * next_line()
        * parse_peer_meta_votes(ctx).repeat(0..)
        - comment_prefix()
        - sym(b'}')
        - next_line())
    .map(|v| v.into_iter().collect())
}

fn parse_peer_meta_votes(ctx: &Rc<ParserCtx>) -> Parser<u8, (PeerId, Vec<MetaVote>)> {
    let peer_line = comment_prefix() * is_a(alphanum).repeat(1..).convert(String::from_utf8)
        - seq(b": ")
        + parse_meta_vote()
        - next_line();
    let next_line = comment_prefix() * parse_meta_vote() - next_line();
    let ctx = Rc::clone(ctx);

    (peer_line + next_line.repeat(0..)).map(move |((peer_short_name, first_mv), other_mvs)| {
        let mut mvs = vec![first_mv];
        mvs.extend(other_mvs);
        (ctx.peer_id_from_short_name(&peer_short_name), mvs)
    })
}

fn parse_meta_vote() -> Parser<u8, MetaVote> {
    (parse_usize() - sym(b'/') + parse_usize() - spaces() + parse_bool_set() - spaces()
        + parse_bool_set()
        - spaces()
        + parse_opt_bool()
        - spaces()
        + parse_opt_bool())
    .map(|(((((round, step), est), bin), aux), dec)| {
        let step = match step {
            0 => Step::ForcedTrue,
            1 => Step::ForcedFalse,
            2 => Step::GenuineFlip,
            _ => unreachable!(),
        };
        MetaVote::new(round, step, est, bin, aux, dec)
    })
}

fn parse_bool_set() -> Parser<u8, BoolSet> {
    sym(b'-').map(|_| BoolSet::Empty)
        | sym(b'f').map(|_| BoolSet::Single(false))
        | sym(b't').map(|_| BoolSet::Single(true))
        | sym(b'b').map(|_| BoolSet::Both)
}

fn parse_opt_bool() -> Parser<u8, Option<bool>> {
    sym(b'-').map(|_| None) | sym(b'f').map(|_| Some(false)) | sym(b't').map(|_| Some(true))
}

fn parse_end() -> Parser<u8, ()> {
    one_of(b" \r\n").repeat(0..) * end()
}

/// The event graph and associated info that were parsed from the dumped dot file.
pub(crate) struct ParsedContents {
    pub our_id: PeerId,
    pub graph: Graph<PeerId>,
    pub meta_election: MetaElection,
    pub peer_list: PeerList<PeerId>,
    pub observations: ObservationStore<Transaction, PeerId>,
    pub consensus_mode: ConsensusMode,
}

impl ParsedContents {
    /// Create empty `ParsedContents`.
    pub fn new(our_id: PeerId) -> Self {
        let peer_list = PeerList::new(our_id.clone());
        let meta_election = MetaElection::new(PeerIndexSet::default());

        ParsedContents {
            our_id,
            graph: Graph::new(),
            meta_election,
            peer_list,
            observations: ObservationStore::new(),
            consensus_mode: ConsensusMode::Supermajority,
        }
    }
}

impl ParsedContents {
    /// Remove and return the last (newest) event from the `ParsedContents`, if any.
    #[cfg(all(test, feature = "mock"))]
    pub fn remove_last_event(&mut self) -> Option<Event<PeerId>> {
        let (index_0, event) = self.graph.remove_last()?;
        let index_1 = self.peer_list.remove_last_event(event.creator());
        assert_eq!(Some(index_0), index_1);

        Some(event)
    }

    #[cfg(all(test, feature = "malice-detection", feature = "mock"))]
    /// Insert event into the `ParsedContents`. Note this does not perform any validations
    /// whatsoever, so this is useful for simulating all kinds of invalid or malicious situations.
    pub fn add_event(&mut self, event: Event<PeerId>) -> EventIndex {
        let indexed_event = self.graph.insert(event);
        self.peer_list.add_event(indexed_event);

        let start_index = indexed_event.event_index().topological_index() + 1;
        self.meta_election.new_consensus_start_index = start_index;
        self.meta_election.continue_consensus_start_index = start_index;

        indexed_event.event_index()
    }

    #[cfg(any(all(test, feature = "mock"), feature = "testing"))]
    pub fn event_context(&self) -> EventContextRef<Transaction, PeerId> {
        EventContextRef {
            graph: &self.graph,
            peer_list: &self.peer_list,
            observations: &self.observations,
            consensus_mode: self.consensus_mode,
        }
    }

    #[cfg(all(test, feature = "malice-detection", feature = "mock"))]
    pub fn new_event_from_observation(
        &mut self,
        self_parent: EventIndex,
        observation: Observation<Transaction, PeerId>,
    ) -> Result<Event<PeerId>, Error> {
        let (event, observation_for_store) =
            Event::new_from_observation(self_parent, observation, self.event_context())?;

        if let Some((payload_key, observation_info)) = observation_for_store {
            let _ = self
                .observations
                .entry(payload_key)
                .or_insert_with(|| observation_info);
        }

        Ok(event)
    }
}

/// Read a dumped dot file and return with parsed event graph and associated info.
pub(crate) fn parse_dot_file<P: AsRef<Path>>(full_path: P) -> io::Result<ParsedContents> {
    let name: Option<String> = full_path.as_ref().to_str().map(ToString::to_string);
    let result = unwrap!(read(File::open(full_path)?), "Failed to read {:?}", name);
    Ok(convert_into_parsed_contents(result))
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This puts the
/// test name as part of the path automatically, but depends on not explicitly running the tests
/// single-threaded, i.e. by passing '--test-threads=1' on the command line or setting the env var
/// 'RUST_TEST_THREADS=1'.
#[cfg(test)]
pub(crate) fn parse_test_dot_file(filename: &str) -> ParsedContents {
    let test_name = derive_test_name_from_current_thread_name();
    parse_dot_file_with_test_name(filename, &test_name)
}

#[cfg(test)]
fn derive_test_name_from_current_thread_name() -> String {
    use std::{env, thread};

    let test_name = unwrap!(thread::current().name()).replace("::", "_");
    if test_name == "main" {
        let panic = |arg: &str| {
            panic!(
                "Current thread name is 'main' since running with '{}=1', so can't be used to \
                 deduce test name for parsing correct dot file.",
                arg
            );
        };

        const THREADS_ARG: &str = "--test-threads";
        let mut args_itr = env::args().skip_while(|arg| !arg.starts_with(THREADS_ARG));
        match (
            args_itr.next().as_ref().map(|x| &**x),
            args_itr.next().as_ref().map(|x| &**x),
        ) {
            (Some(THREADS_ARG), Some("1")) | (Some("--test-threads=1"), _) => {
                panic(THREADS_ARG);
            }
            _ => (),
        }

        const THREADS_ENV_VAR: &str = "RUST_TEST_THREADS";
        if let Ok("1") = env::var(THREADS_ENV_VAR).as_ref().map(|x| &**x) {
            panic(THREADS_ENV_VAR);
        }
    }
    test_name
}

/// For use by functional/unit tests which provide a dot file for the test setup.  This reads and
/// parses the dot file as per `parse_dot_file()` above, with test name being part of the path.
#[cfg(test)]
fn parse_dot_file_with_test_name(filename: &str, test_name: &str) -> ParsedContents {
    use std::path::PathBuf;

    let mut dot_path = PathBuf::from("input_graphs");
    dot_path.push(test_name);
    dot_path.push(filename);
    assert!(
        dot_path.exists(),
        "\nDot file {} doesn't exist.",
        dot_path.display()
    );

    unwrap!(
        parse_dot_file(&dot_path),
        "Failed to parse {}",
        dot_path.display()
    )
}

fn read(mut file: File) -> PomResult<ParsedFile> {
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return Err(::pom::Error::Custom {
            message: "file not found".to_string(),
            position: 0,
            inner: None,
        });
    }

    let mut input = DataInput::new(contents.as_bytes());
    let ctx = ParserCtx::new_rc();
    parse_file(&ctx).parse(&mut input)
}

fn convert_into_parsed_contents(result: ParsedFile) -> ParsedContents {
    let ParsedFile {
        our_id,
        peer_list,
        consensus_mode,
        mut graph,
        meta_election,
    } = result;

    let mut parsed_contents = ParsedContents::new(our_id.clone());

    let peer_data = peer_list.0.into_iter().collect();
    let mut peer_list = PeerList::build_from_dot_input(our_id, peer_data);

    let mut event_indices = create_events(
        &mut graph.graph,
        graph.event_details,
        &mut parsed_contents,
        &mut peer_list,
        consensus_mode,
    );

    parsed_contents.observations.extend(
        meta_election
            .observation_map
            .iter()
            .map(|(key, obs)| (*key, ObservationInfo::new(obs.clone()))),
    );
    let meta_election = convert_to_meta_election(
        meta_election,
        &mut event_indices,
        &peer_list,
        &parsed_contents.graph,
    );

    parsed_contents.peer_list = peer_list;
    parsed_contents.meta_election = meta_election;
    parsed_contents.consensus_mode = consensus_mode;
    parsed_contents
}

fn convert_to_meta_election(
    meta_election: ParsedMetaElection,
    event_indices: &mut BTreeMap<String, EventIndex>,
    peer_list: &PeerList<PeerId>,
    graph: &Graph<PeerId>,
) -> MetaElection {
    let meta_events: FnvHashMap<_, _> = meta_election
        .meta_events
        .into_iter()
        .map(|(ev_id, mev)| {
            let event_index = *event_indices
                .entry(ev_id.clone())
                .or_insert_with(|| EventIndex::PHONY);
            let meta_event = convert_to_meta_event(mev, peer_list);
            (event_index, meta_event)
        })
        .collect();

    let interesting_events = meta_election
        .interesting_events
        .into_iter()
        .map(|(peer_id, events)| {
            let indices = events
                .into_iter()
                .map(|ev_id| {
                    *unwrap!(
                        event_indices.get(&ev_id),
                        "Missing {:?} from meta_events section of meta election.  \
                         This meta-event must be defined here as it's an Interesting Event.",
                        ev_id,
                    )
                })
                .collect_vec();
            let contents: FnvHashSet<_> = indices
                .iter()
                .filter_map(|index| meta_events.get(index))
                .flat_map(|meta_event| &meta_event.interesting_content)
                .cloned()
                .collect();

            (unwrap!(peer_list.get_index(&peer_id)), (indices, contents))
        })
        .collect();

    let unconsensused_events_indices: BTreeSet<_> = meta_election
        .unconsensused_events
        .into_iter()
        .filter_map(|id| event_indices.get(&id))
        .cloned()
        .collect();
    let unconsensused_events_keyed_indices = unconsensused_events_indices
        .iter()
        .filter_map(|index| graph.get(*index))
        .map(|indexed_event| {
            (
                indexed_event.event_index(),
                indexed_event.payload_key().cloned(),
            )
        })
        .filter_map(|(event_index, payload_key)| payload_key.map(|key| (event_index, key)))
        .fold(
            FnvHashMap::default(),
            |mut map, (event_index, payload_key)| {
                let _ = map
                    .entry(payload_key)
                    .or_insert_with(BTreeSet::new)
                    .insert(event_index);
                map
            },
        );
    let unconsensused_events = UnconsensusedEvents {
        ordered_indices: unconsensused_events_indices,
        indices_by_key: unconsensused_events_keyed_indices,
    };

    MetaElection {
        meta_events,
        voters: convert_peer_id_set(meta_election.voters, peer_list),
        interesting_events,
        unconsensused_events,
        consensus_history: meta_election.consensus_history,
        continue_consensus_start_index: 0,
        new_consensus_start_index: 0,
    }
}

fn convert_to_meta_event(meta_event: ParsedMetaEvent, peer_list: &PeerList<PeerId>) -> MetaEvent {
    let observees = convert_peer_id_set(meta_event.observees, peer_list);

    MetaEvent {
        observer: Observer::new(observees),
        interesting_content: meta_event.interesting_content,
        meta_votes: convert_peer_id_map(meta_event.meta_votes, peer_list),
    }
}

fn convert_peer_id_set(ids: BTreeSet<PeerId>, peer_list: &PeerList<PeerId>) -> PeerIndexSet {
    ids.into_iter()
        .map(|id| unwrap!(peer_list.get_index(&id)))
        .collect()
}

fn convert_peer_id_map<T>(
    ids: BTreeMap<PeerId, T>,
    peer_list: &PeerList<PeerId>,
) -> PeerIndexMap<T> {
    ids.into_iter()
        .map(|(id, value)| (unwrap!(peer_list.get_index(&id)), value))
        .collect()
}

fn create_events(
    graph: &mut BTreeMap<String, ParsedEvent>,
    mut details: BTreeMap<String, EventDetails>,
    parsed_contents: &mut ParsedContents,
    peer_list: &mut PeerList<PeerId>,
    consensus_mode: ConsensusMode,
) -> BTreeMap<String, EventIndex> {
    let mut event_indices = BTreeMap::new();

    let graph = std::mem::replace(graph, BTreeMap::new());
    let mut graph = in_peer_order(graph, peer_list);

    while !graph.is_empty() {
        let (ev_id, next_parsed_event) = next_topological_event(&mut graph, &event_indices);
        let next_event_details = unwrap!(details.remove(&ev_id));

        let (self_parent, other_parent, index_by_creator) = {
            let self_parent = next_parsed_event
                .self_parent
                .and_then(|ref id| get_event_by_id(&parsed_contents.graph, &event_indices, id));

            let other_parent = next_parsed_event
                .other_parent
                .and_then(|ref id| get_event_by_id(&parsed_contents.graph, &event_indices, id));

            let index_by_creator = self_parent
                .map(|ie| ie.index_by_creator() + 1)
                .unwrap_or(0usize);

            (
                self_parent.map(|e| (e.event_index(), *e.hash(), e.ancestor_info().clone())),
                other_parent.map(|e| (e.event_index(), *e.hash(), e.ancestor_info().clone())),
                index_by_creator,
            )
        };

        let next_event_cause = if let CauseInput::Malice(offender, malice_input) =
            next_event_details.cause
        {
            let malice = match malice_input {
                MaliceInput::Fork(ref id) => Malice::Fork(
                    *unwrap!(get_event_by_id(&parsed_contents.graph, &event_indices, id)).hash(),
                ),
                MaliceInput::InvalidAccusation(ref id) => Malice::InvalidAccusation(
                    *unwrap!(get_event_by_id(&parsed_contents.graph, &event_indices, id)).hash(),
                ),
            };
            CauseInput::Observation(Observation::Accusation { offender, malice })
        } else {
            next_event_details.cause
        };

        let next_event = Event::new_from_dot_input(
            &next_parsed_event.creator,
            next_event_cause,
            self_parent,
            other_parent,
            index_by_creator,
            consensus_mode,
            peer_list,
            &mut parsed_contents.observations,
        );

        let indexed_event_ref = parsed_contents.graph.insert(next_event);
        peer_list.add_event(indexed_event_ref);
        let event_index = indexed_event_ref.event_index();
        peer_list.record_gossiped_event_by(indexed_event_ref.creator(), event_index);
        let _ = event_indices.insert(ev_id, event_index);
    }

    event_indices
}

fn get_event_by_id<'a>(
    graph: &'a Graph<PeerId>,
    indices: &BTreeMap<String, EventIndex>,
    id: &str,
) -> Option<IndexedEventRef<'a, PeerId>> {
    indices.get(id).cloned().and_then(|index| graph.get(index))
}

fn in_peer_order(
    graph: BTreeMap<String, ParsedEvent>,
    peer_list: &PeerList<PeerId>,
) -> BTreeMap<(Option<PeerIndex>, String), PeerParsedEvents> {
    type Key = (Option<PeerIndex>, (String, PeerEventKey));

    let graph: BTreeMap<Key, (String, ParsedEvent)> = graph
        .into_iter()
        .map(|(name, evt)| {
            let sep0 = unwrap!(name.find('_'));
            let sep1 = name.find(',');

            let prefix = name[0..sep0].to_string();
            let index_by_creator: u32;
            let fork_index: u32;

            if let Some(sep1) = sep1 {
                index_by_creator = unwrap!(name[(sep0 + 1)..sep1].parse());
                fork_index = unwrap!(name[(sep1 + 1)..].parse());
            } else {
                index_by_creator = unwrap!(name[(sep0 + 1)..].parse());
                fork_index = 0;
            };

            let event_key = PeerEventKey {
                index_by_creator,
                fork_index,
            };

            ((prefix, event_key), (name.clone(), evt))
        })
        .map(|(name, evt)| ((peer_list.get_index(&evt.1.creator), name), evt))
        .collect();

    let mut new_graph = BTreeMap::new();
    for ((peer_index, (prefix, event_key)), event) in graph.into_iter() {
        let _ = new_graph
            .entry((peer_index, prefix))
            .or_insert_with(BTreeMap::new)
            .insert(event_key, event);
    }
    new_graph
}

fn next_topological_event(
    graph: &mut BTreeMap<(Option<PeerIndex>, String), PeerParsedEvents>,
    indices: &BTreeMap<String, EventIndex>,
) -> (String, ParsedEvent) {
    let next_event = graph
        .values_mut()
        .filter_map(|peer_events| {
            let index_with_parents = peer_events
                .iter()
                .next()
                .filter(|(_, (_, event))| {
                    let self_parent_found = event
                        .self_parent
                        .as_ref()
                        .map(|ev_id| indices.contains_key(ev_id))
                        .unwrap_or(true);
                    let other_parent_found = event
                        .other_parent
                        .as_ref()
                        .map(|ev_id| indices.contains_key(ev_id))
                        .unwrap_or(true);

                    self_parent_found && other_parent_found
                })
                .map(|(index, _)| *index);

            index_with_parents.map(|index| unwrap!(peer_events.remove(&index)))
        })
        .next();

    let empty_key = graph
        .iter()
        .find(|(_, peer_events)| peer_events.is_empty())
        .map(|(key, _)| key.clone());
    let _ = empty_key.map(|key| unwrap!(graph.remove(&key)));

    unwrap!(next_event)
}

#[cfg(all(test, feature = "dump-graphs"))]
mod tests {
    use super::*;
    use crate::{
        dev_utils::{Environment, RngChoice, Schedule, ScheduleOptions},
        dump_graph::DIR,
        gossip::GraphSnapshot,
        maidsafe_utilities::serialisation::deserialise,
        meta_voting::MetaElectionSnapshot,
        mock::PeerId,
    };
    use std::fs;

    type Snapshot = (GraphSnapshot, MetaElectionSnapshot<PeerId>);

    // Alter the seed here to reproduce failures
    static SEED: RngChoice = RngChoice::SeededRandom;

    #[test]
    fn dot_parser() {
        let mut env = Environment::new(SEED);
        let options = ScheduleOptions {
            genesis_size: 4,
            opaque_to_add: 5,
            prob_gossip: 0.1,
            ..Default::default()
        };
        let schedule = Schedule::new(&mut env, &options);

        unwrap!(env.network.execute_schedule(&mut env.rng, schedule));

        let mut num_of_files = 0u8;
        let entries = DIR.with(|dir| unwrap!(fs::read_dir(dir)));
        for entry in entries {
            let entry = unwrap!(entry);

            if !unwrap!(entry.file_name().to_str()).contains(".core") {
                continue;
            }
            num_of_files += 1;
            let mut core_file = unwrap!(File::open(entry.path()));
            let mut core_info = Vec::new();
            assert_ne!(unwrap!(core_file.read_to_end(&mut core_info)), 0);
            let expected_snapshot: Snapshot = unwrap!(deserialise(&core_info));

            let mut dot_file_path = entry.path();
            assert!(dot_file_path.set_extension("dot"));

            let parsed = unwrap!(parse_dot_file(&dot_file_path));
            let actual_snapshot = (
                GraphSnapshot::new(&parsed.graph),
                MetaElectionSnapshot::new(&parsed.meta_election, &parsed.graph, &parsed.peer_list),
            );

            assert_eq!(actual_snapshot, expected_snapshot);
        }
        assert_ne!(num_of_files, 0u8);
    }
}
