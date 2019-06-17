// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::dot_parser::{parse_dot_file, ParsedContents};
use crate::{
    gossip::{Cause, Event, IndexedEventRef, PackedEvent, Request, Response},
    hash::Hash,
    mock::{PeerId, Transaction},
    observation::{ConsensusMode, Observation, ObservationKey, ObservationStore},
    parsec::Parsec,
    peer_list::PeerIndex,
};
use std::{collections::BTreeSet, io, path::Path};

/// Record of a Parsec session which consist of sequence of operations (`vote_for`, `handle_request`
/// and `handle_response`). Can be produced from a previously dumped DOT file and after replaying,
/// produces the same gossip graph. Useful for benchmarking.
#[derive(Clone)]
pub struct Record {
    our_id: PeerId,
    genesis_group: BTreeSet<PeerId>,
    actions: Vec<Action>,
    // Keys of the consensused blocks' payloads in the order they were consensused.
    consensus_history: Vec<ObservationKey>,
    // Consensus mode to play
    consensus_mode: ConsensusMode,
    // True if when parsing the graph we had to add a final `Requesting` sync event and schedule a
    // Request to be sent to us in order to learn of any remaining events.
    added_final_requesting_event: bool,
}

impl Record {
    pub fn parse<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let contents = parse_dot_file(path.as_ref())?;
        Ok(Self::from(contents))
    }

    pub fn play(self) -> Parsec<Transaction, PeerId> {
        let mut parsec = Parsec::from_genesis(
            self.our_id,
            &self.genesis_group,
            vec![],
            self.consensus_mode,
        );

        for action in self.actions {
            action.run(&mut parsec)
        }

        parsec
    }

    pub fn consensus_history(&self) -> Vec<Hash> {
        self.consensus_history
            .iter()
            .map(|observation| observation.hash().0)
            .collect()
    }
}

impl From<ParsedContents> for Record {
    fn from(contents: ParsedContents) -> Self {
        // Find the genesis group
        let genesis_group = unwrap!(
            contents
                .graph
                .iter()
                .find_map(|event| extract_genesis_group(event.inner(), &contents.observations))
                .cloned(),
            "No event carrying Observation::Genesis found"
        );

        assert!(
            genesis_group.contains(&contents.our_id),
            "Records currently supported only for the members of the genesis group"
        );

        let mut actions = Vec::new();
        let mut skip_our_accusations = false;
        let mut known = vec![false; contents.graph.len()];

        for event in &contents.graph {
            if event.topological_index() == 0 {
                // Skip the initial event
                assert!(event.is_initial());
                assert_eq!(event.creator(), PeerIndex::OUR);
                continue;
            }

            if event.topological_index() == 1 {
                // Skip the genesis event
                assert!(extract_genesis_group(&*event, &contents.observations).is_some());
                assert_eq!(event.creator(), PeerIndex::OUR);
                continue;
            }

            if event.creator() == PeerIndex::OUR {
                if let Some(observation) = event
                    .payload_key()
                    .and_then(|key| contents.observations.get(key))
                    .map(|info| &info.observation)
                {
                    known[event.topological_index()] = true;

                    if let Observation::Accusation { .. } = *observation {
                        if skip_our_accusations {
                            continue;
                        } else {
                            // Accusations by us must follow our sync event.
                            panic!("Unexpected accusation {:?}", *event);
                        }
                    }

                    actions.push(Action::Vote(observation.clone()));
                } else if event.is_request() || event.is_response() {
                    known[event.topological_index()] = true;

                    let other_parent = unwrap!(
                        event
                            .other_parent()
                            .and_then(|hash| contents.graph.get(hash)),
                        "Sync event without other-parent: {:?}",
                        *event
                    );

                    let src = unwrap!(contents
                        .peer_list
                        .get(other_parent.creator())
                        .map(|peer| peer.id().clone()));

                    let events_to_gossip =
                        collect_events_to_gossip(&contents, other_parent, &mut known);

                    if event.is_request() {
                        actions.push(Action::Request(src, Request::new(events_to_gossip)))
                    } else {
                        actions.push(Action::Response(src, Response::new(events_to_gossip)))
                    }

                    // Skip all accusations directly following our sync event, as they will be
                    // created during replay.
                    skip_our_accusations = true;
                } else if event.is_requesting() {
                    known[event.topological_index()] = true;
                    let recipient_id = match event.cause() {
                        Cause::Requesting { recipient, .. } => {
                            unwrap!(contents.peer_list.get(*recipient)).id().clone()
                        }
                        _ => unreachable!(),
                    };
                    actions.push(Action::Requesting(recipient_id));
                    skip_our_accusations = true;
                } else {
                    panic!("Unexpected event {:?}", *event);
                }
            } else {
                skip_our_accusations = false;
            }
        }

        let mut events_to_gossip = collect_remaining_events_to_gossip(&contents, &mut known);
        let added_final_requesting_event = !events_to_gossip.is_empty();
        if let Some(packed_event) = events_to_gossip.last() {
            let src = packed_event.creator().clone();
            let self_parent = packed_event.compute_hash();
            let requesting_event =
                PackedEvent::new_requesting(src.clone(), contents.our_id.clone(), self_parent);
            events_to_gossip.push(requesting_event);
            actions.push(Action::Request(src, Request::new(events_to_gossip)));
        }

        Record {
            our_id: contents.our_id,
            genesis_group,
            actions,
            consensus_history: contents.meta_election.consensus_history,
            consensus_mode: contents.consensus_mode,
            added_final_requesting_event,
        }
    }
}

#[derive(Clone)]
enum Action {
    Vote(Observation<Transaction, PeerId>),
    Requesting(PeerId),
    Request(PeerId, Request<Transaction, PeerId>),
    Response(PeerId, Response<Transaction, PeerId>),
}

impl Action {
    fn run(self, parsec: &mut Parsec<Transaction, PeerId>) {
        match self {
            Action::Vote(observation) => unwrap!(parsec.vote_for_internal(observation)),
            Action::Requesting(recipient) => {
                let _ = unwrap!(parsec.create_gossip(&recipient));
            }
            Action::Request(src, request) => {
                let _ = unwrap!(parsec.handle_request(&src, request));
            }
            Action::Response(src, response) => unwrap!(parsec.handle_response(&src, response)),
        }
    }
}

fn extract_genesis_group<'a>(
    event: &Event<PeerId>,
    observations: &'a ObservationStore<Transaction, PeerId>,
) -> Option<&'a BTreeSet<PeerId>> {
    event
        .payload_key()
        .and_then(|key| observations.get(key))
        .map(|info| &info.observation)
        .and_then(|observation| {
            if let Observation::Genesis { ref group, .. } = *observation {
                Some(group)
            } else {
                None
            }
        })
}

fn collect_events_to_gossip(
    contents: &ParsedContents,
    other_parent: IndexedEventRef<PeerId>,
    known: &mut Vec<bool>,
) -> Vec<PackedEvent<Transaction, PeerId>> {
    let mut events_to_gossip = Vec::new();
    let other_parent_tindex = other_parent.topological_index();
    for event in contents.graph.ancestors(other_parent) {
        let event_tindex = event.topological_index();
        if known[event_tindex] && other_parent_tindex != event_tindex {
            continue;
        } else {
            known[event_tindex] = true;
        }

        events_to_gossip.push(unwrap!(event.pack(contents.event_context())));
    }
    events_to_gossip.reverse();
    events_to_gossip
}

fn collect_remaining_events_to_gossip(
    contents: &ParsedContents,
    known: &mut Vec<bool>,
) -> Vec<PackedEvent<Transaction, PeerId>> {
    let mut events_to_gossip = Vec::new();
    for event in contents.graph.iter() {
        let event_tindex = event.topological_index();
        if known[event_tindex] {
            continue;
        } else {
            known[event_tindex] = true;
        }

        events_to_gossip.push(unwrap!(event.pack(contents.event_context())));
    }
    events_to_gossip
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsec::get_graph_snapshot;
    use std::{iter, path::PathBuf, thread};

    #[derive(PartialEq, Eq, Debug)]
    struct TruncatedHashes<'th> {
        actual_len: usize,
        hashes: &'th [Hash],
    }

    impl<'th> TruncatedHashes<'th> {
        fn new_with_one_missing_element(hashes: &'th [Hash]) -> Self {
            Self {
                actual_len: hashes.len() + 1,
                hashes,
            }
        }

        fn new_with_one_truncated_element(hashes: &'th [Hash]) -> Self {
            Self {
                actual_len: hashes.len(),
                hashes: &hashes[0..hashes.len().saturating_sub(1)],
            }
        }
    }

    // The path of the dot file used to construct the Record.  Used for printing while panicking.
    struct PathPrinter(PathBuf);

    impl Drop for PathPrinter {
        fn drop(&mut self) {
            if thread::panicking() {
                let msg = format!("!  Record constructed from '{}'  !", self.0.display());
                let border = iter::repeat('!').take(msg.len()).collect::<String>();
                println!("\n{1}\n{}\n{1}\n", msg, border);
            }
        }
    }

    /// Run smoke test using given dot file.
    fn smoke<P: AsRef<Path>>(path: P) {
        let _p = PathPrinter(path.as_ref().to_owned());
        let contents = unwrap!(parse_dot_file(path.as_ref()));
        let expected = Parsec::from_parsed_contents(contents);
        let expected_events = {
            let ignore_last_events = 0;
            get_graph_snapshot(&expected, ignore_last_events)
        };

        let replay = unwrap!(Record::parse(path));
        let ignore_last_events = if replay.added_final_requesting_event {
            // Ignore the `Requesting` event we created when parsing the graph, and the associated
            // `Request` we'll create when receiving the message.
            2
        } else {
            0
        };
        let actual = replay.play();
        let actual_events = get_graph_snapshot(&actual, ignore_last_events);

        assert_eq!(expected_events, actual_events);
    }

    /// Run smoke test using given dot file checking the consensus history.
    /// `missing_one_consensus=true` if the dump-graphs was taken when consensus is reached (last
    /// block missing).
    fn smoke_consensus_history(path: &str, missing_one_consensus: bool) {
        let replay = unwrap!(Record::parse(path));
        let expected_history = replay.consensus_history();

        let actual = replay.play();
        let actual_history = actual.meta_election_consensus_history_hash();

        if missing_one_consensus {
            assert_eq!(
                TruncatedHashes::new_with_one_missing_element(&expected_history),
                TruncatedHashes::new_with_one_truncated_element(&actual_history)
            );
        } else {
            assert_eq!(expected_history, actual_history);
        }
    }

    // Note: skip this test when malice-detection is enabled, because there could be a mismatch
    // between parsed and replayed graphs when the dot file contains malice (e.g.: fork). This is
    // because parsing does not create accusation events but replaying does.
    #[cfg(not(feature = "malice-detection"))]
    #[test]
    fn smoke_parsec() {
        use std::fs;
        use walkdir::WalkDir;

        let is_dot_file = |path: &PathBuf| {
            path.extension()
                .map(|extension| extension.to_string_lossy() == "dot")
                .unwrap_or(false)
        };

        // 50kB seems to strike a reasonable balance between including quite a few dot files, while
        // not having too big of an impact on the test's running time.
        let max_file_size = 50_000;
        let mut checked_at_least_one_file = false;
        for path in WalkDir::new("input_graphs")
            .into_iter()
            .map(|entry| unwrap!(entry).path().to_owned())
            .filter(is_dot_file)
            .filter(|path| unwrap!(fs::metadata(path)).len() < max_file_size)
        {
            smoke(path);
            checked_at_least_one_file = true;
        }
        assert!(
            checked_at_least_one_file,
            "All dot files are over {} bytes, so none were checked.",
            max_file_size
        );
    }

    #[test]
    fn smoke_other_peer_names() {
        smoke("input_graphs/dev_utils_record_tests_smoke_other_peer_names/annie.dot")
    }

    #[test]
    fn smoke_routing() {
        smoke("input_graphs/dev_utils_record_tests_smoke_routing/minimal.dot")
    }

    #[test]
    fn smoke_consensus_history_parsec() {
        let missing_one_consensus = false;
        smoke_consensus_history("input_graphs/benches/minimal.dot", missing_one_consensus)
    }

    #[test]
    fn smoke_consensus_history_other_peer_names() {
        let missing_one_consensus = true;
        smoke_consensus_history(
            "input_graphs/dev_utils_record_tests_smoke_other_peer_names/annie.dot",
            missing_one_consensus,
        )
    }
}
