// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::gossip::Graph;
use crate::id::SecretId;
use crate::meta_voting::MetaElection;
use crate::network_event::NetworkEvent;
use crate::observation::ObservationStore;
use crate::peer_list::PeerList;

/// Use this to initialise the folder into which the dot files will be dumped.  This allows the
/// folder's path to be displayed at the start of a run, rather than at the arbitrary point when
/// the first node's first stable block is about to be returned.  No-op for case where `dump-graphs`
/// feature not enabled.
pub(crate) fn init() {
    #[cfg(feature = "dump-graphs")]
    detail::init()
}

/// This function will dump the graphs from the specified peer in dot format to a random folder in
/// the system's temp dir.  It will also try to create an SVG from each such dot file, but will not
/// fail or report failure if the SVG files can't be created.  The location of this folder will be
/// printed to stdout.  The function will never panic, and hence is suitable for use in creating
/// these files after a thread has already panicked, e.g. in the case of a test failure.  No-op for
/// case where `dump-graphs` feature not enabled.
#[cfg(feature = "dump-graphs")]
pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
    owner_id: &S::PublicId,
    gossip_graph: &Graph<S::PublicId>,
    meta_election: &MetaElection,
    peer_list: &PeerList<S>,
    observations: &ObservationStore<T, S::PublicId>,
) {
    detail::to_file(
        owner_id,
        gossip_graph,
        meta_election,
        peer_list,
        observations,
    )
}
#[cfg(not(feature = "dump-graphs"))]
pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
    _: &S::PublicId,
    _: &Graph<S::PublicId>,
    _: &MetaElection,
    _: &PeerList<S>,
    _: &ObservationStore<T, S::PublicId>,
) {
}

#[cfg(feature = "dump-graphs")]
pub use self::detail::DIR;

#[cfg(feature = "dump-graphs")]
mod detail {
    use crate::gossip::{
        Cause, Event, EventHash, EventIndex, Graph, GraphSnapshot, IndexedEventRef,
    };
    use crate::id::{PublicId, SecretId};
    use crate::meta_voting::{MetaElection, MetaElectionSnapshot, MetaEvent, MetaVote};
    use crate::network_event::NetworkEvent;
    use crate::observation::{Observation, ObservationKey, ObservationStore};
    use crate::peer_list::{PeerIndex, PeerIndexMap, PeerIndexSet, PeerList};
    use crate::serialise;
    use rand::{self, Rng};
    use std::cell::RefCell;
    use std::cmp::{self, min};
    use std::collections::{BTreeMap, BTreeSet};
    use std::env;
    use std::fmt::{self, Debug, Formatter};
    use std::fs::{self, File};
    use std::io::{self, BufWriter, Write};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;

    lazy_static! {
        static ref ROOT_DIR_PREFIX: PathBuf = { env::temp_dir().join("parsec_graphs") };
        static ref ROOT_DIR_SUFFIX: String = {
            rand::thread_rng()
                .gen_ascii_chars()
                .take(6)
                .collect::<String>()
        };
        static ref ROOT_DIR: PathBuf = { ROOT_DIR_PREFIX.join(&*ROOT_DIR_SUFFIX) };

        static ref GENERATE_SVG: bool = {
            // PARSEC_DUMP_GRAPH_SVG=0 to disable svg file generation
            env::var("PARSEC_DUMP_GRAPH_SVG").ok().map_or(true, |x| x != "0")
        };

        static ref FILTER_PEERS: Option<Vec<String>> = {
            // PARSEC_DUMP_GRAPH_PEERS=Alice,Bob to only dump graph for them.
            env::var("PARSEC_DUMP_GRAPH_PEERS").ok().map(|x| {
                x.split(',').map(|x | x.to_string()).collect::<Vec<String>>()
            })
        };
    }

    thread_local!(
        /// The directory to which test data is dumped
        pub static DIR: PathBuf = {
            let dir = match thread::current().name() {
                Some(thread_name) if thread_name != "main" => {
                    ROOT_DIR.join(thread_name.replace("::", "_"))
                }
                _ => ROOT_DIR.clone(),
            };
            if let Err(error) = fs::create_dir_all(&dir) {
                println!(
                    "Failed to create folder {} for dot files: {:?}",
                    dir.display(),
                    error
                );
            } else {
                println!("Writing dot files in {}", dir.display());
            }
            dir
        };
    );

    thread_local!(static DUMP_COUNTS: RefCell<BTreeMap<String, usize>> =
        RefCell::new(BTreeMap::new()));

    fn catch_dump<S: SecretId>(
        mut file_path: PathBuf,
        gossip_graph: &Graph<S::PublicId>,
        peer_list: &PeerList<S>,
        meta_election: &MetaElection,
    ) {
        if let Some("dev_utils::dot_parser::tests::dot_parser") = thread::current().name() {
            let snapshot = (
                GraphSnapshot::new(gossip_graph),
                MetaElectionSnapshot::new(meta_election, gossip_graph, peer_list),
            );
            let snapshot = serialise(&snapshot);

            assert!(file_path.set_extension("core"));
            let mut file = unwrap!(File::create(&file_path));
            unwrap!(file.write_all(&snapshot));
        }
    }

    pub(crate) fn init() {
        DIR.with(|_| ());
    }

    pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
        owner_id: &S::PublicId,
        gossip_graph: &Graph<S::PublicId>,
        meta_election: &MetaElection,
        peer_list: &PeerList<S>,
        observations: &ObservationStore<T, S::PublicId>,
    ) {
        let id = sanitize_peer_id(owner_id).value;

        if let Some(ref filter_peers) = *FILTER_PEERS {
            if !filter_peers.contains(&id) {
                return;
            }
        }

        let call_count = DUMP_COUNTS.with(|counts| {
            let mut borrowed_counts = counts.borrow_mut();
            let count = borrowed_counts.entry(id.clone()).or_insert(0);
            *count += 1;
            *count
        });
        let file_path = DIR.with(|dir| dir.join(format!("{}-{:03}.dot", id, call_count)));
        catch_dump(file_path.clone(), gossip_graph, peer_list, meta_election);

        let peer_ids = sanitize_peer_ids(peer_list);
        let short_peer_ids = short_peer_id_names(&peer_ids);

        match DotWriter::new(
            &file_path,
            gossip_graph,
            meta_election,
            peer_list,
            &observations
                .iter()
                .map(|(key, info)| (*key, DotObservation::new(&key, &info.observation)))
                .collect(),
            &peer_ids,
            &short_peer_ids,
        ) {
            Ok(mut dot_writer) => {
                if let Err(error) = dot_writer.write() {
                    println!("Error writing to {:?}: {:?}", file_path, error);
                }
            }
            Err(error) => println!("Failed to create {:?}: {:?}", file_path, error),
        }

        // Try to generate an SVG file from the dot file, but we don't care about failure here.
        if *GENERATE_SVG {
            if let Ok(mut child) = Command::new("dot")
                .args(&["-Tsvg", file_path.to_string_lossy().as_ref(), "-O"])
                .spawn()
            {
                let _ = child.wait();
            }
        }

        // Create symlink so it's easier to find the latest graphs.
        let _ = force_symlink_dir(&*ROOT_DIR, ROOT_DIR_PREFIX.join("latest"));
    }

    fn parent_pos<P: PublicId>(
        index: usize,
        parent: Option<IndexedEventRef<P>>,
        positions: &BTreeMap<EventHash, usize>,
    ) -> Option<usize> {
        if let Some(parent_hash) = parent.map(|e| e.inner().hash()) {
            if let Some(parent_pos) = positions.get(parent_hash) {
                Some(*parent_pos)
            } else if *parent_hash == EventHash::ZERO {
                Some(index)
            } else {
                None
            }
        } else {
            Some(index)
        }
    }

    fn force_symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
        use std::io::ErrorKind;
        // Try to overwrite the destination if it exists, but only if it is a symlink, to prevent
        // accidental data loss.
        match fs::symlink_metadata(&dst) {
            Err(ref error) if error.kind() == ErrorKind::NotFound => (),
            Err(error) => return Err(error),
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    let _ = remove_symlink_dir(&dst);
                }
            }
        }

        symlink_dir(src, dst)
    }

    #[cfg(unix)]
    fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
        use std::os::unix::fs::symlink;
        symlink(src, dst)
    }

    #[cfg(unix)]
    fn remove_symlink_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
        fs::remove_file(path)
    }

    #[cfg(windows)]
    fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> io::Result<()> {
        use std::os::windows::fs::symlink_dir;
        symlink_dir(src, dst)
    }

    #[cfg(windows)]
    fn remove_symlink_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
        fs::remove_dir(path)
    }

    fn as_short_string(value: Option<bool>) -> &'static str {
        match value {
            None => "-",
            Some(true) => "t",
            Some(false) => "f",
        }
    }

    fn dump_meta_votes(
        short_peer_ids: &PeerIndexMap<DotPeerId>,
        meta_votes: &PeerIndexMap<Vec<MetaVote>>,
        comment: bool,
    ) -> Vec<String> {
        let mut lines = vec![];
        if comment {
            lines.push("  stage est bin aux dec".to_string());
        } else {
            lines.push(
                "<tr><td></td><td width=\"50\">stage</td>\
                 <td width=\"30\">est</td>\
                 <td width=\"30\">bin</td>\
                 <td width=\"30\">aux</td>\
                 <td width=\"30\">dec</td></tr>"
                    .to_string(),
            );
        }
        for (peer_index, meta_votes) in meta_votes {
            let prefix = format!("{}: ", unwrap!(short_peer_ids.get(peer_index)).value);
            let blank_prefix = " ".repeat(prefix.len()).to_string();

            let mut prefix: &str = prefix.as_str();
            for mv in meta_votes {
                let est = mv.estimates.as_short_string();
                let bin = mv.bin_values.as_short_string();
                let aux = as_short_string(mv.aux_value);
                let dec = as_short_string(mv.decision);
                let line = if comment {
                    format!(
                        "{}{}/{:?}   {}   {}   {}   {} ",
                        prefix, mv.round, mv.step, est, bin, aux, dec
                    )
                } else {
                    format!(
                        "<tr><td>{}</td><td>{}/{:?}</td><td>{}</td>\
                         <td>{}</td><td>{}</td><td>{}</td></tr>",
                        prefix, mv.round, mv.step, est, bin, aux, dec
                    )
                };

                // Only the first line have the prefix
                prefix = blank_prefix.as_str();

                lines.push(line);
            }
        }
        lines
    }

    struct DotWriter<'a, S: SecretId + 'a> {
        file: BufWriter<File>,
        gossip_graph: &'a Graph<S::PublicId>,
        meta_election: &'a MetaElection,
        peer_list: &'a PeerList<S>,
        observations: &'a DotObservationStore,
        peer_ids: &'a PeerIndexMap<DotPeerId>,
        short_peer_ids: &'a PeerIndexMap<DotPeerId>,
        indent: usize,
    }

    impl<'a, S: SecretId + 'a> DotWriter<'a, S> {
        const COMMENT: &'static str = "/// ";

        fn new(
            file_path: &Path,
            gossip_graph: &'a Graph<S::PublicId>,
            meta_election: &'a MetaElection,
            peer_list: &'a PeerList<S>,
            observations: &'a DotObservationStore,
            peer_ids: &'a PeerIndexMap<DotPeerId>,
            short_peer_ids: &'a PeerIndexMap<DotPeerId>,
        ) -> io::Result<Self> {
            File::create(&file_path).map(|file| DotWriter {
                file: BufWriter::new(file),
                gossip_graph,
                meta_election,
                peer_list,
                observations,
                peer_ids,
                short_peer_ids,
                indent: 0,
            })
        }

        fn indentation(&self) -> String {
            " ".repeat(self.indent)
        }

        fn indent(&mut self) {
            self.indent += 2;
        }

        fn dedent(&mut self) {
            self.indent -= 2;
        }

        fn index_to_peer_id(&self, index: PeerIndex) -> DotPeerId {
            self.peer_ids
                .get(index)
                .cloned()
                .unwrap_or_else(|| DotPeerId {
                    value: "???".to_string(),
                })
        }

        fn index_to_short_name(&self, index: EventIndex) -> Option<String> {
            self.gossip_graph
                .get(index)
                .map(|event| self.event_to_short_name(&event))
        }

        fn event_to_short_name(&self, event: &Event<S::PublicId>) -> String {
            let peer_short_name: &str = self
                .short_peer_ids
                .get(event.creator())
                .map(|id| id.value.as_str())
                .unwrap_or("???");

            format!("{}_{}", peer_short_name, event.index_by_creator())
        }

        fn writeln(&mut self, args: fmt::Arguments) -> io::Result<()> {
            writeln!(self.file, "{}", args)
        }

        fn write(&mut self) -> io::Result<()> {
            self.write_peer_list()?;

            self.writeln(format_args!("digraph GossipGraph {{"))?;
            self.writeln(format_args!("  splines=false"))?;
            self.writeln(format_args!("  rankdir=BT\n"))?;

            let positions = self.calculate_positions();
            let peer_ids = self.peer_ids;
            for (peer_index, peer_id) in self
                .peer_list
                .iter()
                .filter_map(|(index, _)| peer_ids.get(index).map(|id| (index, id)))
            {
                self.write_subgraph(peer_index, peer_id, &positions)?;
                self.write_other_parents(peer_index)?;
            }

            self.write_peers()?;

            self.writeln(format_args!("/// ===== details of events ====="))?;
            for (peer_index, _) in self.peer_list.iter() {
                self.write_event_details(peer_index)?;
            }
            self.writeln(format_args!("}}\n"))?;

            self.write_meta_elections()?;

            Ok(())
        }

        fn write_peer_list(&mut self) -> io::Result<()> {
            let indent = self.indentation();
            self.writeln(format_args!(
                "{}{}our_id: {:?}",
                Self::COMMENT,
                indent,
                sanitize_peer_id(self.peer_list.our_id().public_id())
            ))?;
            self.writeln(format_args!("{}{}peer_list: {{", Self::COMMENT, indent,))?;
            self.indent();
            let indent = self.indentation();
            for (index, peer) in self.peer_list.iter() {
                self.writeln(format_args!(
                    "{}{}{:?}: {:?}",
                    Self::COMMENT,
                    indent,
                    self.index_to_peer_id(index),
                    peer.state(),
                ))?;
            }
            self.dedent();
            let indent = self.indentation();
            self.writeln(format_args!("{}{}}}", Self::COMMENT, indent))
        }

        fn calculate_positions(&self) -> BTreeMap<EventHash, usize> {
            let mut positions = BTreeMap::new();
            while positions.len() < self.gossip_graph.len() {
                for event in self.gossip_graph {
                    if !positions.contains_key(event.hash()) {
                        let self_parent_pos = if let Some(position) = parent_pos(
                            event.index_by_creator(),
                            self.gossip_graph.self_parent(event),
                            &positions,
                        ) {
                            position
                        } else {
                            continue;
                        };
                        let other_parent_pos = if let Some(position) = parent_pos(
                            event.index_by_creator(),
                            self.gossip_graph.other_parent(event),
                            &positions,
                        ) {
                            position
                        } else {
                            continue;
                        };
                        let _ = positions.insert(
                            *event.hash(),
                            cmp::max(self_parent_pos, other_parent_pos) + 1,
                        );
                        break;
                    }
                }
            }
            positions
        }

        fn write_subgraph(
            &mut self,
            peer_index: PeerIndex,
            peer_id: &DotPeerId,
            positions: &BTreeMap<EventHash, usize>,
        ) -> io::Result<()> {
            self.writeln(format_args!("  style=invis"))?;
            self.writeln(format_args!("  subgraph cluster_{:?} {{", peer_id))?;
            self.writeln(format_args!("    label=\"{:?}\"", peer_id))?;
            self.writeln(format_args!("    \"{:?}\" [style=invis]", peer_id))?;
            self.write_self_parents(peer_index, peer_id, positions)?;
            self.writeln(format_args!("  }}"))
        }

        fn write_self_parents(
            &mut self,
            peer_index: PeerIndex,
            peer_id: &DotPeerId,
            positions: &BTreeMap<EventHash, usize>,
        ) -> io::Result<()> {
            let mut lines = vec![];
            for event in self
                .peer_list
                .peer_events(peer_index)
                .filter_map(|hash| self.gossip_graph.get(hash))
            {
                let (before_arrow, suffix) = match event
                    .self_parent()
                    .and_then(|index| self.gossip_graph.get(index))
                {
                    None => (format!("\"{:?}\"", peer_id), "[style=invis]".to_string()),
                    Some(parent) => {
                        let event_pos = *positions.get(event.hash()).unwrap_or(&0);
                        let parent_pos = *positions.get(parent.hash()).unwrap_or(&0);
                        let minlen = if event_pos > parent_pos {
                            event_pos - parent_pos
                        } else {
                            1
                        };
                        (
                            format!(
                                "\"{}\"",
                                self.index_to_short_name(parent.event_index())
                                    .unwrap_or_else(|| "???".to_string())
                            ),
                            format!("[minlen={}]", minlen),
                        )
                    }
                };
                lines.push(format!(
                    "    {} -> \"{}\" {}",
                    before_arrow,
                    self.event_to_short_name(&event),
                    suffix
                ));
            }
            if !lines.is_empty() {
                self.writeln(format_args!("{}", lines.join("\n")))?;
            }
            Ok(())
        }

        fn write_other_parents(&mut self, peer_index: PeerIndex) -> io::Result<()> {
            let mut lines = vec![];
            for event in self
                .peer_list
                .peer_events(peer_index)
                .filter_map(|hash| self.gossip_graph.get(hash))
            {
                if let Some(other_parent) = event
                    .other_parent()
                    .and_then(|other_hash| self.gossip_graph.get(other_hash))
                {
                    lines.push(format!(
                        "  \"{}\" -> \"{}\" [constraint=false]",
                        self.event_to_short_name(&other_parent),
                        self.event_to_short_name(&event)
                    ));
                }
            }
            self.writeln(format_args!("{}", lines.join("\n")))?;
            self.writeln(format_args!(""))
        }

        fn write_peers(&mut self) -> io::Result<()> {
            self.writeln(format_args!("  {{"))?;
            self.writeln(format_args!("    rank=same"))?;
            let mut peer_ids = self
                .peer_list
                .iter()
                .filter_map(|(index, _)| self.peer_ids.get(index))
                .collect::<Vec<_>>();
            for peer_id in &peer_ids {
                self.writeln(format_args!(
                    "    \"{:?}\" [style=filled, color=white]",
                    peer_id
                ))?;
            }
            self.writeln(format_args!("  }}"))?;

            let mut peer_order = String::new();
            let last_peer_id = peer_ids.pop();
            for peer_id in peer_ids {
                peer_order.push_str(&format!("\"{:?}\" -> ", peer_id));
            }
            if let Some(peer_id) = last_peer_id {
                peer_order.push_str(&format!("\"{:?}\" [style=invis]", peer_id));
            }
            self.writeln(format_args!("  {}\n", peer_order))
        }

        fn write_event_details(&mut self, peer_index: PeerIndex) -> io::Result<()> {
            let meta_events = self.meta_election.meta_events();
            for event_index in self.peer_list.peer_events(peer_index) {
                if let Some(event) = self.gossip_graph.get(event_index) {
                    let attr = EventAttributes::new(
                        event.inner(),
                        self.event_to_short_name(event.inner()),
                        meta_events.get(&event_index),
                        self.observations,
                        &self.short_peer_ids,
                    );
                    self.writeln(format_args!(
                        "  \"{}\" {}",
                        self.event_to_short_name(&event),
                        attr.to_string()
                    ))?;

                    self.write_cause_to_dot_format(&event)?;

                    let last_ancestors = self.convert_peer_index_map(event.last_ancestors());
                    writeln!(&mut self.file, "/// last_ancestors: {:?}", last_ancestors)?;

                    self.writeln(format_args!(""))?;
                }
            }
            Ok(())
        }

        pub fn write_cause_to_dot_format(
            &mut self,
            event: &IndexedEventRef<S::PublicId>,
        ) -> io::Result<()> {
            let observation = match event.cause() {
                Cause::Request { .. } => "Request".to_string(),
                Cause::Response { .. } => "Response".to_string(),
                Cause::Observation { ref vote, .. } => {
                    if let Some(observation) = self.observations.get(vote.payload_key()) {
                        format!("Observation({:?})", observation)
                    } else {
                        "Observation(?)".to_string()
                    }
                }
                Cause::Initial => "Initial".to_string(),
            };

            writeln!(&mut self.file, "/// cause: {}", observation)
        }

        fn write_meta_elections(&mut self) -> io::Result<()> {
            let indent = self.indentation();
            self.writeln(format_args!(
                "{}{}===== meta-elections =====",
                Self::COMMENT,
                indent
            ))?;
            let mut lines = vec![];
            lines.push(format!(
                "{}{}consensus_history:",
                Self::COMMENT,
                self.indentation()
            ));
            for key in self.meta_election.consensus_history() {
                lines.push(format!(
                    "{}{}{}",
                    Self::COMMENT,
                    self.indentation(),
                    key.hash().0.full_display()
                ));
            }

            lines.push("".to_string());

            // write round hashes
            lines.push(format!(
                "{}{}round_hashes: {{",
                Self::COMMENT,
                self.indentation()
            ));
            self.indent();
            let round_hashes = self.convert_peer_index_map(&self.meta_election.round_hashes);
            for (peer, hashes) in round_hashes {
                lines.push(format!(
                    "{}{}{:?} -> [",
                    Self::COMMENT,
                    self.indentation(),
                    peer
                ));
                self.indent();
                for hash in hashes {
                    lines.push(format!(
                        "{}{}RoundHash {{ round: {}, latest_block_hash: {} }}",
                        Self::COMMENT,
                        self.indentation(),
                        hash.round(),
                        hash.latest_block_hash().0.full_display(),
                    ));
                }
                self.dedent();
                lines.push(format!("{}{}]", Self::COMMENT, self.indentation()));
            }
            self.dedent();
            lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));

            // write interesting events
            lines.push(format!(
                "{}{}interesting_events: {{",
                Self::COMMENT,
                self.indentation()
            ));
            self.indent();

            let interesting_events =
                self.convert_peer_index_map(&self.meta_election.interesting_events);
            for (peer, events) in interesting_events {
                let event_names: Vec<String> = events
                    .iter()
                    .filter_map(|index| self.index_to_short_name(*index))
                    .collect();
                lines.push(format!(
                    "{}{}{:?} -> {:?}",
                    Self::COMMENT,
                    self.indentation(),
                    peer,
                    event_names
                ));
            }
            self.dedent();
            lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));

            // write all voters
            lines.push(format!(
                "{}{}all_voters: {:?}",
                Self::COMMENT,
                self.indentation(),
                self.convert_peer_index_set(&self.meta_election.all_voters)
            ));

            // write unconsensused events
            let unconsensused_events: BTreeSet<_> = self
                .meta_election
                .unconsensused_events
                .iter()
                .filter_map(|index| self.index_to_short_name(*index))
                .collect();
            lines.push(format!(
                "{}{}unconsensused_events: {:?}",
                Self::COMMENT,
                self.indentation(),
                unconsensused_events
            ));

            // write meta-events
            lines.push(format!(
                "{}{}meta_events: {{",
                Self::COMMENT,
                self.indentation()
            ));
            self.indent();
            // sort by creator, then index
            let meta_events = self
                .meta_election
                .meta_events
                .iter()
                .filter_map(|(index, mev)| {
                    let event = self.gossip_graph.get(*index)?;
                    let creator_id = self.index_to_peer_id(event.creator());

                    let creator_and_index = (creator_id, event.index_by_creator());
                    let short_name_and_mev = (self.event_to_short_name(&event), mev);
                    Some((creator_and_index, short_name_and_mev))
                })
                .collect::<BTreeMap<_, _>>();

            for (short_name, mev) in meta_events.values() {
                lines.push(format!(
                    "{}{}{} -> {{",
                    Self::COMMENT,
                    self.indentation(),
                    short_name
                ));
                self.indent();
                lines.push(format!(
                    "{}{}observees: {:?}",
                    Self::COMMENT,
                    self.indentation(),
                    self.convert_peer_index_set(&mev.observees)
                ));
                let interesting_content = mev
                    .interesting_content
                    .iter()
                    .map(|obs_key| unwrap!(self.observations.get(obs_key)).clone())
                    .collect::<Vec<_>>();
                lines.push(format!(
                    "{}{}interesting_content: {:?}",
                    Self::COMMENT,
                    self.indentation(),
                    interesting_content
                ));

                if !mev.meta_votes.is_empty() {
                    lines.push(format!(
                        "{}{}meta_votes: {{",
                        Self::COMMENT,
                        self.indentation()
                    ));
                    self.indent();
                    lines.extend(
                        dump_meta_votes(&self.short_peer_ids, &mev.meta_votes, true)
                            .into_iter()
                            .map(|s| format!("{}{}{}", Self::COMMENT, self.indentation(), s)),
                    );
                    self.dedent();
                    lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));
                }
                self.dedent();

                lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));
            }
            self.dedent();
            lines.push(format!("{}{}}}", Self::COMMENT, self.indentation()));

            self.writeln(format_args!("{}", lines.join("\n")))?;
            Ok(())
        }

        fn convert_peer_index_set(&self, input: &PeerIndexSet) -> BTreeSet<DotPeerId> {
            input
                .iter()
                .map(|index| self.index_to_peer_id(index))
                .collect()
        }

        fn convert_peer_index_map<'v, V>(
            &self,
            input: &'v PeerIndexMap<V>,
        ) -> BTreeMap<DotPeerId, &'v V> {
            input
                .iter()
                .map(|(index, value)| (self.index_to_peer_id(index), value))
                .collect()
        }
    }

    struct EventAttributes {
        label: String,
        fillcolor: &'static str,
        is_rectangle: bool,
    }

    impl EventAttributes {
        fn new<P: PublicId>(
            event: &Event<P>,
            event_short_name: String,
            opt_meta_event: Option<&MetaEvent>,
            observations: &DotObservationStore,
            short_peer_ids: &PeerIndexMap<DotPeerId>,
        ) -> Self {
            let mut attr = EventAttributes {
                fillcolor: "fillcolor=white",
                is_rectangle: false,
                label: event_short_name,
            };

            attr.label = format!(
                "<table border=\"0\" cellborder=\"0\" \
                 cellpadding=\"0\" cellspacing=\"0\">\n\
                 <tr><td colspan=\"6\">{}</td></tr>\n",
                attr.label
            );

            if let Some(event_payload) = event.payload_key().and_then(|key| observations.get(key)) {
                attr.label = format!(
                    "{}<tr><td colspan=\"6\">{:?}</td></tr>\n",
                    attr.label, event_payload
                );
                attr.fillcolor = "style=filled, fillcolor=cyan";
                attr.is_rectangle = true;
            }

            if let Some(meta_event) = opt_meta_event {
                if !meta_event.interesting_content.is_empty() {
                    let interesting_content = meta_event
                        .interesting_content
                        .iter()
                        .map(|obs_key| unwrap!(observations.get(obs_key)))
                        .collect::<Vec<_>>();
                    attr.label = format!(
                        "{}<tr><td colspan=\"6\">{:?}</td></tr>",
                        attr.label, interesting_content
                    );
                    attr.fillcolor = "style=filled, fillcolor=crimson";
                    attr.is_rectangle = true;
                }
                if !meta_event.meta_votes.is_empty() {
                    let meta_votes =
                        dump_meta_votes(short_peer_ids, &meta_event.meta_votes, false).join("\n");
                    attr.label = format!("{}{}", attr.label, meta_votes);
                }
                attr.is_rectangle = true;
            }

            attr.label = format!("{}</table>", attr.label);
            attr
        }

        fn to_string(&self) -> String {
            format!(
                "[{}, {}label=<{}>]",
                self.fillcolor,
                if self.is_rectangle {
                    "shape=rectangle, "
                } else {
                    ""
                },
                self.label
            )
        }
    }

    #[derive(PartialEq, Eq, Ord, PartialOrd, Clone)]
    struct DotPeerId {
        value: String,
    }

    impl Debug for DotPeerId {
        fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "{}", self.value)
        }
    }

    type DotObservationStore = BTreeMap<ObservationKey, DotObservation>;

    struct DotObservation {
        value: String,
    }

    impl Debug for DotObservation {
        fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
            write!(formatter, "{}", self.value)
        }
    }

    impl DotObservation {
        fn new<T: NetworkEvent, P: PublicId>(
            key: &ObservationKey,
            observation: &Observation<T, P>,
        ) -> Self {
            let value = match observation {
                Observation::Genesis(group) => format!(
                    "Genesis({:?})",
                    group.iter().map(sanitize_peer_id).collect::<BTreeSet<_>>()
                ),
                Observation::Add { peer_id, .. } => format!("Add({:?})", sanitize_peer_id(peer_id)),
                Observation::Remove { peer_id, .. } => {
                    format!("Remove({:?})", sanitize_peer_id(peer_id))
                }
                Observation::Accusation { offender, malice } => format!(
                    "Accusation {{ {:?}, {:?} }}",
                    sanitize_peer_id(offender),
                    malice
                ),
                Observation::OpaquePayload(payload) => {
                    let max_length = 16;
                    let mut payload_str = sanitize_string(format!("{:?}", payload));

                    if payload_str.len() > max_length {
                        let key_length = 10;
                        let mut payload_hash = format!("{:?}", key.hash());

                        payload_hash.truncate(key_length);
                        payload_str.truncate(max_length - key_length);

                        payload_str = payload_hash + &payload_str;
                    }
                    format!("OpaquePayload({})", payload_str)
                }
            };

            DotObservation { value: value }
        }
    }

    fn sanitize_peer_ids<S: SecretId>(peer_list: &PeerList<S>) -> PeerIndexMap<DotPeerId> {
        peer_list
            .iter()
            .map(|(index, peer)| (index, sanitize_peer_id(peer.id())))
            .collect()
    }

    fn sanitize_peer_id<P: PublicId>(peer_id: &P) -> DotPeerId {
        DotPeerId {
            value: sanitize_string(format!("{:?}", peer_id)),
        }
    }

    fn sanitize_string(mut value: String) -> String {
        value.retain(|c| c.is_ascii() && c.is_alphanumeric());
        value
    }

    fn short_peer_id_names(names: &PeerIndexMap<DotPeerId>) -> PeerIndexMap<DotPeerId> {
        if names.is_empty() {
            return PeerIndexMap::new();
        }

        let ids = {
            let mut ids: Vec<_> = names.iter().map(|(_index, id)| id.value.as_str()).collect();
            ids.sort();
            ids
        };

        let common_prefixes_len = ids
            .windows(2)
            .map(|adjacent: &[&str]| find_mismatch(adjacent[0].as_bytes(), adjacent[1].as_bytes()))
            .collect::<Vec<_>>();

        let prefix_len: usize = *unwrap!(common_prefixes_len.iter().min());
        let mismatch_len: usize = *unwrap!(common_prefixes_len.iter().max()) + 1;

        names
            .iter()
            .map(|(index, id)| {
                (
                    index,
                    DotPeerId {
                        value: id.value[prefix_len..min(mismatch_len, id.value.len())].to_string(),
                    },
                )
            })
            .collect()
    }

    fn find_mismatch(s1: &[u8], s2: &[u8]) -> usize {
        s1.iter()
            .enumerate()
            .position(|(index, c)| s2.get(index) != Some(&c))
            .unwrap_or_else(|| min(s1.len(), s2.len()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn new_dot_peer_id_peer_index_map(values: &[(usize, &str)]) -> PeerIndexMap<DotPeerId> {
            values
                .iter()
                .map(|(index, string)| {
                    (
                        PeerIndex::new_test_peer_index(*index),
                        DotPeerId {
                            value: string.to_string(),
                        },
                    )
                })
                .collect()
        }

        #[test]
        /// Basic happy path
        fn test_find_mismatch() {
            let expected = [
                ("Alice", "Bob", 0),
                ("Alice", "Al", 2),
                ("", "", 0),
                ("Alice", "Aline", 3),
            ];

            let actual = expected
                .iter()
                .map(|(s1, s2, _)| (*s1, *s2, find_mismatch(s1.as_bytes(), s2.as_bytes())))
                .collect::<Vec<_>>();

            assert_eq!(expected, actual.as_slice());
        }

        #[test]
        /// Basic happy path
        fn test_short_peer_id_names() {
            //
            // Arrange
            //
            let names = [
                [(3, "Alice"), (2, "Bob"), (6, "Carol")],
                [(3, "Alice"), (2, "Al"), (6, "Aline")],
                [(3, "Alice"), (2, "Bob"), (6, "Anne")],
            ]
            .iter()
            .map(|list| new_dot_peer_id_peer_index_map(list))
            .collect::<Vec<_>>();

            let expected = [
                [(3, "A"), (2, "B"), (6, "C")],
                [(3, "ic"), (2, ""), (6, "in")],
                [(3, "Al"), (2, "Bo"), (6, "An")],
            ]
            .iter()
            .map(|list| new_dot_peer_id_peer_index_map(list))
            .collect::<Vec<_>>();

            //
            // Act
            //
            let actual = names
                .iter()
                .map(|ids| short_peer_id_names(&ids))
                .collect::<Vec<_>>();

            //
            // Assert
            //
            assert_eq!(expected, actual);
        }
    }
}
