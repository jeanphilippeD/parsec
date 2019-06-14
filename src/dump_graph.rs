// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    gossip::Graph,
    id::SecretId,
    meta_voting::MetaElection,
    network_event::NetworkEvent,
    observation::{ConsensusMode, ObservationStore},
    peer_list::PeerList,
};

/// Use this to initialise the folder into which the dot files will be dumped.  This allows the
/// folder's path to be displayed at the start of a run, rather than at the arbitrary point when
/// the first node's first stable block is about to be returned.  No-op for case where `dump-graphs`
/// feature not enabled.
pub(crate) fn init() {
    #[cfg(feature = "dump-graphs")]
    detail::init()
}

#[derive(Clone)]
pub enum DumpGraphContext {
    ConsensusReached,
    DroppingParsec,
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
    consensus_mode: ConsensusMode,
    gossip_graph: &Graph<S::PublicId>,
    meta_election: &MetaElection,
    peer_list: &PeerList<S>,
    observations: &ObservationStore<T, S::PublicId>,
    info: &DumpGraphContext,
) {
    detail::to_file(
        owner_id,
        consensus_mode,
        gossip_graph,
        meta_election,
        peer_list,
        observations,
        info,
    )
}
#[cfg(not(feature = "dump-graphs"))]
pub(crate) fn to_file<T: NetworkEvent, S: SecretId>(
    _: &S::PublicId,
    _: ConsensusMode,
    _: &Graph<S::PublicId>,
    _: &MetaElection,
    _: &PeerList<S>,
    _: &ObservationStore<T, S::PublicId>,
    _: &DumpGraphContext,
) {
}

#[cfg(feature = "dump-graphs")]
pub use self::detail::{DumpGraphMode, DIR, DUMP_MODE};

#[cfg(feature = "dump-graphs")]
mod detail {
    use super::DumpGraphContext;
    use crate::{
        gossip::{Cause, Event, EventIndex, Graph, GraphSnapshot, IndexedEventRef},
        id::{PublicId, SecretId},
        meta_voting::{MetaElection, MetaElectionSnapshot, MetaEvent, MetaVote, Observer},
        network_event::NetworkEvent,
        observation::{ConsensusMode, Malice, Observation, ObservationKey, ObservationStore},
        peer_list::{PeerIndex, PeerIndexMap, PeerIndexSet, PeerList},
        serialise,
    };
    use itertools::Itertools;
    use rand::{self, Rng};
    use std::{
        cell::RefCell,
        cmp,
        collections::{BTreeMap, BTreeSet},
        env,
        fmt::{self, Debug, Formatter},
        fs::{self, File},
        io::{self, BufWriter, Write},
        path::{Path, PathBuf},
        process::Command,
        thread,
    };

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
                x.split(',').map(ToString::to_string).collect_vec()
            })
        };

        static ref DUMP_GRAPH_MODE: DumpGraphMode = {
            // PARSEC_DUMP_GRAPH_MODE=on_parsec_drop to only dump graph when parsec is dropped.
            env::var("PARSEC_DUMP_GRAPH_MODE").ok().and_then(|x| {
                match x.as_ref() {
                    "on_parsec_drop" => Some(DumpGraphMode::OnParsecDrop),
                    _ => None
                }
            }).unwrap_or(DumpGraphMode::OnConsensus)
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

        /// Which dumps to output
        pub static DUMP_MODE: RefCell<DumpGraphMode> = RefCell::new(DUMP_GRAPH_MODE.clone());
    );

    thread_local!(static DUMP_COUNTS: RefCell<BTreeMap<String, usize>> =
        RefCell::new(BTreeMap::new()));

    /// To control the dump graph behaviour.
    /// In all modes, also dump when parsec is dropped if panicking.
    #[derive(Clone)]
    pub enum DumpGraphMode {
        /// Only dump on consensus.
        OnConsensus,
        /// Only dump when parsec is dropped.
        OnParsecDrop,
    }

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
        consensus_mode: ConsensusMode,
        gossip_graph: &Graph<S::PublicId>,
        meta_election: &MetaElection,
        peer_list: &PeerList<S>,
        observations: &ObservationStore<T, S::PublicId>,
        info: &DumpGraphContext,
    ) {
        let need_process = DUMP_MODE.with(|mode| match (info, &*mode.borrow_mut()) {
            (DumpGraphContext::DroppingParsec, DumpGraphMode::OnParsecDrop)
            | (DumpGraphContext::ConsensusReached, DumpGraphMode::OnConsensus) => true,
            (DumpGraphContext::DroppingParsec, _) if thread::panicking() => true,
            _ => false,
        });
        if !need_process {
            return;
        }

        let id = sanitise_string(format!("{:?}", owner_id));

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

        let peer_ids = sanitise_peer_ids(peer_list);
        let short_peer_ids = short_peer_id_names(&peer_ids);

        match File::create(&file_path) {
            Ok(file) => {
                let mut dot_writer = DotWriter {
                    file: BufWriter::new(file),
                    consensus_mode,
                    gossip_graph,
                    meta_election,
                    peer_list,
                    observations: &DotObservation::from_observations(
                        &observations,
                        gossip_graph,
                        &peer_list,
                        &short_peer_ids,
                    ),
                    peer_ids: &peer_ids,
                    short_peer_ids: &short_peer_ids,
                    indent: 0,
                };

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

    fn dump_meta_votes(
        short_peer_ids: &PeerIndexMap<String>,
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
        let meta_votes = meta_votes
            .iter()
            .map(|(peer_index, meta_votes)| (unwrap!(short_peer_ids.get(peer_index)), meta_votes))
            .sorted_by(|(lhs_short_id, _), (rhs_short_id, _)| Ord::cmp(lhs_short_id, rhs_short_id));

        for (short_peer_id, meta_votes) in meta_votes {
            let prefix = format!("{}: ", short_peer_id);
            let blank_prefix = " ".repeat(prefix.len()).to_string();

            let mut prefix: &str = prefix.as_str();
            for mv in meta_votes {
                let (est, bin, aux, dec) = mv.values.as_chars();
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
        consensus_mode: ConsensusMode,
        gossip_graph: &'a Graph<S::PublicId>,
        meta_election: &'a MetaElection,
        peer_list: &'a PeerList<S>,
        observations: &'a DotObservationStore,
        peer_ids: &'a PeerIndexMap<DotPeerId>,
        short_peer_ids: &'a PeerIndexMap<String>,
        indent: usize,
    }

    impl<'a, S: SecretId + 'a> DotWriter<'a, S> {
        const COMMENT: &'static str = "/// ";

        fn indentation(&self) -> String {
            " ".repeat(self.indent)
        }

        fn indent(&mut self) {
            self.indent += 2;
        }

        fn dedent(&mut self) {
            self.indent -= 2;
        }

        fn index_to_short_name(&self, index: EventIndex) -> Option<String> {
            self.gossip_graph
                .get(index)
                .map(|event| self.event_to_short_name(event))
        }

        fn event_to_short_name(&self, event: IndexedEventRef<S::PublicId>) -> String {
            sanitise_event_short_name(event, &self.peer_list, &self.short_peer_ids)
        }

        fn writeln(&mut self, args: fmt::Arguments) -> io::Result<()> {
            writeln!(self.file, "{}", args)
        }

        fn write(&mut self) -> io::Result<()> {
            self.write_peer_list()?;
            self.write_consensus_mode()?;

            self.writeln(format_args!("digraph GossipGraph {{"))?;
            self.writeln(format_args!("  splines=false"))?;
            self.writeln(format_args!("  rankdir=BT\n"))?;

            let positions = self.calculate_positions();
            for (peer_index, peer_id) in self.peer_ids {
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
                self.peer_ids
                    .get(PeerIndex::OUR)
                    .unwrap_or(&DotPeerId::unknown())
            ))?;
            self.writeln(format_args!("{}{}peer_list: {{", Self::COMMENT, indent,))?;
            self.indent();
            let indent = self.indentation();
            for (index, peer) in self.peer_list.iter() {
                self.writeln(format_args!(
                    "{}{}{:?}: {:?}",
                    Self::COMMENT,
                    indent,
                    self.peer_ids.get(index).unwrap_or(&DotPeerId::unknown()),
                    peer.state(),
                ))?;
            }
            self.dedent();
            let indent = self.indentation();
            self.writeln(format_args!("{}{}}}", Self::COMMENT, indent))
        }

        fn write_consensus_mode(&mut self) -> io::Result<()> {
            let indent = self.indentation();
            let consensus_mode = self.consensus_mode;
            self.writeln(format_args!(
                "{}{}consensus_mode: {:?}",
                Self::COMMENT,
                indent,
                consensus_mode
            ))
        }

        fn calculate_positions(&self) -> Vec<usize> {
            let mut positions = Vec::new();
            positions.resize(self.gossip_graph.len(), 0);

            // gossip_graph in topological order: parent processed before children:
            for event in self.gossip_graph.iter() {
                let (self_parent_pos, other_parent_pos) = {
                    let position = |index: &Option<EventIndex>| {
                        index
                            .and_then(|index| positions.get(index.topological_index()))
                            .cloned()
                            .unwrap_or(0)
                    };
                    (
                        position(&event.self_parent()),
                        position(&event.other_parent()),
                    )
                };

                positions[event.topological_index()] =
                    cmp::max(&self_parent_pos, &other_parent_pos) + 1;
            }
            positions
        }

        fn write_subgraph(
            &mut self,
            peer_index: PeerIndex,
            peer_id: &DotPeerId,
            positions: &[usize],
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
            positions: &[usize],
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
                        let event_pos = *positions.get(event.topological_index()).unwrap_or(&0);
                        let parent_pos = *positions.get(parent.topological_index()).unwrap_or(&0);
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
                    self.event_to_short_name(event),
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
                        self.event_to_short_name(other_parent),
                        self.event_to_short_name(event)
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
                .peer_ids
                .iter()
                .map(|(_, id)| id)
                .sorted()
                .collect_vec();
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
                        self.event_to_short_name(event),
                        meta_events.get(&event_index),
                        self.observations,
                        &self.short_peer_ids,
                    );
                    self.writeln(format_args!(
                        "  \"{}\" {}",
                        self.event_to_short_name(event),
                        attr.to_string()
                    ))?;

                    self.write_cause_to_dot_format(&event)?;

                    let last_ancestors = event.last_ancestors().collect();
                    let last_ancestors = self.convert_peer_index_map(&last_ancestors);
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
            let mut buffer;
            let cause = match event.cause() {
                Cause::Requesting { recipient, .. } => {
                    buffer = format!(
                        "Requesting({:?})",
                        self.peer_ids
                            .get(*recipient)
                            .unwrap_or(&DotPeerId::unknown())
                    );
                    buffer.as_str()
                }
                Cause::Request { .. } => "Request",
                Cause::Response { .. } => "Response",
                Cause::Observation { ref vote, .. } => {
                    if let Some(observation) = self.observations.get(vote.payload_key()) {
                        buffer = format!("Observation({:?})", observation);
                        buffer.as_str()
                    } else {
                        "Observation(?)"
                    }
                }
                Cause::Initial => "Initial",
            };

            writeln!(&mut self.file, "/// cause: {}", cause)
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

            // write interesting events
            lines.push(format!(
                "{}{}interesting_events: {{",
                Self::COMMENT,
                self.indentation()
            ));
            self.indent();

            let interesting_events =
                self.convert_peer_index_map(&self.meta_election.interesting_events);
            for (peer, (events, _)) in &interesting_events {
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
                self.convert_peer_index_set(&self.meta_election.voters)
            ));

            // write unconsensused events
            let unconsensused_events: BTreeSet<_> = self
                .meta_election
                .unconsensused_events
                .ordered_indices
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
                    let creator_id = self.peer_ids.get(event.creator())?;

                    let creator_and_index = (creator_id, event.index_by_creator());
                    let short_name_and_mev = (self.event_to_short_name(event), mev);
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

                let observees = match mev.observer {
                    Observer::This(ref observees) => self.convert_peer_index_set(observees),
                    _ => BTreeSet::new(),
                };

                lines.push(format!(
                    "{}{}observees: {:?}",
                    Self::COMMENT,
                    self.indentation(),
                    observees
                ));
                let interesting_content = mev
                    .interesting_content
                    .iter()
                    .map(|obs_key| unwrap!(self.observations.get(obs_key)))
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
                .filter_map(|index| self.peer_ids.get(index))
                .cloned()
                .collect()
        }

        fn convert_peer_index_map<'v, V>(
            &self,
            input: &'v PeerIndexMap<V>,
        ) -> BTreeMap<DotPeerId, &'v V> {
            input
                .iter()
                .filter_map(|(index, value)| self.peer_ids.get(index).map(|id| (id.clone(), value)))
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
            short_peer_ids: &PeerIndexMap<String>,
        ) -> Self {
            let mut attr = Self {
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

                if meta_event.is_observer() {
                    attr.fillcolor = "style=filled, fillcolor=orange";
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

    impl DotPeerId {
        fn unknown() -> Self {
            Self {
                value: "???".to_string(),
            }
        }
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
        fn from_observations<T: NetworkEvent, S: SecretId>(
            observations: &ObservationStore<T, S::PublicId>,
            graph: &Graph<S::PublicId>,
            peer_list: &PeerList<S>,
            short_peer_ids: &PeerIndexMap<String>,
        ) -> DotObservationStore {
            observations
                .iter()
                .map(|(key, info)| {
                    let observation = DotObservation::new(
                        &key,
                        &info.observation,
                        graph,
                        peer_list,
                        short_peer_ids,
                    );
                    (*key, observation)
                })
                .collect()
        }

        fn new<T: NetworkEvent, S: SecretId>(
            key: &ObservationKey,
            observation: &Observation<T, S::PublicId>,
            graph: &Graph<S::PublicId>,
            peer_list: &PeerList<S>,
            short_peer_ids: &PeerIndexMap<String>,
        ) -> Self {
            let value = match observation {
                Observation::Genesis { group, .. } => format!(
                    "Genesis({:?})",
                    group.iter().map(sanitise_peer_id).collect::<BTreeSet<_>>()
                ),
                Observation::Add { peer_id, .. } => format!("Add({:?})", sanitise_peer_id(peer_id)),
                Observation::Remove { peer_id, .. } => {
                    format!("Remove({:?})", sanitise_peer_id(peer_id))
                }
                Observation::Accusation { offender, malice } => format!(
                    "Accusation {{ {:?}, {} }}",
                    sanitise_peer_id(offender),
                    write_malice_to_string(malice, graph, peer_list, short_peer_ids),
                ),
                Observation::DkgResult(result) => format!("DkgResult({:?})", result),
                Observation::DkgMessage(msg) => format!("DkgMessage({:?})", msg),
                Observation::OpaquePayload(payload) => {
                    let max_length = 16;
                    let mut payload_str = sanitise_string(format!("{:?}", payload));

                    // Make unique if cannot show all
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

            DotObservation { value }
        }
    }

    fn write_malice_to_string<T: NetworkEvent, S: SecretId>(
        malice: &Malice<T, S::PublicId>,
        graph: &Graph<S::PublicId>,
        peer_list: &PeerList<S>,
        short_peer_ids: &PeerIndexMap<String>,
    ) -> String {
        let get_short_name_by_hash = |event_hash| {
            sanitise_event_short_name(
                unwrap!(graph.get_by_hash(event_hash)),
                peer_list,
                short_peer_ids,
            )
        };
        match malice {
            Malice::Fork(event_hash) => format!("Fork({})", get_short_name_by_hash(event_hash)),
            Malice::InvalidAccusation(event_hash) => {
                format!("InvalidAccusation({})", get_short_name_by_hash(event_hash))
            }
            Malice::Accomplice(event_hash, boxed_malice) => format!(
                "Accomplice({}, {})",
                get_short_name_by_hash(event_hash),
                write_malice_to_string(boxed_malice, graph, peer_list, short_peer_ids),
            ),
            _ => panic!("unsupported yet"),
        }
    }

    fn fork_index<S: SecretId>(
        event: IndexedEventRef<S::PublicId>,
        peer_list: &PeerList<S>,
    ) -> Option<usize> {
        if peer_list
            .events_by_index(event.creator(), event.index_by_creator())
            .take(2)
            .count()
            <= 1
        {
            return None;
        }

        peer_list
            .events_by_index(event.creator(), event.index_by_creator())
            .position(|event_index| event_index == event.event_index())
    }

    fn sanitise_event_short_name<S: SecretId>(
        event: IndexedEventRef<S::PublicId>,
        peer_list: &PeerList<S>,
        short_peer_ids: &PeerIndexMap<String>,
    ) -> String {
        let peer_short_name: &str = short_peer_ids
            .get(event.creator())
            .map(String::as_str)
            .unwrap_or("???");

        if let Some(fork_index) = fork_index(event, peer_list) {
            format!(
                "{}_{},{}",
                peer_short_name,
                event.index_by_creator(),
                fork_index
            )
        } else {
            format!("{}_{}", peer_short_name, event.index_by_creator())
        }
    }

    fn sanitise_peer_ids<S: SecretId>(peer_list: &PeerList<S>) -> PeerIndexMap<DotPeerId> {
        peer_list
            .iter()
            .map(|(index, peer)| (index, sanitise_peer_id(peer.id())))
            .collect()
    }

    fn sanitise_peer_id<P: PublicId>(peer_id: &P) -> DotPeerId {
        let value = sanitise_string(format!("{:?}", peer_id));
        DotPeerId { value }
    }

    fn sanitise_string(mut value: String) -> String {
        value.retain(|c| c.is_ascii() && c.is_alphanumeric());
        value
    }

    fn short_peer_id_names(peer_ids: &PeerIndexMap<DotPeerId>) -> PeerIndexMap<String> {
        // Sort ids so we can find difference in most similar names
        let sorted_ids = peer_ids
            .iter()
            .map(|(_index, id)| id.value.as_str())
            .sorted()
            .collect_vec();

        // Keep character after the longest adjacent mismatch so each truncated names is different
        let num_char_if_only_one_element = 1;
        let mismatch_len = sorted_ids
            .windows(2)
            .map(|adjacent: &[&str]| find_mismatch(adjacent[0].as_bytes(), adjacent[1].as_bytes()))
            .max()
            .map(|len| len + 1)
            .unwrap_or(num_char_if_only_one_element);

        // Have all short names the same length or shorter
        let make_short_name = |name: &str| {
            let copy_len = cmp::min(mismatch_len, name.len());
            name[0..copy_len].to_string()
        };

        peer_ids
            .iter()
            .map(|(index, id)| (index, make_short_name(&id.value)))
            .collect()
    }

    fn find_mismatch(s1: &[u8], s2: &[u8]) -> usize {
        s1.iter()
            .enumerate()
            .position(|(index, c)| s2.get(index) != Some(&c))
            .unwrap_or_else(|| cmp::min(s1.len(), s2.len()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn new_peer_id_peer_index_map(values: &[(usize, &str)]) -> PeerIndexMap<String> {
            values
                .iter()
                .map(|(index, string)| (PeerIndex::new_test_peer_index(*index), string.to_string()))
                .collect()
        }

        fn new_dot_peer_id_peer_index_map(values: &[(usize, &str)]) -> PeerIndexMap<DotPeerId> {
            new_peer_id_peer_index_map(values)
                .iter()
                .map(|(index, value)| (index, value.clone()))
                .map(|(index, value)| (index, DotPeerId { value }))
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
                [(3, "Alic"), (2, "Al"), (6, "Alin")],
                [(3, "Al"), (2, "Bo"), (6, "An")],
            ]
            .iter()
            .map(|list| new_peer_id_peer_index_map(list))
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
