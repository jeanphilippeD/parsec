// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Tool to generate dot files for Parsec's functional tests.
//!
//! # Usage
//!
//! First, define your scenario below. Example:
//!
//! ```
//! scenarios
//!     .add("parsec::functional_tests::my_test_function", |env| {
//!         Schedule::new(
//!             env,
//!             &ScheduleOptions {
//!                 genesis_size: 6,
//!                 opaque_to_add: 1,
//!             }
//!         )
//!     })
//!     .seed([1, 2, 3, 4])
//!     .file("Alice", "alice.dot")
//!     .file("Dave", "dave.dot");
//! ```
//!
//! Notes:
//! - The name of the scenario is the fully-qualified name of the test function for which the dot
//!   files are to be generated.
//! - The body of the scenario is a lambda that returns `Schedule` according to which the scenario
//!   runs.
//! - Optionally, specify the seed to initialise the random number generator.
//!   If not specified, a randomly generated seed is used.
//! - Optionally specify the peers whose graphs should be outputted and the names of the files the
//!   graphs should be outputted to. If not specified, the default is to take Alice's graph and put
//!   it into a file named "alice.dot"
//!
//! When scenarios are defined, run the tool from within Parsec's root directory:
//!
//!     cargo run --release --manifest-path=dot_gen/Cargo.toml -- ARGS
//!
//! where ARGS are the arguments to the tool. Run with --help for more info.
//!
//! To speed up generation of bigger test cases:
//!     Use PARSEC_DUMP_GRAPH_SVG=0 to disable generation of .svg files with .dot files
//!     PARSEC_DUMP_GRAPH_PEERS=Alice,Bob,Carol to only generate temporary .dot/.svg files for Alice,Bob,Carol peers.
//!     PARSEC_DUMP_GRAPH_SVG=0 PARSEC_DUMP_GRAPH_PEERS=Alice,Bob,Carol cargo run --release --manifest-path=dot_gen/Cargo.toml -- ARGS
//!

#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types,
    warnings
)]
#![deny(
    bad_style,
    deprecated,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    plugin_as_library,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    unused,
    clippy::unreadable_literal
)]

#[macro_use]
extern crate clap;
extern crate parsec;
#[macro_use]
extern crate unwrap;

use clap::{App, Arg};
use parsec::dev_utils::ObservationEvent::*;
use parsec::dev_utils::{Environment, ObservationSchedule, RngChoice, Schedule, ScheduleOptions};
use parsec::mock::{PeerId, Transaction};
use parsec::{ConsensusMode, DumpGraphMode, Observation, DIR, DUMP_MODE};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::slice;

const DST_ROOT: &str = "input_graphs";

/// Construct set of `PeerId`s with the given names.
macro_rules! peer_ids {
    ($($name:expr),*) => {{
        let mut result = BTreeSet::new();
        $(let _ = result.insert(PeerId::new($name));)*
        result
    }}
}

fn main() {
    let mut scenarios = Scenarios::new();

    // -------------------------------------------------------------------------
    // Define scenarios here:

    let _ = scenarios
        .add("consensus_with_forks", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave", "Eric"),
                schedule: vec![],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([3138683280, 3174364583, 1286743511, 1450990187])
        .file("Alice", "alice.dot")
        .file("Bob", "bob.dot")
        .file("Carol", "carol.dot")
        .file("Dave", "dave.dot")
        .file("Eric", "eric.dot");

    let _ = scenarios
        .add("gossip::graph::tests::ancestors_iterator", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                schedule: vec![],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([174994228, 1445633118, 3041276290, 90293447])
        .file("Carol", "carol.dot");

    // Do not edit below this line.
    // -------------------------------------------------------------------------

    add_functional_tests(&mut scenarios);
    add_dev_utils_record_smoke_tests(&mut scenarios);
    add_benches(&mut scenarios);
    add_bench_section_size(&mut scenarios);

    run(scenarios)
}

fn add_functional_tests(scenarios: &mut Scenarios) {
    let _ = scenarios
        .add("functional_tests::from_parsed_contents", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol"),
                schedule: vec![(1, AddPeer(PeerId::new("Dave")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .file("Alice", "0.dot")
        .file("Bob", "1.dot");

    let _ = scenarios
        .add("functional_tests::add_peer", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave", "Eric"),
                schedule: vec![(1, AddPeer(PeerId::new("Fred")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([411278735, 3293288956, 208850454, 2872654992])
        .file("Alice", "alice.dot");

    let _ = scenarios
        .add("functional_tests::remove_peer", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave", "Eric"),
                schedule: vec![(1, RemovePeer(PeerId::new("Eric")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([1048220270, 1673192006, 3171321266, 2580820785])
        .file("Alice", "alice.dot");

    let _ = scenarios
        .add(
            "functional_tests::unpolled_and_unconsensused_observations",
            |env| {
                let obs = ObservationSchedule {
                    genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                    schedule: vec![(1, AddPeer(PeerId::new("Eric")))],
                };
                Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
            },
        )
        .seed([3016139397, 1416620722, 2110786801, 3768414447])
        .file("Alice-002", "alice.dot");

    let _ = scenarios
        .add(
            "functional_tests::handle_malice::genesis_event_not_after_initial",
            |env| {
                let obs = ObservationSchedule {
                    genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                    schedule: vec![],
                };
                Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
            },
        )
        .seed([926181213, 2524489310, 392196615, 406869071])
        .file("Alice", "alice.dot");

    let _ = scenarios
        .add(
            "functional_tests::handle_malice::genesis_event_creator_not_genesis_member",
            |env| {
                let obs = ObservationSchedule {
                    genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                    schedule: vec![(0, AddPeer(PeerId::new("Eric")))],
                };
                Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
            },
        )
        .seed([848911612, 2362592349, 3178199135, 2458552022])
        .file("Alice", "alice.dot");

    let _ = scenarios
        .add("functional_tests::handle_malice::duplicate_votes", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                schedule: vec![(0, Opaque(Transaction::new("ABCD")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([3987596322, 492026741, 1827755430, 3015390549])
        .file("Alice", "alice.dot")
        .file("Carol", "carol.dot");

    let _ = scenarios
        .add(
            "functional_tests::handle_malice::invalid_accusation",
            |env| {
                let obs = ObservationSchedule {
                    genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                    schedule: vec![],
                };
                Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
            },
        )
        .seed([935566334, 935694090, 88607029, 861330491])
        .file("Alice", "alice.dot")
        .file("Carol", "carol.dot");

    let _ = scenarios
        .add("functional_tests::handle_malice::accomplice", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                schedule: vec![(0, Opaque(Transaction::new("EFGH")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([3932887254, 691979681, 2029125979, 3359276664])
        .file("Alice", "alice.dot")
        .file("Bob", "bob.dot")
        .file("Carol", "carol.dot");

    let _ = scenarios
        .add("functional_tests::handle_malice::handle_fork", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave"),
                schedule: vec![(0, Opaque(Transaction::new("IJKL")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([1573595827, 2035773878, 1331264098, 154770609])
        .file("Alice", "alice.dot")
        .file("Bob", "bob.dot")
        .file("Dave", "dave.dot");

    let _ = scenarios
        .add(
            "functional_tests::handle_malice::self_parent_by_different_creator",
            |env| {
                let obs = ObservationSchedule {
                    genesis: peer_ids!("Alice", "Bob", "Carol"),
                    schedule: vec![],
                };
                Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
            },
        )
        .seed([856368386, 135728199, 764559083, 3829746197])
        .file("Alice", "alice.dot")
        .file("Carol", "carol.dot");

    let _ = scenarios
        .add("functional_tests::handle_malice::premature_gossip", |env| {
            let obs = ObservationSchedule {
                genesis: peer_ids!("Alice", "Bob", "Carol", "Dave", "Eric"),
                schedule: vec![(0, AddPeer(PeerId::new("Fred")))],
            };
            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([411278735, 3293288956, 208850454, 2872654992])
        .file("Alice", "alice.dot");
}

fn add_dev_utils_record_smoke_tests(scenarios: &mut Scenarios) {
    let _ = scenarios
        .add("dev_utils::record::tests::smoke_other_peer_names", |env| {
            let obs = ObservationSchedule {
                // Non hard-coded name, 2 with same initial, one smaller than short name
                // Last consensus reached in event not from Annie.
                genesis: peer_ids!("Annie", "B", "Claire", "Carol"),
                schedule: vec![(0, Opaque(Transaction::new("1")))],
            };

            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([1, 2, 3, 4])
        .file("Annie", "annie.dot");

    let _ = scenarios
        .add("dev_utils::record::tests::smoke_routing", |env| {
            let routing_peer_id = |name| format!("PublicId(name: {}..)", name);
            let routing_transaction =
                |prefix| format!("SectionInfo(SectionInfo(prefix: Prefix({}), ...))", prefix);

            let obs = ObservationSchedule {
                genesis: peer_ids!(
                    &routing_peer_id("12abcd"),
                    &routing_peer_id("ab4598"),
                    &routing_peer_id("cdb63e"),
                    &routing_peer_id("ef4fb9")
                ),
                schedule: vec![
                    (0, Opaque(Transaction::new(routing_transaction("123")))),
                    (0, Opaque(Transaction::new(routing_transaction("234")))),
                    (0, AddPeer(PeerId::new(&routing_peer_id("ffffff")))),
                    (0, RemovePeer(PeerId::new(&routing_peer_id("ef4fb9")))),
                ],
            };

            Schedule::from_observation_schedule(env, &ScheduleOptions::default(), obs)
        })
        .seed([1, 2, 3, 4])
        .file("PublicIdname12abcd", "minimal.dot");
}

fn add_benches(scenarios: &mut Scenarios) {
    let _ = scenarios
        .add("benches", |env| {
            Schedule::new(
                env,
                &ScheduleOptions {
                    genesis_size: 4,
                    opaque_to_add: 1,
                    ..Default::default()
                },
            )
        })
        .seed([1, 2, 3, 4])
        .file("Alice", "minimal.dot")
        .dump_mode(DumpGraphMode::OnParsecDrop);

    let _ = scenarios
        .add("benches", |env| {
            Schedule::new(
                env,
                &ScheduleOptions {
                    genesis_size: 5,
                    opaque_to_add: 5,
                    ..Default::default()
                },
            )
        })
        .seed([1, 2, 3, 4])
        .file("Alice", "static.dot")
        .dump_mode(DumpGraphMode::OnParsecDrop);

    let _ = scenarios
        .add("benches", |env| {
            Schedule::new(
                env,
                &ScheduleOptions {
                    genesis_size: 3,
                    peers_to_add: 3,
                    opaque_to_add: 5,
                    ..Default::default()
                },
            )
        })
        .seed([1, 2, 3, 4])
        .file("Alice", "dynamic.dot")
        .dump_mode(DumpGraphMode::OnParsecDrop);
}

fn add_bench_section_size(scenarios: &mut Scenarios) {
    let mut add_bench_one_event_batch =
        |scenarios: &mut Scenarios, opaque_to_add: usize, genesis_size: usize| {
            let single_batch_options = ScheduleOptions {
                genesis_size,
                opaque_to_add,
                votes_before_gossip: true,
                intermediate_consistency_checks: false,
                ..Default::default()
            };

            add_bench_scalability_common(
                scenarios,
                single_batch_options.clone(),
                ConsensusMode::Supermajority,
                &format!("{}", opaque_to_add),
            );
            add_bench_scalability_common(
                scenarios,
                single_batch_options,
                ConsensusMode::Single,
                &format!("{}_single", opaque_to_add),
            );
        };

    for genesis_size in &[4, 8, 16, 32, 48] {
        let opaque_to_add = 8;
        add_bench_one_event_batch(scenarios, opaque_to_add, *genesis_size);
    }

    for genesis_size in &[4, 8, 16, 32, 48] {
        let opaque_to_add = 16;
        add_bench_one_event_batch(scenarios, opaque_to_add, *genesis_size);
    }

    for genesis_size in &[4, 8, 16, 32] {
        let opaque_to_add = 1024;
        add_bench_scalability_common(
            scenarios,
            ScheduleOptions {
                genesis_size: *genesis_size,
                opaque_to_add,
                // 1 gossip event every 10 steps in one peer in the network
                prob_gossip: 0.1 / *genesis_size as f64,
                // 1 opaque event per 10 steps
                prob_opaque: 0.1,
                // Events will be seen within 2 gossip events
                max_observation_delay: 20,
                // For speed only check consistency at the end
                intermediate_consistency_checks: false,
                ..Default::default()
            },
            ConsensusMode::Single,
            &format!("{}_interleave", opaque_to_add),
        );
    }

    for genesis_size in &[4, 8, 16, 32] {
        let opaque_to_add = 8192;
        add_bench_scalability_common(
            scenarios,
            ScheduleOptions {
                genesis_size: *genesis_size,
                opaque_to_add,
                // 1 gossip event every 10 steps in one peer in the network
                prob_gossip: 0.1 / (*genesis_size as f64 * 8.0),
                // 1 opaque event per 10 steps
                prob_opaque: 0.1,
                // Events will be seen within 2 gossip events
                max_observation_delay: 20 * 8,
                // For speed only check consistency at the end
                intermediate_consistency_checks: false,
                ..Default::default()
            },
            ConsensusMode::Single,
            &format!("{}_interleave", opaque_to_add),
        );
    }
}

fn add_bench_scalability_common(
    s: &mut Scenarios,
    options: ScheduleOptions,
    consensus_mode: ConsensusMode,
    bench_tag: &str,
) {
    let file_name_a = format!(
        "a_node{}_opaque_evt{}.dot",
        options.genesis_size, options.opaque_to_add
    );
    let bench_name = format!("bench_section_size_evt{}", bench_tag);

    let _ = s
        .add(bench_name, move |env| Schedule::new(env, &options))
        .seed([1, 2, 3, 4])
        .consensus_mode(consensus_mode)
        .dump_mode(DumpGraphMode::OnParsecDrop)
        .file("Alice", &file_name_a);
}

struct Scenario {
    name: String,
    seed: RngChoice,
    schedule_fn: Box<FnMut(&mut Environment) -> Schedule>,
    files: BTreeMap<String, String>,
    consensus_mode: ConsensusMode,
    dump_mode: DumpGraphMode,
}

impl Scenario {
    fn new<N, F>(name: N, schedule: F) -> Self
    where
        N: Into<String>,
        F: FnMut(&mut Environment) -> Schedule + 'static,
    {
        Scenario {
            name: name.into(),
            seed: RngChoice::SeededRandom,
            schedule_fn: Box::new(schedule),
            files: BTreeMap::new(),
            consensus_mode: ConsensusMode::Supermajority,
            dump_mode: DumpGraphMode::OnConsensus,
        }
    }

    /// Use the given seed instead of randomly generated one.
    #[allow(unused)]
    pub fn seed(&mut self, seed: [u32; 4]) -> &mut Self {
        self.seed = RngChoice::Seeded(seed);
        self
    }

    /// Set the name of the output file for the graph of the given peer.
    #[allow(unused)]
    pub fn file(&mut self, peer_name: &str, dst_file: &str) -> &mut Self {
        let _ = self.files.insert(peer_name.into(), dst_file.into());
        self
    }

    /// Use the given consensus mode instead of ConsensusMode::Supermajority.
    #[allow(unused)]
    pub fn consensus_mode(&mut self, consensus_mode: ConsensusMode) -> &mut Self {
        self.consensus_mode = consensus_mode;
        self
    }

    /// Use the given dump mode instead of DumpGraphMode::OnConsensus.
    #[allow(unused)]
    pub fn dump_mode(&mut self, dump_mode: DumpGraphMode) -> &mut Self {
        self.dump_mode = dump_mode;
        self
    }

    fn matches(&self, pattern: &str) -> bool {
        if self.files.is_empty() {
            self.name.contains(pattern)
        } else {
            self.files
                .values()
                .any(|file| format!("{}/{}", self.name, file).contains(pattern))
        }
    }

    fn run(&mut self, mode: Mode) {
        println!("Running scenario {}", self.name);
        {
            DUMP_MODE.with(|mode| {
                *mode.borrow_mut() = self.dump_mode.clone();
            });

            let mut env = Environment::with_consensus_mode(self.seed, self.consensus_mode);
            let schedule = (self.schedule_fn)(&mut env);
            println!("Using {:?}", env.rng);
            let result = env.network.execute_schedule(&mut env.rng, schedule);
            assert!(result.is_ok(), "{:?}", result);
        }

        if self.files.is_empty() {
            self.collect_files(&default_file_map(), mode);
        } else {
            self.collect_files(&self.files, mode);
        }
    }

    fn collect_files(&self, files: &BTreeMap<String, String>, mode: Mode) {
        let src_dir = DIR.with(|dir| dir.clone());
        let dst_dir = self.dst_dir();

        if let Err(error) = fs::create_dir_all(&dst_dir) {
            panic!(
                "Failed to create destination dir {}: {}",
                dst_dir.display(),
                error
            );
        }

        for (peer_name, dst_file) in files {
            let src_path = match find_file_for_peer(&src_dir, peer_name) {
                Ok(path) => path,
                Err(error) => panic!("{}", error),
            };
            let dst_path = self.dst_dir().join(dst_file);

            println!("    o {}", dst_path.display());

            if dst_path.exists() {
                print!("      Already exists: ");

                match mode {
                    Mode::Overwrite => println!("overwriting."),
                    Mode::Skip => {
                        println!("skipping.");
                        continue;
                    }
                    Mode::Fail => {
                        println!("aborting.");
                        panic!(
                            "Destination file {} already exists. Re-run with --existing=overwrite (or -f) to overwrite",
                            dst_path.display()
                        );
                    }
                }
            }

            if let Err(error) = fs::copy(&src_path, &dst_path) {
                panic!(
                    "Failed to copy {} to {}: {}",
                    src_path.display(),
                    dst_path.display(),
                    error
                )
            }
        }
    }

    fn dst_dir(&self) -> PathBuf {
        PathBuf::from(DST_ROOT).join(self.name.replace("::", "_"))
    }
}

struct Scenarios(Vec<Scenario>);

impl Scenarios {
    pub fn new() -> Self {
        Scenarios(Vec::new())
    }

    /// Define new scenario for a test with the given fully qualified name
    /// using `Schedule` returned by the given lambda.
    pub fn add<N, F>(&mut self, name: N, schedule: F) -> &mut Scenario
    where
        N: Into<String>,
        F: FnMut(&mut Environment) -> Schedule + 'static,
    {
        self.0.push(Scenario::new(name, schedule));
        unwrap!(self.0.last_mut())
    }

    fn iter(&self) -> slice::Iter<Scenario> {
        self.0.iter()
    }

    fn iter_mut(&mut self) -> slice::IterMut<Scenario> {
        self.0.iter_mut()
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Overwrite,
    Skip,
    Fail,
}

fn run(mut scenarios: Scenarios) {
    let matches = App::new("Parsec Dot Generator")
        .version(crate_version!())
        .arg(
            Arg::with_name("name")
                .index(1)
                .help("Run all scenarios matching this name")
                .required_unless("all")
                .required_unless("list"),
        )
        .arg(
            Arg::with_name("all")
                .short("a")
                .long("all")
                .help("Run all scenarios")
                .conflicts_with("name"),
        )
        .arg(
            Arg::with_name("list")
                .short("l")
                .long("list")
                .help("List all scenarios")
                .conflicts_with("name")
                .conflicts_with("all"),
        )
        .arg(
            Arg::with_name("existing")
                .short("e")
                .long("existing")
                .takes_value(true)
                .possible_values(&["overwrite", "skip", "fail"])
                .help("What to do with existing destination files")
                .conflicts_with("list"),
        )
        .arg(
            Arg::with_name("force")
                .short("f")
                .help("Same as --existing=overwrite")
                .conflicts_with("list"),
        )
        .get_matches();

    check_root_dir();

    if matches.is_present("list") {
        for scenario in scenarios.iter() {
            println!("- {}", scenario.name);

            for file in scenario.files.values() {
                println!("  - {}", file);
            }
        }

        return;
    }

    let mode = if matches.is_present("force") {
        Mode::Overwrite
    } else {
        match matches.value_of("existing") {
            Some("overwrite") => Mode::Overwrite,
            Some("skip") => Mode::Skip,
            _ => Mode::Fail,
        }
    };

    if matches.is_present("all") {
        for scenario in scenarios.iter_mut() {
            scenario.run(mode);
        }
    }

    if let Some(name) = matches.value_of("name") {
        let mut matched = false;
        for scenario in scenarios
            .iter_mut()
            .filter(|scenario| scenario.matches(name))
        {
            matched = true;
            scenario.run(mode);
        }

        if !matched {
            println!("No scenario matching {:?} found", name);
        }
    }
}

fn default_file_map() -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let _ = result.insert("Alice".into(), "alice.dot".into());
    result
}

fn find_file_for_peer(dir: &Path, peer_name: &str) -> io::Result<PathBuf> {
    if let Some(name) = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(peer_name) && name.ends_with(".dot"))
        .max()
    {
        Ok(dir.join(name))
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Dot file for {} not found", peer_name),
        ))
    }
}

// Check that the tool is run from the parsec crate root.
fn check_root_dir() {
    // TODO: maybe there is a better way to do this?

    if let Ok(mut file) = File::open("Cargo.toml") {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() && contents.contains("name = \"parsec\"") {
            return;
        }
    }

    panic!("This tool must be run from the Parsec crate root");
}
