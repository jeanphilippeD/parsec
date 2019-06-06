// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Observation;
#[cfg(feature = "testing")]
use super::ParsedContents;
use crate::block::Block;
use crate::common_coin::CommonCoin;
use crate::mock::{PeerId, Transaction};
use crate::observation::{ConsensusMode, Malice, Observation as ParsecObservation};
use crate::parsec::Parsec;
use rand::{seq::SliceRandom, Rng};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PeerStatus {
    Active,
    Pending,
    Removed,
    Failed,
}

pub struct Peer {
    pub id: PeerId,
    pub parsec: Parsec<Transaction, PeerId>,
    /// The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    pub blocks: Vec<Block<Transaction, PeerId>>,
    pub status: PeerStatus,
    votes_to_make: Vec<Observation>,
}

impl Peer {
    pub fn from_genesis(
        id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        consensus_mode: ConsensusMode,
        common_coin: CommonCoin<PeerId>,
    ) -> Self {
        Self {
            id: id.clone(),
            parsec: Parsec::from_genesis(id, genesis_group, consensus_mode, common_coin),
            blocks: vec![],
            status: PeerStatus::Active,
            votes_to_make: vec![],
        }
    }

    pub fn from_existing(
        id: PeerId,
        genesis_group: &BTreeSet<PeerId>,
        current_group: &BTreeSet<PeerId>,
        consensus_mode: ConsensusMode,
        common_coin: CommonCoin<PeerId>,
    ) -> Self {
        Self {
            id: id.clone(),
            parsec: Parsec::from_existing(
                id,
                genesis_group,
                current_group,
                consensus_mode,
                common_coin,
            ),
            blocks: vec![],
            status: PeerStatus::Pending,
            votes_to_make: vec![],
        }
    }

    #[cfg(feature = "testing")]
    pub(crate) fn from_parsed_contents(contents: ParsedContents) -> Self {
        let id = contents.our_id.clone();
        let parsec = Parsec::from_parsed_contents(contents);
        Self {
            id,
            parsec,
            blocks: vec![],
            status: PeerStatus::Active,
            votes_to_make: vec![],
        }
    }

    pub fn vote_for(&mut self, observation: &Observation) {
        self.votes_to_make.push(observation.clone());
    }

    pub fn make_votes(&mut self) {
        let parsec = &mut self.parsec;
        self.votes_to_make
            .retain(|obs| !parsec.have_voted_for(obs) && parsec.vote_for(obs.clone()).is_err());
    }

    fn make_active_if_added(&mut self, block: &Block<Transaction, PeerId>) {
        if self.status == PeerStatus::Pending {
            if let ParsecObservation::Add { ref peer_id, .. } = *block.payload() {
                if self.id == *peer_id {
                    self.status = PeerStatus::Active;
                }
            }
        }
    }

    /// Returns the index of the first new block.
    pub fn poll(&mut self) -> usize {
        let first = self.blocks.len();

        while let Some(block) = self.parsec.poll() {
            self.make_active_if_added(&block);
            self.blocks.push(block);
        }

        first
    }

    /// Returns self.blocks
    pub fn blocks(&self) -> &[Block<Transaction, PeerId>] {
        &self.blocks
    }

    /// Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<&Observation> {
        self.blocks
            .iter()
            .map(Block::payload)
            .filter(|obs| match obs {
                ParsecObservation::DkgMessage(_) => false,
                _ => true,
            })
            .collect()
    }

    /// Returns iterator over all accusations raised by this peer that haven't been retrieved by
    /// `poll` yet.
    pub fn unpolled_accusations(
        &self,
    ) -> impl Iterator<Item = (&PeerId, &Malice<Transaction, PeerId>)> {
        self.parsec
            .our_unpolled_observations()
            .filter_map(|payload| match payload {
                ParsecObservation::Accusation {
                    ref offender,
                    ref malice,
                } => Some((offender, malice)),
                _ => None,
            })
    }
}

impl Debug for Peer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}: Blocks: {:?}", self.id, self.blocks)
    }
}

pub struct PeerStatuses {
    statuses: BTreeMap<PeerId, PeerStatus>,
}

impl PeerStatuses {
    /// Creates a new PeerStatuses struct with the given active peers
    pub fn new(names: &BTreeSet<PeerId>) -> PeerStatuses {
        PeerStatuses {
            statuses: names
                .iter()
                .map(|x| (x.clone(), PeerStatus::Active))
                .collect(),
        }
    }

    fn peers_by_status<F: Fn(&PeerStatus) -> bool>(
        &self,
        f: F,
    ) -> impl Iterator<Item = (&PeerId, &PeerStatus)> {
        self.statuses.iter().filter(move |&(_, status)| f(status))
    }

    fn choose_name_to_remove<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .peers_by_status(|s| *s == PeerStatus::Active || *s == PeerStatus::Failed)
            .map(|(id, _)| id)
            .collect();
        (*unwrap!(names.choose(rng))).clone()
    }

    fn choose_name_to_fail<R: Rng>(&self, rng: &mut R) -> PeerId {
        let names: Vec<&PeerId> = self
            .peers_by_status(|s| *s == PeerStatus::Active)
            .map(|(id, _)| id)
            .collect();
        (*unwrap!(names.choose(rng))).clone()
    }

    /// Returns an iterator through all the peers
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.statuses.keys()
    }

    fn num_active_peers(&self) -> usize {
        self.peers_by_status(|s| *s == PeerStatus::Active).count()
    }

    /// Returns an iterator through the list of active peers
    pub fn active_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Active)
            .map(|(id, _)| id)
    }

    /// Returns an iterator through the list of present peers (active or pending)
    pub fn present_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Active || *s == PeerStatus::Pending)
            .map(|(id, _)| id)
    }

    /// Returns an iterator through the list of inactive peers (removed and failed)
    pub fn inactive_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers_by_status(|s| *s == PeerStatus::Removed || *s == PeerStatus::Failed)
            .map(|(id, _)| id)
    }

    fn num_failed_peers(&self) -> usize {
        self.peers_by_status(|s| *s == PeerStatus::Failed).count()
    }

    /// Adds an active peer.
    pub fn add_peer(&mut self, p: PeerId) {
        let _ = self.statuses.insert(p, PeerStatus::Active);
    }

    /// Randomly chooses a peer to remove.
    pub fn remove_random_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let name = self.choose_name_to_remove(rng);

        let mut active_peers = self.num_active_peers();
        let mut failed_peers = self.num_failed_peers();

        match self.statuses[&name] {
            PeerStatus::Active => active_peers -= 1,
            PeerStatus::Failed => failed_peers -= 1,
            _ => return None,
        }

        if 2 * failed_peers < active_peers && active_peers >= min_active {
            self.remove_peer(&name);
            Some(name)
        } else {
            None
        }
    }

    /// Remove the given peer
    pub fn remove_peer(&mut self, peer: &PeerId) {
        let status = self.statuses.get_mut(peer).unwrap();
        *status = PeerStatus::Removed;
    }

    /// Randomly chooses a peer to fail.
    pub fn fail_random_peer<R: Rng>(&mut self, rng: &mut R, min_active: usize) -> Option<PeerId> {
        let name = self.choose_name_to_fail(rng);

        let active_peers = self.num_active_peers() - 1;
        let failed_peers = self.num_failed_peers() + 1;

        if 2 * failed_peers < active_peers && active_peers >= min_active {
            self.fail_peer(&name);
            Some(name)
        } else {
            None
        }
    }

    pub fn fail_peer(&mut self, peer: &PeerId) {
        let status = self.statuses.get_mut(peer).unwrap();
        *status = PeerStatus::Failed;
    }
}

impl Into<BTreeMap<PeerId, PeerStatus>> for PeerStatuses {
    fn into(self) -> BTreeMap<PeerId, PeerStatus> {
        self.statuses
    }
}
