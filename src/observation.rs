// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::gossip::{EventHash, PackedEvent};
use crate::hash::Hash;
use crate::id::PublicId;
use crate::network_event::NetworkEvent;
use crate::peer_list::PeerIndex;
use crate::serialise;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Debug, Formatter};

/// An enum of the various network events for which a peer can vote.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Observation<T: NetworkEvent, P: PublicId> {
    /// Genesis group
    Genesis(BTreeSet<P>),
    /// Vote to add the indicated peer to the network.
    Add {
        /// Public id of the peer to be added
        peer_id: P,
        /// Extra arbitrary information for use by the client
        related_info: Vec<u8>,
    },
    /// Vote to remove the indicated peer from the network.
    Remove {
        /// Public id of the peer to be removed
        peer_id: P,
        /// Extra arbitrary information for use by the client
        related_info: Vec<u8>,
    },
    /// Vote to accuse a peer of malicious behaviour.
    Accusation {
        /// Public id of the peer committing the malice.
        offender: P,
        /// Type of the malice committed.
        malice: Malice<T, P>,
    },
    /// Vote for an event which is opaque to Parsec.
    OpaquePayload(T),
}

impl<T: NetworkEvent, P: PublicId> Observation<T, P> {
    pub(crate) fn is_opaque(&self) -> bool {
        if let Observation::OpaquePayload(_) = *self {
            true
        } else {
            false
        }
    }
}

impl<T: NetworkEvent, P: PublicId> Debug for Observation<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match self {
            Observation::Genesis(group) => write!(formatter, "Genesis({:?})", group),
            Observation::Add { peer_id, .. } => write!(formatter, "Add({:?})", peer_id),
            Observation::Remove { peer_id, .. } => write!(formatter, "Remove({:?})", peer_id),
            Observation::Accusation { offender, malice } => {
                write!(formatter, "Accusation {{ {:?}, {:?} }}", offender, malice)
            }
            Observation::OpaquePayload(payload) => {
                write!(formatter, "OpaquePayload({:?})", payload)
            }
        }
    }
}

/// Type of malicious behaviour.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Malice<T: NetworkEvent, P: PublicId> {
    /// Event carries a vote for `Observation::Genesis`, but shouldn't.
    UnexpectedGenesis(EventHash),
    /// Two or more votes with the same observation by the same creator.
    DuplicateVote(EventHash, EventHash),
    /// Event should be carrying a vote for `Observation::Genesis`, but doesn't
    MissingGenesis(EventHash),
    /// Event carries a vote for `Observation::Genesis` which doesn't correspond to what we know.
    IncorrectGenesis(EventHash),
    /// More than one events having this event as its self_parent.
    Fork(EventHash),
    /// A node incorrectly accused other node of malice. Contains hash of the invalid Accusation
    /// event.
    InvalidAccusation(EventHash),
    /// We receive a gossip containing an event whose creator should not be known to the sender.
    /// Contains hash of the sync event whose ancestor has the invalid creator.
    InvalidGossipCreator(EventHash),
    /// Event's creator is the same to its other_parent's creator. The accusation contains the
    /// original event so other peers can verify the accusation directly.
    OtherParentBySameCreator(Box<PackedEvent<T, P>>),
    /// Event's creator is different to its self_parent's creator. The accusation contains the
    /// original event so other peers can verify the accusation directly.
    SelfParentByDifferentCreator(Box<PackedEvent<T, P>>),
    /// Detectable but unprovable malice. Relies on consensus.
    Unprovable(UnprovableMalice),
    /// A node is not reporting malice when it should
    Accomplice(EventHash, Box<Malice<T, P>>),
    // TODO: add other malice variants
}

impl<T: NetworkEvent, P: PublicId> Malice<T, P> {
    #[cfg(any(test, feature = "malice-detection", feature = "testing"))]
    pub(crate) fn is_provable(&self) -> bool {
        match *self {
            Malice::Unprovable(_) => false,
            _ => true,
        }
    }

    #[cfg(feature = "malice-detection")]
    // If the malice specifies a single event as its source, return it.
    pub(crate) fn single_hash(&self) -> Option<&EventHash> {
        match self {
            Malice::UnexpectedGenesis(hash)
            | Malice::MissingGenesis(hash)
            | Malice::IncorrectGenesis(hash)
            | Malice::Fork(hash)
            | Malice::InvalidAccusation(hash)
            | Malice::InvalidGossipCreator(hash)
            | Malice::Accomplice(hash, _) => Some(hash),
            Malice::DuplicateVote(_, _)
            | Malice::OtherParentBySameCreator(_)
            | Malice::SelfParentByDifferentCreator(_)
            | Malice::Unprovable(_) => None,
        }
    }
}

// For internal diagnostics only. The value is ignored in comparison, ordering or hashing.
#[derive(Clone, Debug)]
pub enum UnprovableMalice {
    // A node is spamming us.
    Spam,
    // Other, unspecified malice.
    Unspecified,
}

impl PartialEq for UnprovableMalice {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for UnprovableMalice {}

impl PartialOrd for UnprovableMalice {
    fn partial_cmp(&self, _: &Self) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

impl Ord for UnprovableMalice {
    fn cmp(&self, _: &Self) -> Ordering {
        Ordering::Equal
    }
}

impl Serialize for UnprovableMalice {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_unit()
    }
}

impl<'a> Deserialize<'a> for UnprovableMalice {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_unit(UnprovableMaliceVisitor)
    }
}

struct UnprovableMaliceVisitor;

impl<'a> Visitor<'a> for UnprovableMaliceVisitor {
    type Value = UnprovableMalice;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "UnprovableMalice")
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        Ok(UnprovableMalice::Unspecified)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub(crate) struct ObservationHash(pub(crate) Hash);

impl ObservationHash {
    pub const ZERO: Self = ObservationHash(Hash::ZERO);
}

impl<'a, T: NetworkEvent, P: PublicId> From<&'a Observation<T, P>> for ObservationHash {
    fn from(observation: &'a Observation<T, P>) -> Self {
        ObservationHash(Hash::from(serialise(observation).as_slice()))
    }
}

impl Debug for ObservationHash {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.0)
    }
}

// Container for observation with its metadata.
#[derive(Debug)]
pub(crate) struct ObservationInfo<T: NetworkEvent, P: PublicId> {
    pub(crate) observation: Observation<T, P>,
    pub(crate) consensused: bool,
    pub(crate) created_by_us: bool,
}

impl<T: NetworkEvent, P: PublicId> ObservationInfo<T, P> {
    pub fn new(observation: Observation<T, P>) -> Self {
        Self {
            observation,
            consensused: false,
            created_by_us: false,
        }
    }
}

// Storage for observations
pub(crate) type ObservationStore<T, P> = BTreeMap<ObservationKey, ObservationInfo<T, P>>;

// Observation with corresponding key for ObservationStore
pub(crate) type ObservationForStore<T, P> = Option<(ObservationKey, ObservationInfo<T, P>)>;

// Key to compare observations.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub(crate) enum ObservationKey {
    Single(ObservationHash, PeerIndex),
    Supermajority(ObservationHash),
}

impl ObservationKey {
    pub fn new(hash: ObservationHash, creator: PeerIndex, consensus_mode: ConsensusMode) -> Self {
        match consensus_mode {
            ConsensusMode::Single => ObservationKey::Single(hash, creator),
            ConsensusMode::Supermajority => ObservationKey::Supermajority(hash),
        }
    }

    pub fn hash(&self) -> &ObservationHash {
        match *self {
            ObservationKey::Single(ref hash, _) => hash,
            ObservationKey::Supermajority(ref hash) => hash,
        }
    }

    pub fn matches(&self, other_hash: &ObservationHash, other_creator: PeerIndex) -> bool {
        match *self {
            ObservationKey::Single(ref hash, creator) => {
                other_hash == hash && other_creator == creator
            }
            ObservationKey::Supermajority(ref hash) => other_hash == hash,
        }
    }

    pub fn consensus_mode(&self) -> ConsensusMode {
        match *self {
            ObservationKey::Single(..) => ConsensusMode::Single,
            ObservationKey::Supermajority(..) => ConsensusMode::Supermajority,
        }
    }
}

/// Number of votes necessary to reach consensus on an `OpaquePayload`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusMode {
    /// One vote is enough.
    Single,
    /// Supermajority (more than 2/3) is required.
    Supermajority,
}

impl ConsensusMode {
    pub(crate) fn of<T: NetworkEvent, P: PublicId>(self, observation: &Observation<T, P>) -> Self {
        if observation.is_opaque() {
            self
        } else {
            ConsensusMode::Supermajority
        }
    }
}

/// Returns whether `small` is more than two thirds of `large`.
pub fn is_more_than_two_thirds(small: usize, large: usize) -> bool {
    3 * small > 2 * large
}

#[cfg(any(all(test, feature = "mock"), feature = "dump-graphs"))]
pub(crate) mod snapshot {
    use super::*;
    use crate::id::SecretId;
    use crate::peer_list::PeerList;

    #[serde(bound = "")]
    #[derive(Eq, PartialEq, Debug, Serialize, Deserialize)]
    pub(crate) enum ObservationKeySnapshot<P: PublicId> {
        Supermajority(ObservationHash),
        Single(ObservationHash, P),
    }

    impl<P: PublicId> ObservationKeySnapshot<P> {
        pub fn new<S>(key: &ObservationKey, peer_list: &PeerList<S>) -> Option<Self>
        where
            S: SecretId<PublicId = P>,
        {
            match *key {
                ObservationKey::Supermajority(hash) => {
                    Some(ObservationKeySnapshot::Supermajority(hash))
                }
                ObservationKey::Single(hash, peer_index) => peer_list
                    .get(peer_index)
                    .map(|peer| peer.id().clone())
                    .map(|peer_id| ObservationKeySnapshot::Single(hash, peer_id)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{PeerId, Transaction};
    use maidsafe_utilities::serialisation::deserialise;

    #[test]
    fn malice_comparison_and_hashing_ignores_unprovable_value() {
        let malice1 = Malice::Unprovable::<Transaction, PeerId>(UnprovableMalice::Spam);
        let malice2 = Malice::Unprovable::<Transaction, PeerId>(UnprovableMalice::Unspecified);

        assert!(malice1 == malice2);
        assert!(!(malice1 < malice2));
        assert!(!(malice1 > malice2));

        assert_eq!(
            Hash::from(serialise(&malice1).as_slice()),
            Hash::from(serialise(&malice2).as_slice())
        );
    }

    #[test]
    fn unprovable_malice_is_deserialisable() {
        let before = Malice::Unprovable::<Transaction, PeerId>(UnprovableMalice::Spam);
        let serialised = serialise(&before);
        let _: Malice<Transaction, PeerId> = unwrap!(deserialise(&serialised));
    }
}
