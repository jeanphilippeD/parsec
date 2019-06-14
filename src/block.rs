// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Error,
    id::{Proof, PublicId},
    network_event::NetworkEvent,
    observation::Observation,
    vote::Vote,
    DkgResult,
};
use std::{
    collections::{vec_deque, BTreeMap, BTreeSet, VecDeque},
    ops::{Deref, DerefMut},
};

/// A struct representing a collection of votes by peers for an `Observation`.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Block<T: NetworkEvent, P: PublicId> {
    payload: Observation<T, P>,
    proofs: BTreeSet<Proof<P>>,
}

impl<T: NetworkEvent, P: PublicId> Block<T, P> {
    /// Create a `Block` with no signatures for a single DkgResult
    pub fn new_dkg_block(result: DkgResult) -> Self {
        Self {
            payload: Observation::DkgResult(result),
            proofs: BTreeSet::new(),
        }
    }

    /// Creates a `Block` from `votes`.
    pub fn new(votes: &BTreeMap<P, Vote<T, P>>) -> Result<Self, Error> {
        let payload = if let Some(vote) = votes.values().next() {
            vote.payload().clone()
        } else {
            return Err(Error::MissingVotes);
        };

        let proofs: Result<BTreeSet<_>, _> = votes
            .iter()
            .map(|(public_id, vote)| {
                if *vote.payload() == payload {
                    vote.create_proof(public_id)
                } else {
                    Err(Error::MismatchedPayload)
                }
            })
            .collect();
        let proofs = proofs?;

        Ok(Self { payload, proofs })
    }

    /// Returns the payload of this block.
    pub fn payload(&self) -> &Observation<T, P> {
        &self.payload
    }

    /// Returns the proofs of this block.
    pub fn proofs(&self) -> &BTreeSet<Proof<P>> {
        &self.proofs
    }

    /// Is this block signed by the given peer?
    pub fn is_signed_by(&self, peer_id: &P) -> bool {
        self.proofs.iter().any(|proof| proof.public_id() == peer_id)
    }

    /// Converts `vote` to a `Proof` and attempts to add it to the block.  Returns an error if
    /// `vote` is invalid (i.e. signature check fails or the `vote` is for a different network
    /// event), `Ok(true)` if the `Proof` wasn't previously held in this `Block`, or `Ok(false)` if
    /// it was previously held.
    pub fn add_vote(&mut self, peer_id: &P, vote: &Vote<T, P>) -> Result<bool, Error> {
        if &self.payload != vote.payload() {
            return Err(Error::MismatchedPayload);
        }
        let proof = vote.create_proof(peer_id)?;
        Ok(self.proofs.insert(proof))
    }
}

/// Group of blocks that were all created within the same meta-election.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct BlockGroup<T: NetworkEvent, P: PublicId>(pub VecDeque<Block<T, P>>);

impl<T: NetworkEvent, P: PublicId> BlockGroup<T, P> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: NetworkEvent, P: PublicId> IntoIterator for BlockGroup<T, P> {
    type Item = Block<T, P>;
    type IntoIter = vec_deque::IntoIter<Block<T, P>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T: NetworkEvent, P: PublicId> IntoIterator for &'a BlockGroup<T, P> {
    type Item = &'a Block<T, P>;
    type IntoIter = vec_deque::Iter<'a, Block<T, P>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: NetworkEvent, P: PublicId> Deref for BlockGroup<T, P> {
    type Target = VecDeque<Block<T, P>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: NetworkEvent, P: PublicId> DerefMut for BlockGroup<T, P> {
    fn deref_mut(&mut self) -> &mut VecDeque<Block<T, P>> {
        &mut self.0
    }
}
