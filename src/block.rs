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
    observation::{InputObservation, Observation, ObservationRef, ParsecObservation},
    vote::Vote,
    DkgResult,
};
use std::{
    collections::{vec_deque, BTreeMap, BTreeSet, VecDeque},
    convert::TryFrom,
    ops::{Deref, DerefMut},
};

/// A struct representing a collection of votes by peers for an `Observation`.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Block<T: NetworkEvent, P: PublicId> {
    payload: BlockPayload<T, P>,
    proofs: BTreeSet<Proof<P>>,
}

impl<T: NetworkEvent, P: PublicId> Block<T, P> {
    /// Create a `Block` with no signatures for a single DkgResult
    pub fn new_dkg_block(result: DkgResult) -> Self {
        Self {
            payload: BlockPayload::DkgResult(result),
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
        let payload = BlockPayload::try_from(payload)?;

        Ok(Self { payload, proofs })
    }

    /// Returns the payload of this block.
    pub fn payload(&self) -> &BlockPayload<T, P> {
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
}

/// The public payload for a block
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum BlockPayload<T: NetworkEvent, P: PublicId> {
    /// Observation added with vote_for
    InputObservation(InputObservation<T, P>),
    /// Observation created by Parsec
    ParsecObservation(ParsecObservation<T, P>),
    /// A DKG result: No associated proof
    DkgResult(DkgResult),
}

impl<T: NetworkEvent, P: PublicId> BlockPayload<T, P> {
    /// Is this observation's payload opaque to PARSEC?
    pub fn is_opaque(&self) -> bool {
        if let BlockPayload::InputObservation(InputObservation::OpaquePayload(_)) = *self {
            true
        } else {
            false
        }
    }

    /// Is this observation's an result only `DkgResult`
    pub fn is_dkg_result(&self) -> bool {
        match *self {
            BlockPayload::DkgResult(_) => true,
            _ => false,
        }
    }

    /// Get an ObservationRef
    pub fn as_observation_ref(&self) -> ObservationRef<T, P> {
        match self {
            BlockPayload::ParsecObservation(ParsecObservation::Genesis {
                group,
                related_info,
            }) => ObservationRef::Genesis {
                group,
                related_info,
            },
            BlockPayload::ParsecObservation(ParsecObservation::Accusation { offender, malice }) => {
                ObservationRef::Accusation { offender, malice }
            }
            BlockPayload::InputObservation(InputObservation::Add {
                peer_id,
                related_info,
            }) => ObservationRef::Add {
                peer_id,
                related_info,
            },
            BlockPayload::InputObservation(InputObservation::Remove {
                peer_id,
                related_info,
            }) => ObservationRef::Remove {
                peer_id,
                related_info,
            },
            BlockPayload::InputObservation(InputObservation::OpaquePayload(payload)) => {
                ObservationRef::OpaquePayload(payload)
            }
            BlockPayload::DkgResult(result) => ObservationRef::DkgResult(result),
        }
    }
}

impl<T: NetworkEvent, P: PublicId> TryFrom<Observation<T, P>> for BlockPayload<T, P> {
    type Error = Error;

    fn try_from(obs: Observation<T, P>) -> Result<Self, Error> {
        match obs {
            Observation::Genesis {
                group,
                related_info,
            } => Ok(BlockPayload::ParsecObservation(
                ParsecObservation::Genesis {
                    group,
                    related_info,
                },
            )),
            Observation::Accusation { offender, malice } => Ok(BlockPayload::ParsecObservation(
                ParsecObservation::Accusation { offender, malice },
            )),
            Observation::Add {
                peer_id,
                related_info,
            } => Ok(BlockPayload::InputObservation(InputObservation::Add {
                peer_id,
                related_info,
            })),
            Observation::Remove {
                peer_id,
                related_info,
            } => Ok(BlockPayload::InputObservation(InputObservation::Remove {
                peer_id,
                related_info,
            })),
            Observation::OpaquePayload(payload) => Ok(BlockPayload::InputObservation(
                InputObservation::OpaquePayload(payload),
            )),
            Observation::DkgResult(result) => Ok(BlockPayload::DkgResult(result)),
            Observation::DkgMessage(_) => Err(Error::InternalPayload),
        }
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
