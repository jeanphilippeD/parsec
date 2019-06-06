// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(any(test, feature = "testing"))]
use super::event::CauseInput;
use super::{
    event_context::{EventContextMut, EventContextRef},
    event_hash::EventHash,
    graph::{EventIndex, Graph},
};
use crate::error::Error;
use crate::id::{PublicId, SecretId};
#[cfg(any(test, feature = "testing"))]
use crate::mock::{PeerId, Transaction};
use crate::network_event::NetworkEvent;
#[cfg(any(test, feature = "testing"))]
use crate::observation::ConsensusMode;
use crate::observation::ObservationInfo;
#[cfg(any(test, feature = "dump-graphs", feature = "testing"))]
use crate::observation::ObservationStore;
use crate::peer_list::PeerIndex;
use crate::round_hash::RoundHash;
use crate::vote::{Vote, VoteKey};
#[cfg(feature = "dump-graphs")]
use maidsafe_utilities::serialisation::serialise;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(feature = "dump-graphs")]
use std::fmt::{self, Display, Formatter};
use threshold_crypto::SignatureShare;

#[serde(bound(
    serialize = "V: Serialize, E: Serialize",
    deserialize = "V: Deserialize<'de>, E: Deserialize<'de>"
))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub(super) enum Cause<V, E> {
    // Identifiers of the latest `Event`s of own and the peer which sent the request.
    Request {
        self_parent: E,
        other_parent: E,
    },
    // Identifiers of the latest `Event`s of own and the peer which sent the response.
    Response {
        self_parent: E,
        other_parent: E,
    },
    // Identifier of our latest `Event`. Vote for a single network event.
    Observation {
        self_parent: E,
        vote: V,
    },
    // Signature shares for common coin flips; not an observation because it doesn't require
    // consensus
    CoinShares {
        self_parent: E,
        shares: BTreeMap<RoundHash, SignatureShare>,
    },
    // Initial empty `Event` of this peer.
    Initial,
}

impl<P: PublicId> Cause<VoteKey<P>, EventIndex> {
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn unpack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        packed_cause: Cause<Vote<T, P>, EventHash>,
        creator: PeerIndex,
        ctx: EventContextMut<T, S>,
    ) -> Result<Self, Error> {
        let cause = match packed_cause {
            Cause::Request {
                ref self_parent,
                ref other_parent,
            } => Cause::Request {
                self_parent: self_parent_index(ctx.graph, self_parent)?,
                other_parent: other_parent_index(ctx.graph, other_parent)?,
            },
            Cause::Response {
                ref self_parent,
                ref other_parent,
            } => Cause::Response {
                self_parent: self_parent_index(ctx.graph, self_parent)?,
                other_parent: other_parent_index(ctx.graph, other_parent)?,
            },
            Cause::Observation { self_parent, vote } => {
                let self_parent = self_parent_index(ctx.graph, &self_parent)?;

                let (vote_key, observation) = VoteKey::new(vote, creator, ctx.consensus_mode);
                let _ = ctx
                    .observations
                    .entry(*vote_key.payload_key())
                    .or_insert_with(|| ObservationInfo::new(observation));

                Cause::Observation {
                    self_parent,
                    vote: vote_key,
                }
            }
            Cause::CoinShares {
                self_parent,
                shares,
            } => Cause::CoinShares {
                self_parent: self_parent_index(ctx.graph, &self_parent)?,
                shares,
            },
            Cause::Initial => Cause::Initial,
        };

        Ok(cause)
    }

    pub(crate) fn pack<T: NetworkEvent, S: SecretId<PublicId = P>>(
        &self,
        ctx: EventContextRef<T, S>,
    ) -> Result<Cause<Vote<T, P>, EventHash>, Error> {
        let cause = match *self {
            Cause::Request {
                self_parent,
                other_parent,
            } => Cause::Request {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                other_parent: other_parent_hash(ctx.graph, other_parent)?,
            },
            Cause::Response {
                self_parent,
                other_parent,
            } => Cause::Response {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                other_parent: other_parent_hash(ctx.graph, other_parent)?,
            },
            Cause::Observation {
                self_parent,
                ref vote,
            } => Cause::Observation {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                vote: vote.resolve(ctx.observations)?,
            },
            Cause::CoinShares {
                self_parent,
                ref shares,
            } => Cause::CoinShares {
                self_parent: self_parent_hash(ctx.graph, self_parent)?,
                shares: shares.clone(),
            },
            Cause::Initial => Cause::Initial,
        };
        Ok(cause)
    }

    /// Returns an object that implements Display for printing the payload instead of just the
    /// payload key.
    #[cfg(feature = "dump-graphs")]
    pub(crate) fn display<'a, 'b, T: NetworkEvent>(
        &'a self,
        observations: &'b ObservationStore<T, P>,
    ) -> CauseDisplay<'a, 'b, T, P> {
        CauseDisplay {
            cause: self,
            observations,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Cause<Vote<Transaction, PeerId>, EventHash> {
    pub(crate) fn new_from_dot_input(
        input: CauseInput,
        creator_id: &PeerId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
    ) -> Self {
        // When the dot file contains only partial graph, we have to manually change the info of
        // ancestor to null for some events. In that case, populate ancestors with empty hash.
        let self_parent = self_parent.unwrap_or(EventHash::ZERO);
        let other_parent = other_parent.unwrap_or(EventHash::ZERO);

        match input {
            CauseInput::Initial => Cause::Initial,
            CauseInput::Request => Cause::Request {
                self_parent,
                other_parent,
            },
            CauseInput::Response => Cause::Response {
                self_parent,
                other_parent,
            },
            CauseInput::Observation(observation) => Cause::Observation {
                self_parent,
                vote: Vote::new(creator_id, observation),
            },
            CauseInput::CoinShares(shares) => Cause::CoinShares {
                self_parent,
                shares,
            },
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Cause<VoteKey<PeerId>, EventIndex> {
    pub(crate) fn unpack_from_dot_input(
        packed_cause: Cause<Vote<Transaction, PeerId>, EventHash>,
        creator: PeerIndex,
        self_parent: Option<EventIndex>,
        other_parent: Option<EventIndex>,
        observations: &mut ObservationStore<Transaction, PeerId>,
    ) -> Self {
        let self_parent = self_parent.unwrap_or(EventIndex::PHONY);
        let other_parent = other_parent.unwrap_or(EventIndex::PHONY);

        match packed_cause {
            Cause::Initial => Cause::Initial,
            Cause::Request { .. } => Cause::Request {
                self_parent,
                other_parent,
            },
            Cause::Response { .. } => Cause::Response {
                self_parent,
                other_parent,
            },
            Cause::Observation { vote, .. } => {
                let (vote_key, observation) =
                    VoteKey::new(vote, creator, ConsensusMode::Supermajority);
                let _ = observations
                    .entry(*vote_key.payload_key())
                    .or_insert_with(|| ObservationInfo::new(observation));

                Cause::Observation {
                    vote: vote_key,
                    self_parent,
                }
            }
            Cause::CoinShares { shares, .. } => Cause::CoinShares {
                self_parent,
                shares,
            },
        }
    }
}

#[cfg(feature = "dump-graphs")]
pub(crate) struct CauseDisplay<'a, 'b, T: NetworkEvent, P: PublicId> {
    cause: &'a Cause<VoteKey<P>, EventIndex>,
    observations: &'b ObservationStore<T, P>,
}

#[cfg(feature = "dump-graphs")]
impl<'a, 'b, T: NetworkEvent, P: PublicId> Display for CauseDisplay<'a, 'b, T, P> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.cause {
            Cause::Request { .. } => write!(f, "Request"),
            Cause::Response { .. } => write!(f, "Response"),
            Cause::Observation { ref vote, .. } => {
                if let Some(observation) = self
                    .observations
                    .get(vote.payload_key())
                    .map(|info| &info.observation)
                {
                    write!(f, "Observation({:?})", observation)
                } else {
                    write!(f, "Observation(?)")
                }
            }
            Cause::Initial => write!(f, "Initial"),
            Cause::CoinShares { shares, .. } => {
                write!(f, "CoinShares({:?})", unwrap!(serialise(shares)))
            }
        }
    }
}

pub(super) fn self_parent_hash<P: PublicId>(
    graph: &Graph<P>,
    index: EventIndex,
) -> Result<EventHash, Error> {
    graph
        .get(index)
        .map(|event| *event.hash())
        .ok_or(Error::UnknownSelfParent)
}

pub(super) fn other_parent_hash<P: PublicId>(
    graph: &Graph<P>,
    index: EventIndex,
) -> Result<EventHash, Error> {
    graph
        .get(index)
        .map(|event| *event.hash())
        .ok_or(Error::UnknownOtherParent)
}

fn self_parent_index<P: PublicId>(graph: &Graph<P>, hash: &EventHash) -> Result<EventIndex, Error> {
    graph.get_index(hash).ok_or_else(|| {
        debug!("unknown self-parent with hash {:?}", hash);
        Error::UnknownSelfParent
    })
}

fn other_parent_index<P: PublicId>(
    graph: &Graph<P>,
    hash: &EventHash,
) -> Result<EventIndex, Error> {
    graph.get_index(hash).ok_or_else(|| {
        debug!("unknown other-parent with hash {:?}", hash);
        Error::UnknownOtherParent
    })
}
