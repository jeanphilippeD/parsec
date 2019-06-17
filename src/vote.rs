// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{
    error::Error,
    id::{Proof, PublicId, SecretId},
    network_event::NetworkEvent,
    observation::{ConsensusMode, Observation, ObservationHash, ObservationKey, ObservationStore},
    peer_list::PeerIndex,
};
use serde::de::DeserializeOwned;
use std::fmt::{self, Debug, Formatter};

/// A helper struct carrying an `Observation` and a signature of this `Observation`.
#[serde(bound(deserialize = "T: DeserializeOwned"))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote<T: NetworkEvent, P: PublicId> {
    payload: Observation<T, P>,
    signature: P::Signature,
}

impl<T: NetworkEvent, P: PublicId> Vote<T, P> {
    /// Creates a `Vote` for `payload`.
    pub fn new<S: SecretId<PublicId = P>>(secret_id: &S, payload: Observation<T, P>) -> Self {
        let signature = secret_id.sign_detached(&payload.as_ref().serialise_for_signature());
        Self { payload, signature }
    }

    /// Returns the payload being voted for.
    pub fn payload(&self) -> &Observation<T, P> {
        &self.payload
    }

    /// Returns the signature of this `Vote`'s payload.
    pub fn signature(&self) -> &P::Signature {
        &self.signature
    }

    /// Validates this `Vote`'s signature and payload against the given public ID.
    pub fn is_valid(&self, public_id: &P) -> bool {
        public_id.verify_signature(
            &self.signature,
            &self.payload.as_ref().serialise_for_signature(),
        )
    }

    /// Creates a `Proof` from this `Vote`.  Returns `Err` if this `Vote` is not valid (i.e. if
    /// `!self.is_valid()`).
    pub fn create_proof(&self, public_id: &P) -> Result<Proof<P>, Error> {
        if self.is_valid(public_id) {
            return Ok(Proof {
                public_id: public_id.clone(),
                signature: self.signature.clone(),
            });
        }
        Err(Error::SignatureFailure)
    }
}

impl<T: NetworkEvent, P: PublicId> Debug for Vote<T, P> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.payload)
    }
}

/// Key representing a vote when stored inside the gossip graph.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct VoteKey<P: PublicId> {
    payload_key: ObservationKey,
    signature: P::Signature,
}

impl<P: PublicId> VoteKey<P> {
    pub fn new<T: NetworkEvent>(
        vote: Vote<T, P>,
        creator: PeerIndex,
        consensus_mode: ConsensusMode,
    ) -> (Self, Observation<T, P>) {
        let consensus_mode = consensus_mode.of(&vote.payload.as_ref());
        let hash = ObservationHash::from(&vote.payload.as_ref());
        let payload_key = ObservationKey::new(hash, creator, consensus_mode);

        let vote_key = Self {
            payload_key,
            signature: vote.signature,
        };

        (vote_key, vote.payload)
    }

    /// Fetch the `Vote` corresponding to `key`.
    pub fn resolve<T: NetworkEvent>(
        &self,
        observations: &ObservationStore<T, P>,
    ) -> Result<Vote<T, P>, Error> {
        Ok(Vote {
            payload: observations
                .get(&self.payload_key)
                .map(|info| info.observation.clone())
                .ok_or(Error::UnknownPayload)?,
            signature: self.signature.clone(),
        })
    }

    pub fn payload_key(&self) -> &ObservationKey {
        &self.payload_key
    }
}

impl<P: PublicId> Debug for VoteKey<P> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.payload_key)
    }
}
