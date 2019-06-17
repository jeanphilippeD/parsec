// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{content::Content, event_hash::EventHash};
#[cfg(all(feature = "mock", any(feature = "testing", test)))]
use crate::{
    gossip::Cause,
    id::SecretId,
    mock::{PeerId, Transaction},
};
use crate::{hash::Hash, serialise, vote::Vote, NetworkEvent, PublicId};
use std::fmt::{self, Debug, Formatter};

/// Packed event contains only content and signature.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackedEvent<T: NetworkEvent, P: PublicId> {
    pub(super) content: Content<Vote<T, P>, EventHash, P>,
    pub(super) signature: P::Signature,
}

impl<T: NetworkEvent, P: PublicId> Debug for PackedEvent<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Event{{ {:?}, creator: {:?}, self_parent: {:?}, other_parent: {:?} }}",
            self.content.cause,
            self.content.creator,
            self.content.self_parent(),
            self.content.other_parent()
        )
    }
}

impl<T: NetworkEvent, P: PublicId> PackedEvent<T, P> {
    pub(crate) fn compute_hash(&self) -> EventHash {
        EventHash(Hash::from(serialise(&self.content).as_slice()))
    }
}

#[cfg(all(feature = "mock", any(feature = "testing", test)))]
impl PackedEvent<Transaction, PeerId> {
    /// Construct a new `Requesting` packed event.
    pub fn new_requesting(creator: PeerId, recipient: PeerId, self_parent: EventHash) -> Self {
        let content = Content {
            creator,
            cause: Cause::Requesting {
                self_parent,
                recipient,
            },
        };
        Self::new(content)
    }

    /// Construct a new `Request` packed event.
    pub fn new_request(creator: PeerId, self_parent: EventHash, other_parent: EventHash) -> Self {
        let content = Content {
            creator,
            cause: Cause::Request {
                self_parent,
                other_parent,
            },
        };
        Self::new(content)
    }

    /// Construct a new `Response` packed event.
    pub fn new_response(creator: PeerId, self_parent: EventHash, other_parent: EventHash) -> Self {
        let content = Content {
            creator,
            cause: Cause::Response {
                self_parent,
                other_parent,
            },
        };
        Self::new(content)
    }

    /// Construct a new `Observation` packed event.
    #[cfg(all(test, feature = "malice-detection"))]
    pub(crate) fn new_observation(
        creator: PeerId,
        self_parent: EventHash,
        observation: crate::observation::Observation<Transaction, PeerId>,
    ) -> Self {
        let vote = Vote::new(&creator, observation);
        let content = Content {
            creator,
            cause: Cause::Observation { self_parent, vote },
        };
        Self::new(content)
    }

    /// Construct a new `Initial` packed event.
    pub fn new_initial(creator: PeerId) -> Self {
        let content = Content {
            creator,
            cause: Cause::Initial,
        };
        Self::new(content)
    }

    fn new(content: Content<Vote<Transaction, PeerId>, EventHash, PeerId>) -> Self {
        let serialised_content = serialise(&content);
        let signature = content.creator.sign_detached(&serialised_content);
        PackedEvent { content, signature }
    }

    /// Getter for the event's creator.
    pub fn creator(&self) -> &PeerId {
        &self.content.creator
    }

    /// Getter for the event's self-parent.
    pub fn self_parent(&self) -> Option<&EventHash> {
        self.content.self_parent()
    }

    /// Getter for the event's self-parent.
    pub fn other_parent(&self) -> Option<&EventHash> {
        self.content.other_parent()
    }
}
