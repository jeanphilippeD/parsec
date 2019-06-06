// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Ack, Part};
use crate::parsec::BlockNumber;
use std::fmt;

#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DkgMessage {
    Part {
        block_number: BlockNumber,
        part: Part,
    },
    Ack {
        block_number: BlockNumber,
        ack: Ack,
    },
}

impl fmt::Debug for DkgMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DkgMessage::Part { block_number, .. } => write!(formatter, "DkgPart({})", block_number),
            DkgMessage::Ack { block_number, .. } => write!(formatter, "DkgAck({})", block_number),
        }
    }
}
