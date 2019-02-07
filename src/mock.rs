// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::{PublicId, SecretId};
use crate::network_event::NetworkEvent;
use rand::{Rand, Rng};
use safe_crypto::Signature as SafeSignature;
use safe_crypto::{gen_sign_keypair, PublicSignKey, SecretSignKey};
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::cell::RefCell;

pub const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
    "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina", "Ulf", "Vera", "Will",
    "Xaviera", "Yakov", "Zaida", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
];

lazy_static! {
    static ref PEERS: Vec<PeerId> = NAMES
        .iter()
        .map(|name| PeerId::new_with_random_keypair(name))
        .collect();
}

static PEER_IDS: RefCell<BTreeMap<String, PeerId>> =
    RefCell::new(
        PEERS.uter().enumerate().map(|(index, id)| {
            (Names[index].to_string(), id.clone())
        }).collect());

/// **NOT FOR PRODUCTION USE**: Mock signature type.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature(SafeSignature);

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "..")
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerId {
    id: String,
    pub_sign: PublicSignKey,
    sec_sign: SecretSignKey,
}

impl PeerId {
    pub fn new(id: &str) -> Self {
        PEERS
            .iter()
            .find(|peer| peer.id == id)
            .unwrap_or(&PeerId::new_with_random_keypair(id))
            .clone()
    }

    pub fn new_with_random_keypair(id: &str) -> Self {
        let (pub_sign, sec_sign) = gen_sign_keypair();
        Self {
            id: id.to_string(),
            pub_sign,
            sec_sign,
        }
    }

    // Only being used by the dot_parser.
    #[cfg(any(test, feature = "testing"))]
    pub fn from_initial(initial: char) -> Self {
        for name in NAMES.iter() {
            if name.starts_with(initial) {
                return PeerId::new(name);
            }
        }
        panic!(
            "cannot find a name starts with {:?} within {:?}",
            initial, NAMES
        );
    }

    pub fn from_index(peer_index: usize) -> Option<Self> {
        NAMES.get(peer_index).map(|name| PeerId::new(name))
    }
}

impl Debug for PeerId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.pub_sign.hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.id == other.id && self.pub_sign == other.pub_sign
    }
}

impl Eq for PeerId {}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &PeerId) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &PeerId) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PublicId for PeerId {
    type Signature = Signature;
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.pub_sign.verify_detached(&signature.0, data)
    }
}

impl SecretId for PeerId {
    type PublicId = PeerId;
    fn public_id(&self) -> &Self::PublicId {
        &self
    }
    fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature(self.sec_sign.sign_detached(data))
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `NetworkEvent` trait.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Transaction(String);

impl Transaction {
    pub fn new<T: Into<String>>(id: T) -> Self {
        Transaction(id.into())
    }
}

impl NetworkEvent for Transaction {}

impl Display for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transaction({})", self.0)
    }
}

impl Debug for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Rand for Transaction {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        Transaction(rng.gen_ascii_chars().take(5).collect())
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    assert!(count <= NAMES.len());
    NAMES.iter().take(count).cloned().map(PeerId::new).collect()
}
