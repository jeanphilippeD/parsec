// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
};
use threshold_crypto::{PublicKeySet, SecretKeyShare};

#[derive(Clone)]
/// DKG result
pub struct DkgResult {
    /// Public key set to verify threshold signatures
    pub public_key_set: PublicKeySet,
    /// Secret Key share: None if the node was not participating in the DKG and did not receive
    /// encrypted shares.
    pub secret_key_share: Option<SecretKeyShare>,
}

impl DkgResult {
    /// Create DkgResult from components
    pub fn new(public_key_set: PublicKeySet, secret_key_share: Option<SecretKeyShare>) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }

    fn comparison_value(&self) -> (&PublicKeySet, bool) {
        (&self.public_key_set, self.secret_key_share.is_some())
    }
}

impl Debug for DkgResult {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "DkgResult({:?}, {})",
            self.public_key_set,
            self.secret_key_share.is_some()
        )
    }
}

impl PartialEq for DkgResult {
    fn eq(&self, rhs: &Self) -> bool {
        self.comparison_value().eq(&rhs.comparison_value())
    }
}

impl Eq for DkgResult {}

impl PartialOrd for DkgResult {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.comparison_value().partial_cmp(&rhs.comparison_value())
    }
}

impl Ord for DkgResult {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.comparison_value().cmp(&rhs.comparison_value())
    }
}

impl Serialize for DkgResult {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.public_key_set.serialize(s)
    }
}

impl<'a> Deserialize<'a> for DkgResult {
    fn deserialize<D: Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        PublicKeySet::deserialize(deserializer).map(|public_key_set| Self {
            public_key_set,
            secret_key_share: None,
        })
    }
}
