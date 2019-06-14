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
    /// Aggregate public key
    pub public_key_set: PublicKeySet,
    /// Secrect Key share
    pub secret_key_share: Option<SecretKeyShare>,
}

impl DkgResult {
    /// New DkgResult
    pub fn new(public_key_set: PublicKeySet, secret_key_share: Option<SecretKeyShare>) -> Self {
        Self {
            public_key_set,
            secret_key_share,
        }
    }

    fn comparaison_value(&self) -> (&PublicKeySet, bool) {
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
        self.comparaison_value().eq(&rhs.comparaison_value())
    }
}

impl Eq for DkgResult {}

impl PartialOrd for DkgResult {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.comparaison_value()
            .partial_cmp(&rhs.comparaison_value())
    }
}

impl Ord for DkgResult {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.comparaison_value().cmp(&rhs.comparaison_value())
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
