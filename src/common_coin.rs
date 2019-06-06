// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::PublicId;
use crate::round_hash::RoundHash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare, SignatureShare};

/// A struct allowing for creation of common coin shares and getting a coin flip result from
/// gathered shares
#[derive(Debug)]
pub struct CommonCoin<P: PublicId> {
    public_ids: BTreeSet<P>,
    public_key_set: PublicKeySet,
    secret_key_share: Option<SecretKeyShare>,
}

impl<P: PublicId> CommonCoin<P> {
    /// Creates a new CommonCoin instance
    pub fn new(
        public_ids: BTreeSet<P>,
        public_key_set: PublicKeySet,
        secret_key_share: Option<SecretKeyShare>,
    ) -> Self {
        CommonCoin {
            public_ids,
            public_key_set,
            secret_key_share,
        }
    }

    /// Returns the public key set for validating shares
    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.public_key_set
    }

    /// Returns a clone of the CommonCoin without a secret key share (can only be used for
    /// validation purposes, cannot create new shares)
    pub fn validator_coin(&self) -> Self {
        CommonCoin {
            public_ids: self.public_ids.clone(),
            public_key_set: self.public_key_set.clone(),
            secret_key_share: None,
        }
    }

    pub(crate) fn sign_round_hash(&self, round_hash: &RoundHash) -> Option<SignatureShare> {
        self.secret_key_share
            .as_ref()
            .map(|sks| sks.sign(round_hash.value()))
    }

    pub(crate) fn verify_share(
        &self,
        round_hash: &RoundHash,
        author: P,
        sig_share: &SignatureShare,
    ) -> bool {
        self.public_ids
            .iter()
            .position(|id| *id == author)
            .map(|idx| idx as u64)
            .map_or(false, |author_idx| {
                self.public_key_set
                    .public_key_share(author_idx)
                    .verify(sig_share, round_hash.value())
            })
    }

    pub(crate) fn get_value(
        &self,
        round_hash: &RoundHash,
        shares: BTreeMap<P, SignatureShare>,
    ) -> Option<bool> {
        if shares.len() <= self.public_key_set.threshold() {
            return None;
        }
        let shares_iter = self
            .public_ids
            .iter()
            .enumerate()
            .filter_map(|(idx, pub_id)| {
                shares.get(pub_id).and_then(|share| {
                    if self
                        .public_key_set
                        .public_key_share(idx)
                        .verify(share, round_hash.value())
                    {
                        Some((idx, share))
                    } else {
                        None
                    }
                })
            });
        self.public_key_set
            .combine_signatures(shares_iter)
            .map_err(|err| log_or_panic!("Error when combining signatures: {}", err))
            .ok()
            .map(|sig| sig.parity())
    }
}

impl<P: PublicId> Serialize for CommonCoin<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            &self.public_ids,
            &self.public_key_set,
            self.secret_key_share.as_ref().map(|sks| SerdeSecret(sks)),
        )
            .serialize(serializer)
    }
}

impl<'de, P: PublicId> Deserialize<'de> for CommonCoin<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (public_ids, public_key_set, SerdeSecret(secret_key_share)) =
            Deserialize::deserialize(deserializer)?;
        Ok(CommonCoin {
            public_ids,
            public_key_set,
            secret_key_share,
        })
    }
}
