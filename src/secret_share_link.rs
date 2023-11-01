#![cfg(feature = "secret_share_link")]

use aes_gcm::{self, Aes256Gcm};
use base64::{Engine, engine::general_purpose};
use ed25519_compact::Noise;
use sha3::{Digest, Sha3_224};
use time::OffsetDateTime;

use crate::{share_link::BucketSharePermissionFlags, util::DOMAIN_URL};
use crate::util::SECRET_SHARE_PATH_URL;


// Only difference between ShareLink and SecretShareLink is that SecretShareLink has a bucket key Aes256Gcm.
// And that SecretShareLink use
#[derive(Debug, Copy, Clone)]
pub struct SecretShareLink {
    pub user_id: uuid::Uuid,
    pub bucket_id: uuid::Uuid,
    pub bucket_key: aes_gcm::Key<Aes256Gcm>,
    pub permission: BucketSharePermissionFlags,
    pub expires: Option<OffsetDateTime>,
    // Recommended to always have an expiration date. because reuse of an old share-link to create signature signature.
    pub signature: ed25519_compact::Signature, // The signature is stored in the link. This makes sure that the link is not tampered with.
}

// Hash the secret share link to get a unique identifier that is then signed with ed22219 key to create the signature.
// Does not include the signature in the hash.
// https://github.com/RustCrypto/hashes
fn hash_secret_share_link<D: Digest>(user_id: uuid::Uuid, bucket_id: uuid::Uuid, bucket_key: aes_gcm::Key<Aes256Gcm>, permission: BucketSharePermissionFlags, expires: Option<OffsetDateTime>, output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.update(user_id.as_bytes());
    hasher.update(bucket_id.as_bytes());
    hasher.update(bucket_key.as_slice());
    hasher.update(permission.bits().to_be_bytes());
    if let Some(expires) = expires {
        hasher.update(bincode::serialize(&expires).unwrap());
    }
    output.copy_from_slice(&hasher.finalize());
}

impl ToString for SecretShareLink {
    fn to_string(&self) -> String {
        match self.expires {
            Some(expires) => {
                format!(
                    "{}{}/{}/{}#{}#{}#{}#{}",
                    DOMAIN_URL,
                    SECRET_SHARE_PATH_URL,
                    self.user_id,
                    self.bucket_id,
                    general_purpose::URL_SAFE_NO_PAD.encode(self.bucket_key.as_slice()),
                    general_purpose::URL_SAFE_NO_PAD.encode(self.permission.bits().to_be_bytes()),
                    general_purpose::URL_SAFE_NO_PAD
                        .encode(bincode::serialize(&expires).unwrap().as_slice()),
                    general_purpose::URL_SAFE_NO_PAD.encode(self.signature.as_slice()),
                )
            }
            None => {
                format!(
                    "{}{}/{}/{}#{}#{}#{}",
                    DOMAIN_URL,
                    SECRET_SHARE_PATH_URL,
                    self.user_id,
                    self.bucket_id,
                    general_purpose::URL_SAFE_NO_PAD.encode(self.bucket_key.as_slice()),
                    general_purpose::URL_SAFE_NO_PAD.encode(self.permission.bits().to_be_bytes()),
                    general_purpose::URL_SAFE_NO_PAD.encode(self.signature.as_slice()),
                )
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretShareLinkParsingError {
    #[error("Invalid host")]
    InvalidHostDomain,
    #[error("Invalid version format")]
    InvalidVersionFormat,

    #[error(transparent)]
    Base64Decoding(#[from] base64::DecodeError),
    #[error(transparent)]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

impl TryFrom<url::Url> for SecretShareLink {
    type Error = SecretShareLinkParsingError;

    fn try_from(value: url::Url) -> Result<Self, Self::Error> {
        let domain = value.domain().ok_or(Self::Error::InvalidHostDomain)?;
        if domain != DOMAIN_URL {
            return Err(Self::Error::InvalidHostDomain);
        }
        let path = value.path();
        let parts = path.split('/').take(1).collect::<Vec<&str>>(); // First element should be empty.
        let user_id = parts[0].parse::<uuid::Uuid>().unwrap();
        let bucket_id = parts[1].parse::<uuid::Uuid>().unwrap();
        let fragments = parts[3].split('#').take(1).collect::<Vec<&str>>(); // Guessing first part is just the path.
        let bucket_key = *aes_gcm::Key::<Aes256Gcm>::from_slice(
            general_purpose::URL_SAFE_NO_PAD
                .decode(fragments[1].as_bytes())
                .unwrap()
                .as_slice(),
        );
        let permission = BucketSharePermissionFlags::from_bits(u32::from_be_bytes(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(fragments[2].as_bytes())
                .unwrap()
                .try_into()
                .unwrap(),
        ))
            .unwrap();
        let has_expires_field = fragments.len() == 4;
        let expires: Option<OffsetDateTime> = match has_expires_field {
            true => Some(
                bincode::deserialize(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(fragments[3])
                        .unwrap()
                        .as_slice(),
                )
                    .unwrap(),
            ),
            false => None,
        };
        let mut signature_index = 5;
        if !has_expires_field {
            signature_index -= 1;
        }
        let signature = ed25519_compact::Signature::from_slice(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(fragments[signature_index])
                .unwrap()
                .as_slice(),
        )
            .unwrap();
        Ok(Self {
            user_id,
            bucket_id,
            bucket_key,
            permission,
            expires,
            signature,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SecretShareLinkVerifySignatureError {
    #[error("Invalid signature")]
    InvalidSignature(#[from] ed25519_compact::Error),
}


impl SecretShareLink {
    // Verify the signature against the signature file with special identifier.
    pub fn verify_signature(
        &self,
        public_signing_key: ed25519_compact::PublicKey,
    ) -> Result<(), SecretShareLinkVerifySignatureError> {
        let mut hash_output = [0; 64];
        hash_secret_share_link::<Sha3_224>(self.user_id, self.bucket_id, self.bucket_key, self.permission, self.expires, &mut hash_output);
        Ok(public_signing_key.verify(hash_output, &self.signature)?)
    }


    pub fn new(user_id: uuid::Uuid,
               bucket_id: uuid::Uuid,
               bucket_key: aes_gcm::Key<Aes256Gcm>,
               permission: BucketSharePermissionFlags,
               expires: Option<OffsetDateTime>,
               secret_key: &ed25519_compact::SecretKey) -> Self {
        let mut hash_output = [0; 64];
        hash_secret_share_link::<Sha3_224>(user_id, bucket_id, bucket_key, permission, expires, &mut hash_output);

        let noise = Noise::from_slice(bucket_id.as_bytes().as_slice()).unwrap(); // Do we even need it?
        let signature = secret_key.sign(hash_output, Some(noise));
        Self {
            user_id,
            bucket_id,
            bucket_key,
            permission,
            expires,
            signature,
        }
    }
    // TODO: There is no way for the server to invalidate a secret share link.
    /*
    Generate a token that is used by the server to identify the link.
    */
    pub fn get_token(&self) -> [u8; 32] {
        let mut hash_output = [0; 64];
        hash_secret_share_link::<Sha3_224>(self.user_id, self.bucket_id, self.bucket_key, self.permission, self.expires, &mut hash_output);
        let mut output: [u8; 32] = [0; 32];
        output.clone_from_slice(&hash_output[0..32]);
        output
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretShareLinkFormatError {
    #[error(transparent)]
    SecretShareLinkFormatError(#[from] SecretShareLinkParsingError),
}

impl TryInto<url::Url> for SecretShareLink {
    type Error = SecretShareLinkFormatError;

    fn try_into(self) -> Result<url::Url, Self::Error> {
        let res: String = self.to_string();
        Ok(url::Url::parse(&res).unwrap())
    }
}


#[cfg(test)]
mod tests {
    use rand::random;
    use rand::rngs::OsRng;
    use super::*;

    #[test]
    fn create_secret_share_link() {
        //Generate pseudo random bytes for the base64 conversion
        let bucket_key_bytes = rand::random::<[u8; 32]>();
        let bucket_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&bucket_key_bytes);

        let permission = BucketSharePermissionFlags::VIEW;

        //Create a dummy secret key for the signing process
        let secret_key_bytes = random::<[u8;32]>();
        let secret_key = ed25519_compact::SecretKey::from_slice(&secret_key_bytes).unwrap();

        let ssl = SecretShareLink::new(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            *bucket_key,
            permission,
            Some(OffsetDateTime::now_utc()),
            &secret_key,
        );
        assert!(ssl.bucket_key != *aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]));
        assert!(ssl.permission == permission);
    }

    #[test]
    fn secret_share_link_to_and_from_url() {
        // Set up values for a SecretShareLink
        let user_id = uuid::Uuid::new_v4();
        let bucket_id = uuid::Uuid::new_v4();
        let bucket_key_bytes = [0u8; 32];
        let bucket_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&bucket_key_bytes);
        let permission = BucketSharePermissionFlags::VIEW; //You need to replace ValorA
        let expires = Some(OffsetDateTime::now_utc());
        let secret_key = ed25519_compact::SecretKey::from_slice(&[0u8; 32]).unwrap();

        // Create a SecretShareLink
        let original_link = SecretShareLink::new(
            user_id,
            bucket_id,
            *bucket_key,
            permission,
            expires,
            &secret_key,
        );

        // Convert it to a URL and back to a SecretShareLink
        let url: url::Url = original_link.try_into().unwrap();
        let parsed_link: SecretShareLink = url.try_into().unwrap();

        // Assert that both links are equivalent
        assert_eq!(original_link.user_id, parsed_link.user_id);
        assert_eq!(original_link.bucket_id, parsed_link.bucket_id);
        assert_eq!(original_link.bucket_key, parsed_link.bucket_key);
        assert_eq!(original_link.permission, parsed_link.permission);
        assert_eq!(original_link.expires.unwrap().date(), parsed_link.expires.unwrap().date());
    }

    #[test]
    fn signature_verification() {
        let user_id = uuid::Uuid::new_v4();
        let bucket_id = uuid::Uuid::new_v4();
        // Create a SecretKey and corresponding PublicKey for the signing process
        let bytes = random::<[u8;32]>();
        let key_pair = ed25519_compact::KeyPair::from_slice(&bytes).unwrap();

        let bucket_key_bytes = rand::random::<[u8; 32]>();
        let bucket_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&bucket_key_bytes);
        let permission = BucketSharePermissionFlags::VIEW; //You need to replace ValorA
        let expires = Some(OffsetDateTime::now_utc());

        let link = SecretShareLink::new(
            user_id,
            bucket_id,
            *bucket_key,
            permission,
            expires,
            &key_pair.sk,
        );

        assert_eq!(link.verify_signature(key_pair.pk), Ok(()));
    }
}