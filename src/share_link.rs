#![cfg(feature = "share_link")]

use base64::{Engine, engine::general_purpose};
use serde::{Deserialize, Serialize};
use crate::util::{DOMAIN_URL, SHARE_PATH_URL};


bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    pub struct BucketSharePermissionFlags : u32 {
        const VIEW =            0b00000000_00000000_00000000_00000001; // The ability to view the bucket files, but not read or write. basically just view the file-structure.
        const READ =            0b00000000_00000000_00000000_00000010; // The ability to read from the bucket.
        const WRITE =           0b00000000_00000000_00000000_00000100; // The ability to write to the bucket.
        const DELETE_FILE =     0b00000000_00000000_00000000_00001000; // The ability to delete file from the bucket.
        const DELETE_BUCKET =   0b00000000_00000000_00000000_00010000; // The ability to delete the bucket
        const SHARE_BUCKET =    0b00000000_00000000_00000000_00100000; // The ability to share the bucket with others.
        const CLONE =           0b00000000_00000000_00000000_01000000; // The ability to clone the bucket.
        const SEARCH =          0b00000000_00000000_00000000_10000000; // The ability to search inside the bucket.
    }
}

/*
*  Bucket share link
*  bucketdrive.co/api/v1/share/user_id/bucket_id#permissions#expires#signature
*/
pub struct ShareLink {
    pub token: [u8; 32],
}

impl ToString for ShareLink {
    fn to_string(&self) -> String {
        format!(
            "{}{}/share/{}",
            DOMAIN_URL,
            SHARE_PATH_URL,
            general_purpose::URL_SAFE_NO_PAD.encode(self.token),
        )
    }
}

impl TryInto<url::Url> for ShareLink {
    type Error = url::ParseError;
    fn try_into(self) -> Result<url::Url, Self::Error> {
        url::Url::parse(self.to_string().as_str())
    }
}

pub enum ShareLinkParsingError {}

// Compress Share Link???
//TODO: FIX THIS
// Very strict parser.
impl TryFrom<url::Url> for ShareLink {
    type Error = ShareLinkParsingError;
    fn try_from(url: url::Url) -> Result<Self, Self::Error> {
        let path = url.path();
        let parts = path.split('/').take(1).collect::<Vec<&str>>(); // First element should be empty.
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1].parse::<String>().unwrap()).unwrap();

        Ok(Self {
            token: token.try_into().unwrap()
        })
    }
}
/*
Each file is hashed in the bucket.
The hash is stored in a file with a unique signature.
The hash is signed by the clients private key.
The hash can then be verified against the created signature by the client.
This leads to the file being verifiable to the client. Meaning no one can tamper with the file without the client knowing.
*/
impl ShareLink {
    pub fn new() -> Self {
        let token = rand::random::<[u8;32]>(); // 256 bits
        Self{
            token,
        }
    }

    pub fn get_token(&self) -> [u8;32] {
        self.token
    }
    pub fn gen_token() -> [u8; 32] {
        rand::random::<[u8;32]>()
    }
}
