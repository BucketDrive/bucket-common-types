pub mod secret_share_link;
pub mod share_link;
pub mod util;

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::EnumIter;

// Inspired https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
    EnumIter,
)]
pub enum BucketRegion {
    #[strum(serialize = "eu-center")]
    EuropeCentral(u32),
    #[strum(serialize = "eu-north")]
    EuropeNorth(u32),
    #[strum(serialize = "eu-south")]
    EuropeSouth(u32),
    #[strum(serialize = "eu-west")]
    EuropeWest(u32),
    #[strum(serialize = "eu-east")]
    EuropeEast(u32),

    #[strum(serialize = "us-central")]
    AmericaCentral(u32),
    #[strum(serialize = "us-north")]
    AmericaNorth(u32),
    #[strum(serialize = "us-south")]
    AmericaSouth(u32),
    #[strum(serialize = "us-west")]
    AmericaWest(u32),
    #[strum(serialize = "us-east")]
    AmericaEast(u32),

    #[strum(serialize = "af-central")]
    AfricaCentral(u32),
    #[strum(serialize = "af-north")]
    AfricaNorth(u32),
    #[strum(serialize = "af-south")]
    AfricaSouth(u32),
    #[strum(serialize = "af-west")]
    AfricaWest(u32),
    #[strum(serialize = "af-east")]
    AfricaEast(u32),

    #[strum(serialize = "ap-center")]
    AsiaPacificCentral(u32),
    #[strum(serialize = "ap-north")]
    AsiaPacificNorth(u32),
    #[strum(serialize = "ap-south")]
    AsiaPacificSouth(u32),
    #[strum(serialize = "ap-west")]
    AsiaPacificWest(u32),
    #[strum(serialize = "ap-east")]
    AsiaPacificEast(u32),

    #[strum(serialize = "me-central")]
    MiddleEastCentral(u32),
    #[strum(serialize = "me-north")]
    MiddleEastNorth(u32),
    #[strum(serialize = "me-south")]
    MiddleEastSouth(u32),
    #[strum(serialize = "me-west")]
    MiddleEastWest(u32),
    #[strum(serialize = "me-east")]
    MiddleEastEast(u32),

    #[strum(serialize = "sa-central")]
    SouthAmericaCentral(u32),
    #[strum(serialize = "sa-north")]
    SouthAmericaNorth(u32),
    #[strum(serialize = "sa-south")]
    SouthAmericaSouth(u32),
    #[strum(serialize = "sa-west")]
    SouthAmericaWest(u32),
    #[strum(serialize = "sa-east")]
    SouthAmericaEast(u32),
}

pub type ClusterId = u32;

pub struct RegionCluster {
    region: BucketRegion,
    cluster_id: ClusterId,
}

impl FromStr for RegionCluster {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('-');
        let region = split.next().ok_or(())?;
        let cluster_id = split.next().ok_or(())?.parse().map_err(|_| ())?;
        Ok(RegionCluster {
            region: region.parse().map_err(|_| ())?,
            cluster_id,
        })
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
pub enum BucketCompression {
    None,
    Gzip,
    Brotli,
    Zstd,
}

/*
Video Codec Support Matrix TODO: Add...
*/
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
pub enum VideoCodec {
    AV1,
    H264,
}

enum BucketPermission {}

#[derive(Debug, Clone, Eq, PartialEq)]
enum BucketAvailabilityStatus {
    Creating,
    Available,
    Deleting,
    Deleted,
    Updating,
    Archiving,
    Restoring,
    Unavailable,
    Unreachable,
    Corrupted,
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
pub enum AvailabilityStatus {
    //TODO: REMOVE?
    Creating,
    Available,
    Deleting,
    Deleted,
    Updating,
    Archiving,
    Restoring,
    Unavailable,
    Unreachable,
    Corrupted,
}
/*
* General: Standard storage class. Will use HDD.
* Reduced Redundancy: Will use HDD but with less redundancy and more risk for the end user.
*/
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
pub enum BucketStorageClass {
    General,
    ReducedRedundancy,
}

/*
https://stripe.com/docs/products-prices/pricing-models#volume-tiers
User can only have one active subscription at a time.
either metered or subscription.
Both can not be active at the same time.
The user is able to do one time payments as well whenever.


The payment plans available will be

Pricing
- Pay Once.
- Metered. (Pay per usage)
- Subscription.
- One Time Payment.

When ever a user uses subscription or onetime-payment then user balance is used.
When a user runs out of balance they can no longer use services that cost.

metered subscription provide unlimited usage. But

*/
#[derive(Debug, Clone, Eq, PartialEq, strum::Display, strum::EnumString, Serialize, Deserialize)]
pub enum PaymentModel {
    Metered,
    Subscription,
    OneTime,
}

/*
* None: uses no encryption.
* AES256: uses server side encryption.
* Zero-Knowledge: uses client side encryption.
* Custom: uses custom encryption. Relies on the client implementing the encryption specifics.
*/
#[derive(Debug, Clone, Eq, PartialEq, strum::Display, Serialize, Deserialize)]
pub enum BucketEncryption {
    None,
    AES256,
    ZeroKnowledge,
    // Must start with 'Custom-' and then the name of the encryption. with a max length of 64 characters entirely.
    Custom(String),
}
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum BucketEncryptionParsingError {
    #[error("invalid custom encryption format")]
    InvalidCustomFormat(),
}

impl FromStr for BucketEncryption {
    type Err = BucketEncryptionParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "None" => Ok(BucketEncryption::None),
            "AES256" => Ok(BucketEncryption::AES256),
            "ZeroKnowledge" => Ok(BucketEncryption::ZeroKnowledge),
            x => {
                if !x.starts_with("Custom-") {
                    return Err(BucketEncryptionParsingError::InvalidCustomFormat());
                }
                if x.len() > 64 {
                    return Err(BucketEncryptionParsingError::InvalidCustomFormat());
                }
                Ok(BucketEncryption::Custom(s.to_string()))
            }
        }
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
pub enum BucketVisibility {
    /// Anyone can see the bucket
    Public,
    /// Only author and invited users can see the bucket, Bucket will be made private-shared if private bucket is shared.
    PrivateShared,
    /// Only author.
    Private,
}

// All the available addons/features a bucket has active.
bitflags::bitflags! {
    #[derive(Debug,Copy, Clone, Eq,PartialEq)]
    pub struct BucketFeaturesFlags: u32 {
        const IS_SEARCHABLE         = 0b00000001;
        const IS_PASSWORD_PROTECTED = 0b00000010;
        const IS_SHARABLE           = 0b00000100;
        const IS_SEARCH_INDEXED     = 0b00001000;
    }
}

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
)]
pub enum DownloadFormat {
    Zip,
    Tar,
    Raw,
}

/*
* Metered Subscription is the intended usage with monthly subscription being the main alternative in the form of. But to make it easier for regular users to use the service it also offers basic and premium plans.
*/
#[derive(Debug, Clone, Copy, Eq, PartialEq, strum::Display, strum::EnumString, Serialize, Deserialize)]
pub enum PaymentPlan {
    Free,
    //MonthlyBasic,
    //MonthlyPremium,
    MeteredSubscription,
    MonthlySubscription,
    OneTime,
    Canceled, // When using any subscription type and the user want's to cancel it. An update account with payment plan as canceled is requested.
}

/*
* https://stripe.com/en-se/guides/payment-methods-guide
*/
#[derive(Debug, Clone, Eq, PartialEq, strum::Display, strum::EnumString, Serialize, Deserialize)]
pub enum PaymentMethod {
    Card,
    Wallet,
    BankDebit,
    //Crypto, // Support later, maybe?
}

bitflags::bitflags! {
    /// NOTE* can not just cast verifaction between u32 and i32 because of bit flip
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Verification : i16 {
        const UNVERIFIED = 0b0000_0000_0000_0000;
        const EMAIL = 0b0000_0000_0000_0001;
        const PHONE = 0b0000_0000_0000_0010;
        const TOTP = 0b0000_0000_0000_0100;
    }
}
