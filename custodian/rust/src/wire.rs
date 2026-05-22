//! Wire-format helpers (base64 byte encoding used by sealed state and grants).

/// `serde` adapter that encodes `Vec<u8>` as standard base64.
pub mod b64bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Serialize a byte slice as standard base64.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        base64::engine::general_purpose::STANDARD
            .encode(v)
            .serialize(s)
    }

    /// Deserialize a base64-encoded string into bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}
