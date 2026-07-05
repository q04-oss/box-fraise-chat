use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Bytes on the wire are base64. Signal's own protobufs use base64
// too when JSON'd; matching that keeps the client mapping trivial.

#[derive(Debug, Deserialize)]
pub struct RegisterBundleRequest {
    pub registration_id: i32,
    /// 33 bytes, base64.
    pub identity_key: String,
    pub signed_prekey: SignedPrekeyInput,
    /// Client should upload ~100 initially; we accept any non-empty count.
    pub one_time_prekeys: Vec<OneTimePrekeyInput>,
}

#[derive(Debug, Deserialize)]
pub struct SignedPrekeyInput {
    pub key_id: i32,
    /// 33 bytes, base64.
    pub public_key: String,
    /// 64 bytes, base64. XEd25519 signature over public_key by identity_key.
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct OneTimePrekeyInput {
    pub key_id: i32,
    /// 33 bytes, base64.
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterBundleResponse {
    pub user_id: Uuid,
    pub one_time_prekeys_stored: usize,
}

#[derive(Debug, Serialize)]
pub struct PrekeyBundleResponse {
    pub user_id: Uuid,
    pub registration_id: i32,
    /// 33 bytes, base64.
    pub identity_key: String,
    pub signed_prekey: SignedPrekeyOutput,
    /// Present when the user still has an unconsumed one-time prekey.
    /// The client must gracefully handle this being absent — in Signal
    /// terms, an initial session without an OPK is weaker but valid.
    pub one_time_prekey: Option<OneTimePrekeyOutput>,
}

#[derive(Debug, Serialize)]
pub struct SignedPrekeyOutput {
    pub key_id: i32,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct OneTimePrekeyOutput {
    pub key_id: i32,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct RotateSignedPrekeyRequest {
    pub key_id: i32,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct RefillOneTimePrekeysRequest {
    pub one_time_prekeys: Vec<OneTimePrekeyInput>,
}

#[derive(Debug, Serialize)]
pub struct KeyCountResponse {
    pub unconsumed_one_time_prekeys: i64,
}
