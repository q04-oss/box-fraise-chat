use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SendMessageRequest {
    /// Envelope kind: 1 = whisper (ongoing session), 3 = prekey (X3DH init).
    pub envelope_type: i16,
    /// Base64-encoded ciphertext blob. Opaque to the server.
    pub ciphertext: String,
}

#[derive(Debug, Serialize)]
pub struct SendMessageResponse {
    pub id: Uuid,
    pub received_at: DateTime<Utc>,
    pub pushed_over_ws: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub id: Uuid,
    pub sender_user_id: Uuid,
    pub envelope_type: i16,
    /// Base64-encoded ciphertext.
    pub ciphertext: String,
    pub received_at: DateTime<Utc>,
}
