use base64::Engine;
use uuid::Uuid;

use crate::db::{Pool, RlsTransaction};
use crate::domain::messages::{repository, types::*};
use crate::domain::ws::hub::WsHub;
use crate::error::{AppError, AppResult};

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn stored_to_envelope(m: repository::StoredEnvelope) -> Envelope {
    Envelope {
        id: m.id,
        sender_user_id: m.sender_user_id,
        envelope_type: m.envelope_type,
        ciphertext: encode_b64(&m.ciphertext),
        received_at: m.received_at,
    }
}

pub async fn send(
    pool: &Pool,
    hub: &WsHub,
    sender: Uuid,
    recipient: Uuid,
    req: SendMessageRequest,
) -> AppResult<SendMessageResponse> {
    if sender == recipient {
        return Err(AppError::bad_request("cannot send to yourself"));
    }
    if !matches!(req.envelope_type, 1 | 3) {
        return Err(AppError::bad_request("envelope_type must be 1 or 3"));
    }
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&req.ciphertext)
        .map_err(|_| AppError::bad_request("ciphertext: not valid base64"))?;
    if ciphertext.is_empty() || ciphertext.len() > 65536 {
        return Err(AppError::bad_request("ciphertext length 1..=65536"));
    }

    let mut tx = RlsTransaction::begin(pool, sender).await?;
    let stored =
        repository::enqueue(tx.conn(), sender, recipient, req.envelope_type, &ciphertext).await?;
    tx.commit().await?;

    let env = stored_to_envelope(stored);
    let pushed = hub.deliver(recipient, &env);
    Ok(SendMessageResponse {
        id: env.id,
        received_at: env.received_at,
        pushed_over_ws: pushed,
    })
}

pub async fn list_pending(pool: &Pool, recipient: Uuid, limit: i64) -> AppResult<Vec<Envelope>> {
    let mut tx = RlsTransaction::begin(pool, recipient).await?;
    let rows = repository::list_pending_for(tx.conn(), recipient, limit).await?;
    tx.commit().await?;
    Ok(rows.into_iter().map(stored_to_envelope).collect())
}

pub async fn acknowledge(pool: &Pool, recipient: Uuid, message_id: Uuid) -> AppResult<()> {
    let mut tx = RlsTransaction::begin(pool, recipient).await?;
    let ok = repository::acknowledge_one(tx.conn(), recipient, message_id).await?;
    tx.commit().await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    Ok(())
}
