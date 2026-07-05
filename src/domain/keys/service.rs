use base64::Engine;
use uuid::Uuid;

use crate::db::{AdminRlsTransaction, Pool, RlsTransaction};
use crate::domain::keys::{repository, types::*};
use crate::error::{AppError, AppResult};

fn decode_b64(s: &str, expected_len: usize, label: &str) -> AppResult<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| AppError::bad_request(format!("{label}: not valid base64")))?;
    if bytes.len() != expected_len {
        return Err(AppError::bad_request(format!(
            "{label}: expected {expected_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub async fn register_bundle(
    pool: &Pool,
    user_id: Uuid,
    req: RegisterBundleRequest,
) -> AppResult<RegisterBundleResponse> {
    if !(1..=16383).contains(&req.registration_id) {
        return Err(AppError::bad_request(
            "registration_id out of range 1..=16383",
        ));
    }
    let identity_key = decode_b64(&req.identity_key, 33, "identity_key")?;
    let spk_public = decode_b64(
        &req.signed_prekey.public_key,
        33,
        "signed_prekey.public_key",
    )?;
    let spk_sig = decode_b64(&req.signed_prekey.signature, 64, "signed_prekey.signature")?;

    // Decode + validate all OPKs before we touch the DB.
    let mut opks: Vec<(i32, Vec<u8>)> = Vec::with_capacity(req.one_time_prekeys.len());
    for k in &req.one_time_prekeys {
        let pk = decode_b64(&k.public_key, 33, "one_time_prekey.public_key")?;
        opks.push((k.key_id, pk));
    }

    let mut tx = RlsTransaction::begin(pool, user_id).await?;
    repository::upsert_identity(tx.conn(), user_id, req.registration_id, &identity_key).await?;
    repository::upsert_signed_prekey(
        tx.conn(),
        user_id,
        req.signed_prekey.key_id,
        &spk_public,
        &spk_sig,
    )
    .await?;
    let stored = repository::insert_one_time_prekeys(tx.conn(), user_id, &opks).await?;
    tx.commit().await?;

    Ok(RegisterBundleResponse {
        user_id,
        one_time_prekeys_stored: stored,
    })
}

pub async fn rotate_signed_prekey(
    pool: &Pool,
    user_id: Uuid,
    req: RotateSignedPrekeyRequest,
) -> AppResult<()> {
    let pk = decode_b64(&req.public_key, 33, "public_key")?;
    let sig = decode_b64(&req.signature, 64, "signature")?;
    let mut tx = RlsTransaction::begin(pool, user_id).await?;
    repository::upsert_signed_prekey(tx.conn(), user_id, req.key_id, &pk, &sig).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn refill_one_time_prekeys(
    pool: &Pool,
    user_id: Uuid,
    req: RefillOneTimePrekeysRequest,
) -> AppResult<usize> {
    let mut opks: Vec<(i32, Vec<u8>)> = Vec::with_capacity(req.one_time_prekeys.len());
    for k in &req.one_time_prekeys {
        let pk = decode_b64(&k.public_key, 33, "one_time_prekey.public_key")?;
        opks.push((k.key_id, pk));
    }
    let mut tx = RlsTransaction::begin(pool, user_id).await?;
    let n = repository::insert_one_time_prekeys(tx.conn(), user_id, &opks).await?;
    tx.commit().await?;
    Ok(n)
}

pub async fn count_own_one_time_prekeys(pool: &Pool, user_id: Uuid) -> AppResult<i64> {
    let mut tx = RlsTransaction::begin(pool, user_id).await?;
    let n = repository::count_unconsumed_one_time_prekeys(tx.conn(), user_id).await?;
    tx.commit().await?;
    Ok(n)
}

/// Fetch a prekey bundle for `target_user_id`, consuming one OPK.
/// Runs under admin context so the caller can atomically read+consume
/// even though they are not the target. This is the intended
/// distribution path — no PII is exposed, only public key material.
pub async fn fetch_bundle(pool: &Pool, target_user_id: Uuid) -> AppResult<PrekeyBundleResponse> {
    let mut tx = AdminRlsTransaction::begin(pool).await?;
    let identity = repository::get_identity(tx.conn(), target_user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let spk = repository::get_signed_prekey(tx.conn(), target_user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let opk = repository::take_one_one_time_prekey(tx.conn(), target_user_id).await?;
    tx.commit().await?;

    Ok(PrekeyBundleResponse {
        user_id: target_user_id,
        registration_id: identity.registration_id,
        identity_key: encode_b64(&identity.identity_key),
        signed_prekey: SignedPrekeyOutput {
            key_id: spk.key_id,
            public_key: encode_b64(&spk.public_key),
            signature: encode_b64(&spk.signature),
        },
        one_time_prekey: opk.map(|k| OneTimePrekeyOutput {
            key_id: k.key_id,
            public_key: encode_b64(&k.public_key),
        }),
    })
}
