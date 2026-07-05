use sqlx::PgConnection;
use uuid::Uuid;

pub async fn upsert_identity(
    conn: &mut PgConnection,
    user_id: Uuid,
    registration_id: i32,
    identity_key: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO chat_identities (user_id, registration_id, identity_key)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id) DO UPDATE
           SET registration_id = EXCLUDED.registration_id,
               identity_key    = EXCLUDED.identity_key,
               updated_at      = now()",
    )
    .bind(user_id)
    .bind(registration_id)
    .bind(identity_key)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn upsert_signed_prekey(
    conn: &mut PgConnection,
    user_id: Uuid,
    key_id: i32,
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO chat_signed_prekeys (user_id, key_id, public_key, signature)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id) DO UPDATE
           SET key_id     = EXCLUDED.key_id,
               public_key = EXCLUDED.public_key,
               signature  = EXCLUDED.signature,
               created_at = now()",
    )
    .bind(user_id)
    .bind(key_id)
    .bind(public_key)
    .bind(signature)
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn insert_one_time_prekeys(
    conn: &mut PgConnection,
    user_id: Uuid,
    keys: &[(i32, Vec<u8>)],
) -> Result<usize, sqlx::Error> {
    if keys.is_empty() {
        return Ok(0);
    }
    let (key_ids, pubs): (Vec<i32>, Vec<Vec<u8>>) = keys.iter().cloned().unzip();
    let n = sqlx::query(
        "INSERT INTO chat_one_time_prekeys (user_id, key_id, public_key)
         SELECT $1, kid, pk
           FROM UNNEST($2::int[], $3::bytea[]) AS t(kid, pk)
         ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(&key_ids)
    .bind(&pubs)
    .execute(conn)
    .await?
    .rows_affected();
    Ok(n as usize)
}

pub struct IdentityRow {
    pub registration_id: i32,
    pub identity_key: Vec<u8>,
}

pub async fn get_identity(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    let row: Option<(i32, Vec<u8>)> = sqlx::query_as(
        "SELECT registration_id, identity_key FROM chat_identities WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(registration_id, identity_key)| IdentityRow {
        registration_id,
        identity_key,
    }))
}

pub struct SignedPrekeyRow {
    pub key_id: i32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub async fn get_signed_prekey(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<Option<SignedPrekeyRow>, sqlx::Error> {
    let row: Option<(i32, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT key_id, public_key, signature FROM chat_signed_prekeys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(key_id, public_key, signature)| SignedPrekeyRow {
        key_id,
        public_key,
        signature,
    }))
}

pub struct OneTimePrekeyRow {
    pub key_id: i32,
    pub public_key: Vec<u8>,
}

/// Consume one unconsumed OPK for the given user. Returns None if
/// none are available. Uses SKIP LOCKED for the concurrent-fetch race.
pub async fn take_one_one_time_prekey(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<Option<OneTimePrekeyRow>, sqlx::Error> {
    let row: Option<(i32, Vec<u8>)> = sqlx::query_as(
        "WITH picked AS (
             SELECT key_id
               FROM chat_one_time_prekeys
              WHERE user_id = $1 AND consumed_at IS NULL
              ORDER BY key_id ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
         )
         UPDATE chat_one_time_prekeys
            SET consumed_at = now()
          WHERE user_id = $1 AND key_id IN (SELECT key_id FROM picked)
          RETURNING key_id, public_key",
    )
    .bind(user_id)
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|(key_id, public_key)| OneTimePrekeyRow { key_id, public_key }))
}

pub async fn count_unconsumed_one_time_prekeys(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM chat_one_time_prekeys
          WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(conn)
    .await?;
    Ok(n)
}
