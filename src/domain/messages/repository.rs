use chrono::{DateTime, Utc};
use sqlx::PgConnection;
use uuid::Uuid;

pub struct StoredEnvelope {
    pub id: Uuid,
    pub sender_user_id: Uuid,
    pub envelope_type: i16,
    pub ciphertext: Vec<u8>,
    pub received_at: DateTime<Utc>,
}

pub async fn enqueue(
    conn: &mut PgConnection,
    sender: Uuid,
    recipient: Uuid,
    envelope_type: i16,
    ciphertext: &[u8],
) -> Result<StoredEnvelope, sqlx::Error> {
    let (id, received_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO chat_messages (sender_user_id, recipient_user_id, envelope_type, ciphertext)
         VALUES ($1, $2, $3, $4)
         RETURNING id, received_at",
    )
    .bind(sender)
    .bind(recipient)
    .bind(envelope_type)
    .bind(ciphertext)
    .fetch_one(conn)
    .await?;
    Ok(StoredEnvelope {
        id,
        sender_user_id: sender,
        envelope_type,
        ciphertext: ciphertext.to_vec(),
        received_at,
    })
}

type PendingRow = (Uuid, Uuid, i16, Vec<u8>, DateTime<Utc>);

pub async fn list_pending_for(
    conn: &mut PgConnection,
    recipient: Uuid,
    limit: i64,
) -> Result<Vec<StoredEnvelope>, sqlx::Error> {
    let rows: Vec<PendingRow> = sqlx::query_as(
        "SELECT id, sender_user_id, envelope_type, ciphertext, received_at
           FROM chat_messages
          WHERE recipient_user_id = $1 AND acknowledged_at IS NULL
          ORDER BY received_at ASC
          LIMIT $2",
    )
    .bind(recipient)
    .bind(limit)
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, sender_user_id, envelope_type, ciphertext, received_at)| StoredEnvelope {
                id,
                sender_user_id,
                envelope_type,
                ciphertext,
                received_at,
            },
        )
        .collect())
}

/// Acknowledge one message and hard-delete it. Returns true if a row
/// was actually removed (idempotent from the client's perspective).
pub async fn acknowledge_one(
    conn: &mut PgConnection,
    recipient: Uuid,
    message_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let n = sqlx::query(
        "DELETE FROM chat_messages
          WHERE id = $1 AND recipient_user_id = $2",
    )
    .bind(message_id)
    .bind(recipient)
    .execute(conn)
    .await?
    .rows_affected();
    Ok(n > 0)
}
