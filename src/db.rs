// Two-role Postgres wrapper. Mirrors box-fraise-server/src/db.rs: the
// app connects as bf_chat (no BYPASSRLS) and every request opens one
// of these transaction guards, which set the RLS GUCs transaction-
// locally. Always `set_config(..., true)` so the value doesn't leak
// onto the next borrower of this pool connection.

use anyhow::Result;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

pub type Pool = PgPool;

pub async fn connect(url: &str) -> Result<Pool> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(url)
        .await?;
    Ok(pool)
}

pub struct RlsTransaction<'a> {
    tx: Transaction<'a, Postgres>,
}

impl<'a> RlsTransaction<'a> {
    pub async fn begin(pool: &'a Pool, user_id: Uuid) -> Result<Self, sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('app.user_id', $1, true)")
            .bind(user_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(Self { tx })
    }
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }
}

pub struct AdminRlsTransaction<'a> {
    tx: Transaction<'a, Postgres>,
}

impl<'a> AdminRlsTransaction<'a> {
    pub async fn begin(pool: &'a Pool) -> Result<Self, sqlx::Error> {
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('app.is_admin', 'true', true)")
            .execute(&mut *tx)
            .await?;
        Ok(Self { tx })
    }
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
    pub async fn commit(self) -> Result<(), sqlx::Error> {
        self.tx.commit().await
    }
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }
}
