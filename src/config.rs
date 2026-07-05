use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    /// Base URL of box-fraise-server. Chat auth verifies bearer
    /// tokens by calling GET {this}/v1/me and reading user_id.
    pub identity_base_url: String,
    /// Optional shared secret. If set, chat requests carrying the
    /// header `X-BF-Internal: <secret>` may present a raw
    /// `X-BF-User-Id` UUID and bypass upstream token verification.
    /// Used for tests and internal-service-to-service traffic.
    pub internal_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;
        let port = std::env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);
        let identity_base_url =
            std::env::var("IDENTITY_BASE_URL").unwrap_or_else(|_| "https://fraise.box".to_string());
        let internal_secret = std::env::var("INTERNAL_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
        Ok(Self {
            database_url,
            port,
            identity_base_url,
            internal_secret,
        })
    }
}
