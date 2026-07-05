// Bearer-token → user_id resolver.
//
// Chat has no users of its own. box-fraise-server owns identity.
// Every authenticated chat request presents the same
// `Authorization: Bearer <token>` the app already uses against
// box-fraise-server; we resolve it by calling `GET {identity_base_url}
// /v1/me` and reading `user_id`.
//
// Results are cached in memory briefly to keep the fan-out from
// slamming the identity service on a chatty connection.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::Deserialize;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};

#[derive(Clone)]
pub struct Verifier {
    cfg: Arc<Config>,
    http: reqwest::Client,
    // token hash → (user_id, expires_at). We key on the token itself
    // for now; token hashing is a pending hardening.
    cache: Arc<DashMap<String, (Uuid, Instant)>>,
}

impl Verifier {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(cfg),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Resolve a bearer token to a Box Fraise user_id.
    pub async fn resolve(&self, token: &str) -> AppResult<Uuid> {
        if token.is_empty() {
            return Err(AppError::Unauthorized);
        }
        if let Some(hit) = self.cache.get(token) {
            let (user_id, exp) = *hit;
            if Instant::now() < exp {
                return Ok(user_id);
            }
        }
        let url = format!("{}/v1/me", self.cfg.identity_base_url.trim_end_matches('/'));
        let resp = self.http.get(url).bearer_auth(token).send().await?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(AppError::Unauthorized);
        }
        if !resp.status().is_success() {
            return Err(AppError::Upstream(format!(
                "identity /v1/me {}",
                resp.status()
            )));
        }
        let me: MeResponse = resp.json().await?;
        self.cache.insert(
            token.to_string(),
            (me.id, Instant::now() + Duration::from_secs(30)),
        );
        Ok(me.id)
    }

    /// Internal-service escape hatch: skip upstream and trust an
    /// `X-BF-User-Id` header if the caller proved the shared secret.
    pub fn resolve_internal(&self, secret: &str, user_id_header: &str) -> AppResult<Uuid> {
        let Some(ref want) = self.cfg.internal_secret else {
            return Err(AppError::Unauthorized);
        };
        if secret != want {
            return Err(AppError::Unauthorized);
        }
        user_id_header
            .parse::<Uuid>()
            .map_err(|_| AppError::bad_request("X-BF-User-Id must be a uuid"))
    }
}

#[derive(Deserialize)]
struct MeResponse {
    // box-fraise-server returns the user's UUID under `id`, not
    // `user_id`. Alias in case that ever changes.
    #[serde(alias = "user_id")]
    id: Uuid,
}
