use axum::routing::get;
use axum::Router;

use crate::auth::Verifier;
use crate::config::Config;
use crate::db::Pool;
use crate::domain::ws::hub::WsHub;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub verifier: Verifier,
    pub hub: WsHub,
    pub cfg: Config,
}

impl AppState {
    pub fn new(pool: Pool, cfg: Config) -> Self {
        Self {
            pool,
            verifier: Verifier::new(cfg.clone()),
            hub: WsHub::new(),
            cfg,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let v1 = Router::new()
        .merge(crate::domain::keys::routes::router())
        .merge(crate::domain::messages::routes::router())
        .merge(crate::domain::ws::routes::router());

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/v1", v1)
        .with_state(state)
}
