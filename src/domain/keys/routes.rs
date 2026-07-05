use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::app::AppState;
use crate::domain::keys::{service, types::*};
use crate::error::AppResult;
use crate::http::extractors::AuthedUser;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/keys/bundle", post(register_bundle))
        .route("/keys/signed", post(rotate_signed_prekey))
        .route(
            "/keys/one-time",
            post(refill_one_time_prekeys).get(count_own_one_time_prekeys),
        )
        .route("/keys/of/{user_id}", get(fetch_bundle))
}

async fn register_bundle(
    AuthedUser(user_id): AuthedUser,
    State(state): State<AppState>,
    Json(req): Json<RegisterBundleRequest>,
) -> AppResult<Json<RegisterBundleResponse>> {
    Ok(Json(
        service::register_bundle(&state.pool, user_id, req).await?,
    ))
}

async fn rotate_signed_prekey(
    AuthedUser(user_id): AuthedUser,
    State(state): State<AppState>,
    Json(req): Json<RotateSignedPrekeyRequest>,
) -> AppResult<()> {
    service::rotate_signed_prekey(&state.pool, user_id, req).await
}

async fn refill_one_time_prekeys(
    AuthedUser(user_id): AuthedUser,
    State(state): State<AppState>,
    Json(req): Json<RefillOneTimePrekeysRequest>,
) -> AppResult<Json<KeyCountResponse>> {
    let stored = service::refill_one_time_prekeys(&state.pool, user_id, req).await?;
    let unconsumed = service::count_own_one_time_prekeys(&state.pool, user_id).await?;
    tracing::debug!(stored, unconsumed, "opk refill");
    Ok(Json(KeyCountResponse {
        unconsumed_one_time_prekeys: unconsumed,
    }))
}

async fn count_own_one_time_prekeys(
    AuthedUser(user_id): AuthedUser,
    State(state): State<AppState>,
) -> AppResult<Json<KeyCountResponse>> {
    let n = service::count_own_one_time_prekeys(&state.pool, user_id).await?;
    Ok(Json(KeyCountResponse {
        unconsumed_one_time_prekeys: n,
    }))
}

async fn fetch_bundle(
    AuthedUser(_who): AuthedUser,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<PrekeyBundleResponse>> {
    Ok(Json(service::fetch_bundle(&state.pool, user_id).await?))
}
