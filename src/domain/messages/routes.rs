use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::app::AppState;
use crate::domain::messages::{service, types::*};
use crate::error::AppResult;
use crate::http::extractors::AuthedUser;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/messages/to/{recipient_id}", post(send_to))
        .route("/messages", get(list_pending))
        .route("/messages/{id}", delete(acknowledge))
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}
fn default_limit() -> i64 {
    200
}

async fn send_to(
    AuthedUser(sender): AuthedUser,
    State(state): State<AppState>,
    Path(recipient): Path<Uuid>,
    Json(req): Json<SendMessageRequest>,
) -> AppResult<Json<SendMessageResponse>> {
    Ok(Json(
        service::send(&state.pool, &state.hub, sender, recipient, req).await?,
    ))
}

async fn list_pending(
    AuthedUser(user_id): AuthedUser,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Vec<Envelope>>> {
    Ok(Json(
        service::list_pending(&state.pool, user_id, q.limit.clamp(1, 1000)).await?,
    ))
}

async fn acknowledge(
    AuthedUser(user_id): AuthedUser,
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> AppResult<()> {
    service::acknowledge(&state.pool, user_id, id).await
}
