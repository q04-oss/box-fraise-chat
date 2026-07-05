// Wire protocol on the socket:
// - server → client: JSON `Envelope` messages, one per WS text frame
// - client → server: currently ignored (ping/pong handled by axum;
//   ACKs go via DELETE /v1/messages/:id over HTTP)
//
// Auth: the browser can't set Authorization on WebSocket handshake,
// so we accept `?token=<bearer>` on the connect URL. Same verifier.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::routing::get;
use axum::Router;
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;

pub fn router() -> Router<AppState> {
    Router::new().route("/ws", get(ws_connect))
}

#[derive(Deserialize)]
struct WsQuery {
    token: Option<String>,
    // Internal-secret path (tests, sidecars).
    internal_secret: Option<String>,
    user_id: Option<Uuid>,
}

async fn ws_connect(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(q): Query<WsQuery>,
) -> Result<axum::response::Response, AppError> {
    let user_id = match (q.internal_secret.as_deref(), q.user_id) {
        (Some(sec), Some(uid)) => state.verifier.resolve_internal(sec, &uid.to_string())?,
        _ => {
            let token = q.token.ok_or(AppError::Unauthorized)?;
            state.verifier.resolve(&token).await?
        }
    };
    Ok(ws.on_upgrade(move |socket| run(socket, state, user_id)))
}

async fn run(socket: WebSocket, state: AppState, user_id: Uuid) {
    let (mut tx, mut rx) = socket.split();
    let mut inbox = state.hub.subscribe(user_id);
    tracing::debug!(?user_id, "ws connected");

    // Task 1: forward envelopes from the hub to the socket.
    let sender = tokio::spawn(async move {
        while let Some(env) = inbox.recv().await {
            let payload = match serde_json::to_string(&env) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(?e, "serialize env");
                    continue;
                }
            };
            if tx.send(Message::Text(payload.into())).await.is_err() {
                break;
            }
        }
    });

    // Task 2: consume client frames (ignored today, kept for future).
    while let Some(Ok(msg)) = rx.next().await {
        match msg {
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Binary(_) => {}
        }
    }
    sender.abort();
    tracing::debug!(?user_id, "ws disconnected");
    // Hub sender halves get pruned on the next deliver() when send()
    // fails; nothing to do here.
}
