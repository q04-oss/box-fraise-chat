// In-process fan-out for connected clients. When a user connects
// their WebSocket, they register a channel here; a send() to that
// user pushes any freshly-enqueued envelope over the socket
// instantly. Recipient still has to ACK via DELETE /v1/messages/:id
// for the row to leave the queue — WS delivery is best-effort.
//
// Single-process only. Horizontal scale-out requires a fan-out layer
// (Redis pub/sub, NATS, etc.); noted for later.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::domain::messages::types::Envelope;

#[derive(Clone)]
pub struct WsHub {
    // user_id → list of live sender channels (a user may connect
    // from multiple devices).
    inboxes: Arc<DashMap<Uuid, Vec<mpsc::UnboundedSender<Envelope>>>>,
}

impl Default for WsHub {
    fn default() -> Self {
        Self::new()
    }
}

impl WsHub {
    pub fn new() -> Self {
        Self {
            inboxes: Arc::new(DashMap::new()),
        }
    }

    /// Register a new WebSocket subscriber. Returns the receiver
    /// half; caller drives an event loop reading from it and writing
    /// to the socket.
    pub fn subscribe(&self, user_id: Uuid) -> mpsc::UnboundedReceiver<Envelope> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.inboxes.entry(user_id).or_default().push(tx);
        rx
    }

    /// Deliver an envelope to every live socket for the user.
    /// Returns true if at least one send succeeded.
    pub fn deliver(&self, user_id: Uuid, env: &Envelope) -> bool {
        let Some(mut entry) = self.inboxes.get_mut(&user_id) else {
            return false;
        };
        // Drop dead senders as we go.
        let mut delivered = false;
        entry.retain(|sender| {
            if sender.send(env.clone()).is_ok() {
                delivered = true;
                true
            } else {
                false
            }
        });
        if entry.is_empty() {
            drop(entry);
            self.inboxes.remove(&user_id);
        }
        delivered
    }
}
