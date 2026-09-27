//! Process-wide event bus built on `named_queue` broadcasting queues.
//! Every mutation publishes a [`ChangeEvent`]; every DNS query publishes a
//! [`QueryEvent`]. Subscribers (websocket sessions, loggers) each get their
//! own bounded buffer and can lag without slowing publishers.

use crate::model::{ChangeEvent, QueryEvent};
use named_queue::{QueueRegistry, Receiver, Sender};

pub const CHANGES: &str = "changes";
pub const QUERIES: &str = "queries";

pub struct Bus {
    registry: QueueRegistry,
    changes: Sender<ChangeEvent>,
    queries: Sender<QueryEvent>,
}

impl Bus {
    pub fn new(change_capacity: usize, query_capacity: usize) -> Self {
        let registry = QueueRegistry::new();
        registry
            .create_broadcasting::<ChangeEvent>(CHANGES, change_capacity)
            .expect("fresh registry");
        registry
            .create_broadcasting::<QueryEvent>(QUERIES, query_capacity)
            .expect("fresh registry");
        let changes = registry
            .acquire_sender::<ChangeEvent>(CHANGES)
            .expect("queue exists");
        let queries = registry
            .acquire_sender::<QueryEvent>(QUERIES)
            .expect("queue exists");
        Bus {
            registry,
            changes,
            queries,
        }
    }

    pub fn publish_change(&self, ev: ChangeEvent) {
        // Broadcast sends never block; an error only means shutdown.
        let _ = self.changes.send(ev);
    }

    pub fn publish_query(&self, ev: QueryEvent) {
        let _ = self.queries.send(ev);
    }

    pub fn subscribe_changes(&self) -> Option<Receiver<ChangeEvent>> {
        self.registry.acquire_receiver::<ChangeEvent>(CHANGES).ok()
    }

    pub fn subscribe_queries(&self) -> Option<Receiver<QueryEvent>> {
        self.registry.acquire_receiver::<QueryEvent>(QUERIES).ok()
    }

    pub fn shutdown(&self) {
        let _ = self.registry.shutdown(CHANGES);
        let _ = self.registry.shutdown(QUERIES);
    }
}
