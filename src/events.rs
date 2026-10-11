//! Process-wide event bus built on `named_queue` broadcasting queues.
//! Every mutation publishes a [`ChangeEvent`]; every DNS query publishes a
//! [`QueryEvent`]. Subscribers (websocket sessions, loggers) each get their
//! own bounded buffer and can lag without slowing publishers.

use crate::model::{ChangeEvent, QueryEvent};
use named_queue::{QueueRegistry, Receiver, Sender};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub const CHANGES: &str = "changes";
pub const QUERIES: &str = "queries";
pub const ACCESS: &str = "access";

/// O2: a local signal that someone's access may just have shrunk: a session
/// or API token revoked or changed, an account changed (disabled, demoted)
/// or deleted. Ids only, never a secret, never replicated: each server
/// publishes it for its own commits (a standby for the account changes it
/// applied). Websocket streams re-check at once instead of at their next
/// periodic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessEvent {
    /// Something about this user's sessions, tokens or account changed.
    User(i64),
    /// Anything may have changed (a standby applied account changes or a
    /// snapshot): every stream re-checks.
    All,
}

impl AccessEvent {
    /// Does this event concern a stream of `user_id`?
    pub fn concerns(self, user_id: i64) -> bool {
        match self {
            AccessEvent::User(u) => u == user_id,
            AccessEvent::All => true,
        }
    }
}

pub struct Bus {
    registry: QueueRegistry,
    changes: Sender<ChangeEvent>,
    queries: Sender<QueryEvent>,
    access: Sender<AccessEvent>,
    /// Live subscribers of the query feed (websocket sessions, the query
    /// log). With none, the DNS path does not build query events at all.
    query_subscribers: Arc<AtomicUsize>,
}

/// A subscription to the query feed; counted while it lives.
pub struct QuerySubscription {
    rx: Receiver<QueryEvent>,
    count: Arc<AtomicUsize>,
}

impl std::ops::Deref for QuerySubscription {
    type Target = Receiver<QueryEvent>;
    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}

impl Drop for QuerySubscription {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
    }
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
        registry
            .create_broadcasting::<AccessEvent>(ACCESS, 256)
            .expect("fresh registry");
        let changes = registry
            .acquire_sender::<ChangeEvent>(CHANGES)
            .expect("queue exists");
        let queries = registry
            .acquire_sender::<QueryEvent>(QUERIES)
            .expect("queue exists");
        let access = registry
            .acquire_sender::<AccessEvent>(ACCESS)
            .expect("queue exists");
        Bus {
            registry,
            changes,
            queries,
            access,
            query_subscribers: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Publish a committed DNS change. Only a `DnsEvent` (made from a DNS
    /// change, never from a secret one) can be published.
    pub fn publish_change(&self, ev: crate::mutation::DnsEvent) {
        // Broadcast sends never block; an error only means shutdown.
        let _ = self.changes.send(ev.into_event());
    }

    /// A standby applied a replicated DNS change (changelog v2): what the
    /// console needs to refresh (zone, entity, action, who), never row data,
    /// so no secret can travel this way.
    pub fn publish_replicated(&self, ev: ChangeEvent) {
        let _ = self.changes.send(ev);
    }

    pub fn publish_query(&self, ev: QueryEvent) {
        let _ = self.queries.send(ev);
    }

    /// O2: publish an access signal (see [`AccessEvent`]).
    pub fn publish_access(&self, ev: AccessEvent) {
        let _ = self.access.send(ev);
    }

    pub fn subscribe_access(&self) -> Option<Receiver<AccessEvent>> {
        self.registry.acquire_receiver::<AccessEvent>(ACCESS).ok()
    }

    pub fn subscribe_changes(&self) -> Option<Receiver<ChangeEvent>> {
        self.registry.acquire_receiver::<ChangeEvent>(CHANGES).ok()
    }

    pub fn subscribe_queries(&self) -> Option<QuerySubscription> {
        let rx = self.registry.acquire_receiver::<QueryEvent>(QUERIES).ok()?;
        self.query_subscribers.fetch_add(1, Ordering::SeqCst);
        Some(QuerySubscription {
            rx,
            count: self.query_subscribers.clone(),
        })
    }

    /// Is anyone listening to the query feed (live view or query log)?
    pub fn has_query_subscribers(&self) -> bool {
        self.query_subscribers.load(Ordering::Relaxed) > 0
    }

    pub fn shutdown(&self) {
        let _ = self.registry.shutdown(CHANGES);
        let _ = self.registry.shutdown(QUERIES);
        let _ = self.registry.shutdown(ACCESS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D4: the DNS path asks whether anyone listens before it builds a
    /// query event; the count follows the subscriptions.
    #[test]
    fn query_subscribers_are_counted() {
        let bus = Bus::new(8, 8);
        assert!(!bus.has_query_subscribers());
        let a = bus.subscribe_queries().unwrap();
        let b = bus.subscribe_queries().unwrap();
        assert!(bus.has_query_subscribers());
        drop(a);
        assert!(bus.has_query_subscribers());
        drop(b);
        assert!(!bus.has_query_subscribers());
        // Change subscribers do not count.
        let _c = bus.subscribe_changes().unwrap();
        assert!(!bus.has_query_subscribers());
    }
}
