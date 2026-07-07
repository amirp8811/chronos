//! Session/circuit lifecycle manager for local prototypes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::RouteHopSecret;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct CircuitSession {
    pub session_id: u64,
    pub stream_id: u64,
    pub route_secret: RouteHopSecret,
    pub state: SessionState,
    pub created_at: Instant,
    pub last_active: Instant,
    pub rekey_counter: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    NotFound(u64),
    Closed(u64),
}

#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<u64, CircuitSession>,
    next_session_id: u64,
    next_stream_id: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: 1,
            next_stream_id: 10_000,
        }
    }

    pub fn open(&mut self, route_secret: RouteHopSecret) -> CircuitSession {
        let now = Instant::now();
        let session = CircuitSession {
            session_id: self.next_session_id,
            stream_id: self.next_stream_id,
            route_secret,
            state: SessionState::Open,
            created_at: now,
            last_active: now,
            rekey_counter: 0,
        };
        self.next_session_id += 1;
        self.next_stream_id += 1;
        self.sessions.insert(session.session_id, session.clone());
        session
    }

    pub fn touch(&mut self, session_id: u64) -> Result<(), SessionError> {
        let s = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;
        if s.state == SessionState::Closed {
            return Err(SessionError::Closed(session_id));
        }
        s.last_active = Instant::now();
        Ok(())
    }

    pub fn mark_closing(&mut self, session_id: u64) -> Result<(), SessionError> {
        let s = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;
        s.state = SessionState::Closing;
        Ok(())
    }

    pub fn close(&mut self, session_id: u64) -> Result<(), SessionError> {
        let s = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;
        s.state = SessionState::Closed;
        Ok(())
    }

    pub fn rekey(
        &mut self,
        session_id: u64,
        new_secret: RouteHopSecret,
    ) -> Result<(), SessionError> {
        let s = self
            .sessions
            .get_mut(&session_id)
            .ok_or(SessionError::NotFound(session_id))?;
        if s.state == SessionState::Closed {
            return Err(SessionError::Closed(session_id));
        }
        s.route_secret = new_secret;
        s.rekey_counter = s.rekey_counter.saturating_add(1);
        s.last_active = Instant::now();
        Ok(())
    }

    pub fn expire_idle(&mut self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let before = self.sessions.len();
        self.sessions.retain(|_, s| {
            now.duration_since(s.last_active) < max_idle && s.state != SessionState::Closed
        });
        before - self.sessions.len()
    }

    pub fn get(&self, session_id: u64) -> Option<&CircuitSession> {
        self.sessions.get(&session_id)
    }
    pub fn len(&self) -> usize {
        self.sessions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_manager_opens_rekeys_and_closes() {
        let mut sm = SessionManager::new();
        let s = sm.open(RouteHopSecret([1; 32]));
        assert_eq!(s.session_id, 1);
        sm.rekey(1, RouteHopSecret([2; 32])).unwrap();
        assert_eq!(sm.get(1).unwrap().rekey_counter, 1);
        sm.close(1).unwrap();
        assert_eq!(sm.expire_idle(Duration::from_secs(999)), 1);
        assert!(sm.is_empty());
    }
}
