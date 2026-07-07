//! Tiny TCP directory API for local prototype use.
//!
//! Line protocol:
//! - `UPSERT <node_id> <addr> <expires_unix>`
//! - `GET <node_id> <now_unix>`
//! - `PRUNE <now_unix>`

use crate::store::{DirectoryStore, RelayRecord};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryApiError {
    BadCommand,
    BadAddress,
    BadInteger,
    Io(String),
}

impl std::fmt::Display for DirectoryApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DirectoryApiError {}

pub fn handle_command(store: &mut DirectoryStore, line: &str) -> Result<String, DirectoryApiError> {
    let mut parts = line.split_whitespace();
    match parts.next() {
        Some("UPSERT") => {
            let node_id = parts
                .next()
                .ok_or(DirectoryApiError::BadCommand)?
                .to_string();
            let address = parts
                .next()
                .ok_or(DirectoryApiError::BadCommand)?
                .parse::<SocketAddr>()
                .map_err(|_| DirectoryApiError::BadAddress)?;
            let expires_at_unix = parts
                .next()
                .ok_or(DirectoryApiError::BadCommand)?
                .parse::<u64>()
                .map_err(|_| DirectoryApiError::BadInteger)?;
            store.upsert(RelayRecord {
                node_id,
                address,
                x25519_public: [0; 32],
                ml_kem_public_hash: [0; 32],
                expires_at_unix,
            });
            Ok("OK\n".to_string())
        }
        Some("GET") => {
            let node_id = parts.next().ok_or(DirectoryApiError::BadCommand)?;
            let now = parts
                .next()
                .ok_or(DirectoryApiError::BadCommand)?
                .parse::<u64>()
                .map_err(|_| DirectoryApiError::BadInteger)?;
            if let Some(record) = store.get(node_id, now) {
                Ok(format!(
                    "FOUND {} {} {}\n",
                    record.node_id, record.address, record.expires_at_unix
                ))
            } else {
                Ok("NOT_FOUND\n".to_string())
            }
        }
        Some("PRUNE") => {
            let now = parts
                .next()
                .ok_or(DirectoryApiError::BadCommand)?
                .parse::<u64>()
                .map_err(|_| DirectoryApiError::BadInteger)?;
            store.prune_expired(now);
            Ok(format!("OK {}\n", store.len()))
        }
        _ => Err(DirectoryApiError::BadCommand),
    }
}

pub async fn serve_directory_api(
    bind_addr: &str,
    store: Arc<Mutex<DirectoryStore>>,
) -> Result<(), DirectoryApiError> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| DirectoryApiError::Io(e.to_string()))?;
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| DirectoryApiError::Io(e.to_string()))?;
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok(len) = stream.read(&mut buf).await
                && len > 0
            {
                let line = String::from_utf8_lossy(&buf[..len]);
                let response = {
                    let mut guard = store.lock().expect("directory store lock");
                    handle_command(&mut guard, &line).unwrap_or_else(|e| format!("ERR {e:?}\n"))
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_api_upserts_gets_and_prunes_records() {
        let mut store = DirectoryStore::new();
        assert_eq!(
            handle_command(&mut store, "UPSERT n1 127.0.0.1:7000 10").unwrap(),
            "OK\n"
        );
        assert_eq!(
            handle_command(&mut store, "GET n1 9").unwrap(),
            "FOUND n1 127.0.0.1:7000 10\n"
        );
        assert_eq!(
            handle_command(&mut store, "GET n1 10").unwrap(),
            "NOT_FOUND\n"
        );
        assert_eq!(handle_command(&mut store, "PRUNE 10").unwrap(), "OK 0\n");
    }
}
