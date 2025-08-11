use std::sync::Arc;
use std::collections::VecDeque;
use tokio::sync::RwLock;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use chrono::{DateTime, Utc, Duration};

use crate::{ExecEvent, MAX_EVENTS};
use crate::ARGV_OFFSET;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecution {
    pub pid: u32,
    pub timestamp: DateTime<Utc>,
    pub commandstr: String,
    pub argstr: String,
    pub full_command: String,
}

impl ProcessExecution {
    pub fn from_event(event: &ExecEvent, boot_offset: Duration) -> Self {
        // Translate monotonic ns (since boot) to wall-clock
        let wall = boot_offset + Duration::nanoseconds(event.timestamp as i64);
        let commandstr = String::from_utf8_lossy(&event.command[..event.command_len]).to_string();
        let mut args = Vec::new();
        for i in 0..ARGV_OFFSET.min(event.argvs_offset.len()) {
            let argv_len = event.argvs_offset[i];
            if argv_len == 0 { break; }
            let arg = String::from_utf8_lossy(&event.argvs[i][..argv_len]).to_string();
            args.push(arg);
        }
        let argstr = args.join(" ");
        let full_command = if argstr.is_empty() { commandstr.clone() } else { format!("{} {}", commandstr, argstr) };
        ProcessExecution { pid: event.pid, timestamp: DateTime::<Utc>::from_timestamp(wall.num_seconds(), (wall.num_nanoseconds().unwrap_or(0) % 1_000_000_000) as u32).unwrap_or_else(|| Utc::now()), commandstr, argstr, full_command }
    }
}

// Thread-safe storage for process executions
#[derive(Clone)]
pub struct ExecutionStorage {
    // Global storage with max 500 events (FIFO)
    executions: Arc<RwLock<VecDeque<ProcessExecution>>>,
}

impl ExecutionStorage {
    pub fn new() -> Self {
        Self {
            executions: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_EVENTS))),
        }
    }

    pub async fn add_execution(&self, execution: ProcessExecution) {
        let mut executions = self.executions.write().await;
        if executions.len() >= MAX_EVENTS {
            executions.pop_front();
        }
        executions.push_back(execution);
    }

    pub async fn get_all_executions(&self) -> Vec<ProcessExecution> {
        let executions = self.executions.read().await;
        executions.iter().cloned().collect()
    }

    pub async fn get_executions_by_pid(&self, pid: u32) -> Vec<ProcessExecution> {
        let executions = self.executions.read().await;
        executions.iter().filter(|e| e.pid == pid).cloned().collect()
    }
}

// HTTP API handlers
pub async fn get_all_executions(State(storage): State<ExecutionStorage>) -> Json<Vec<ProcessExecution>> {
    let executions = storage.get_all_executions().await;
    info!("Returning {} executions", executions.len());
    Json(executions)
}

pub async fn get_executions_by_pid(
    Path(pid): Path<u32>,
    State(storage): State<ExecutionStorage>,
) -> Result<Json<Vec<ProcessExecution>>, StatusCode> {
    let executions = storage.get_executions_by_pid(pid).await;
    if executions.is_empty() {
        info!("No executions found for PID {}", pid);
        Err(StatusCode::NOT_FOUND)
    } else {
        info!("Returning {} executions for PID {}", executions.len(), pid);
        Ok(Json(executions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use task_common::{ARGV_LEN, ARGV_OFFSET};

    fn mk_exec(pid: u32, ts: u64, cmd: &str, args: &[&str]) -> ProcessExecution {
        // Build ExecEvent
        let mut command = [0u8; 64];
        let cb = cmd.as_bytes(); // command gets converted to bytes
        let clen = cb.len().min(64); // command buf len
        command[..clen].copy_from_slice(&cb[..clen]); // copying the bytes from cmd to command (basically &str to [0u8; 64])
        let mut argvs = [[0u8; ARGV_LEN]; ARGV_OFFSET];
        let mut arg_lens = [0usize; ARGV_OFFSET];
        for (i, a) in args.iter().enumerate().take(ARGV_OFFSET) {
            let ab = a.as_bytes(); // similarly convert &&str to bytes for storing them into argvs
            let alen = ab.len().min(ARGV_LEN);
            argvs[i][..alen].copy_from_slice(&ab[..alen]); // copy takes place here
            arg_lens[i] = alen;
        }
        let event = crate::ExecEvent { pid, timestamp: ts, command, command_len: clen, argvs, argvs_offset: arg_lens };
        ProcessExecution::from_event(&event, Duration::zero())
    }

    // Basic conversion test for ProcessExecution::from_event
    #[tokio::test]
    async fn from_event_basic() {
        // Build ExecEvent manually
        let cmd = b"/bin/echo"; // 9 bytes
        let arg0 = b"hello";    // 5 bytes
        let mut command_arr = [0u8; 64];
        command_arr[..cmd.len()].copy_from_slice(cmd);
        let mut argvs = [[0u8; ARGV_LEN]; ARGV_OFFSET];
        argvs[0][..arg0.len()].copy_from_slice(arg0);
        let mut arg_lens = [0usize; ARGV_OFFSET];
        arg_lens[0] = arg0.len();
        let event = crate::ExecEvent {
            pid: 42,
            timestamp: 1_500_000_123, // ns since boot (1.500000123 s)
            command: command_arr,
            command_len: cmd.len(),
            argvs,
            argvs_offset: arg_lens,
        };
        let boot_offset = Duration::zero();
        let pe = ProcessExecution::from_event(&event, boot_offset);
        assert_eq!(pe.pid, 42);
        assert_eq!(pe.commandstr, "/bin/echo");
        assert_eq!(pe.argstr, "hello");
        assert_eq!(pe.full_command, "/bin/echo hello");
        // Timestamp should match seconds + nanos from event.timestamp
        assert_eq!(pe.timestamp.timestamp(), 1); // whole seconds
        assert_eq!(pe.timestamp.timestamp_subsec_nanos(), 500_000_123); // remaining nanos
    }
    #[tokio::test]
    async fn add_and_get_all() {
        let storage = ExecutionStorage::new();
        storage.add_execution(mk_exec(1, 10, "/bin/a", &[])).await;
        storage.add_execution(mk_exec(2, 20, "/bin/b", &["x"])).await;
        let all = storage.get_all_executions().await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].pid, 1);
        assert_eq!(all[1].pid, 2);
    }

    #[tokio::test]
    async fn fifo_eviction() {
        let storage = ExecutionStorage::new();
        for i in 0..crate::MAX_EVENTS { storage.add_execution(mk_exec(i as u32, i as u64, "/bin/cmd", &[])).await; }
        // first pid should be 0
        let first_before = storage.get_all_executions().await.first().unwrap().pid;
        assert_eq!(first_before, 0);
        storage.add_execution(mk_exec(9999, 9999, "/bin/extra", &[])).await;
        let all = storage.get_all_executions().await;
        assert_eq!(all.len(), crate::MAX_EVENTS);
        // pid 9999 SHOULD exist
        assert!(all.iter().any(|e| e.pid == 9999));
        // pid 0 SHOULDN'T because it gets evicted
        assert!(!all.iter().any(|e| e.pid == 0));
    }

    #[tokio::test]
    async fn get_by_pid() {
        let storage = ExecutionStorage::new();
        storage.add_execution(mk_exec(1, 1, "/bin/a", &[])).await;
        storage.add_execution(mk_exec(2, 2, "/bin/b", &[])).await;
        storage.add_execution(mk_exec(1, 3, "/bin/c", &[])).await;
        let p1 = storage.get_executions_by_pid(1).await;
        assert_eq!(p1.len(), 2);
        assert!(p1.iter().all(|e| e.pid == 1));
        let p2 = storage.get_executions_by_pid(2).await;
        assert_eq!(p2.len(), 1);
    }
}

