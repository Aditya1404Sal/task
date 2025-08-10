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
use dashmap::DashMap;

// Import from main.rs or task_common
use crate::{ExecEvent, MAX_EVENTS};
use crate::ARGV_OFFSET;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecution {
    pub pid: u32,
    pub timestamp: DateTime<Utc>, // wall clock time
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
    // Per-PID storage for quick lookups
    pid_executions: Arc<DashMap<u32, Vec<ProcessExecution>>>,
}

impl ExecutionStorage {
    pub fn new() -> Self {
        Self {
            executions: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_EVENTS))),
            pid_executions: Arc::new(DashMap::new()),
        }
    }

    pub async fn add_execution(&self, execution: ProcessExecution) {
        let mut executions = self.executions.write().await;
        
        // If we're at capacity, remove the oldest
        if executions.len() >= MAX_EVENTS {
            if let Some(removed) = executions.pop_front() {
                // Also clean up from PID storage
                if let Some(mut pid_vec) = self.pid_executions.get_mut(&removed.pid) {
                    pid_vec.retain(|e| e.timestamp != removed.timestamp);
                    if pid_vec.is_empty() {
                        drop(pid_vec);
                        self.pid_executions.remove(&removed.pid);
                    }
                }
            }
        }
        
        // Add new execution
        executions.push_back(execution.clone());
        
        // Add to PID-specific storage
        self.pid_executions
            .entry(execution.pid)
            .or_insert_with(Vec::new)
            .push(execution);
    }

    pub async fn get_all_executions(&self) -> Vec<ProcessExecution> {
        let executions = self.executions.read().await;
        executions.iter().cloned().collect()
    }

    pub fn get_executions_by_pid(&self, pid: u32) -> Vec<ProcessExecution> {
        self.pid_executions
            .get(&pid)
            .map(|executions| executions.clone())
            .unwrap_or_default()
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
    let executions = storage.get_executions_by_pid(pid);
    if executions.is_empty() {
        info!("No executions found for PID {}", pid);
        Err(StatusCode::NOT_FOUND)
    } else {
        info!("Returning {} executions for PID {}", executions.len(), pid);
        Ok(Json(executions))
    }
}
