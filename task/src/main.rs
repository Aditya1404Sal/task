use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::maps::HashMap;
use bytes::BytesMut;
use task_common::{ExecEvent, ARGV_OFFSET, COMMAND_LEN};
use std::convert::TryInto;
use tokio::signal;
use tracing::{info, warn, error};
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::Duration as ChronoDuration;

mod store;
mod server;
mod constant;
use store::{ProcessExecution, ExecutionStorage};
use server::start_http_server;
use crate::constant::EXCLUDE_LIST;

pub const MAX_EVENTS: usize = 500;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting eBPF runtime process monitor with HTTP API");

    // Create shared storage
    let storage = ExecutionStorage::new();
    let storage_clone = storage.clone();

    // Establish boot offset: wall_clock_now - monotonic_now
    let start_wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // Use clock_gettime for monotonic ns since boot
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    let mono_now_ns = (ts.tv_sec as i128) * 1_000_000_000 + (ts.tv_nsec as i128);
    let wall_now_ns = start_wall.as_nanos() as i128;
    let boot_offset_ns = wall_now_ns - mono_now_ns; // so: wall_event = boot_offset_ns + event_mono
    let boot_offset = ChronoDuration::nanoseconds(boot_offset_ns as i64);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/task"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut TracePoint = ebpf.program_mut("task").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    // Populate exclusion map in kernel (EXCLUDED_CMDS)
    let map = ebpf.map_mut("EXCLUDED_CMDS").unwrap();
    let mut excluded_cmds: HashMap<_, [u8; COMMAND_LEN], u8> = HashMap::try_from(map)?;
    for cmd in EXCLUDE_LIST.iter() {
        let key = cmd_to_key(cmd);
        excluded_cmds.insert(key, 1, 0)?;
    }

    info!("eBPF program loaded and attached");

    let mut perf_command_events =
        AsyncPerfEventArray::try_from(ebpf.take_map("COMMAND_EVENTS").unwrap())?;

    // Spawn eBPF event processing tasks
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = perf_command_events.open(cpu_id, None)?;
        let storage_task = storage.clone();

        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            let boot_offset = boot_offset;

            loop {
                match buf.read_events(&mut buffers).await {
                    Ok(events) => {
                        for i in 0..events.read {
                            let buf = &mut buffers[i];
                            let ptr = buf.as_ptr() as *const ExecEvent;
                            let raw_event = unsafe { ptr.read_unaligned() };

                            let execution = ProcessExecution::from_event(&raw_event, boot_offset);

                            // Log the execution event with structured logging
                            info!(
                                pid = execution.pid,
                                command = %execution.commandstr,
                                args = %execution.argstr,
                                timestamp = %execution.timestamp,
                                "Process execution captured"
                            );

                            // Store the execution
                            storage_task.add_execution(execution).await;
                        }
                    }
                    Err(err) => {
                        error!("Error reading eBPF events: {:?}", err);
                    }
                }
            }
        });
    }

    // Start HTTP server
    let server_handle = start_http_server(storage_clone).await?;

    // Wait for Ctrl-C
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    // Clean shutdown
    server_handle.abort();
    Ok(())
}

fn cmd_to_key(cmd: &str) -> [u8; COMMAND_LEN] {
    let mut key = [0u8; COMMAND_LEN];
    let bytes = cmd.as_bytes();
    key[..bytes.len()].copy_from_slice(bytes);
    key
}