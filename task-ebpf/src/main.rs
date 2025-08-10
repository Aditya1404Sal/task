#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes, r#gen::bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use task_common::{ARGV_LEN, ARGV_OFFSET, COMMAND_LEN};

const FILENAME_OFFSET: usize = 16;

#[repr(C)]
#[derive(Clone)]
pub struct ExecEvent {
    // Reordered to match user-space struct
    pub pid: u32,
    pub timestamp: u64,
    pub command: [u8; COMMAND_LEN],
    pub command_len: usize,
    pub argvs: [[u8; ARGV_LEN]; ARGV_OFFSET],
    pub argvs_offset: [usize; ARGV_OFFSET],
}

#[map]
static mut COMMAND_EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::<ExecEvent>::new(0);

#[map]
static mut EXCLUDED_CMDS: HashMap<[u8; COMMAND_LEN], u8> = HashMap::<[u8; COMMAND_LEN], u8>::with_max_entries(10, 0);

#[tracepoint]
pub fn task(ctx: TracePointContext) -> u32 {
    match try_task(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn is_excluded(command: &[u8], command_len: usize) -> bool {
    let mut key = [0u8; COMMAND_LEN];
    let len = core::cmp::min(command_len, COMMAND_LEN);
    key[..len].copy_from_slice(&command[..len]);
    unsafe {
        (*core::ptr::addr_of_mut!(EXCLUDED_CMDS)).get(&key).is_some()
    }
}

fn try_task(ctx: TracePointContext) -> Result<u32, i64> {
    let timestamp = unsafe { bpf_ktime_get_ns() };
    let pid = bpf_get_current_pid_tgid() as u32;

    let mut event = ExecEvent {
        pid,
        timestamp,
        command: [0; COMMAND_LEN],
        command_len: 0,
        argvs: [[0; ARGV_LEN]; ARGV_OFFSET],
        argvs_offset: [0; ARGV_OFFSET],
    };

    let command_ptr = unsafe { ctx.read_at::<*const u8>(FILENAME_OFFSET)? };
    let command_slice = unsafe { bpf_probe_read_user_str_bytes(command_ptr, &mut event.command)? };
    event.command_len = command_slice.len();

    if is_excluded(command_slice, command_slice.len()) {
        return Ok(0);
    }

    let argv_ptrs = unsafe { ctx.read_at::<*const *const u8>(24)? };
    for i in 0..ARGV_OFFSET {
        let ptr: *const u8 = unsafe { bpf_probe_read_user(argv_ptrs.add(i))? };
        if ptr.is_null() { break; }
        let slice = unsafe { bpf_probe_read_user_str_bytes(ptr, &mut event.argvs[i])? };
        let len = slice.len();
        event.argvs_offset[i] = if len >= ARGV_LEN { ARGV_LEN } else { len };
    }

    unsafe {
        let map_ptr: *mut PerfEventArray<ExecEvent> = core::ptr::addr_of_mut!(COMMAND_EVENTS);
        (*map_ptr).output(&ctx, &event, 0);
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
