#![no_std]
#![no_main]

use core::str::from_utf8_unchecked;

use aya_ebpf::{helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes}, macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

const LEN_MAX_PATH: usize = 16;
const FILENAME_OFFSET: usize = 16;


#[tracepoint]
pub fn task(ctx: TracePointContext) -> u32 {
    match try_task(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}
// Modify this
fn try_task(ctx: TracePointContext) -> Result<u32, i64> {

    let mut buf = [0u8; LEN_MAX_PATH];
    // Thread group ID and process ID
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    // Command executed
    let filename = unsafe {
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_src_addr, &mut buf)?;
        from_utf8_unchecked(filename_bytes)
    };
    info!(&ctx, "tracepoint sys_enter_execve called");
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
