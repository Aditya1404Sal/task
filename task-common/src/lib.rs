#![no_std]
pub static ARGV_LEN: usize = 32;
pub static ARGV_OFFSET: usize = 4;
pub static COMMAND_LEN: usize = 64;

#[repr(C)]
#[derive(Clone)]
pub struct ExecEvent {
    pub pid: u32,
    pub timestamp: u64,
    pub command: [u8; COMMAND_LEN],
    pub command_len: usize,
    pub argvs: [[u8; ARGV_LEN]; ARGV_OFFSET],
    pub argvs_offset: [usize; ARGV_OFFSET],
}