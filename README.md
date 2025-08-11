# task

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Dependencies

- rust version : 1.86.0 nightly (for local running you'll need to override your rustup to 1.86.0)

## Running this applicaation via docker-compose

- a simple `docker compose up --build` will work

## system binary filtering

- modify `/task/src/constant.rs` with the commands of your choice (I have pre-loaded a few based on my testing) [ **max entries are 10**, can be modified at `/task-ebpf/src/main.rs` and increasing the max entries of `EXCLUDED_CMDS`]

## tracing

### RUST_LOG=info -> logs all captured events on the usersapce side

control env trace via the `docker-compose.yml`
```yml
  environment:
      - RUST_LOG=info
```

## Endpoints

**Server runs on port 3000**

| Endpoint | Description | Example |
|----------|-------------|---------|
| `GET /executions` | Returns 500 most recent execve syscall events | `curl http://localhost:3000/executions` |
| `GET /executions/:pid` | Returns event info for a specific PID | `curl http://localhost:3000/executions/31145` |



## Unit tests : 

- check out `/task/src/store.rs` for the added unit tests

---

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package task --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/task` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, task is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
