extern crate bcc_friendly;
extern crate libc;
extern crate failure;
extern crate ruby_fork_test;
use ruby_fork_test::*;
use libc::*;
use bcc_friendly::*;
use bpf_rust::*;
use failure::Error;

use std::ffi::CString;

fn main() {
    do_main().unwrap();
}

fn do_main() -> Result<(), Error> {
    let code = "
#include <uapi/linux/ptrace.h>
struct readline_event_t {
        u32 pid;
        char str[80];
} __attribute__((packed));
BPF_PERF_OUTPUT(readline_events);
int get_return_value(struct pt_regs *ctx) {
        struct readline_event_t event = {};
        u32 pid;
        if (!PT_REGS_RC(ctx))
                return 0;
        pid = bpf_get_current_pid_tgid();
        event.pid = pid;
        bpf_probe_read(&event.str, sizeof(event.str), (void *)PT_REGS_RC(ctx));
        readline_events.perf_submit(ctx, &event, sizeof(event));
        return 0;
}
    ";
    let mut module = Module::new(code);
    let retprobe = module.load_uprobe("get_return_value".to_string())?;
    println!("{:?}", retprobe);
    module.attach_uretprobe("/bin/bash".to_string(), "readline".to_string(), retprobe, -1)?;
    Ok(())
}


