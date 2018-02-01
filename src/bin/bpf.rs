extern crate bcc_sys;
extern crate libc;
use libc::*;

use bcc_sys::bccapi::*;
use std::ffi::CString;

fn main() {
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
    new_module(code);
}

fn new_module(code: &str) {
    let cs = CString::new(code).unwrap();
    unsafe {
        bpf_module_create_c_from_string(cs.as_ptr(), 2, 0 as *mut *const c_char, 0)
    };
}

