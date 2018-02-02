extern crate bcc_friendly;
extern crate libc;
extern crate failure;
extern crate ruby_fork_test;
use ruby_fork_test::*;
use libc::*;
use bcc_friendly::core::BCC;
use failure::Error;

use std::ffi::CString;

fn main() {
    do_main().unwrap();
}

fn do_main() -> Result<(), Error> {
    let code = "

#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
    ";
    let mut module = BCC::new(code);
    let uprobe = module.load_uprobe("count".to_string())?;
    println!("{:?}", uprobe);
    module.attach_uprobe("/lib/x86_64-linux-gnu/libc.so.6".to_string(), "strlen".to_string(), uprobe, -1)?;
    let mut table = module.table("counts".to_string());
    println!("{:?}", table.key_size());
    println!("{:?}", table.leaf_size());
    Ok(())
}


