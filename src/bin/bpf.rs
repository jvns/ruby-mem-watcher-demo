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
typedef char strlenkey_t[80];
BPF_HASH(counts, strlenkey_t);
int count(struct pt_regs *ctx) {
	if (!PT_REGS_PARM1(ctx))
		return 0;
	strlenkey_t key;
	u64 zero = 0, *val;
	bpf_probe_read(&key, sizeof(key), (void *)PT_REGS_PARM1(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}
    ";
    let mut module = BCC::new(code);
    let retprobe = module.load_uprobe("count".to_string())?;
    println!("{:?}", retprobe);
    module.attach_uprobe("c".to_string(), "strlen".to_string(), retprobe, -1)?;
    Ok(())
}


