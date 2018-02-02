extern crate bcc_friendly;
extern crate byteorder;
extern crate libc;
extern crate failure;
extern crate ruby_fork_test;
use byteorder::{NativeEndian, ReadBytesExt};
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
    module.attach_uprobe("/lib/x86_64-linux-gnu/libc.so.6".to_string(), "strlen".to_string(), uprobe, -1)?;
    let mut table = module.table("counts".to_string());
    println!("{:?}", table.key_size());
    println!("{:?}", table.leaf_size());
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let iter = table.into_iter();
        let mut i = 0;
        for e in iter {
            i += 1;
            let key = match e.key.iter().position(|&r| r == 0) {
                Some(zero_pos) => String::from_utf8_lossy(&e.key[0..zero_pos]),
                None => String::from_utf8_lossy(&e.key),
            };
            let value = e.value.read_u64::<BigEndian>().unwrap();
            println!("{:?} {:?}", key, value);
        }
        println!("{}", i);
    }
    Ok(())
}


