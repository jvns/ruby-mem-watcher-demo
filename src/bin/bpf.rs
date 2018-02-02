extern crate bcc_friendly;
extern crate byteorder;
extern crate libc;
extern crate failure;
use byteorder::{NativeEndian, ReadBytesExt};
use bcc_friendly::core::BPF;
use failure::Error;
use std::io::Cursor;

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
    let mut module = BPF::new(code)?;
    let uprobe = module.load_uprobe("count".to_string())?;
    module.attach_uprobe("/lib/x86_64-linux-gnu/libc.so.6".to_string(), "strlen".to_string(), uprobe, -1)?;
    let mut table = module.table("counts");
    println!("{:?}", table.key_size());
    println!("{:?}", table.leaf_size());
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let iter = table.into_iter();
        for e in iter {
            let key = match e.key.iter().position(|&r| r == 0) {
                Some(zero_pos) => String::from_utf8_lossy(&e.key[0..zero_pos]),
                None => String::from_utf8_lossy(&e.key),
            };
            let value = Cursor::new(e.value).read_u64::<NativeEndian>().unwrap();
            if value > 10 {
                println!("{:?} {:?}", key, value);
            }
        }
    }
}


