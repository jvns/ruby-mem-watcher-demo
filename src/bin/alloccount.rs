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

typedef struct blah {
    size_t ptr;
    pid_t pid;
} blah_t;

BPF_HASH(counts, blah_t);

int count(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    u64 zero = 0, *val;
    blah_t key = {};
    size_t ptr = PT_REGS_PARM1(ctx);
    key.ptr = ptr;
    key.pid = pid;
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
    ";
    let mut module = BPF::new(code)?;
    let uprobe = module.load_uprobe("count".to_string())?;
    module.attach_uprobe("/home/bork/.rbenv/versions/2.4.0/bin/ruby".to_string(), "newobj_slowpath".to_string(), uprobe, -1)?;
    let mut table = module.table("counts");
    println!("{:?}", table.key_size());
    println!("{:?}", table.leaf_size());
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let iter = table.into_iter();
        for e in iter {
            let mut kcursor = Cursor::new(e.key);
            let ptr = kcursor.read_u64::<NativeEndian>().unwrap();
            let pid = kcursor.read_i32::<NativeEndian>().unwrap();
            let value = Cursor::new(e.value).read_u64::<NativeEndian>().unwrap();
            if value > 10 {
                println!("{:x} {:?} {:?}", ptr, pid, value);
            }
        }
    }
}

