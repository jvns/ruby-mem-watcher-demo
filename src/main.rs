extern crate libc;
extern crate read_process_memory;
use read_process_memory::*;
use libc::pid_t;

mod proc_maps;
use proc_maps::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid: pid_t = args[1].parse().unwrap();
    let source = pid.try_into_process_handle().unwrap();
    let maps = get_proc_maps(pid).unwrap();
    for map in maps {
        if map.flags == "rw-p" {
            if map.pathname.as_ref().is_some() && map.pathname.as_ref().unwrap().contains(".so") {
                continue;
            }
            println!("{:?}", map);
        }
    }
}

pub fn copy_address_raw<T>(
    addr: usize,
    length: usize,
    source: &T,
    ) -> Vec<u8>
where
T: CopyAddress,
{
    let mut copy = vec![0; length];
    source.copy_address(addr as usize, &mut copy).unwrap();
    copy
}



