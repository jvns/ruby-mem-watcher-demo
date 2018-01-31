extern crate libc;
extern crate read_process_memory;
use read_process_memory::*;
use libc::*;

mod proc_maps;
use proc_maps::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid: pid_t = args[1].parse().unwrap();
    let source = pid.try_into_process_handle().unwrap();
    let maps = get_proc_maps(pid).unwrap();
    for map in maps {
        if map.flags == "rw-p" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE);
        }
        if map.flags == "r-xp" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE | PROT_EXEC);
        }
    }
}

fn copy_map(map: &MapRange, source: &ProcessHandle, perms: i32) {
    let start = map.range_start;
    let length = map.range_end - map.range_start;
    unsafe {
        let vec = copy_address(start, length, source);
        if !vec.is_ok() {
            println!("failed: {:?}", map);
        }
        let ptr = mmap(start as * mut c_void, length, perms, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        std::slice::from_raw_parts_mut(start as * mut u8, length).copy_from_slice(&vec.unwrap());
        println!("success: {:?}", map);
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



