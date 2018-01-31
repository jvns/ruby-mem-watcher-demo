extern crate libc;
extern crate read_process_memory;
extern crate elf;

#[macro_use]
extern crate failure;

use read_process_memory::*;
use libc::*;
use failure::Error;

mod proc_maps;
use proc_maps::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid: pid_t = args[1].parse().unwrap();
    let source = pid.try_into_process_handle().unwrap();
    let maps = get_proc_maps(pid).unwrap();
    for map in &maps {
        let path = map.pathname.as_ref();
        if path.is_some() && path.unwrap().contains("syscall") {
            continue;
        }
        if map.flags == "rw-p" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE);
        }
        if map.flags == "r-xp" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE | PROT_EXEC);
        }
    }

    let map = get_map(&maps, "bin/ruby", "r-xp").unwrap();
    let file = open_elf_file(pid, &map).unwrap();
    let rb_mod_name_addr = get_symbol_addr(&map, &file, "rb_mod_name").unwrap();
    println!("mod name addr {:x}", rb_mod_name_addr);

    if args.len() > 2 {
        let value: u64 = args[2].parse().unwrap();
        println!("{:x}", value);
        std::thread::sleep(std::time::Duration::from_millis(100000));
        unsafe {
            let f = std::mem::transmute::<u64, extern "C" fn (u64) -> u64>(rb_mod_name_addr as u64);
            let out = f(value);
            println!("{}, {:?} {:x}", out as usize, out, value);
        }
    } else {
        println!("usage: ruby-fork-test PID value-to-get");
    }
}

fn open_elf_file(pid: pid_t, map: &MapRange) -> Result<elf::File, Error> {
    // Read binaries from `/proc/PID/root` because the target process might be in a different
    // mount namespace. /proc/PID/root is the view of the filesystem that the target process
    // has. (see the proc man page for more)
    // So we read /usr/bin/ruby from /proc/PID/root/usr/bin/ruby
    let map_path = map.pathname.as_ref().expect("map's pathname shouldn't be None");
    let elf_path = format!("/proc/{}/root{}", pid, map_path);
    elf::File::open_path(&elf_path)
        .map_err(|_| format_err!("Couldn't open ELF file: {:?}", elf_path))
}

fn get_map(maps: &Vec<MapRange>, contains: &str, flags: &str) -> Option<MapRange> {
    maps.iter()
        .find(|ref m| {
            if let Some(ref pathname) = m.pathname {
                pathname.contains(contains) && &m.flags == flags
            } else {
                false
            }
        })
    .map(|x| x.clone())
}

fn copy_map(map: &MapRange, source: &ProcessHandle, perms: i32) {
    let start = map.range_start;
    let length = map.range_end - map.range_start;
    println!("trying: {:?}", map);
    unsafe {
        let vec = copy_address(start, length, source);
        if !vec.is_ok() {
            println!("...failed");
        }
        let ptr = mmap(start as * mut c_void, length, perms, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        std::slice::from_raw_parts_mut(start as * mut u8, length).copy_from_slice(&vec.unwrap());
        if perms & PROT_EXEC != 0 {
            libc::mprotect(start as *mut c_void, length, PROT_READ | PROT_EXEC);
        }
        println!("...success");
    }
}

fn get_symbol_addr(map: &MapRange, elf_file: &elf::File, symbol_name: &str) -> Option<usize> {
        elf_symbol_value(elf_file, symbol_name).map(|addr| {
            let load_header = elf_load_header(elf_file);
            map.range_start + addr - load_header.vaddr as usize
        })
}

fn elf_symbol_value(elf_file: &elf::File, symbol_name: &str) -> Option<usize> {
    // TODO: maybe move this to goblin so that it works on OS X & BSD, not just linux
    let sections = &elf_file.sections;
    for s in sections {
        for sym in elf_file
            .get_symbols(&s)
                .expect("Failed to get symbols from section")
                {
                    if sym.name == symbol_name {
                        return Some(sym.value as usize);
                    }
                }
    }
    None
}

fn elf_load_header(elf_file: &elf::File) -> elf::types::ProgramHeader {
    elf_file
        .phdrs
        .iter()
        .find(|ref ph| {
            ph.progtype == elf::types::PT_LOAD && (ph.flags.0 & elf::types::PF_X.0) != 0
        })
    .expect("No executable LOAD header found in ELF file. Please report this!")
        .clone()
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



