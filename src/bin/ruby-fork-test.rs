extern crate read_process_memory;
extern crate elf;
extern crate bcc_friendly;
extern crate byteorder;
extern crate libc;
#[macro_use]
extern crate failure;

use std::collections::HashMap;
use byteorder::{NativeEndian, ReadBytesExt};
use bcc_friendly::core::BPF;
use bcc_friendly::table::Table;
use bcc_friendly::table;
use failure::Error;
use std::io::Cursor;
use std::fs::File;
use std::io::Write;
use std::io::Read;

use read_process_memory::*;
use libc::*;

extern crate ruby_fork_test;
use ruby_fork_test::*;

use proc_maps::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pid: pid_t = args[1].parse().unwrap();
    let table = &connect(pid).unwrap();
    let elf_struct = set_up_elf_struct(pid);
    let rb_class2name_addr = get_symbol_addr(&elf_struct.map, &elf_struct.elf_file, "rb_class2name").unwrap();
    let mut cache: HashMap<u64, Option<String>> = HashMap::new();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        let iter: table::EntryIter = table.into_iterz();
        let mut blah: Vec<(u64, Option<String>)> = vec!();
        for e in iter {
            let mut kcursor = Cursor::new(e.key);
            let ptr = kcursor.read_u64::<NativeEndian>().unwrap();
            let value = Cursor::new(e.value).read_u64::<NativeEndian>().unwrap();
            if value > 50 {
                let name = cache.entry(ptr).or_insert_with(|| get_class_name(&elf_struct, ptr, rb_class2name_addr as u64));
                blah.push((value, name.clone()));
            }
        }
        blah.sort();
        for (value, name) in blah {
            let n = match name {
                None => "???",
                Some(ref n) => n,
            };
            println!("{name:>20} {value:?}", name=n, value=value);
        }
        print!("{}[2J", 27 as char);
    }
}

struct ElfStruct {
    elf_file: elf::File,
    map: MapRange,
    maps: Vec<MapRange>,
}

fn connect(pid: pid_t) -> Result<Table, Error> {
    let code = "
#include <uapi/linux/ptrace.h>

typedef struct blah {
    size_t ptr;
} blah_t;

BPF_HASH(counts, blah_t);

int count(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    u64 zero = 0, *val;
    blah_t key = {};
    size_t ptr = PT_REGS_PARM1(ctx);
    key.ptr = ptr;
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
    ";
    let mut module = BPF::new(code)?;
    let uprobe = module.load_uprobe("count".to_string())?;
    module.attach_uprobe(format!("/proc/{}/exe", pid), "newobj_slowpath".to_string(), uprobe, pid)?;
    Ok(module.table("counts"))
}

fn set_up_elf_struct(pid: pid_t) -> ElfStruct {
    let source = pid.try_into_process_handle().unwrap();
    let maps = get_proc_maps(pid).unwrap();
    for map in &maps {
        let path = map.pathname.as_ref();
        if path.is_some() && (path.unwrap().contains("syscall") | path.unwrap().contains("vvar")) {
            continue;
        }
        if map.flags == "rw-p" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE).unwrap();
        }
        if map.flags == "r--p" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE).unwrap();
        }
        if map.flags == "r-xp" {
            copy_map(&map, &source, PROT_READ | PROT_WRITE | PROT_EXEC).unwrap();
        }
    }

    let map = get_map(&maps, "bin/ruby", "r-xp").unwrap();
    let file = open_elf_file(pid, &map).unwrap();
    ElfStruct {
        maps: maps,
        map: map.clone(),
        elf_file: file,
    }
}

fn get_class_name(elf_struct: &ElfStruct, ptr: u64, rb_class2name_addr: u64) -> Option<String> {
    let f = unsafe {std::mem::transmute::<u64, extern "C" fn (u64) -> u64>(rb_class2name_addr as u64)};
    if !maps_contain_addr(ptr as usize, &elf_struct.maps) || ptr == 0 {
        return None;
    }
    let filename = "/tmp/out.txt";
    match unsafe {libc::fork()} {
        0 => {
            let s = unsafe {
                let mut out = f(ptr);
                std::slice::from_raw_parts_mut(out as * mut u8, 20)
            };
            let name = std::string::String::from_utf8_lossy(s);
            let name = name.trim_right_matches("\0");
            let mut f = File::create(filename).unwrap();
            write!(f, "{}", name);
            std::process::exit(0);
        },
        -1 => panic!("oh no"),
        _ => {
            let mut status: c_int = 0;
            unsafe {libc::wait(&mut status)};
            let mut f = match File::open(filename) {
                Ok(x) => x,
                _ => {return None;}
            };
            let mut contents = String::new();
            f.read_to_string(&mut contents).unwrap();
            Some(contents)
        },
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

fn copy_map(map: &MapRange, source: &ProcessHandle, perms: i32) -> Result<(), Error> {
    let start = map.range_start;
    let length = map.range_end - map.range_start;
    unsafe {
        let vec = copy_address(start, length, source);
        if !vec.is_ok() {
            return Err(format_err!("failed to copy map: {:?}", map));
        }
        let vec = vec.unwrap();
        let ptr = mmap(start as * mut c_void, length, perms, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if ptr == MAP_FAILED {
            return Err(format_err!("failed to copy map: {:?}", map));
        }
        let slice = std::slice::from_raw_parts_mut(start as * mut u8, length);
        slice.copy_from_slice(&vec);
        if perms & PROT_EXEC != 0 {
            libc::mprotect(start as *mut c_void, length, PROT_READ | PROT_EXEC);
        }
        Ok(())
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



