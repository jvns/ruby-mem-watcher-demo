//use libc::*;
use std::ffi::CString;
use std::ffi::CStr;
extern crate bcc_sys;
extern crate regex;
use failure::Error;
use self::bcc_sys::bccapi::*;
use std;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use regex::Regex;
use symbol;

type fd_t = i32;
type Pointer = * const std::os::raw::c_void;
type MutPointer = * mut std::os::raw::c_void;
const NULL_POINTER: Pointer = 0 as * const std::os::raw::c_void;

#[derive(Debug, Clone)]
pub struct BCC {
    pub p: MutPointer,
    uprobes: HashMap<String, MutPointer>,
    kprobes: HashMap<String, MutPointer>,
    funcs: HashMap<String, fd_t>,
// 	funcs   map[string]int
}

pub struct compileRequest {
	code: String,
	cflags: Vec<String>,
	// rspCh  chan *BCC
}
impl BCC {

    pub fn new(code: &str) -> BCC {
        let cs = CString::new(code).unwrap();
        let ptr = unsafe {
            bpf_module_create_c_from_string(cs.as_ptr(), 2, 0 as *mut *const i8, 0)
        };

        BCC {
            p: ptr,
            uprobes: HashMap::new(),
            kprobes: HashMap::new(),
            funcs: HashMap::new(),
        }
    }

    pub fn table_id(&self, name: String) -> usize {
        let cname = CString::new(name).unwrap();
        unsafe { bpf_table_id(self.p as MutPointer, cname.as_ptr()) }
    }

    pub fn load_net(&mut self, name: String) -> Result<fd_t, Error> { 
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_SCHED_ACT, 0, 0)
    }

    pub fn load_kprobe(&mut self, name: String) -> Result<fd_t, Error> { 
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0)
    }

    pub fn load_uprobe(&mut self, name: String) -> Result<fd_t, Error> { 
        // really??
        return self.load(name, bpf_prog_type_BPF_PROG_TYPE_KPROBE, 0, 0)
    }

    pub fn load(&mut self, name: String, prog_type: u32, logLevel: i32, log_size: u32) -> Result<fd_t, Error> {
        match self.funcs.entry(name.clone()) {
            Entry::Occupied(o) => {return Ok(o.into_mut().clone());},
            _ => {},
        };
        let fd = self.load_inner(&name, prog_type, logLevel, log_size)?;
        self.funcs.insert(name.clone(), fd);
        Ok(fd)
    }

    pub fn load_inner(&mut self, name: &str, prog_type: u32, logLevel: i32, log_size: u32) -> Result<fd_t, Error> {
        let cname = CString::new(name.to_string()).unwrap();
        unsafe {
            let start: *mut bpf_insn = bpf_function_start(self.p, cname.as_ptr()) as *mut bpf_insn;
            let size  = bpf_function_size(self.p, cname.as_ptr()) as i32;
            let license = bpf_module_license(self.p);
            let version = bpf_module_kern_version(self.p);
            if start == 0 as *mut bpf_insn {
                return Err(format_err!("BCC: unable to find {}", &name));
            }
            let log_buf: Vec<u8> = Vec::with_capacity(log_size as usize);
            let fd = bpf_prog_load(prog_type, cname.as_ptr(), start, size, license, version, logLevel, log_buf.as_ptr() as *mut i8, log_buf.capacity() as u32);
            if fd < 0 {
                return Err(format_err!("error loading BPF program: {}", &name));
            }
            Ok(fd)
        }
    }

    pub fn attach_uretprobe(&mut self, name: String, symbol: String, fd: fd_t, pid: pid_t) -> Result<(), Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new("[^a-zA-Z0-9]").unwrap();
        }
        let (path, addr) = symbol::resolve_symbol_path(name, symbol, 0x0, pid)?;
        let evName = format!("r_{}_0x{:x}", RE.replace_all(&path, "_"), addr);
        self.attach_uprobe_inner(evName, bpf_probe_attach_type_BPF_PROBE_RETURN, path.to_string(), addr, fd, pid)
    }
    pub fn attach_uprobe(&mut self, name: String, symbol: String, fd: fd_t, pid: pid_t) -> Result<(), Error> {
        lazy_static! {
            static ref RE: Regex = Regex::new("[^a-zA-Z0-9]").unwrap();
        }
        let (path, addr) = symbol::resolve_symbol_path(name, symbol, 0x0, pid)?;
        let evName = format!("r_{}_0x{:x}", RE.replace_all(&path, "_"), addr);
        self.attach_uprobe_inner(evName, bpf_probe_attach_type_BPF_PROBE_ENTRY, path.to_string(), addr, fd, pid)
    }

    fn attach_uprobe_inner(&mut self, name: String, attachType: u32, path: String, addr: u64, fd: i32, pid: pid_t) -> Result<(), Error> {
        let cname = CString::new(name.clone()).unwrap();
        let cpath = CString::new(path).unwrap();
        let group_fd = (-1 as i32) as MutPointer; // something is wrong with the type of this but it's a groupfd
        let uprobe = unsafe {
            println!("{:?} {:?} {:?} {:?} {:x} {:?}  ", fd, attachType, cname, cpath, addr, pid);
            bpf_attach_uprobe(fd, attachType, cname.as_ptr(), cpath.as_ptr(), addr, pid, None /* cpu */, group_fd)
        };
        if uprobe as Pointer == NULL_POINTER {
            return Err(format_err!("Failed to attach uprobe"));
        }
        self.uprobes.insert(name, uprobe);
        Ok(())
    }
}


