use libc::size_t;
extern crate bcc_sys;
extern crate regex;
use self::bcc_sys::bccapi::*;
use std::ffi::CStr;
use std;

type Pointer = * const std::os::raw::c_void;
type MutPointer = * mut std::os::raw::c_void;

use core::BCC;

#[derive(Clone)]
pub struct Table {
    id: size_t,
    p: MutPointer,
}

impl Table {
    pub fn new(id: usize, module: BCC) -> Table{
        Table {id, p: module.p}
    }

    pub fn key_size(&mut self) -> usize {
        unsafe {bpf_table_key_size_id(self.p, self.id)}
    }

    pub fn fd(&mut self) -> fd_t {
        unsafe {bpf_table_fd_id(self.p, self.id)}
    }

    pub fn leaf_size(&mut self) -> usize {
        unsafe {bpf_table_leaf_size_id(self.p, self.id)}
    }

    pub fn name(&mut self) -> String {
        unsafe {
            let cs = bpf_table_name(self.p, self.id);
            CStr::from_ptr(cs).to_str().unwrap().to_string()
        }
    }

    pub fn into_iter(&self) -> EntryIter {
        EntryIter{key: None, leaf: None, table: self.clone(), key_size: 0, leaf_size: 0, fd: None}
    }
}

pub struct Entry {
	pub key: Vec<u8>,
	pub value: Vec<u8>,
}


type fd_t = i32;

pub struct EntryIter {
    key: Option<Vec<u8>>,
    leaf: Option<Vec<u8>>,
    key_size: usize,
    leaf_size: usize,
    fd: Option<fd_t>,
    table: Table,
}

impl EntryIter {
    pub fn key_ptr(&mut self) -> *mut std::os::raw::c_void {
        self.key.as_mut().unwrap().as_mut_ptr() as *mut u8 as  *mut std::os::raw::c_void 
    }

    pub fn start(&mut self) -> Entry {
        self.fd = Some(self.table.fd());
        self.key_size = self.table.key_size();
        self.leaf_size = self.table.leaf_size();
        self.key = Some(Vec::with_capacity(self.key_size));
        self.leaf = Some(Vec::with_capacity(self.leaf_size));
        unsafe {
            bpf_get_first_key(self.fd.unwrap(), self.key_ptr(), self.key_size);
            self.entry().unwrap()
        }
    }

    pub fn entry(&self) -> Option<Entry> {
        match self.key.as_ref() {
            None => None,
            Some(k) => Some(Entry {
                key: k.clone(),
                value: self.leaf.as_ref().unwrap().clone(),
            }),
        }
    }
}



impl Iterator for EntryIter {
    type Item = Entry;
    
    fn next(&mut self) -> Option<Entry> {
        if let Some(e) = self.entry() {
            return Some(e);
        }
        let k = self.key_ptr();
        match unsafe {bpf_get_next_key(self.fd.expect("oh no"), k, k) } {
            -1 => None,
            _ => self.entry()
        }
    }
}
