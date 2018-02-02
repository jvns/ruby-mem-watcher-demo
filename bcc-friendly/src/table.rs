use libc::size_t;
use std::ffi::CString;
extern crate bcc_sys;
extern crate regex;
use self::bcc_sys::bccapi::*;
use std;

use core::BCC;

#[derive(Clone)]
pub struct Table {
    pub id: size_t,
    pub module: BCC,
}

impl Table {
    pub fn new(id: usize, module: BCC) -> Table{
        Table {id, module}
    }

    pub fn id(&mut self) -> String {
        let cstr = unsafe {
            bpf_table_name(self.module.p, self.id)
        };
        "TODO".to_string()
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
        self.key.unwrap().as_mut_ptr() as *mut u8 as  *mut std::os::raw::c_void 
    }

    pub fn start(&mut self) -> Entry {
        unsafe {
            let p = self.table.module.p;
            let fd = bpf_table_fd_id(p, self.table.id);
            self.fd = Some(fd);
            self.key_size = bpf_table_key_size_id(p, self.table.id);
            self.leaf_size = bpf_table_leaf_size_id(p, self.table.id);
            self.key = Some(Vec::with_capacity(self.key_size));
            self.leaf = Some(Vec::with_capacity(self.leaf_size));
            bpf_get_first_key(fd, self.key_ptr(), self.key_size);
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
