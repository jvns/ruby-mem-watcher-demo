use libc::size_t;
extern crate bcc_sys;
extern crate regex;
use self::bcc_sys::bccapi::*;
use std::ffi::CStr;
use std;

use types::*;

#[derive(Clone, Debug)]
pub struct Table {
    id: size_t,
    p: MutPointer,
}

impl Table {
    pub fn new(id: usize, p: MutPointer) -> Table{
        Table {id, p}
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
        EntryIter{key: None, leaf: None, table: self.clone(), fd: None}
    }
}

pub struct Entry {
	pub key: Vec<u8>,
	pub value: Vec<u8>,
}


pub struct EntryIter {
    key: Option<Vec<u8>>,
    leaf: Option<Vec<u8>>,
    fd: Option<fd_t>,
    table: Table,
}

impl EntryIter {
    pub fn key_ptr(&mut self) -> Option<(*mut std::os::raw::c_void, *mut std::os::raw::c_void)> {
        match self.key.as_mut() {
            Some(k) => Some((
                    k.as_mut_ptr() as *mut u8 as  *mut std::os::raw::c_void,
                    self.leaf.as_mut().unwrap().as_mut_ptr() as *mut u8 as *mut std::os::raw::c_void)),
            None => None,
        }
    }

    fn zero_vec(&self, size: usize) -> Vec<u8> {
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size {
            vec.push(0);
        }
        vec
    }

    pub fn start(&mut self) -> Entry {
        self.fd = Some(self.table.fd());
        let key_size = self.table.key_size();
        let leaf_size = self.table.leaf_size();
        self.key = Some(self.zero_vec(key_size));
        self.leaf = Some(self.zero_vec(leaf_size));
        unsafe {
            let (k, _) = self.key_ptr().unwrap();
            bpf_get_first_key(self.fd.unwrap(), k, key_size);
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
        if let Some((k, l)) = self.key_ptr() {
            let fd = self.fd.expect("oh no");
            match unsafe {bpf_get_next_key(fd, k, k) } {
                -1 => None,
                _ => {
                    unsafe {bpf_lookup_elem(fd, k, l)};
                    self.entry()
                }

            }
        } else {
            Some(self.start())
        }
    }
}
