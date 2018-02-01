extern crate bcc_sys;
extern crate libc;
use libc::*;

use bcc_sys::bccapi::*;
use std::ffi::CString;

fn main() {
    new_module("hi");
}

fn new_module(code: &str) {
    let cs = CString::new(code).unwrap();
    unsafe {
        bpf_module_create_c_from_string(cs.as_ptr(), 2, 0 as *mut *const c_char, 0)
    };
}

