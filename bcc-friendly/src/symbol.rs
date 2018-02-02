use std::ffi::CString;
extern crate bcc_sys;
use failure::Error;
use self::bcc_sys::bccapi::*;
use std::mem;

pub fn resolve_symbol_path(module: String, symname: String, addr: u64, pid: pid_t) -> Result<(String, u64), Error> {
    let pid: pid_t = match pid {
        -1 => 0,
        x => x,
    };

	resolve_symname(module, symname, addr, pid)
}

pub fn resolve_symname(module: String, symname: String, addr: u64, pid: pid_t) -> Result<(String, u64), Error> {
    let mut symbol = unsafe {mem::zeroed::<bcc_symbol>()};
    let cmodule = CString::new(module.clone()).unwrap();
    let csymname = CString::new(symname.clone()).unwrap();

	let res = unsafe {
        bcc_resolve_symname(cmodule.as_ptr(), csymname.as_ptr(), addr, pid, 0 as *mut bcc_symbol_option, &mut symbol as *mut bcc_symbol)
    };
	if res < 0 {
		Err(format_err!("unable to locate symbol {} in module {}: {}", &symname, module, res))
	} else {
        // TODO: should be symbol.module, not module i think
        Ok((module, symbol.offset))
    }
}


