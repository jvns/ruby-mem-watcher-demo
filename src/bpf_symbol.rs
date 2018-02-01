use std::ffi::CString;
extern crate bcc_sys;
use failure::Error;
use self::bcc_sys::bccapi::*;
use std::mem;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

pub fn resolveSymbolPath(module: String, symname: String, addr: u64, pid: pid_t) > Result<(String, u64), Error> {
    let pid: pid_t = match pid {
        -1 => 0,
        x => x,
    };

	bccResolveSymname(module, symname, addr, pid)
}

pub fn bccResolveSymname(module: String, symname: String, addr: u64, pid: pid_t) > Result<(String, u64), Error> {
    let mut symbol = unsafe {mem::zeroed::<bcc_symbol>()};
    let cmodule = CString::new(module).unwrap();
    let csymname = CString::new(symname).unwrap();

	let res = bcc_resolve_symname(cmodule.as_ptr(), csymname.as_ptr(), addr, pid, 0 as *mut bcc_symbol_option, symbol.as_mut_ptr())
	if res < 0 {
		Err(format_err!("unable to locate symbol %s in module %s: %v", symname, module, res))
	} else {
        Ok((symbol.module.into_string().unwrap(), symbol.offset))
    }
}


