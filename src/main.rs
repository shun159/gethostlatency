// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

extern crate regex;

use core::time::Duration;

use anyhow::{bail, Result};
use chrono::Local;
use libbpf_rs::PerfBufferBuilder;
use libc::{rlimit, setrlimit, RLIMIT_MEMLOCK};
use plain::Plain;
use std::path::{Path, PathBuf};
use std::process::exit;
use structopt::StructOpt;

mod bpf;
//use bpf::*;

mod uprobe;
use uprobe::*;

#[derive(Debug, StructOpt)]
struct Command {
    #[structopt(short, long)]
    verbose: bool,
    #[structopt(short, long, default_value = "target/bpf/gethostlatency.bpf.o")]
    obj_path: PathBuf,
}

pub mod gethostlatency_bss_types {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct data_t {
        pub pid: u32,
        pub __pad_4: [u8; 4],
        pub delta: u64,
        pub comm: [u8; 16],
        pub host: [u8; 80],
    }
}

impl Default for gethostlatency_bss_types::data_t {
    fn default() -> Self {
        Self {
            pid: 0,
            __pad_4: [0; 4],
            delta: 0,
            comm: [0; 16],
            host: [0; 80],
        }
    }
}

unsafe impl Plain for gethostlatency_bss_types::data_t {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { setrlimit(RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    };

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = gethostlatency_bss_types::data_t::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
    let now = Local::now();
    let pid = event.pid;
    let comm = std::str::from_utf8(&event.comm).unwrap();
    let host = std::str::from_utf8(&event.host).unwrap();
    let lat = event.delta as f64 / 1_000_000.0;
    println!(
        "{:<9} pid: {:<6} comm: {:<16} host: {:<30} {:>10.2} msec",
        now,
        pid,
        comm.trim_end_matches(char::from(0)),
        host.trim_end_matches(char::from(0)),
        lat
    )
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu)
}

fn main() -> Result<()> {
    let options = Command::from_args();

    if !options.obj_path.as_path().exists() {
        eprintln!("{} doesn't exist", options.obj_path.as_path().display());
        exit(1);
    }

    let mut obj_builder = libbpf_rs::ObjectBuilder::default();
    if options.verbose {
        obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut obj = obj_builder.open_file(options.obj_path)?.load()?;
    let func_ofs = SymbolResolver::find_in_file(
        Path::new("/lib/x86_64-linux-gnu/libc.so.6"),
        "gethostbyname",
    )
    .unwrap()
    .unwrap();
    let mut pathname = String::from("/lib/x86_64-linux-gnu/libc.so.6");
    pathname.push_str("\0");
    let _ret = obj
        .prog_unwrap("handle__entry_gethostbyname")
        .attach_uprobe(false, -1, pathname, func_ofs)
        .unwrap();
    println!("ret: OK?");
    let mut pathname = String::from("/lib/x86_64-linux-gnu/libc.so.6");
    pathname.push_str("\0");
    let _ret = obj
        .prog_unwrap("handle__return_gethostbyname")
        .attach_uprobe(true, -1, pathname, func_ofs)
        .unwrap();
    println!("ret: OK?");
    let func_ofs = SymbolResolver::find_in_file(
        Path::new("/lib/x86_64-linux-gnu/libc.so.6"),
        "gethostbyname2",
    )
    .unwrap()
    .unwrap();
    let mut pathname = String::from("/lib/x86_64-linux-gnu/libc.so.6");
    pathname.push_str("\0");
    let _ret = obj
        .prog_unwrap("handle__entry_gethostbyname2")
        .attach_uprobe(false, -1, pathname, func_ofs)
        .unwrap();
    println!("ret: OK?");
    let mut pathname = String::from("/lib/x86_64-linux-gnu/libc.so.6");
    pathname.push_str("\0");
    let _ret = obj
        .prog_unwrap("handle__return_gethostbyname2")
        .attach_uprobe(true, -1, pathname, func_ofs)
        .unwrap();
    println!("ret: OK?");

    let func_ofs =
        SymbolResolver::find_in_file(Path::new("/lib/x86_64-linux-gnu/libc.so.6"), "getaddrinfo")
            .unwrap()
            .unwrap();
    let mut pathname = String::from("/lib/x86_64-linux-gnu/libc.so.6");
    pathname.push_str("\0");
    let _ret = obj
        .prog_unwrap("handle__entry_getaddrinfo")
        .attach_uprobe(false, -1, pathname, func_ofs)
        .unwrap();
    println!("ret: OK?");
    let mut pathname = String::from("/lib/x86_64-linux-gnu/libc.so.6");
    pathname.push_str("\0");
    let _ret = obj
        .prog_unwrap("handle__return_getaddrinfo")
        .attach_uprobe(true, -1, pathname, func_ofs)
        .unwrap();
    println!("ret: OK?");
    //attach_uprobes(&mut obj);

    let events = obj.map_unwrap("events");
    let perf = PerfBufferBuilder::new(events)
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()
        .unwrap();

    loop {
        let ret = perf.poll(Duration::from_millis(100));
        match ret {
            Ok(()) => (),
            Err(e) => {
                eprintln!("Error polling perf buffer: {}", e);
                exit(1);
            }
        };
    }
}