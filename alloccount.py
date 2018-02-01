#!/usr/bin/python
#
# strlen_count  Trace strlen() and print a frequency count of strings.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of BCC and uprobes.
#
# Also see strlensnoop.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from time import sleep
import os

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

typedef struct blah {
    size_t ptr;
    pid_t pid;
} blah_t;

BPF_HASH(counts, blah_t);


int count(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    u64 zero = 0, *val;
    blah_t key = {};
    size_t ptr = PT_REGS_PARM1(ctx);
    key.ptr = ptr;
    key.pid = pid;
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
""")

b.attach_uprobe(name="/home/bork/.rbenv/versions/2.4.0/bin/ruby", sym="newobj_slowpath", fn_name="count")

# header
print("Tracing newobj_slowpath()... Hit Ctrl-C to end.")


counts = b.get_table("counts")

h = {}

import subprocess
from collections import namedtuple
Stats = namedtuple('Stats', ['count', 'pid', 'ptr'])

def update_cache(top):
    missing_ptrs = []
    missing_ptr_stats = []
    for stat in top:
        if stat.ptr == 0:
            continue
        if (stat.ptr, stat.pid) not in h:
            missing_ptrs.append(str(stat.ptr))
            missing_ptr_stats.append(stat)
    if len(missing_ptrs) == 0:
        return
    args = ["./target/debug/ruby-fork-test", str(missing_ptr_stats[0].pid)] + missing_ptrs
    # print(' '.join(args))
    out = subprocess.check_output(args)
    lines = out.split("\n")
    for l in lines:
        if len(l) == 0:
            continue
        (ptr, name, pid) = l.split()
        h[(int(ptr), int(pid))] = name



while True:
    os.system('clear')
    print("%30s | %s" % ("CLASS", "COUNT"))
    print("%30s | %s" % ("", ""))
    top = list(reversed(sorted([Stats(count=counts.get(key).value, ptr=key.ptr, pid=key.pid) for key in counts.keys()])))
    top = top[:20]
    if len(h) < 10:
        update_cache(top)
    for stat in top:
        s = h.get((stat.ptr, stat.pid), "?? %s" % stat.ptr)
        print("%30s | %s" % (s, stat.count))
    sleep(1)
