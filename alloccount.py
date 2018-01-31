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

def get_thing(ptr, pid):
    if (ptr, pid) not in h:
        h[(ptr, pid)] = get_thing2(ptr, pid)
    return h[(ptr, pid)]

import subprocess
def get_thing2(ptr, pid):
    out = subprocess.check_output(["./target/debug/ruby-fork-test", str(pid), str(ptr)])
    return out.strip()

while True:
    sleep(1)
    os.system('clear')
    print("%20s | %s" % ("CLASS POINTER", "COUNT"))
    print("%20s | %s" % ("", ""))
    top = list(reversed(sorted([(counts.get(key).value, key.ptr, key.pid) for key in counts.keys()])))
    top = top[:25]
    for (count, ptr, pid) in top:
        s = get_thing(ptr, pid)
        print("%20s | %s" % (s, count))
