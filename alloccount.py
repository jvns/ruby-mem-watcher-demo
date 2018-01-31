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

BPF_HASH(counts, size_t);

int count(struct pt_regs *ctx) {
    u64 zero = 0, *val;
    u64 key = 1;
    size_t ptr = PT_REGS_PARM1(ctx);
    val = counts.lookup_or_init(&ptr, &zero);
    (*val)++;
    return 0;
};
""")

b.attach_uprobe(name="/home/bork/.rbenv/versions/2.4.0/bin/ruby", sym="newobj_slowpath", fn_name="count")

# header
print("Tracing newobj_slowpath()... Hit Ctrl-C to end.")


counts = b.get_table("counts")

while True:
    sleep(1)
    os.system('clear')
    print("%20s | %s" % ("CLASS POINTER", "COUNT"))
    print("%20s | %s" % ("", ""))
    top = list(reversed(sorted([(counts.get(key).value, key.value) for key in counts.keys()])))
    top = top[:10]
    for (count, ptr) in top:
        print("%20s | %s" % (ptr, count))
    counts.clear()
