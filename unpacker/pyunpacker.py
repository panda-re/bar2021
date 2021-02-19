#!/usr/bin/env python3
from pandare import Panda, blocking, ffi
from argparse import ArgumentParser
from os.path import exists
from sys import exit
from multiprocessing import Process, Manager, Value
from webserver import run_flask_server 
from utility import read_all_process_memory
from scipy.stats import entropy

# parse our arguments
parser = ArgumentParser(description="Interactive tool to plot entropy and transition to ghidra")
parser.add_argument("recording_name", type=str,
                    help="name of the PANDA recording to use") 
parser.add_argument("--program-name",type=str,
                    default="bash.upx", help="name of program to apply entropy analysis to")
parser.add_argument("--granularity",type=int, default=100000,
                    help="number of basic blocks between samples. Lower numbers result in higher run times")
args = parser.parse_args()

if not exists(args.recording_name + "-rr-snp"):
    print(f"Recording does not exist: {args.recording_name}")
    exit()

# set up our initial PANDA object
panda = Panda(generic="x86_64")

# share lists and values with our web server process 
manager = Manager()
x_axis = manager.list()
y_axis = manager.list()
selected = Value('i',0)

# start up a new process for our web server
process = Process(target=run_flask_server, args=(x_axis, y_axis, selected, args.recording_name))
process.start()

# do our main PANDA entropy analysis
asid_to_check = None
block_num = 0

'''
This callback allows us to find our program's ASID and then use that for entropy analysis at 
the basic block level. The callback is disabled after the program's asid is found.s
'''
@panda.cb_asid_changed(name="cb_asid_changed")
def asid_changed(env, old_asid, new_asid):
    global asid_to_check
    if args.program_name in panda.get_process_name(env):
        asid_to_check = panda.current_asid(env)
        print(f"FOUND ASID: {asid_to_check:x}")
        panda.disable_callback(name="cb_asid_changed")
    return 0

'''
This callback calculates the entropy of the entire memory region of a specified process as
is made available by Operating System Introspection.

Upon making a calculation it adds its values to shared variables that the web server picks up
and plots.

This callback operates before every basic block. We use the granularity variable to determine
how many of these basic blocks to skip between calls to find entropy of the program.
'''
@panda.cb_before_block_exec
def bbe(cpu,tb):
    global block_num, asid_to_check
    if panda.current_asid(cpu) == asid_to_check and not panda.in_kernel(cpu) and block_num > args.granularity:
        memory = read_all_process_memory(panda, cpu)
        if memory:
            pk = [memory.count(i) for i in range(256)]
            if sum(pk) != 0:
                text_entropy = entropy(pk,base=2)
                x_axis.append(cpu.rr_guest_instr_count)
                y_axis.append(text_entropy)
        block_num = 0
    block_num += 1

panda.run_replay(args.recording_name)