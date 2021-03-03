#!/usr/bin/env python3

from sys import argv
import logging

from pandare import blocking, Panda
import switchboard

# Arg parse ------------------------------------------------------------------------------------------------------------

# Note: PyPANDA not easily compatible with argparse yet!

# Init PANDA
arch = argv[1] if len(argv) > 1 else "i386"
space = argv[2] if len(argv) > 2 else "user"
trgt_proc = argv[3] if len(argv) > 3 else "whoami"
rec_name = argv[4] if len(argv) > 4 else "none"
enable_bap = argv[5] if len(argv) > 5 else "no_bap"

if space == "kernel":
    print("IR TEST ON KERNEL!")
elif space == "user":
    print(f"IR TEST ON USERSPACE BIN: {trgt_proc}")
else:
    print(f"Usage: {argv[0]} <arch> <kernel || user> <user_procname> <opt_recording_name>")
    raise RuntimeError

# Hacky 5th arg -> if present use BAP as well
if enable_bap == "no_bap":
    print("Evalulating VEX and PCODE only.")
    enable_bap = False
else:
    print("Evalulating VEX, PCODE, and BAP.")
    enable_bap = True

# Globals --------------------------------------------------------------------------------------------------------------

bb_cnt = 0
panda = Panda(generic = arch)
ir_eval = switchboard.SBEval(arch, verbose=False, run_bap=enable_bap)

# Helpers --------------------------------------------------------------------------------------------------------------

def try_vm_read(panda, cpu, tb):
    try:
        data = panda.virtual_memory_read(cpu, tb.pc, tb.size)
        return data
    except:
        logging.error(f"Failed to VM read {tb.size} bytes from 0x{tb.pc:08x}")
        return None

# TODO: this is terrible, fix this!
def really_in_kernel(addr):
    if arch == "x86_64":
        return (addr > 0xc000000000000000)
    else:
        return (addr > 0xc0000000)

@blocking
def run_cmd():
    panda.revert_sync("root")
    panda.load_plugin("osi", args={"disable-autoload": True})
    panda.load_plugin("osi_linux")
    print(panda.run_serial_cmd(trgt_proc, no_timeout=True))
    finish_ir_eval()

def finish_ir_eval():
    ir_eval.dump_result(space)
    ir_eval.dump_misses(space)
    print(ir_eval)
    panda.end_analysis()

# Userspace ------------------------------------------------------------------------------------------------------------

@panda.cb_after_block_exec(procname=trgt_proc)
def bb_after_exec_usr(cpu, tb, exit_code):
    if (space == "user") and (not panda.in_kernel(cpu) and not (really_in_kernel(tb.pc))) and (exit_code <= 1):
        data = try_vm_read(panda, cpu, tb)
        if data:
            ir_eval.log_block(tb.pc, data)

@panda.cb_after_block_translate(procname=trgt_proc)
def bb_after_trans_usr(cpu, tb):
    if (space == "user") and (not panda.in_kernel(cpu) and not (really_in_kernel(tb.pc))):
        data = try_vm_read(panda, cpu, tb)
        if data:
            ir_eval.lift_block(tb.pc, data)

# Kernelspace ----------------------------------------------------------------------------------------------------------

@panda.cb_after_block_exec
def bb_after_exec_kern(cpu, tb, exit_code):
    if (space == "kernel") and (panda.in_kernel(cpu)) and (exit_code <= 1):
        data = try_vm_read(panda, cpu, tb)
        if data:
            ir_eval.log_block(tb.pc, data)

@panda.cb_after_block_translate
def bb_after_trans_kern(cpu, tb):
    if (space == "kernel") and (panda.in_kernel(cpu)):
        data = try_vm_read(panda, cpu, tb)
        if data:
            ir_eval.lift_block(tb.pc, data)

# Run ------------------------------------------------------------------------------------------------------------------

if rec_name == "none":
    print("Running live!")
    panda.queue_async(run_cmd)
    panda.run()
else:
    print("Running replay!")
    panda.run_replay(rec_name)
    finish_ir_eval()
