#!/usr/bin/env python3

from sys import argv
from pandare import blocking, Panda

generic_type = argv[1] if len(argv) > 1 else "x86_64"
command = argv[2] if len(argv) > 2 else "whoami"

panda = Panda(generic=generic_type)
rec_name = command + "_" + generic_type

@blocking
def run_cmd():
    panda.revert_sync("root")
    print(f"Running \'{command}\' in guest, saving to \'{rec_name}\'")
    panda.record_cmd(command, recording_name=rec_name)
    panda.end_analysis()

panda.queue_async(run_cmd)

panda.run()
