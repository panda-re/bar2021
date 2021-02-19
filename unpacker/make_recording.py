#!/usr/bin/env python3
from pandare import Panda
from os.path import exists
from argparse import ArgumentParser

# parse arguments
parser = ArgumentParser(description="Make recording for pyunpacker")
parser.add_argument("recording_name", type=str, 
                    help="name of the PANDA recording to make.")
args = parser.parse_args()

# make sure file doesn't exist
if exists(args.recording_name + "-rr-snp"):
    print(f"Recording {args.recording_name} exists. Not re-recording.")
    exit()

# make actual recording
print(f"Beginning PANDA recording for: {args.recording_name}")
panda = Panda(generic="x86_64")

@panda.queue_blocking
def control_machine():
    panda.record_cmd('./bash.upx -c \"echo hello world\"',copy_directory="to_move",
                     setup_command="./to_move/upx /bin/bash -o bash.upx", 
                     recording_name=args.recording_name)
    panda.end_analysis()

panda.run()