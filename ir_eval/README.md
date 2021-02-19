# switchboard

Warning: BAP is not supported in this container because it has some complicated install dependencies. See GitHub Issue [here](https://github.com/BinaryAnalysisPlatform/bap-python/issues/17).

### Classification

Currently collect:

* **True positive** - IR found a call instruction AND accurately computed correct the call target (excludes `call <reg>` right now)
* **False positive** - IR mis-labeled a call instruction OR mis-computed the call target (`call <reg>` doesn't count against this rate right now)

Current DO NOT collect (requires ground truth, could always `copy_to_guest` binary build with debug symbols):

* **False negative** - IR failed to find a call instruction, even though it was present
* **True negative** - IR didn't find a call instruction b/c there wasn't one

### Current Setup

* Clone generic image for supported architecture (`run.py` takes arch name as arg)
* Run command in guest (currently just `whoami`)
* Register BB exec callback for process named after command
* On each BB exec: lift to IR and find call instr (if any, may be no calls present), log call target PC (if any, may be register-based dispatch, unknown to IR)
* On next BB exec: if call instr WAS found in prev BB, is does this subsequent BB start addr equal call target?
    * *Yes* - **True positive**, IR correctly computed call dest
    * *No* - **False positive**, IR computed call wrong dest or mis-labeled an instruction as `call <imm>`
* Data collected per IR:
    * Dst accuracy: `call_imm_cnt`, splits into `true_pos` and `false_pos`
    * Auxiliary: `call_reg_cnt` (currently unused)
    * Volume: `bb_cnt` and `avg_bb_byte_cnt`
    * Speed: `avg_bb_lift_time_sec`
