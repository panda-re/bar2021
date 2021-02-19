'''
This is structured as a function, but is really the start of a new process.

The objective of this process is to populate ghidra at the moment selected.
'''

def do_transition_to_ghidra(rr_instr_count, recording_name):    
    from pandare import Panda, ffi
    from utility import read_memory
    from ghidra_bridge import GhidraBridge

    # initialize new PANDA object for our replay
    panda = Panda(generic="x86_64")

    # start up a new connection to ghidra with our GhidraBridge
    b = GhidraBridge(namespace=globals(),response_timeout=1000)#,hook_import=True)

    # remove all the previous segments
    def delete_all_memory_segments(memory, monitor):
        for block in memory.getBlocks(): 
            memory.removeBlock(block,monitor)

    '''
    This function takes the current process state and transmits it over to ghidra via
    the ghidra bridge.
    ''' 
    def populate_ghidra(cpu, pc):
        tid = currentProgram.startTransaction("BRIDGE: Change Memory Sections")
        memory = currentProgram.getMemory()
        delete_all_memory_segments(memory,monitor)
        for mapping in panda.get_mappings(cpu):
            if mapping.file != ffi.NULL:
                name = ffi.string(mapping.file).decode()+"__"+hex(mapping.base)
            else:
                name = "[unknown]"+"__"+hex(mapping.base)
            print(f"MAPPING {name} {mapping.base:x} {mapping.size}")
            memory.createInitializedBlock(name,toAddr(mapping.base),mapping.size,0,monitor,False)
            memory_read = read_memory(panda, cpu,mapping.base,mapping.size)
            if memory_read:
                memory.setBytes(toAddr(mapping.base), memory_read)
        setCurrentLocation(toAddr(pc))
        currentProgram.endTransaction(tid,True)
        
    '''
    This program iterates over blocks until our rr_instr_count that was selected on the
    graph matches what we selected.
    '''
    @panda.cb_before_block_exec
    def move_ghidra(cpu, tb):
        if cpu.rr_guest_instr_count == rr_instr_count:
            populate_ghidra(cpu, panda.current_pc(cpu))
            panda.end_analysis()

    panda.run_replay(recording_name)
    print("finished ghidra transition")