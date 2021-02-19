'''
This utility just handles some special case memory logic that just seems clunky in the larger
scripts.
'''

def read_memory(panda, cpu, start, size, read_portion_size=0x100):
    '''
    This function reads from virtual memory of size from the start address.
    It differs from our normal virtual memory read function in it that unmapped pages will be 
    returned as zeroes and there is no possibility of exceptions thrown.
    '''
    output = b""
    read_location = start
    while read_location <= start + size:
        try:
            output += panda.virtual_memory_read(cpu, read_location,read_portion_size)
        except:
            output += b"\x00"*read_portion_size
        read_location += read_portion_size
    return output[:size]

def read_all_process_memory(panda, cpu):
    '''
    This function reads all the memory available from the current process via
    Operating System Introspection. On error it does not include the memory.
    '''
    m = b""
    for mapping in panda.get_mappings(cpu):
        size = mapping.size
        while size > 0:
            try:
                m += panda.virtual_memory_read(cpu, mapping.base, mapping.size)
                break
            except:
                # see if pages at the end are mapped out
                size -= 0x1000
    return m