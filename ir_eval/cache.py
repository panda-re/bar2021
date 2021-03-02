def byte_str(byte_arr, sep="\\x"):
    return (sep + sep.join('{:02x}'.format(x) for x in byte_arr)).strip()

class HashableBytearray(bytearray):

    '''
    Hack for Python's hashing rules
    '''

    def __hash__(self):
        return hash(byte_str(self))

class BBResult():

    '''
    Log IR hit/miss
    '''

    def __init__(self, arch, addr, bb_bytes, ir_dst, true_dst, lift_exception = False):
        self.arch = str(arch)
        self.addr = addr
        self.bb_bytes = HashableBytearray(bb_bytes)
        self.ir_dst = ir_dst
        self.true_dst = true_dst
        self.is_miss = None
        if (ir_dst != None) and (true_dst != None) and (ir_dst != true_dst):
            self.is_miss = True
        elif (ir_dst != None) and (true_dst != None) and (ir_dst == true_dst):
            self.is_miss = False
        self.is_lift_exception = lift_exception

    def __eq__(self, other):
        if isinstance(other, BBResult):
            return(
                self.arch == other.arch
                and self.addr == other.addr
                and self.bb_bytes == other.bb_bytes
                and self.ir_dst == other.ir_dst
                #and self.true_dst == other.true_dst
                #and self.is_miss == other.is_miss
            )
        else:
            return False

    def __hash__(self):
        #return hash(tuple(sorted(self.__dict__.items())))
        return hash(tuple(self.arch, self.addr, self.bb_bytes, self.ir_dst))

    @staticmethod
    def opt_int_to_str(val):
        if val == None:
            return "None"
        else:
            assert(isinstance(val, int))
            return f"{val:016x}",

    def to_str_dict(self):
        ir_dst = BBResult.opt_int_to_str(self.ir_dst)
        true_dst = BBResult.opt_int_to_str(self.true_dst)
        return {
            "arch" : f"{self.arch}",
            "addr" : f"{self.addr:016x}",
            "ir_dst": ir_dst,
            "true_dst": true_dst,
            "bytes:": f"{byte_str(self.bb_bytes)}",
        }

class BBResultCache():

    '''
    Result cache to avoid re-lifting
    '''

    def __init__(self):
        self.cache = {}

    def add(self, bbr):
        assert(isinstance(bbr, BBResult))
        key = (bbr.addr, bbr.bb_bytes)
        res = self.cache.get(key, None)
        if res:
            assert(res == bbr)
        else:
            self.cache[key] = bbr

    def get_result(self, addr, bb_byte_arr):
        assert(isinstance(bb_byte_arr, bytearray))
        key = (addr, HashableBytearray(bb_byte_arr))
        return self.cache.get(key, None)

    def finalize(self):
        for bbr in self.cache.values():
            if (bbr.ir_dst != None) and (bbr.true_dst != None) and (bbr.ir_dst == bbr.true_dst):
                bbr.is_miss = False

    def get_hit_list(self):
        self.finalize()
        return [bbr for bbr in self.cache.values() if bbr.is_miss == False]

    def get_miss_list(self):
        self.finalize()
        return [bbr for bbr in self.cache.values() if bbr.is_miss == True]

    def get_fail_list(self):
        self.finalize()
        return [bbr for bbr in self.cache.values() if bbr.is_lift_exception == True]