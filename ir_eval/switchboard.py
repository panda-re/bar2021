import enum
import abc
import collections
import time
import os
import sys
import json
import shutil

import pyvex
import archinfo as pyvex_archinfo
import pypcode
import bap

import cache

# Conveniences ---------------------------------------------------------------------------------------------------------

class PrintableEnum(enum.Enum):

    '''
    Enum display trait
    '''

    def __str__(self):
        return str(self.value)

class Arch(PrintableEnum):

    '''
    Supported architectures
    '''

    i386    = "i386"
    x86_64  = "x86_64"
    arm     = "arm"
    mips    = "mips"

class IR(PrintableEnum):

    '''
    IRs under test
    '''

    VEX     = "VEX"
    BAP     = "BAP"
    PCODE   = "PCODE"

class ErrorCategory(PrintableEnum):

    '''
    Error log types
    '''

    MISS    = "MISS"
    FAIL    = "FAIL"

# IR-based Call Finders ------------------------------------------------------------------------------------------------

class SwitchBoard(abc.ABC):

    '''
    Base class for IR call-finders
    '''

    def __init__(self, arch, verbose = False):
        self.panda_arch = Arch[arch]
        self.verbose = verbose
        self.bb_result_cache = cache.BBResultCache()
        self.arch = None
        self.ir = None
        self.first_bb = True
        self.next_bb_addr = None
        self.last_bbr = None
        self.print_sep_cnt = 80

        # Volume
        self.bb_cnt = 0
        self.avg_bb_byte_cnt = None

        # Work
        self.call_imm_cnt = 0
        self.call_reg_cnt = 0
        self.ret_cnt = 0

        # Speed
        self.avg_bb_lift_time_sec = None

    @abc.abstractmethod
    def lift_block(self, start_addr, data):
        raise NotImplementedError

    def log_block(self, start_addr, data):
        if self.first_bb:
            self.first_bb = False
        else:
            self.update_acc_stats(start_addr)

        self.last_bbr = self.bb_result_cache.get_result(start_addr, bytearray(data))
        if not self.last_bbr:
            self.lift_block(start_addr, data)
            self.last_bbr = self.bb_result_cache.get_result(start_addr, bytearray(data))
            assert(self.last_bbr)

    def update_acc_stats(self, true_dst):
        self.last_bbr.true_dst = true_dst
        if (self.last_bbr.ir_dst != None) and (self.last_bbr.ir_dst != true_dst):
            self.last_bbr.is_miss = True
        elif (self.last_bbr.ir_dst != None) and (self.last_bbr.ir_dst == true_dst):
            self.last_bbr.is_miss = False

        # TODO: add true neg and false neg? Need to feed ground truth func addrs via symbolized binary

    def update_run_stats(self, block_start_addr, block_bytes, lift_start_time, lift_end_time):
        lift_time = (lift_end_time - lift_start_time)
        block_byte_cnt = len(block_bytes)
        self.bb_cnt += 1

        if self.avg_bb_lift_time_sec:
            self.avg_bb_lift_time_sec += ((lift_time - self.avg_bb_lift_time_sec) / self.bb_cnt)
        else:
            self.avg_bb_lift_time_sec = lift_time
            assert(self.bb_cnt == 1)

        if self.avg_bb_byte_cnt:
            self.avg_bb_byte_cnt += ((block_byte_cnt - self.avg_bb_byte_cnt) / self.bb_cnt)
        else:
            self.avg_bb_byte_cnt = block_byte_cnt
            assert(self.bb_cnt == 1)

    def log_fail(self, start_addr, data):
        self.bb_result_cache.add(
            cache.BBResult(
                self.panda_arch,
                start_addr,
                bytearray(data),
                None,
                None,
                True
            )
        )

    def __str__(self):
        return (
            f"[{self.ir}] "
            f"call_imm_cnt: {self.call_imm_cnt} "
            f"(unique_true_pos: {len(self.bb_result_cache.get_hit_list())}, "
            f"unique_false_pos: {len(self.bb_result_cache.get_miss_list())}), "
            f"call_reg_cnt: {self.call_reg_cnt}, "
            f"ret_cnt: {self.ret_cnt}, "
            f"bb_cnt: {self.bb_cnt}, "
            f"avg_bb_byte_cnt: {self.avg_bb_byte_cnt:.6f}, "
            f"avg_bb_lift_time: {self.avg_bb_lift_time_sec:.6f} sec, "
            f"lift_fail_cnt: {len(self.bb_result_cache.get_fail_list())}"
        )

class SBVex(SwitchBoard):

    '''
    Vex IR call/ret finder
    '''

    arch_map = {
        Arch.i386   : pyvex_archinfo.ArchX86(),
        Arch.x86_64 : pyvex_archinfo.ArchAMD64(),
        Arch.arm    : pyvex_archinfo.ArchARM(),
        Arch.mips   : pyvex_archinfo.ArchMIPS32(),
    }

    def __init__(self, arch, verbose = False):
        super().__init__(arch, verbose)
        self.arch = SBVex.arch_map[self.panda_arch]
        self.ir = IR.VEX

    def lift_block(self, start_addr, data):
        if self.bb_result_cache.get_result(start_addr, bytearray(data)):
            return

        start_time = time.process_time()
        irsb = pyvex.lift(data, start_addr, self.arch)
        end_time = time.process_time()
        self.update_run_stats(start_addr, data, start_time, end_time)

        if len(irsb.statements) == 0:
            self.log_fail(start_addr, data)
            if self.verbose:
                print("[VEX] Lift fail logged!")
            return

        if self.verbose:
            print("\n" + self.print_sep_cnt*"-")
            print(f"\n[{self.ir}] Got bytes:")
            print(cache.byte_str(data))
            print(f"\n[{self.ir}] IR for BB:")
            irsb.pp()

        call_trgt = None
        if irsb.jumpkind == "Ijk_Call":
            if isinstance(irsb.next, pyvex.expr.Const):
                call_trgt = int(str(irsb.next), 16) # Eww...gross!
                self.call_imm_cnt += 1
                if self.verbose:
                    print(f"\n[{self.ir}] Call dest: {call_trgt:08x}")
            elif isinstance(irsb.next, pyvex.expr.RdTmp):
                self.call_reg_cnt += 1
                if self.verbose:
                    print(f"\n[{self.ir}] Call dest is register based!")
            else:
                raise RuntimeError
        elif irsb.jumpkind == "Ijk_Ret":
            self.ret_cnt += 1
            if self.verbose:
                print(f"\n[{self.ir}] Ret found in BB.")
        else:
            if self.verbose:
                print(f"\n[{self.ir}] No calls or returns in BB.")

        self.bb_result_cache.add(
            cache.BBResult(
                self.panda_arch,
                start_addr,
                bytearray(data),
                call_trgt,
                None
            )
        )

# TODO: address inner class TODOs
class SBBap(SwitchBoard):

    '''
    BAP IR call/ret finder
    '''

    arch_map = {
        Arch.i386   : "i386",
        Arch.x86_64 : "x86_64",
        Arch.arm    : "arm",
        Arch.mips   : "mips",
    }

    def __init__(self, arch, verbose = False):
        super().__init__(arch, verbose)
        self.arch = SBBap.arch_map[self.panda_arch]
        self.ir = IR.BAP

    def lift_helper(self, data):
        code = cache.byte_str(data, sep=" ")
        args = ['--show-bil=adt', '--arch=' + self.arch,'--', code]
        load_bil = {'load' : lambda s : [bap.bil.loads(n) for n in s.split(b'\n') if n]}
        return bap.run('mc', args, parser=load_bil)

    def analyze_helper(self, bil):
        analyzer = self.CallAnalyzer()
        analyzer.run(bil)
        return analyzer

    def lift_block(self, start_addr, data):
        if self.bb_result_cache.get_result(start_addr, bytearray(data)):
            return

        try:
            start_time = time.process_time()
            ir = self.lift_helper(data)
            end_time = time.process_time()
            self.update_run_stats(start_addr, data, start_time, end_time)
        except:
            self.log_fail(start_addr, data)
            if self.verbose:
                print("[BAP] Lift fail logged!")
            return

        if (len(ir) == 0):
            self.log_fail(start_addr, data)
            if self.verbose:
                print("[BAP] Lift fail logged!")
            return

        if self.verbose:
            print("\n" + self.print_sep_cnt*"-")
            print(f"\n[{self.ir}] Got bytes:")
            print(cache.byte_str(data))
            print(f"\n[{self.ir}] IR for BB:")
            for insn in ir:
                print(f"\n{insn}")

        call_trgt = None
        done = False

        for stmt in ir:
            result = self.analyze_helper(stmt)
            print(vars(result))

            assert(result.call_imm_cnt <= 1)
            if result.call_imm_cnt == 1:
                self.call_imm_cnt += result.call_imm_cnt

            if len(result.call_imm_trgts) != 0:
                assert(len(result.call_imm_trgts) == 1)
                call_trgt = result.call_imm_trgts[0]
                if self.verbose:
                    print(f"\n[{self.ir}] Call dest: {call_trgt:08x}")
                break

            assert(result.call_reg_cnt <= 1)
            if result.call_reg_cnt == 1:
                self.call_reg_cnt += result.call_reg_cnt
                if self.verbose:
                    print(f"\n[{self.ir}] Call dest is register based!")
                break

        '''
        done = False
        for insn in ir:
            for kind in insn.kinds:
                if isinstance(kind, bap.asm.Call):
                    assert(len(insn.operands) >= 1)
                    for stmt in insn.bil:
                        if isinstance(stmt, bap.bil.Jmp):
                            if isinstance(stmt.arg, bap.bil.Int):
                                call_trgt = stmt.arg.value
                    if call_trgt:
                        self.call_imm_cnt += 1
                        if self.verbose:
                            print(f"\n[{self.ir}] Call dest: {call_trgt:08x}")
                        break
                    else:
                        done = True
                        self.call_reg_cnt += 1
                        if self.verbose:
                            print(f"\n[{self.ir}] Call dest is register based!")
                        break
                elif isinstance(kind, bap.asm.Return):
                    done = True
                    self.ret_cnt += 1
                    if self.verbose:
                        print(f"\n[{self.ir}] Ret found in BB.")
                    break
            if done:
                break
            '''

        self.bb_result_cache.add(
            cache.BBResult(
                self.panda_arch,
                start_addr,
                bytearray(data),
                call_trgt,
                None
            )
        )

        if (result.call_imm_cnt + result.call_reg_cnt + result.ret_cnt) == 0:
            if self.verbose:
                    print(f"\n[{self.ir}] No calls or returns in BB.")

    # TODO: This also does not differentiate between Calls and Jumps?
    # TODO: how to find returns?
    # TODO: how to check isinstance(kind, bap.asm.Call)?
    class CallAnalyzer(bap.adt.Visitor):

        '''
        Inner class visitor.
        '''

        def __init__(self):
            self.in_jump = False
            self.call_reg_cnt = 0
            self.call_imm_cnt = 0
            self.call_imm_trgts = list()
            self.ret_cnt = 0

        # https://stackoverflow.com/questions/385572/typecasting-in-python
        def to_signed(self, val, bitness):
            return (val + 2**(bitness - 1)) % 2**bitness - 2**(bitness - 1)

        def run(self, adt):
            if isinstance(adt, tuple):
                for i in adt:
                    if isinstance(i, tuple):
                        self.run(i)
                    else:
                        super().run(i)
            else:
                super().run(adt)

        def visit_Jmp(self, jmp):
            self.in_jump = True
            self.run(jmp.arg)

        def visit_Var(self, var):
            if self.in_jump and not "mem" in var.name:
                self.call_reg_cnt += 1

        def visit_Int(self, var):
            if self.in_jump:
                self.call_imm_cnt += 1
                offset = self.to_signed(var.value, var.size)

                # TODO: how to compute absolute, need PC?
                self.call_imm_trgts.append(offset)

class SBPCode(SwitchBoard):

    '''
    PCODE IR call/ret finder
    Code adapted from example: https://github.com/angr/pypcode/blob/master/pypcode/__main__.py
    Note: printing verbose print affects lift time as written, so always compare to other IRs with verbose == False
    '''

    arch_map = {
        Arch.i386   : "x86.sla",
        Arch.x86_64 : "x86-64.sla",
        Arch.arm    : "ARM7_le.sla",
        Arch.mips   : "mips32R6be.sla",
    }

    SLA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ghidra_v9.2_sla")

    def __init__(self, arch, verbose = False):
        super().__init__(arch, verbose)
        self.arch = SBPCode.arch_map[self.panda_arch]
        self.ir = IR.PCODE
        if Arch[arch] == Arch.x86_64:
            self.var_def = 2
        else:
            self.var_def = 1

        # Pre-init for all BBs
        self.context = pypcode.ContextInternal()
        self.sleighfilename = os.path.join(SBPCode.SLA_PATH, self.arch)
        self.docstorage = pypcode.DocumentStorage()
        self.docstorage.registerTag(self.docstorage.openDocument(self.sleighfilename).getRoot())
        self.loader = pypcode.SimpleLoadImage(0x0, bytearray(b'\x90\x90\x90\x90'), 4)
        self.trans = pypcode.Sleigh(self.loader, self.context)
        self.trans.initialize(self.docstorage)
        if (Arch[arch] == Arch.x86_64) or (Arch[arch] == Arch.i386):
            self.context.setVariableDefault("addrsize", self.var_def)
            self.context.setVariableDefault("opsize", self.var_def)
        self.emit = pypcode.PcodeRawOutHelper(self.trans)
        self.def_space = self.trans.getDefaultSpace()

    @staticmethod
    def print_vardata(data, trans):
        sys.stdout.write('(%s, 0x%x, %d) ' % (data.space.getName(), data.offset, data.size))
        if data.space.getName() == 'register':
            regname = trans.getRegisterName(data.space, data.offset, data.size)
            sys.stdout.write('{%s} ' % regname)

    def lift_block(self, start_addr, data):
        ba_data = bytearray(data)
        bbr = self.bb_result_cache.get_result(start_addr, ba_data)
        if bbr:
            self.call_trgt = bbr.ir_dst
            return

        if self.verbose:
            print("\n" + self.print_sep_cnt*"-")
            print(f"\n[{self.ir}] Got bytes:")
            print(cache.byte_str(data))
            print(f"\n[{self.ir}] IR for BB:")

        start_time = time.process_time()

        self.loader.setData(start_addr, ba_data, len(ba_data))
        addr = pypcode.Address(self.def_space, start_addr)
        lastaddr = pypcode.Address(self.def_space, start_addr + len(ba_data))

        call_trgt = None
        done = False
        while addr < lastaddr:
            self.emit.clearCache()

            try:
                length = self.trans.oneInstruction(self.emit, addr)
            except:
                self.log_fail(start_addr, data)
                if self.verbose:
                    print("[PCODE] Lift fail logged!")
                return

            for op in self.emit.opcache:

                op_name = pypcode.get_opname(op.getOpcode())
                out = op.getOutput()
                if out and self.verbose:
                    SBPCode.print_vardata(out, self.trans)
                    sys.stdout.write('= ')

                if self.verbose:
                    sys.stdout.write('%s ' % op_name)
                    for i in range(op.numInput()):
                        SBPCode.print_vardata(op.getInput(i), self.trans)
                    sys.stdout.write('\n')

                if op_name == "CALL":
                    done = True
                    end_time = time.process_time()
                    self.call_imm_cnt += 1
                    call_trgt = op.getInput(0).offset
                    if self.verbose:
                        print(f"\n[{self.ir}] Call dest: {call_trgt:08x}")
                elif op_name == "CALLIND":
                    done = True
                    end_time = time.process_time()
                    self.call_reg_cnt += 1
                    if self.verbose:
                        print(f"\n[{self.ir}] Call dest is register based!")
                elif op_name == "RETURN":
                    done = True
                    end_time = time.process_time()
                    self.ret_cnt += 1
                    if self.verbose:
                        print(f"\n[{self.ir}] Ret found in BB.")

            if self.verbose:
                sys.stdout.write('\n')

            if done:
                self.update_run_stats(start_addr, data, start_time, end_time)
                self.bb_result_cache.add(
                    cache.BBResult(
                        self.panda_arch,
                        start_addr,
                        bytearray(data),
                        call_trgt,
                        None
                    )
                )
                return
            else:
                addr = addr + length

        end_time = time.process_time()
        self.update_run_stats(start_addr, data, start_time, end_time)
        if self.verbose:
            print(f"\n[{self.ir}] No calls or returns in BB.")

        self.bb_result_cache.add(
            cache.BBResult(
                self.panda_arch,
                start_addr,
                bytearray(data),
                call_trgt,
                None
            )
        )

# Driver ---------------------------------------------------------------------------------------------------------------

class SBEval:

    '''
    Driver for IR-based call/ret finders
    '''

    def __init__(self, arch, verbose = False):
        self.is_first_bb = True
        self.panda_arch = Arch[arch]

        self.ircf_vex = SBVex(arch, verbose)
        self.ircf_pcode = SBPCode(arch, verbose)
        self.ircf_bap = SBBap(arch, verbose)

    def __str__(self):
        return (
            "\nRESULTS:\n"
            f"{self.ircf_vex}\n"
            f"{self.ircf_pcode}\n"
            f"{self.ircf_bap}\n"
        )

    def lift_block(self, start_addr, data):
        self.ircf_vex.lift_block(start_addr, data)
        self.ircf_pcode.lift_block(start_addr, data)
        self.ircf_bap.lift_block(start_addr, data)

    def log_block(self, start_addr, data):
        self.ircf_vex.log_block(start_addr, data)
        self.ircf_pcode.log_block(start_addr, data)
        self.ircf_bap.log_block(start_addr, data)

    @staticmethod
    def dump_json(sb, category, space):
        name = 'ir_' + str(sb.ir)
        data = {}
        data[name] = []

        if category == ErrorCategory.MISS:
            for miss in sb.bb_result_cache.get_miss_list():
                data[name].append(miss.to_str_dict())
        elif category == ErrorCategory.FAIL:
            for fail in sb.bb_result_cache.get_fail_list():
                data[name].append(fail.to_str_dict())
        else:
            raise RuntimeError

        with open(name + "_" + space + "_" + str(category) + "_" + str(sb.panda_arch) + ".json", "w") as f:
            json.dump(data, f, indent = 4)

    def dump_result(self, space):
        with open("result_" + space + "_" + str(self.panda_arch) + ".txt", "w") as f:
            f.write(str(self) + "\n")

    def dump_misses(self, space):
        SBEval.dump_json(self.ircf_vex, ErrorCategory.MISS, space)
        SBEval.dump_json(self.ircf_vex, ErrorCategory.FAIL, space)
        SBEval.dump_json(self.ircf_pcode, ErrorCategory.MISS, space)
        SBEval.dump_json(self.ircf_pcode, ErrorCategory.FAIL, space)
        SBEval.dump_json(self.ircf_bap, ErrorCategory.MISS, space)
        SBEval.dump_json(self.ircf_bap, ErrorCategory.FAIL, space)