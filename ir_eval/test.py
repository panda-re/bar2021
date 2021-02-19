import enum
import collections
import unittest

import switchboard

# Test Data x86 --------------------------------------------------------------------------------------------------------

class SnippetType(enum.Enum):
    CALL_IMM        = "CALL_IMM"
    CALL_NEG_IMM    = "CALL_NEG_IMM"
    CALL_REG        = "CALL_REG"
    RET             = "RET"
    SPECIAL_TEST    = "SPECIAL_TEST"

TestSnippet = collections.namedtuple("TestSnippet", "addr bytes type arch")

bb_call_imm_str = [
    b"\x48\x89\xd8",            # mov rax, rbx
    b"\x48\xff\xc0",            # inc rax
    b"\xe8\x2c\x13\x00\x00",    # call 0x1331
    b"\x48\x31\xc0",            # xor rax, rax /* Unreachable */
]
bb_call_imm_bytes = b"".join(bb_call_imm_str)
bb_call_imm = TestSnippet(addr=0, bytes=bb_call_imm_bytes, type=SnippetType.CALL_IMM, arch="x86_64")

bb_call_reg_str = [
    b"\x48\x89\xd8",            # mov rax, rbx
    b"\x48\xff\xc0",            # inc rax
    b"\xff\xd0",                # call rax
    b"\x48\x31\xc0",            # xor rax, rax /* Unreachable */
]
bb_call_reg_bytes = b"".join(bb_call_reg_str)
bb_call_reg = TestSnippet(addr=0, bytes=bb_call_reg_bytes, type=SnippetType.CALL_REG, arch="x86_64")

bb_ret_str = [
    b"\x48\x89\xd8",            # mov rax, rbx
    b"\x48\xff\xc0",            # inc rax
    b"\xc3",                    # ret
    b"\x48\x31\xc0",            # xor rax, rax /* Unreachable */
]
bb_ret_bytes = b"".join(bb_ret_str)
bb_ret = TestSnippet(addr=0, bytes=bb_ret_bytes, type=SnippetType.RET, arch="x86_64")

bb_call_neg_imm_str = [
    b"\x48\x89\xd8",            # mov rax, rbx
    b"\x48\xff\xc0",            # inc rax
    b"\xe8\xbe\xec\xff\xff",    # call -0x133d
    b"\x48\x31\xc0",            # xor rax, rax /* Unreachable */
]
bb_call_neg_imm_bytes = b"".join(bb_call_neg_imm_str)
bb_call_neg_imm = TestSnippet(addr=0x266e, bytes=bb_call_neg_imm_bytes, type=SnippetType.CALL_NEG_IMM, arch="x86_64")

bb_sysexit_str = [
    b"\x0f\x35",            # sysexit
]
bb_sysexit_bytes = b"".join(bb_sysexit_str)
bb_sysexit = TestSnippet(addr=0x0, bytes=bb_sysexit_bytes, type=SnippetType.SPECIAL_TEST, arch="x86_64")

# Text Data ARM --------------------------------------------------------------------------------------------------------

bb_bl_str = [
    b"\x0f\x00\xa0\xe1", # mov r0, pc
    b"\x02\x10\xa0\xe3", # mov r1, #2
    b"\x01\x20\x81\xe0", # add r2, r1, r1
    b"\xc9\x04\x00\xeb", # bl #0x132c
    b"\x70\x00\x20\xe1", # bkpt /* Unreachable */
]
bb_bl_bytes = b"".join(bb_bl_str)
bb_bl = TestSnippet(addr=0x0, bytes=bb_bl_bytes, type=SnippetType.SPECIAL_TEST, arch="arm")

# Test Runner ----------------------------------------------------------------------------------------------------------

class TestIRs(unittest.TestCase):

    '''
    Verify call and ret detection logic for reach IR on x64
    '''

    def check_invariants(self, sb, addr, snippet):
        bbr = sb.bb_result_cache.get_result(addr, bytearray(snippet.bytes))
        self.assertIsNotNone(bbr)
        if ((snippet.type == SnippetType.CALL_IMM) or (snippet.type == SnippetType.CALL_NEG_IMM)) and snippet.arch != "arm":
            self.assertEqual(sb.call_imm_cnt, 1)
            self.assertEqual(sb.call_reg_cnt, 0)
            self.assertEqual(sb.ret_cnt, 0)
            self.assertEqual(bbr.ir_dst, 0x1337)
        elif ((snippet.type == SnippetType.CALL_IMM) or (snippet.type == SnippetType.CALL_NEG_IMM)) and snippet.arch == "arm":
            self.assertEqual(sb.call_imm_cnt, 1)
            self.assertEqual(sb.call_reg_cnt, 0)
            self.assertEqual(sb.ret_cnt, 0)
            self.assertEqual(bbr.ir_dst, 0x1338)
        elif snippet.type == SnippetType.CALL_REG:
            self.assertEqual(sb.call_imm_cnt, 0)
            self.assertEqual(sb.call_reg_cnt, 1)
            self.assertEqual(sb.ret_cnt, 0)
            self.assertEqual(bbr.ir_dst, None)
        elif snippet.type == SnippetType.RET:
            self.assertEqual(sb.call_imm_cnt, 0)
            self.assertEqual(sb.call_reg_cnt, 0)
            self.assertEqual(sb.ret_cnt, 1)
            self.assertEqual(bbr.ir_dst, None)

    def run_ir(self, ir, snippet):
        assert(isinstance(snippet, TestSnippet))
        if ir == switchboard.IR.VEX:
            sb = switchboard.SBVex(snippet.arch, verbose=True)
        elif ir == switchboard.IR.BAP:
            sb = switchboard.SBBap(snippet.arch, verbose=True)
        elif ir == switchboard.IR.PCODE:
            sb = switchboard.SBPCode(snippet.arch, verbose=True)
        else:
            raise RuntimeError

        sb.lift_block(snippet.addr, snippet.bytes)
        self.check_invariants(sb, snippet.addr, snippet)

    def test_vex(self):
        self.run_ir(switchboard.IR.VEX, bb_call_imm)
        self.run_ir(switchboard.IR.VEX, bb_call_neg_imm)
        self.run_ir(switchboard.IR.VEX, bb_call_reg)
        self.run_ir(switchboard.IR.VEX, bb_ret)

    def test_pcode(self):
        self.run_ir(switchboard.IR.PCODE, bb_call_imm)
        self.run_ir(switchboard.IR.PCODE, bb_call_neg_imm)
        self.run_ir(switchboard.IR.PCODE, bb_call_reg)
        self.run_ir(switchboard.IR.PCODE, bb_ret)

    def test_bap(self):
        self.run_ir(switchboard.IR.BAP, bb_call_imm)
        self.run_ir(switchboard.IR.BAP, bb_call_neg_imm)
        self.run_ir(switchboard.IR.BAP, bb_call_reg)
        self.run_ir(switchboard.IR.BAP, bb_ret)
        self.run_ir(switchboard.IR.BAP, bb_bl)

    '''
    def test_vex_special(self):
        self.run_ir(switchboard.IR.VEX, bb_sysexit)

    def test_pcode_special(self):
        self.run_ir(switchboard.IR.PCODE, bb_sysexit)

    def test_bap_special(self):
        self.run_ir(switchboard.IR.BAP, bb_sysexit)
    '''

if __name__ == "__main__":
    unittest.main()