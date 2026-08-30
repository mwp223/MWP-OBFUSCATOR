#!/usr/bin/env python3
"""Generate test.obf.lua without needing luac — hand-crafts Lua 5.1 bytecode
for a simple print("Hello from MWP Obfuscator") script."""
import struct, sys, os, random
sys.path.insert(0, os.path.dirname(__file__))
from obf import Parser, make_opmap, generate

def _instr(op, A=0, B=0, C=0, fmt='ABC'):
    if fmt == 'ABx':
        Bx = B; B_f = (Bx >> 9) & 0x1FF; C_f = Bx & 0x1FF
    elif fmt == 'AsBx':
        Bx = B + 131071; B_f = (Bx >> 9) & 0x1FF; C_f = Bx & 0x1FF
    else:
        B_f = B & 0x1FF; C_f = C & 0x1FF
    return struct.pack('<I', op | (A << 6) | (C_f << 14) | (B_f << 23))

def _str(s):
    b = s.encode('latin-1') + b'\x00'
    return struct.pack('<I', len(b)) + b

def _u32(n): return struct.pack('<I', n)
def _b(n):   return bytes([n & 0xFF])

def make_bytecode():
    # Script: print("Hello from MWP Obfuscator")
    # GETGLOBAL R0, K0("print")
    # LOADK     R1, K1("Hello from MWP Obfuscator")
    # CALL      R0, 2, 1
    # RETURN    0, 1
    code = (
        _instr(5, A=0, B=0, fmt='ABx')   +  # GETGLOBAL
        _instr(1, A=1, B=1, fmt='ABx')   +  # LOADK
        _instr(28, A=0, B=2, C=1)        +  # CALL
        _instr(30, A=0, B=1, C=0)           # RETURN
    )
    kst  = _b(4) + _str('print') + _b(4) + _str('Hello from MWP Obfuscator')
    proto = (
        _str('@sample.lua') + _u32(0) + _u32(0) +  # source, lines
        _b(0) + _b(0) + _b(1) + _b(2) +            # nups, nparams, vararg, maxstack
        _u32(4) + code +                            # n_code + instructions
        _u32(2) + kst  +                            # n_kst + constants
        _u32(0) +                                   # n_protos
        _u32(4) + _u32(0)*4 +                       # line info (4 entries)
        _u32(0) + _u32(0)                           # locals, upvalue names
    )
    header = b'\x1bLua' + bytes([0x51,0x00,0x01,0x04,0x04,0x04,0x08,0x00])
    return header + proto

if __name__ == '__main__':
    bc  = make_bytecode()
    pr  = Parser(bc).parse()
    rng = random.Random(0x4D5750)  # deterministic seed (MWP in hex)
    opmap = make_opmap(rng)
    mkey  = rng.randint(1, 0xFFFFFFFF)
    out   = generate(pr, opmap, rng, mkey)
    path  = os.path.join(os.path.dirname(__file__), 'test.obf.lua')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(out)
    print(f'[+] Written {path}  ({len(out)} bytes)')
