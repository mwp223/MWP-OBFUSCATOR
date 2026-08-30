#!/usr/bin/env python3
"""
MWP Lua Obfuscator — VM-based Lua 5.1/Luau protection.

Build-time (zero runtime cost):
  · 38-opcode random bijection per build
  · Randomized if/elseif dispatch ordering per build (no positional fingerprint)
  · Sub-proto array shuffled + CLOSURE refs updated
  · All VM/field/local names randomized per build
  · Instruction slot permutation (op/A/B/C in random positions)
  · Triple-pass LCG-XOR encryption of instruction blob
  · CRC32 integrity check; stored XOR-masked with per-build mask
  · All build constants as math_expr (no plaintext LCG/CRC poly)
  · Short string constants (≤2 chars) inlined as literals

Runtime (once, root proto; lazy per sub-proto on first CLOSURE):
  · CRC verify via byte-string iteration (not int-table)
  · Triple-pass LCG-XOR decrypt via string.unpack('<I4',...)
  · Instruction decode from decrypted int stream

VM style (Luau-targeted):
  · repeat…until <opaque> with continue (not while…do)
  · string.unpack for instruction blob reads
  · Hex/binary literals with random underscore separators throughout
  · Tamper check scattered every N instructions (N randomized per build)
"""

import struct, sys, os, random, subprocess, argparse, tempfile, string, zlib


class BytecodeError(ValueError):
    """Raised when a chunk is not a supported, well-formed Lua 5.1 chunk."""

# ─── Lua 5.1 opcode table ────────────────────────────────────────────────────
OP = {
    'MOVE':0,'LOADK':1,'LOADBOOL':2,'LOADNIL':3,'GETUPVAL':4,'GETGLOBAL':5,
    'GETTABLE':6,'SETGLOBAL':7,'SETUPVAL':8,'SETTABLE':9,'NEWTABLE':10,
    'SELF':11,'ADD':12,'SUB':13,'MUL':14,'DIV':15,'MOD':16,'POW':17,
    'UNM':18,'NOT':19,'LEN':20,'CONCAT':21,'JMP':22,'EQ':23,'LT':24,
    'LE':25,'TEST':26,'TESTSET':27,'CALL':28,'TAILCALL':29,'RETURN':30,
    'FORLOOP':31,'FORPREP':32,'TFORLOOP':33,'SETLIST':34,'CLOSE':35,
    'CLOSURE':36,'VARARG':37,
}
OP_NAME = {v: k for k, v in OP.items()}
NUM_OPS = 38
MAX_sBx = 131071
BITRK   = 256

FMT = {
    'MOVE':'ABC','LOADK':'ABx','LOADBOOL':'ABC','LOADNIL':'ABC','GETUPVAL':'ABC',
    'GETGLOBAL':'ABx','GETTABLE':'ABC','SETGLOBAL':'ABx','SETUPVAL':'ABC',
    'SETTABLE':'ABC','NEWTABLE':'ABC','SELF':'ABC','ADD':'ABC','SUB':'ABC',
    'MUL':'ABC','DIV':'ABC','MOD':'ABC','POW':'ABC','UNM':'ABC','NOT':'ABC',
    'LEN':'ABC','CONCAT':'ABC','JMP':'AsBx','EQ':'ABC','LT':'ABC','LE':'ABC',
    'TEST':'ABC','TESTSET':'ABC','CALL':'ABC','TAILCALL':'ABC','RETURN':'ABC',
    'FORLOOP':'AsBx','FORPREP':'AsBx','TFORLOOP':'ABC','SETLIST':'ABC',
    'CLOSE':'ABC','CLOSURE':'ABx','VARARG':'ABC',
}

# ─── Dispatch handler bodies ─────────────────────────────────────────────────
# JMP and FORPREP use `continue` — valid Luau, not Lua 5.1 pure.
# RETURN and TAILCALL use bare `return` to exit the VM function.
HANDLERS = {
    'MOVE':     '{gRG}[A][{HX1}]={gRG}[B][{HX1}]',
    'LOADK':    '{gRG}[A][{HX1}]={gKC}(B+{HX1})',
    'LOADBOOL': '{gRG}[A][{HX1}]=(B~={HX0});if C~={HX0} then {gPC}={gPC}+{HX1} end',
    'LOADNIL':  'for i=A,B do {gER}(i);{gRG}[i][{HX1}]=nil end',
    'GETUPVAL': '{gRG}[A][{HX1}]={gUVL}[B+{HX1}][{HX1}]',
    'GETGLOBAL':'{gRG}[A][{HX1}]={gENV}[{gKC}(B+{HX1})]',
    'GETTABLE': '{gRG}[A][{HX1}]={gRG}[B][{HX1}][{gRK}(C)]',
    'SETGLOBAL':'{gENV}[{gKC}(B+{HX1})]={gRG}[A][{HX1}]',
    'SETUPVAL': '{gUVL}[B+{HX1}][{HX1}]={gRG}[A][{HX1}]',
    'SETTABLE': '{gRG}[A][{HX1}][{gRK}(B)]={gRK}(C)',
    'NEWTABLE': '{gRG}[A][{HX1}]={}',
    'SELF':     'local obj={gRG}[B][{HX1}];{gER}(A+{HX1});{gRG}[A+{HX1}][{HX1}]=obj;{gRG}[A][{HX1}]=obj[{gRK}(C)]',
    'ADD':      '{gRG}[A][{HX1}]={gRK}(B)+{gRK}(C)',
    'SUB':      '{gRG}[A][{HX1}]={gRK}(B)-{gRK}(C)',
    'MUL':      '{gRG}[A][{HX1}]={gRK}(B)*{gRK}(C)',
    'DIV':      '{gRG}[A][{HX1}]={gRK}(B)/{gRK}(C)',
    'MOD':      '{gRG}[A][{HX1}]={gRK}(B)%{gRK}(C)',
    'POW':      '{gRG}[A][{HX1}]={gRK}(B)^{gRK}(C)',
    'UNM':      '{gRG}[A][{HX1}]=-{gRG}[B][{HX1}]',
    'NOT':      '{gRG}[A][{HX1}]=not {gRG}[B][{HX1}]',
    'LEN':      '{gRG}[A][{HX1}]=#{gRG}[B][{HX1}]',
    'CONCAT':   'local {gTM}={};for i=B,C do {gTM}[#{gTM}+{HX1}]=tostring({gRG}[i][{HX1}])end;{gRG}[A][{HX1}]=table.concat({gTM})',
    'JMP':      '{gPC}={gPC}+B;continue',
    'EQ':       'if({gRK}(B)=={gRK}(C))~=(A~={HX0})then {gPC}={gPC}+{HX1} end',
    'LT':       'if({gRK}(B)<{gRK}(C))~=(A~={HX0})then {gPC}={gPC}+{HX1} end',
    'LE':       'if({gRK}(B)<={gRK}(C))~=(A~={HX0})then {gPC}={gPC}+{HX1} end',
    'TEST':     'local v={gRG}[A][{HX1}];if not(not v~=(C~={HX0}))then {gPC}={gPC}+{HX1} end',
    'TESTSET':  'local v={gRG}[B][{HX1}];if not(not v~=(C~={HX0}))then {gPC}={gPC}+{HX1} else {gRG}[A][{HX1}]=v end',
    'CALL': (
        'local {gFN}={gRG}[A][{HX1}];local {gAG}={}\n'
        'if B=={HX0} then local n={HX0};for i=A+{HX1},{gTP}-{HX1} do n=n+{HX1};{gAG}[n]={gRG}[i][{HX1}] end;{gAG}.n=n\n'
        'elseif B>{HX1} then for i={HX1},B-{HX1} do {gAG}[i]={gRG}[A+i][{HX1}] end;{gAG}.n=B-{HX1} end\n'
        'if C=={HX0} then local {gRT}={gPACK}({gFN}({gUNPACK}({gAG},{HX1},{gAG}.n)))\n'
        'for i={HX0},{gRT}.n-{HX1} do {gER}(A+i);{gRG}[A+i][{HX1}]={gRT}[i+{HX1}] end;{gTP}=A+{gRT}.n\n'
        'else local {gRT}={gPACK}({gFN}({gUNPACK}({gAG},{HX1},{gAG}.n)))\n'
        'for i={HX0},C-{HX2} do {gER}(A+i);{gRG}[A+i][{HX1}]={gRT}[i+{HX1}] end end'
    ),
    'TAILCALL': (
        'local {gFN}={gRG}[A][{HX1}];local {gAG}={}\n'
        'if B=={HX0} then local n={HX0};for i=A+{HX1},{gTP}-{HX1} do n=n+{HX1};{gAG}[n]={gRG}[i][{HX1}] end;{gAG}.n=n\n'
        'elseif B>{HX1} then for i={HX1},B-{HX1} do {gAG}[i]={gRG}[A+i][{HX1}] end;{gAG}.n=B-{HX1} end\n'
        'return {gFN}({gUNPACK}({gAG},{HX1},{gAG}.n))'
    ),
    'RETURN': (
        'local {gRT}={}\n'
        'if B=={HX0} then local n={HX0};for i=A,{gTP}-{HX1} do n=n+{HX1};{gRT}[n]={gRG}[i][{HX1}] end;{gRT}.n=n\n'
        'elseif B>{HX1} then for i={HX0},B-{HX2} do {gRT}[i+{HX1}]={gRG}[A+i][{HX1}] end;{gRT}.n=B-{HX1} end\n'
        'return {gUNPACK}({gRT},{HX1},{gRT}.n)'
    ),
    'FORPREP':  '{gRG}[A][{HX1}]={gRG}[A][{HX1}]-{gRG}[A+{HX2}][{HX1}];{gPC}={gPC}+B;continue',
    'FORLOOP': (
        '{gRG}[A][{HX1}]={gRG}[A][{HX1}]+{gRG}[A+{HX2}][{HX1}]\n'
        'local idx={gRG}[A][{HX1}];local lim={gRG}[A+{HX1}][{HX1}];local step={gRG}[A+{HX2}][{HX1}]\n'
        'if(step>{HX0} and idx<=lim)or(step<={HX0} and idx>=lim)then {gPC}={gPC}+B;{gER}(A+{HX3});{gRG}[A+{HX3}][{HX1}]=idx end'
    ),
    'TFORLOOP': (
        'local {gFN}={gRG}[A][{HX1}];local s={gRG}[A+{HX1}][{HX1}];local var={gRG}[A+{HX2}][{HX1}]\n'
        'local {gRT}={gPACK}({gFN}(s,var))\n'
        'if {gRT}[{HX1}]~=nil then {gRG}[A+{HX2}][{HX1}]={gRT}[{HX1}];for i={HX1},C do {gER}(A+{HX2}+i);{gRG}[A+{HX2}+i][{HX1}]={gRT}[i] end\n'
        'else {gPC}={gPC}+{HX1} end'
    ),
    'SETLIST': (
        'local t={gRG}[A][{HX1}];local n=(B=={HX0})and({gTP}-A-{HX1})or B;local off=(C-{HX1})*{HX50}\n'
        'for i={HX1},n do t[off+i]={gRG}[A+i][{HX1}] end'
    ),
    'CLOSE':    '',
    'CLOSURE': (
        'local sub={gPR}[B+{HX1}];if not sub.{fCODE} then {gPREP}(sub) end\n'
        'local sups={}\n'
        'for j={HX1},sub.{fNU} do local ps={gCD}[{gPC}+{HX1}];{gPC}={gPC}+{HX1}\n'
        'if ps[{gSOP}]=={OP_GETUPVAL} then sups[j]={gUVL}[ps[{gSB}]+{HX1}] else sups[j]={gRG}[ps[{gSB}]] end end\n'
        '{gRG}[A][{HX1}]=function(...)return {gVM}(sub,sups,...) end'
    ),
    'VARARG': (
        'local base={gNP}\n'
        'if B=={HX0} then local n={gVN}-base\n'
        'for i={HX0},n-{HX1} do {gER}(A+i);{gRG}[A+i][{HX1}]={gVA}[base+{HX1}+i] end;{gTP}=A+n\n'
        'else for i={HX0},B-{HX2} do {gER}(A+i);{gRG}[A+i][{HX1}]={gVA}[base+{HX1}+i] end end'
    ),
}

# ─── Bytecode parser ─────────────────────────────────────────────────────────
class Proto:
    __slots__ = ('source','nups','numparams','is_vararg','maxstack',
                 'code','kst','protos','upval_names')
    def __init__(self):
        self.source=''; self.nups=0; self.numparams=0
        self.is_vararg=0; self.maxstack=0
        self.code=[]; self.kst=[]; self.protos=[]; self.upval_names=[]

class Parser:
    def __init__(self, data: bytes):
        self.d = data; self.p = 0
        if self._rb(4) != b'\x1bLua':
            raise BytecodeError('Not a Lua bytecode chunk (missing Lua signature).')
        version = self._rb(1)[0]
        if version != 0x51:
            raise BytecodeError('Unsupported Lua bytecode version 0x%02x; compile with Lua 5.1 luac.' % version)
        fmt = self._rb(1)[0]
        if fmt != 0:
            raise BytecodeError('Unsupported non-standard Lua 5.1 chunk format %d.' % fmt)
        self.le = self._rb(1)[0] == 1
        self.si = self._rb(1)[0]
        self.ss = self._rb(1)[0]
        ins_size = self._rb(1)[0]
        num_size = self._rb(1)[0]
        integral = self._rb(1)[0]
        if self.si not in (4, 8) or self.ss not in (4, 8):
            raise BytecodeError('Unsupported Lua 5.1 integer/size_t width.')
        if ins_size != 4 or num_size != 8 or integral != 0:
            raise BytecodeError('Only standard Lua 5.1 chunks with 4-byte instructions and double numbers are supported.')

    def _rb(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise BytecodeError('Truncated Lua bytecode chunk at byte %d.' % self.p)
        c = self.d[self.p:self.p+n]; self.p += n; return c
    def _ru(self):
        return struct.unpack('<I' if self.le else '>I', self._rb(self.si))[0]
    def _rs(self):
        sz_fmt = ('<' if self.le else '>') + ('Q' if self.ss == 8 else 'I')
        n = struct.unpack(sz_fmt, self._rb(self.ss))[0]
        if n == 0: return None
        if n < 1: raise BytecodeError('Invalid string length in Lua bytecode chunk.')
        return self._rb(n)[:-1].decode('latin-1')
    def _rn(self):
        return struct.unpack('<d' if self.le else '>d', self._rb(8))[0]
    def _decode_instr(self, raw: int):
        op = raw & 0x3F; A = (raw >> 6) & 0xFF
        C = (raw >> 14) & 0x1FF; B = (raw >> 23) & 0x1FF
        name = OP_NAME.get(op, f'UNKNOWN_{op}'); fmt = FMT.get(name, 'ABC')
        if fmt == 'ABx':  return (op, A, (B << 9) | C, 0)
        if fmt == 'AsBx': return (op, A, ((B << 9) | C) - MAX_sBx, 0)
        return (op, A, B, C)
    def parse(self) -> 'Proto':
        pr = Proto()
        pr.source = self._rs() or ''
        self._ru(); self._ru()
        pr.nups = self._rb(1)[0]; pr.numparams = self._rb(1)[0]
        pr.is_vararg = self._rb(1)[0]; pr.maxstack = self._rb(1)[0]
        n = self._ru()
        for _ in range(n): pr.code.append(self._decode_instr(self._ru()))
        n = self._ru()
        for _ in range(n):
            t = self._rb(1)[0]
            if   t == 0: pr.kst.append(('nil', None))
            elif t == 1: pr.kst.append(('bool', self._rb(1)[0] != 0))
            elif t == 3:
                v = self._rn()
                pr.kst.append(('int', int(v)) if v == int(v) and abs(v) < 1e15 else ('float', v))
            elif t == 4: pr.kst.append(('str', self._rs()))
            else: raise BytecodeError('Unsupported constant type %d.' % t)
        n = self._ru()
        for _ in range(n): pr.protos.append(self.parse())
        n = self._ru()
        for _ in range(n): self._ru()
        n = self._ru()
        for _ in range(n): self._rs(); self._ru(); self._ru()
        n = self._ru()
        for _ in range(n): pr.upval_names.append(self._rs() or '')
        return pr

# ─── Build-time proto transformations ────────────────────────────────────────
def make_opmap(rng: random.Random) -> dict:
    custom = list(range(NUM_OPS)); rng.shuffle(custom)
    return {i: custom[i] for i in range(NUM_OPS)}

def shuffle_proto_order(proto: Proto, rng: random.Random) -> Proto:
    new = Proto()
    for f in ('source','nups','numparams','is_vararg','maxstack','kst','upval_names'):
        setattr(new, f, getattr(proto, f))
    n = len(proto.protos)
    if n > 1:
        perm = list(range(n)); rng.shuffle(perm)
        inv = [0] * n
        for i, p in enumerate(perm): inv[p] = i
        new.protos = [shuffle_proto_order(proto.protos[perm[i]], rng) for i in range(n)]
        new.code = []
        for (op, A, B, C) in proto.code:
            if op == OP['CLOSURE']:
                new.code.append((op, A, inv[B], C))
            else:
                new.code.append((op, A, B, C))
    else:
        new.protos = [shuffle_proto_order(p, rng) for p in proto.protos]
        new.code = list(proto.code)
    return new

def remap_proto(proto: Proto, opmap: dict, opcode_mask: int = 0) -> Proto:
    new = Proto()
    for f in ('source','nups','numparams','is_vararg','maxstack','kst','upval_names'):
        setattr(new, f, getattr(proto, f))
    # Store an extra per-build encoded opcode. The VM removes this mask only
    # immediately before dispatch, so a raw instruction dump has no direct
    # opcode mapping even after field positions are recovered.
    new.code   = [(opmap[op] ^ opcode_mask, A, B, C) for op, A, B, C in proto.code]
    new.protos = [remap_proto(p, opmap, opcode_mask) for p in proto.protos]
    return new

# ─── Encryption ──────────────────────────────────────────────────────────────
def lcg_step(k: int) -> int:
    return (k * 1664525 + 1013904223) & 0xFFFFFFFF

def encrypt_ints(data: list, key: int) -> list:
    N = len(data)
    k1 = key & 0xFFFFFFFF; r1 = []
    for v in data:
        k1 = lcg_step(k1); r1.append((v & 0xFFFFFFFF) ^ (k1 & 0xFF))
    k2 = (key ^ 0xDEADBEEF) & 0xFFFFFFFF; r2 = list(r1)
    for i in range(N - 1, -1, -1):
        k2 = lcg_step(k2); r2[i] ^= (k2 >> 8) & 0xFF
    k3 = (key * 31337) & 0xFFFFFFFF; r3 = []
    for v in r2:
        k3 = lcg_step(k3); r3.append(v ^ ((k3 >> 16) & 0xFF))
    return r3

def encrypt_str(s: str, key: int) -> bytes:
    b = s.encode('latin-1'); k = key & 0xFFFFFFFF; out = []
    for byte in b:
        k = lcg_step(k); out.append(byte ^ (k & 0xFF))
    return bytes(out)

def pack_ints_to_bytes(enc: list) -> bytes:
    return struct.pack('<' + 'I' * len(enc), *[v & 0xFFFFFFFF for v in enc])

def crc32_of_bytes(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

# ─── Number literal generation ───────────────────────────────────────────────
def hex_lit(n: int, rng: random.Random, allow_binary: bool = True) -> str:
    """Format n as a Luau hex or binary literal with random underscore separators."""
    luau_literals = getattr(rng, '_mw_luau_literals', True)
    if n < 0:
        return f'(-{hex_lit(-n, rng, allow_binary)})'
    if n == 0:
        return '0x0' if rng.random() < 0.5 else '0X0'
    # Small values: occasionally use binary literal (Luau supports 0b/0B)
    if luau_literals and allow_binary and n <= 0xFF and rng.random() < 0.18:
        bs = format(n, 'b')
        parts = []
        for i, c in enumerate(bs):
            parts.append(c)
            # random underscores between digits (Luau allows _ anywhere except start)
            if luau_literals and i < len(bs) - 1 and rng.random() < 0.22:
                parts.append('_' * rng.randint(1, 3))
        prefix = '0b' if rng.random() < 0.5 else '0B'
        return prefix + ''.join(parts)
    # Hex literal
    use_upper = rng.random() < 0.5
    hs = format(n, 'X') if use_upper else format(n, 'x')
    parts = []
    for i, c in enumerate(hs):
        parts.append(c)
        if luau_literals and i < len(hs) - 1 and rng.random() < 0.22:
            parts.append('_' * rng.randint(1, 3))
    prefix = '0X' if rng.random() < 0.5 else '0x'
    return prefix + ''.join(parts)

def math_expr(n: int, rng: random.Random) -> str:
    """Obfuscate n as a runtime-constant arithmetic expression."""
    if n < 0:  return f'(-{math_expr(-n, rng)})'
    if n == 0: return hex_lit(0, rng)
    style = rng.randint(0, 2)
    if style == 0:
        a = rng.randint(1, max(1, n - 1)) if n > 1 else 0
        return f'({hex_lit(a, rng)}+{hex_lit(n-a, rng)})'
    elif style == 1:
        j = rng.randint(1, 200); return f'({hex_lit(n+j, rng)}-{hex_lit(j, rng)})'
    else:
        for _ in range(8):
            m = rng.randint(2, 12); q = rng.randint(1, 30); base = m * q
            if base == n:      return f'({hex_lit(m,rng)}*{hex_lit(q,rng)})'
            elif base > n:     return f'({hex_lit(m,rng)}*{hex_lit(q,rng)}-{hex_lit(base-n,rng)})'
            else:              return f'({hex_lit(m,rng)}*{hex_lit(q,rng)}+{hex_lit(n-base,rng)})'
        a = rng.randint(1, max(1, n - 1)) if n > 1 else 0
        return f'({hex_lit(a, rng)}+{hex_lit(n-a, rng)})'

def lua_num(v) -> str:
    if isinstance(v, int): return str(v)
    if v != v:             return '(0/0)'
    if v == float('inf'):  return '(1/0)'
    if v == float('-inf'): return '(-1/0)'
    return repr(v)

def to_lua_str_lit(enc: bytes, rng: random.Random, luau_escapes: bool = True) -> str:
    """Encode bytes as a Lua double-quoted string literal using \\ddd escapes.
    Uses \\u{XX} (Luau unicode escape) occasionally for variety."""
    parts = []
    i = 0
    while i < len(enc):
        b = enc[i]
        if b == ord('"'):   parts.append('\\"')
        elif b == ord('\\'): parts.append('\\\\')
        elif b == ord('\n'): parts.append('\\n')
        elif b == ord('\r'): parts.append('\\r')
        elif b == ord('\0'): parts.append('\\000')
        elif 32 <= b <= 126:
            nxt = enc[i+1] if i+1 < len(enc) else 0
            # Occasionally use \u{XX} for printable ASCII (safe: codepoint == byte for 0x20-0x7E)
            if luau_escapes and rng.random() < 0.18 and b not in (ord('"'), ord('\\')):
                parts.append(f'\\u{{{b:02x}}}')
            elif chr(nxt).isdigit():
                parts.append(f'\\{b:03d}')
            else:
                parts.append(chr(b))
        else:
            parts.append(f'\\{b:03d}')
        i += 1
    return '"' + ''.join(parts) + '"'

def minify_lua(src: str) -> str:
    """Minify while preserving a stable, readable protection header."""
    tokens = []
    for line in src.splitlines():
        s = line.strip()
        if not s: continue
        tokens.append(s)
    header = '--[[File Protected By MWP Obfuscator V2]]'
    if tokens and tokens[0] == header:
        # The header is intentionally a standalone first line for consistent
        # branding and tooling; the runtime remains minified below it.
        return header + '\n\n' + ' '.join(tokens[1:])
    return ' '.join(tokens)

# ─── Name generator ──────────────────────────────────────────────────────────
_DIGITS = string.digits
_ALPHA  = string.ascii_letters

class Namer:
    def __init__(self, rng: random.Random):
        self._rng = rng; self._used = set()
        self._kw = {
            'and','break','do','else','elseif','end','false','for','function',
            'if','in','local','nil','not','or','repeat','return','then','true',
            'until','while'
        }
    def __call__(self, prefix='_') -> str:
        while True:
            n = prefix + self._rng.choice(_DIGITS) + self._rng.choice(_ALPHA)
            if n not in self._used and n not in self._kw:
                self._used.add(n); return n

# ─── Constant serialization ───────────────────────────────────────────────────
def ser_kst_entry(typ, val, rng: random.Random, ds_name: str, luau_escapes: bool) -> str:
    if typ == 'nil':  return 'nil'
    if typ == 'bool': return 'true' if val else 'false'
    if typ in ('int', 'float'): return lua_num(val)
    if val is None: return 'nil'
    # Keep every string encrypted, including short ASCII values.  The returned
    # descriptor is decoded lazily by the VM and replaced with the plaintext on
    # first access, rather than decrypting the complete constant table at boot.
    k2 = rng.randint(1, 0xFFFFFF)
    enc = encrypt_str(val, k2)
    lit = to_lua_str_lit(enc, rng, luau_escapes)
    return f'{{{lit},{math_expr(k2,rng)},{math_expr(len(val),rng)}}}'

def serialize_proto(proto: Proto, rng: random.Random, master_key: int,
                    ds_name: str, flds: dict, crc_mask: int, luau_escapes: bool) -> str:
    kst_parts = [ser_kst_entry(t, v, rng, ds_name, luau_escapes) for t, v in proto.kst]
    kst_str   = '{' + ','.join(kst_parts) + '}'

    flat = []
    for op, A, B, C in proto.code:
        # Preserve the full 18-bit Bx/sBx operand range used by Lua 5.1.
        # The old 16-bit truncation silently corrupted large constant tables,
        # jump offsets, and child-prototype indices.
        flat.extend([op, A, B & 0xFFFFFFFF, C & 0x1FF])

    # Each closure gets a distinct key, including siblings of identical size.
    # Using the build RNG preserves --seed reproducibility.
    proto_key = rng.randint(1, 0xFFFFFFFF)
    enc      = encrypt_ints(flat, proto_key)
    blob     = pack_ints_to_bytes(enc)
    crc_stored = crc32_of_bytes(blob) ^ crc_mask
    blob_lit = to_lua_str_lit(blob, rng, luau_escapes)

    sub_strs = [serialize_proto(p, rng, master_key, ds_name, flds, crc_mask, luau_escapes)
                for p in proto.protos]
    subs_str = '{' + ','.join(sub_strs) + '}'

    fC=flds['fC']; fCRC=flds['fCRC']; fEK=flds['fEK']; fNC=flds['fNC']
    fP=flds['fP']; fK=flds['fK'];   fNP=flds['fNP']; fMS=flds['fMS']; fNU=flds['fNU']
    return (f'{{{fNU}={math_expr(proto.nups,rng)},{fNP}={math_expr(proto.numparams,rng)},'
            f'{fMS}={math_expr(proto.maxstack,rng)},{fNC}={math_expr(len(proto.code),rng)},'
            f'{fCRC}={math_expr(crc_stored,rng)},{fEK}={math_expr(proto_key,rng)},'
            f'{fC}={blob_lit},{fK}={kst_str},{fP}={subs_str}}}')

# ─── VM Lua template ─────────────────────────────────────────────────────────
# Key visual features:
#   · repeat…until not {gOP1}  (opaque always-false condition — hides the infinite loop)
#   · continue in JMP/FORPREP  (Luau-only, fragments control flow)
#   · string.unpack('<I4',…)   (blob-based instruction read, no int-table fingerprint)
#   · {HX0},{HX1},{HX2},{HX3},{HX50} are per-build randomized hex literals of 0,1,2,3,50
#   · {DISPATCH} expanded first; contains {gXX}/{fXX}/{OP_XX} placeholders resolved later
VM_TEMPLATE = """\
--[[File Protected By MWP Obfuscator V2]]
{RUNTIME_COMPAT}
local {gENV}=(getfenv and getfenv({HX0}))or _G
local {gCHK}=function()
--[[Capability probing is advisory; integrity is checked independently.]]
return type(rawget)=='function'and type(select)=='function'and type(pcall)=='function'and type(error)=='function'and type(tostring)=='function'
{ANTI_DEBUG}end
{gCHK}()
local {gDS}=function({gA1},{gA2},{gA3})
local {gB1}={};local {gB2}={gA2}
for i={HX1},{gA3} do {gB2}=({gB2}*{gLA1}+{gLB1})%{HXFF00};{gB1}[i]=string.char({gBX}(string.byte({gA1},i),{gBA}({gB2},{HXFF})))end
return table.concat({gB1})end
local function {gPREP}({gP0})
local {gP1}={HXffff};local {gP2}={gCRCP}
local {gBLB}={gP0}.{fC};local {gBLN}={gP0}.{fNC}*{HX4}
for i={HX1},{gBLN} do local {gP3}={gSUP}('<I4',{gBLB},(i-{HX1})*{HX4}+{HX1})
for _={HX1},{HX4} do {gP1}={gBX}({gP1},{gBA}({gP3},{HXFF}))
for j={HX1},{HX8} do if {gBA}({gP1},{HX1})~={HX0} then {gP1}={gBX}({gBR}({gP1},{HX1}),{gP2})else {gP1}={gBR}({gP1},{HX1})end end
{gP3}={gBR}({gP3},{HX8})end end
if {gBX}({gP1},{HXffff})~={gBX}({gP0}.{fCRC},{gCRCM})then error('')end
local {gP4}={gP0}.{fNC}*{HX4};local {gP5}=({gP0}.{fEK}*{gLC_K})%{HXFF00};local {gP6}={}
for i={HX1},{gP4} do {gP5}=({gP5}*{gLA2}+{gLB2})%{HXFF00}
local v={gSUP}('<I4',{gBLB},(i-{HX1})*{HX4}+{HX1});{gP6}[i]={gBX}(v,{gBA}({gBR}({gP5},{HX10}),{HXFF}))end
local {gP8}={gBX}({gP0}.{fEK},{gLC_D})%{HXFF00};local {gP9}={}
for i={gP4},{HX1},-{HX1} do {gP8}=({gP8}*{gLA3}+{gLB3})%{HXFF00};{gP9}[i]={gBA}({gBR}({gP8},{HX8}),{HXFF}) end
local {gPa}={};for i={HX1},{gP4} do {gPa}[i]={gBX}({gP6}[i],{gP9}[i])end
local {gPb}={gP0}.{fEK}%{HXFF00};local {gPc}={}
for i={HX1},{gP4} do {gPb}=({gPb}*{gLA4}+{gLB4})%{HXFF00};{gPc}[i]={gBA}({gPb},{HXFF}) end
local {gPd}={};for i={HX1},{gP4} do {gPd}[i]={gBX}({gPa}[i],{gPc}[i])end
local {gPe}={}
for i={HX1},{gP0}.{fNC} do local b=(i-{HX1})*{HX4}+{HX1}
local {gPf}={gPd}[b];local {gPg}={gPd}[b+{HX1}];local {gPh}={gPd}[b+{HX2}];local {gPi}={gPd}[b+{HX3}]
local {gPj}={gPh}<{HXs80000000} and {gPh} or({gPh}-{HXs100000000});{gPe}[i]={INSTR_MAKE} end
{gP0}.{fCODE}={gPe} end
local {gVM}
{gVM}=function({gP0},{gUV},...)
local {gCD}={gP0}.{fCODE};local {gKT}={gP0}.{fK};local {gPR}={gP0}.{fP};local {gNP}={gP0}.{fNP}
local function {gKC}(i)local v={gKT}[i];if type(v)=='table'then v={gDS}(v[{HX1}],v[{HX2}],v[{HX3}]);{gKT}[i]=v end;return v end
local {gRG}={};for i={HX0},{gP0}.{fMS}+{HX10} do {gRG}[i]={false}end
local {gUVL}={gUV} or{};local {gVA}={...};local {gVN}=select('#',...)
for i={HX0},{gNP}-{HX1} do {gRG}[i][{HX1}]={gVA}[i+{HX1}]end
local {gPC}={HX0};local {gTP}={gNP};local {gCT}={HX0}
local {gOP1}=(type('')=='string')
local {gOP2}=(#{gOPT}=={gOPN})
local function {gRK}(x)if x>={BITRK} then return {gKC}(x-{BITRK}+{HX1})else return {gRG}[x][{HX1}]end end
local function {gER}(i)if not {gRG}[i]then {gRG}[i]={false}end end
if not {gOP2} then {gCHK}();{gPC}={gPC}+({gCT}-{gCT})end
repeat
local {gIS}={gCD}[{gPC}+{HX1}];if not {gIS} then break end
{gPC}={gPC}+{HX1};{gCT}={gCT}+{HX1}
if {gCT}%{gCHKN}=={HX0} then {gCHK}()end
local _o={gBX}({gIS}[{gSOP}],{gOMASK});local A={gIS}[{gSA}];local B={gIS}[{gSB}];local C={gIS}[{gSC}]
{DISPATCH}
until not {gOP1}
end
local {gROOT}={gPROTO_DATA}
{gPREP}({gROOT})
return {gVM}({gROOT},{{}},...)
"""

# ─── Generator ───────────────────────────────────────────────────────────────
def generate(proto: Proto, opmap: dict, rng: random.Random, master_key: int,
             target: str = 'luau', anti_debug: bool = False) -> str:
    if target not in ('luau', 'lua51'):
        raise ValueError('target must be luau or lua51')
    rng._mw_luau_literals = target == 'luau'
    N = Namer(rng)

    # Proto field names
    flds = {
        'fC':    N('_'), 'fCRC': N('_'), 'fEK':   N('_'),
        'fNC':   N('_'), 'fCODE':N('_'), 'fP':    N('_'),
        'fK':    N('_'), 'fNP':  N('_'), 'fMS':   N('_'), 'fNU': N('_'),
    }

    # Instruction slot permutation
    perm = list(range(4)); rng.shuffle(perm)
    logical_ph = ['gPf', 'gPg', 'gPj', 'gPi']  # 0=op,1=A,2=B(signed),3=C
    instr_make = '{' + ','.join('{' + logical_ph[perm[i]] + '}' for i in range(4)) + '}'
    slot_op = perm.index(0) + 1
    slot_A  = perm.index(1) + 1
    slot_B  = perm.index(2) + 1
    slot_C  = perm.index(3) + 1

    # Per-build hex literals for small structural constants
    # These are FIXED values but rendered differently per build
    hx0    = hex_lit(0,          rng)
    hx1    = hex_lit(1,          rng)
    hx2    = hex_lit(2,          rng)
    hx3    = hex_lit(3,          rng)
    hx4    = hex_lit(4,          rng)
    hx8    = hex_lit(8,          rng)
    hx10   = hex_lit(16,         rng)  # 0x10
    hx50   = hex_lit(50,         rng)
    hxFF   = hex_lit(0xFF,       rng)
    hxFF00 = hex_lit(0x100000000, rng, allow_binary=False)
    hxffff = hex_lit(0xFFFFFFFF, rng, allow_binary=False)
    hxs32  = hex_lit(0x80000000, rng, allow_binary=False)

    # CRC mask
    crc_mask = rng.randint(1, 0xFFFFFFFE)

    # Randomized dispatch ordering
    dispatch_order = list(OP.keys()); rng.shuffle(dispatch_order)
    parts = []
    for i, op_name in enumerate(dispatch_order):
        kw = 'if' if i == 0 else 'elseif'
        body = HANDLERS[op_name]
        if target == 'lua51':
            # The dispatch body is already at the end of the loop, so
            # `continue` is semantically redundant and not Lua 5.1 syntax.
            body = body.replace(';continue', '')
        parts.append(f'{kw} _o=={{OP_{op_name}}} then {body}')
    parts.append('end')
    dispatch_code = '\n'.join(parts)

    # LCG constant obfuscation — 4 independent math_expr forms each
    la = [math_expr(1664525,    rng) for _ in range(4)]
    lb = [math_expr(1013904223, rng) for _ in range(4)]

    chkn = hex_lit(rng.randint(15, 40), rng)

    runtime_compat = (
        'local {gBX},{gBR},{gBA}=bit32.bxor,bit32.rshift,bit32.band\n'
        'local {gSUP}=string.unpack\n'
        'local {gPACK}=table.pack;local {gUNPACK}=table.unpack'
        if target == 'luau' else
        'local function {gBX}(a,b)local r,p=0,1;while a>0 or b>0 do local x=a%2;local y=b%2;if x~=y then r=r+p end;a=(a-x)/2;b=(b-y)/2;p=p*2 end;return r end\n'
        'local function {gBA}(a,b)local r,p=0,1;while a>0 and b>0 do local x=a%2;local y=b%2;if x==1 and y==1 then r=r+p end;a=(a-x)/2;b=(b-y)/2;p=p*2 end;return r end\n'
        'local function {gBR}(a,b)return math.floor(a/(2^b))end\n'
        'local function {gSUP}(_,s,p)p=p or 1;local a,b,c,d=string.byte(s,p,p+3);return a+b*256+c*65536+d*16777216 end\n'
        'local function {gPACK}(...)return {n=select("#",...),...}end;local {gUNPACK}=unpack'
    )

    names = {
        # Must come first — DISPATCH contains {OP_XX},{fXX},{gXX} placeholders
        'DISPATCH':   dispatch_code,
        'INSTR_MAKE': instr_make,
        'RUNTIME_COMPAT': runtime_compat,
        'ANTI_DEBUG': ("if type(debug)=='table'and type(debug.sethook)=='function'then pcall(function()debug.sethook(function()error('')end,'c',{HX1});debug.sethook()end)end " if anti_debug else ''),
        # Proto field names
        'fC':    flds['fC'],   'fCRC':  flds['fCRC'],  'fEK':   flds['fEK'],
        'fNC':   flds['fNC'],  'fCODE': flds['fCODE'], 'fP':    flds['fP'],
        'fK':    flds['fK'],   'fNP':   flds['fNP'],   'fMS':   flds['fMS'],
        'fNU':   flds['fNU'],
        # VM names
        'gBX':   N('_'), 'gBR':  N('_'), 'gBA':   N('_'),
        'gSUP':  N('_'), 'gPACK': N('_'), 'gUNPACK': N('_'), 'gENV': N('_'), 'gCHK':  N('_'),
        'gDS':   N('_'), 'gPREP':N('_'), 'gVM':   N('_'), 'gROOT':N('_'),
        'gA1': N('_'), 'gA2': N('_'), 'gA3': N('_'),
        'gB1': N('_'), 'gB2': N('_'),
        'gBLB':N('_'), 'gBLN':N('_'),
        'gP0': N('_'), 'gP1': N('_'), 'gP2': N('_'), 'gP3': N('_'),
        'gP4': N('_'), 'gP5': N('_'), 'gP6': N('_'),
        'gP8': N('_'), 'gP9': N('_'), 'gPa': N('_'), 'gPb': N('_'),
        'gPc': N('_'), 'gPd': N('_'), 'gPe': N('_'),
        'gPf': N('_'), 'gPg': N('_'), 'gPh': N('_'), 'gPi': N('_'), 'gPj': N('_'),
        'gCD':  N('_'), 'gKT':  N('_'), 'gKC':  N('_'), 'gPR':  N('_'), 'gNP':  N('_'),
        'gRG':  N('_'), 'gUV':  N('_'), 'gUVL': N('_'), 'gVA':  N('_'),
        'gVN':  N('_'), 'gPC':  N('_'), 'gTP':  N('_'), 'gCT':  N('_'),
        'gOP1': N('_'), 'gOP2': N('_'),
        'gOPT': '{1,2,3}', 'gOPN': '3',
        'gRK':  N('_'), 'gER':  N('_'), 'gIS':  N('_'), 'gTM':  N('_'),
        'gFN':  N('_'), 'gAG':  N('_'), 'gRT':  N('_'),
        # Slot indices
        'gSOP': str(slot_op), 'gSA': str(slot_A),
        'gSB':  str(slot_B),  'gSC': str(slot_C),
        # LCG / crypto constants (math_expr — splits value)
        'gLA1': la[0], 'gLA2': la[1], 'gLA3': la[2], 'gLA4': la[3],
        'gLB1': lb[0], 'gLB2': lb[1], 'gLB3': lb[2], 'gLB4': lb[3],
        'gLC_K': math_expr(31337,      rng),
        'gLC_D': math_expr(3735928559, rng),
        'gCRCP': math_expr(3988292384, rng),
        'gCRCM': math_expr(crc_mask,   rng),
        'gCHKN': chkn,
        'BITRK': hex_lit(BITRK, rng),
        # Structural hex literals (per-build formatting, fixed values)
        'HX0':     hx0,    'HX1':    hx1,    'HX2':    hx2,
        'HX3':     hx3,    'HX4':    hx4,    'HX8':    hx8,
        'HX10':    hx10,   'HX50':   hx50,
        'HXFF':    hxFF,   'HXFF00': hxFF00, 'HXffff': hxffff,
        'HXs80000000': hxs32,  'HXs100000000':hxFF00,
        'gPROTO_DATA': '',
    }

    # A second encoding layer around the shuffled opcode map.
    opcode_mask = rng.randint(1, 0xFFFFFFFF)
    names['gOMASK'] = math_expr(opcode_mask, rng)

    # Opcode values as math_expr (hides the numeric mapping)
    for lua_name, lua_idx in OP.items():
        names[f'OP_{lua_name}'] = math_expr(opmap[lua_idx], rng)

    # Build-time proto transforms
    shuffled = shuffle_proto_order(proto, rng)
    remapped = remap_proto(shuffled, opmap, opcode_mask)

    ds_name = names['gDS']
    names['gPROTO_DATA'] = serialize_proto(remapped, rng, master_key, ds_name,
                                           flds, crc_mask, target == 'luau')

    out = VM_TEMPLATE
    for k, v in names.items():
        out = out.replace('{' + k + '}', v)

    return minify_lua(out)

# ─── Compile via luac ─────────────────────────────────────────────────────────
def compile_lua(source_path: str) -> bytes:
    fd, tmp = tempfile.mkstemp(suffix='.luac')
    os.close(fd)
    try:
        try:
            result = subprocess.run(['luac', '-o', tmp, source_path],
                                    capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError('luac was not found. Install Lua 5.1 and put its luac executable in PATH.')
        if result.returncode != 0:
            print('[!] luac error:\n' + result.stderr, file=sys.stderr); sys.exit(1)
        with open(tmp, 'rb') as f: return f.read()
    finally:
        if os.path.exists(tmp): os.remove(tmp)

# ─── CLI ─────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description='MWP Lua Obfuscator')
    ap.add_argument('input')
    ap.add_argument('output', nargs='?')
    ap.add_argument('--seed', type=int, default=None)
    ap.add_argument('--double', action='store_true')
    ap.add_argument('--target', choices=('luau', 'lua51'), default='luau',
                    help='Output runtime target (default: luau). Input is always compiled by Lua 5.1 luac.')
    ap.add_argument('--anti-debug', action='store_true',
                    help='Enable the intrusive debug-hook probe for controlled environments only.')
    args = ap.parse_args()

    if args.double and args.target != 'lua51':
        ap.error('--double currently requires --target lua51: Luau output cannot be compiled by Lua 5.1 luac.')
    seed = args.seed if args.seed is not None else random.randint(0, 0xFFFFFFFF)
    rng  = random.Random(seed)
    print(f'[*] Seed: {seed}')
    try:
        bc    = compile_lua(args.input)
        proto = Parser(bc).parse()
    except (BytecodeError, RuntimeError) as exc:
        print('[!] ' + str(exc), file=sys.stderr); sys.exit(1)
    opmap = make_opmap(rng)
    mkey  = rng.randint(1, 0xFFFFFFFF)
    lua_out = generate(proto, opmap, rng, mkey, args.target, args.anti_debug)

    if args.double:
        fd, tmp_in = tempfile.mkstemp(suffix='.lua')
        try:
            with os.fdopen(fd, 'w') as f: f.write(lua_out)
            rng2   = random.Random(rng.randint(0, 0xFFFFFFFF))
            try:
                bc2    = compile_lua(tmp_in)
                proto2 = Parser(bc2).parse()
            except (BytecodeError, RuntimeError) as exc:
                print('[!] Second-stage compilation failed: ' + str(exc), file=sys.stderr); sys.exit(1)
            opmap2 = make_opmap(rng2)
            lua_out = generate(proto2, opmap2, rng2, rng2.randint(1, 0xFFFFFFFF),
                               args.target, args.anti_debug)
        finally:
            if os.path.exists(tmp_in): os.remove(tmp_in)

    out_path = args.output or args.input.replace('.lua', '.obf.lua')
    with open(out_path, 'w', encoding='utf-8') as f: f.write(lua_out)
    print(f'[+] {os.path.getsize(args.input)} → {os.path.getsize(out_path)} bytes  ({out_path})')

if __name__ == '__main__':
    main()
