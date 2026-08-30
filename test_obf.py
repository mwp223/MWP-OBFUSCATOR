"""Regression and differential tests for the LuaVM obfuscator.

Run with: python -m unittest test_obf.py
The end-to-end test is skipped unless both `lua` and a Lua 5.1 `luac` are on PATH.
"""
import os
import random
import re
import shutil
import subprocess
import tempfile
import unittest

from gen_sample import make_bytecode
from obf import (BytecodeError, Parser, Proto, make_opmap, generate,
                 serialize_proto, ser_kst_entry, crc32_of_bytes)


class ObfuscatorUnitTests(unittest.TestCase):
    def sample_proto(self):
        return Parser(make_bytecode()).parse()

    def test_lua51_runtime_avoids_luau_syntax(self):
        rng = random.Random(7)
        output = generate(self.sample_proto(), make_opmap(rng), rng, 1, 'lua51')
        self.assertNotIn('continue', output)
        self.assertNotIn('string.unpack', output)
        self.assertNotIn('table.pack', output)
        self.assertNotRegex(output, r'0[bB][01_]+')
        self.assertNotIn(r'\u{', output)
        self.assertTrue(output.startswith('--[[File Protected By MWP Obfuscator V2]]\n\n'))
        self.assertNotRegex(output.split('\n\n', 1)[1], r'--(?!\[\[)',
                            'Minified output must not contain line comments.')

    def test_non_ascii_short_string_is_encrypted(self):
        literal = ser_kst_entry('str', '\xff', random.Random(3), 'decode', False)
        self.assertTrue(literal.startswith('{'))
        self.assertNotIn('ÿ', literal)

    def test_ascii_short_string_is_lazy_encrypted_too(self):
        literal = ser_kst_entry('str', 'ok', random.Random(3), 'decode', False)
        self.assertTrue(literal.startswith('{'))
        self.assertNotIn("'ok'", literal)

    def test_prototypes_receive_distinct_keys(self):
        root = Proto(); root.code = []; root.kst = []; root.protos = [Proto(), Proto()]
        for child in root.protos:
            child.code = []; child.kst = []; child.protos = []
        fields = {name: name for name in ('fC','fCRC','fEK','fNC','fP','fK','fNP','fMS','fNU')}
        text = serialize_proto(root, random.Random(5), 1, 'decode', fields, 9, False)
        keys = re.findall(r'fEK=([^,}]+)', text)
        self.assertEqual(len(keys), 3)
        self.assertEqual(len(set(keys)), 3)

    def test_malformed_chunk_has_actionable_error(self):
        with self.assertRaisesRegex(BytecodeError, 'signature'):
            Parser(b'not lua')

    def test_runtime_crc_algorithm_matches_serialized_blob_crc(self):
        data = bytes(range(64))
        value = 0xFFFFFFFF
        for byte in data:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        self.assertEqual((value ^ 0xFFFFFFFF) & 0xFFFFFFFF, crc32_of_bytes(data))


class DifferentialLua51Tests(unittest.TestCase):
    SOURCE = r'''
local function collect(...)
  local out = {...}; return #out, out[1], out[#out]
end
local function make_adder(n)
  return function(x) return n + x end
end
local obj = setmetatable({v = 4}, {__add = function(a, b) return a.v + b.v end})
local sum = 0
for i = 1, 4 do sum = sum + make_adder(i)(i) end
for _, v in ipairs({2, 3, 5}) do sum = sum + v end
local n, first, last = collect('é', nil, 'z')
print(sum, n, first, last, obj + obj)
return sum, n, first, last
'''

    @classmethod
    def setUpClass(cls):
        cls.lua = shutil.which('lua')
        cls.luac = shutil.which('luac')
        if not cls.lua or not cls.luac:
            raise unittest.SkipTest('lua and luac are required for differential execution')
        version = subprocess.run([cls.luac, '-v'], capture_output=True, text=True).stdout + \
                  subprocess.run([cls.luac, '-v'], capture_output=True, text=True).stderr
        if '5.1' not in version:
            raise unittest.SkipTest('differential execution requires Lua 5.1 luac')

    def test_obfuscated_lua51_matches_original(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, 'source.lua')
            output = os.path.join(directory, 'output.lua')
            with open(source, 'w', encoding='utf-8') as handle:
                handle.write(self.SOURCE)
            original = subprocess.run([self.lua, source], capture_output=True, text=True, check=True)
            subprocess.run(['python', os.path.join(os.path.dirname(__file__), 'obf.py'), source, output,
                            '--target', 'lua51', '--seed', '42'], capture_output=True, text=True, check=True)
            protected = subprocess.run([self.lua, output], capture_output=True, text=True, check=True)
            self.assertEqual(protected.stdout, original.stdout)
            self.assertEqual(protected.stderr, original.stderr)


if __name__ == '__main__':
    unittest.main()
