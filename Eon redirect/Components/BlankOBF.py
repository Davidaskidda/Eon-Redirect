#!/usr/bin/env python3
# Original by: https://github.com/Blank-c/BlankOBF
# Modified & Cleaned for clarity

import os
import sys
import base64
import codecs
import random
import argparse

from textwrap import wrap
from lzma import compress
from marshal import dumps


def printerr(msg):
    print(msg, file=sys.stderr)


class BlankOBF:
    def __init__(self, code: str, output_path: str):
        self.original_code = code.encode()
        self.output_path = output_path
        self.var_length = 3
        self.var_names = {}

        self.stage_marshal()
        self.stage_encrypt1()
        self.stage_encrypt2()
        # self.stage_encrypt3()  # Optional: Increases detection
        self.write_output()

    def _generate_var(self, name: str) -> str:
        if name not in self.var_names:
            self.var_names[name] = "_" + "_" * self.var_length
            self.var_length += 1
        return self.var_names[name]

    def _encrypt_string(self, s: str, conf: dict = None, attr_chain=False) -> str:
        conf = conf or {}
        imp = conf.get("__import__", "__import__")
        gattr = conf.get("getattr", "getattr")
        bts = conf.get("bytes", "bytes")
        evl = conf.get("eval", "eval")

        if not attr_chain:
            b64_bytes = list(base64.b64encode(s.encode()))
            return f'{gattr}({imp}({bts}(b"base64").decode()), {bts}(b"b64decode").decode())({bts}({b64_bytes})).decode()'

        parts = s.split(".")
        root = self._encrypt_string(parts[0], conf)
        for part in parts[1:]:
            root = f'{gattr}({evl}({root}), {self._encrypt_string(part, conf)})'
        return root

    def stage_marshal(self):
        self.original_code = dumps(compile(self.original_code, "<string>", "exec"))

    def stage_encrypt1(self):
        code = base64.b64encode(self.original_code).decode()
        parts = wrap(code, len(code) // 4)
        vars_ = [self._generate_var(name) for name in "abcd"]

        lines = [
            f'{vars_[0]} = "{codecs.encode(parts[0], "rot13")}"',
            f'{vars_[1]} = "{parts[1]}"',
            f'{vars_[2]} = "{parts[2][::-1]}"',
            f'{vars_[3]} = "{parts[3]}"'
        ]
        random.shuffle(lines)
        joined = ";".join(lines)

        rot13_encoded = base64.b64encode(b'rot13').decode()

        self.original_code = f'''
# Obfuscated using https://github.com/Blank-c/BlankOBF
{joined};
__import__({self._encrypt_string("builtins")}).exec(
    __import__({self._encrypt_string("marshal")}).loads(
        __import__({self._encrypt_string("base64")}).b64decode(
            __import__({self._encrypt_string("codecs")}).decode(
                {vars_[0]},
                __import__({self._encrypt_string("base64")}).b64decode("{rot13_encoded}").decode()
            ) + {vars_[1]} + {vars_[2]}[::-1] + {vars_[3]}
        )
    )
)
'''.strip().encode()

    def stage_encrypt2(self):
        compressed_code = compress(self.original_code)
        var_names = [self._generate_var(ch) for ch in "efghijklmn"]
        conf = {
            "eval": var_names[2],
            "getattr": var_names[3],
            "__import__": var_names[7],
            "bytes": var_names[8]
        }
        encrypt = lambda s, chain=False: self._encrypt_string(s, conf, chain)

        self.original_code = f'''# Obfuscated using https://github.com/Blank-c/BlankOBF
{var_names[2]} = eval({self._encrypt_string("eval")})
{var_names[3]} = {var_names[2]}({self._encrypt_string("getattr")})
{var_names[7]} = {var_names[2]}({self._encrypt_string("__import__")})
{var_names[8]} = {var_names[2]}({self._encrypt_string("bytes")})
{var_names[4]} = lambda {var_names[6]}: {var_names[2]}({encrypt("compile")})({var_names[6]}, {encrypt("<string>")}, {encrypt("exec")})
{var_names[0]} = {compressed_code}
{var_names[1]} = {encrypt('__import__("builtins").list', True)}({var_names[0]})
try:
    {encrypt('__import__("builtins").exec', True)}({var_names[4]}({encrypt('__import__("lzma").decompress', True)}({var_names[8]}({var_names[1]})))) or {encrypt('__import__("os")._exit', True)}(0)
except {encrypt('__import__("lzma").LZMAError', True)}: ...
'''.strip().encode()

    def stage_encrypt3(self):
        compressed = compress(self.original_code)
        encoded = base64.b64encode(compressed)
        self.original_code = f'# Obfuscated using https://github.com/Blank-c/BlankOBF\n\nimport base64, lzma; exec(compile(lzma.decompress(base64.b64decode({encoded})), "<string>", "exec"))'.encode()

    def write_output(self):
        output_dir = os.path.dirname(self.output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(self.output_path, "w", encoding="utf-8") as f:
            f.write(self.original_code.decode())


def main():
    parser = argparse.ArgumentParser(
        description="Obfuscates Python code to make it harder to reverse"
    )
    parser.add_argument("FILE", help="Path to the Python file to obfuscate")
    parser.add_argument("-o", dest="output", help='Output file path (default: "Obfuscated_<FILE>.py")')
    args = parser.parse_args()

    if not os.path.isfile(args.FILE):
        printerr(f"No such file: {args.FILE}")
        sys.exit(1)
    if not args.FILE.endswith((".py", ".pyw")):
        printerr("The file must have a valid .py or .pyw extension.")
        sys.exit(1)

    with open(args.FILE, "r", encoding="utf-8") as f:
        code = f.read()

    output_path = args.output or f"Obfuscated_{os.path.basename(args.FILE)}"
    BlankOBF(code, output_path)


if __name__ == "__main__":
    main()
