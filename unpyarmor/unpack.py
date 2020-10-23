# Deobfuscation / unpacking code

import marshal
import struct
import sys
from io import BytesIO

import dis

from .crypto import *

def parse_key(keyi):
    # Decrypt the pytransform.key to the RSA public key
    r = BytesIO(keyi)
    key0_len = struct.unpack("<H", r.read(2))[0]
    key1_len = struct.unpack("<H", r.read(2))[0]
    r.seek(16)
    key0 = r.read(key0_len)
    key1 = r.read(key1_len)
    # decrypt the first part
    keyinp = des3_decrypt(key0[:24], key0[24:32], key0[32:])
    keyinp = decode_buffer(keyinp)
    key, iv = derive_keys(keyinp)[0]
    # decrypt the second part
    decrsa = des3_decrypt(key, iv, key1)
    decrsa = decode_buffer(decrsa)
    return decrsa

def restore_codeobj(enc_co, pubkey):
    # Unwrap the obfuscated code object (from bytes)
    key, iv = derive_keys(pubkey)[0]
    deccode = des3_decrypt(key, iv, enc_co)
    deccode = decode_buffer(deccode)
    co = marshal.loads(deccode)
    return co

JUMP_OPCODES = [111, 112, 113, 114, 115, 119]

def fix_code(code, stub_size):
    # replace jump to stub with return
    code = code[:-2] + b"S\x00" # RETURN_VALUE
    # fix absolute jumps
    extend = None
    code = bytearray(code)
    for i in range(0, len(code), 2):
        op = code[i]
        arg = code[i+1]
        if op == 144:
            extend = arg << 8
            continue
        if op in JUMP_OPCODES:
            if extend is not None:
                arg |= extend
                arg -= stub_size
                code[i+1] = arg & 0xff
                code[i-1] = arg >> 8
            else:
                arg -= stub_size
                code[i+1] = arg
        extend = None
    return bytes(code)

def decrypt_code_wrap(code, flags, pubkey):
    # Decrypt code with wrap enabled
    keys = derive_keys(pubkey)
    # remove stub (different versions have different size stubs,
    # these are actually hardcoded into pyarmor)
    if sys.hexversion < 0x3080000: # 3.7
        sbeg, send = 16, 16
    elif sys.hexversion < 0x3090000: # 3.8
        sbeg, send = 32, 16
    else:
        print("Strange python version {}?".format(hex(sys.hexversion)))
    enc = code[sbeg:-send]
    if flags & 0x40000000: # obf_code == 1
        code = xor_decrypt(keys[2][0], enc)
        code = fix_code(code, sbeg)
    elif flags & 0x8000000: # obf_code == 2
        code = des3_decrypt(keys[0][0], keys[0][1], enc)
        code = fix_code(code, sbeg)
    return code

def decrypt_code_jump(code, flags, pubkey):
    # Decrypt code with wrap disabled
    keys = derive_keys(pubkey)
    # Calculate the start offset
    code_start = 0
    for i in range(0, len(code), 2):
        if code[i] == 110: # JUMP_FORWARD
            code_start = i+2
            break
    enc = code[code_start:-8] # Remove stub
    if flags & 0x40000000: # obf_code == 1
        code = xor_decrypt(keys[2][0], enc)
    elif flags & 0x8000000: # obf_code == 2
        code = des3_decrypt(keys[1][0], keys[1][1], enc)
    return code

def deobfusc_codeobj(co, pubkey):
    # Deobfuscate a code object
    code = co.co_code
    flags = co.co_flags
    consts = []
    # decode sub-functions
    for const in co.co_consts:
        if isinstance(const, type(co)):
            const = deobfusc_codeobj(const, pubkey)
        consts.append(const)
    if flags & 0x48000000:
        if "__armor_enter__" in co.co_names and "__armor_exit__" in co.co_names: # wrap_mode == 1
            code = decrypt_code_wrap(co.co_code, flags, pubkey)
        elif "__armor__" in co.co_names: # wrap_mode == 0
            code = decrypt_code_jump(co.co_code, flags, pubkey)
        else:
            print("warning: could not detect stub in", co)
    # remove obfuscation flags
    # note: 0x20000000 means allow external usage
    flags &= ~(0x40000000 | 0x20000000 | 0x8000000)
    # change the code and flags of the code object to the deobfuscated version
    if sys.hexversion < 0x3080000:
        code_c = type(co)
        co = code_c(co.co_argcount, co.co_kwonlyargcount, co.co_nlocals,
            co.co_stacksize, flags, code, tuple(consts), co.co_names,
            co.co_varnames, co.co_filename, co.co_name, co.co_firstlineno,
            co.co_lnotab, co.co_freevars, co.co_cellvars)
    else:
        # 3.8 changed some code object fields and added 'replace'
        co = co.replace(co_code=code, co_flags=flags, co_consts=tuple(consts))
    return co
