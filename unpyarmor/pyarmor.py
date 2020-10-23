# PyArmor file format

import struct

class Armored:
    py_ver = ()
    import_magic = b""
    code = b""
    
def parse_armored(enc):
    if enc[:7] != b"PYARMOR":
        raise Exception("Invalid magic")
    py_major = enc[9]
    py_minor = enc[10]
    py_ver = (py_major, py_minor)
    import_magic = enc[12:16]
    code_start = struct.unpack("<I", enc[28:32])[0]
    code_length = struct.unpack("<I", enc[32:36])[0]
    code = enc[code_start:code_start+code_length]
    # TODO: find out what the other fields mean
    dec = Armored()
    dec.py_ver = py_ver
    dec.import_magic = import_magic
    dec.code = code
    return dec
