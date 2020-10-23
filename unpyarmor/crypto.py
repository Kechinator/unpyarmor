# Decryption functions

from Crypto.Cipher import DES3

def des3_decrypt(key, iv, enc):
    # DES-CFB decrypt
    cip = DES3.new(key, DES3.MODE_ECB)
    dec = b""
    for i in range(0, len(enc), 8):
        lblock = enc[i-8:i] if i > 7 else iv
        keym = cip.encrypt(lblock)
        dec += xor_decrypt(keym, enc[i:i+8])
    return dec

def xor_decrypt(key, enc):
    out = bytearray()
    for i in range(0, len(enc)):
        out.append(enc[i] ^ key[i % len(key)])
    return bytes(out)

def decode_buffer(inp):
    inp = bytearray(inp)
    inp[0] = (~inp[0]) & 0xff
    if len(inp) > 1:
        inp[0] ^= inp[len(inp)-1]
        for i in range(1, len(inp)):
            inp[i] ^= inp[i-1]
    return bytes(inp)

def derive_keys(inp):
    # Yes, I had to crack their JIT protection for this
    key0 = bytes(inp[(i * 4 + 16) % len(inp)] for i in range(24))
    key1 = bytes(inp[(i * 3 + 17) % len(inp)] for i in range(24))
    key2 = bytes(inp[(i * 17 + 6) % len(inp)] for i in range(24))
    iv0 = bytes(inp[(i * 8 + 24) % len(inp)] for i in range(8))
    iv1 = bytes(inp[(i * 5 + 28) % len(inp)] for i in range(8))
    iv2 = bytes(inp[(i * 7 + 15) % len(inp)] for i in range(8))
    out = [(key0, iv0), (key1, iv1), (key2, iv2)]
    return out
