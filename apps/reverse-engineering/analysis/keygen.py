#!/usr/bin/env python3
# Re-implements the challenge's derive_key + XOR check to produce valid licenses.
# For training purposes.

def checksum(s: str) -> int:
    h = 5381
    for ch in s.encode():
        h = ((h << 5) + h) ^ ch
        h &= 0xFFFFFFFF
    return h

def derive_key(user: str, outlen: int = 19) -> str:
    cs = checksum(user)
    alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    alen = len(alphabet)
    out = bytearray(outlen)
    for i in range(outlen):
        out[i] = alphabet[(cs + i * 7) % alen]
        cs ^= (out[i] + i)
        cs = ((cs << 3) | (cs >> 29)) & 0xFFFFFFFF
    return out.decode()

def xor_bytes(s: str, key: int = 0x5A) -> str:
    return "".join(chr(ord(c) ^ key) for c in s)

def generate_license(user: str) -> str:
    derived = derive_key(user)
    return xor_bytes(derived, 0x5A)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: keygen.py <username>")
        sys.exit(1)
    print(generate_license(sys.argv[1]))
