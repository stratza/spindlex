
from spindlex.crypto.pkey import RSAKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import struct

def test_rsa_public_key_bytes_bug():
    # Create a modulus that has MSB set in the first byte
    # e.g., a 2048-bit modulus usually does.
    # We can just manually create an RSA public key with a specific n.
    e = 65537
    # A 1024-bit n starting with 0x80
    n = (0x80 << (1024 - 8)) | 1
    
    public_numbers = rsa.RSAPublicNumbers(e, n)
    key = RSAKey()
    key._key = public_numbers.public_key(backend=default_backend())
    
    blob = key.get_public_key_bytes()
    
    # Blob structure:
    # 4-byte len("ssh-rsa") + "ssh-rsa"
    # 4-byte len(e_bytes) + e_bytes
    # 4-byte len(n_bytes) + n_bytes
    
    offset = 0
    algo_len = struct.unpack(">I", blob[offset:offset+4])[0]
    offset += 4 + algo_len
    
    e_len = struct.unpack(">I", blob[offset:offset+4])[0]
    offset += 4 + e_len
    
    n_len = struct.unpack(">I", blob[offset:offset+4])[0]
    n_bytes = blob[offset+4:offset+4+n_len]
    
    print(f"n_len: {n_len}")
    print(f"n_bytes[0]: {hex(n_bytes[0])}")
    
    # If the bug exists, n_len will be 128 (1024 bits) and n_bytes[0] will be 0x80.
    # If fixed, n_len will be 129 and n_bytes[0] will be 0x00.
    if n_len == 128 and n_bytes[0] == 0x80:
        print("BUG REPRODUCED: n is not encoded as mpint (missing zero byte padding)")
    elif n_len == 129 and n_bytes[0] == 0x00:
        print("n is correctly encoded as mpint")
    else:
        print(f"Unexpected results: n_len={n_len}, n_bytes[0]={hex(n_bytes[0])}")

if __name__ == "__main__":
    test_rsa_public_key_bytes_bug()
