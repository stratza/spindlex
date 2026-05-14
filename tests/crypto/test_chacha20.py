
import struct
from spindlex.crypto.backend import CryptographyBackend

def test_chacha20_poly1305_roundtrip():
    backend = CryptographyBackend()
    key = backend.generate_random(64)
    seq_num = 42
    length_bytes = struct.pack(">I", 12)
    body_bytes = b"hello world!" # 12 bytes
    
    # Encrypt
    encrypted = backend.chacha20_poly1305_encrypt(key, seq_num, length_bytes, body_bytes)
    
    # The result should be: enc_length (4) + enc_body (12) + tag (16) = 32 bytes
    assert len(encrypted) == 32
    
    enc_length = encrypted[:4]
    enc_body = encrypted[4:16]
    tag = encrypted[16:]
    
    # Decrypt length
    dec_length = backend.chacha20_poly1305_decrypt_length(key, seq_num, enc_length)
    assert dec_length == length_bytes
    
    # Decrypt body
    dec_body = backend.chacha20_poly1305_decrypt_body(key, seq_num, enc_length, enc_body, tag)
    assert dec_body == body_bytes

def test_chacha20_poly1305_invalid_tag():
    backend = CryptographyBackend()
    key = backend.generate_random(64)
    seq_num = 42
    length_bytes = struct.pack(">I", 12)
    body_bytes = b"hello world!"
    
    encrypted = backend.chacha20_poly1305_encrypt(key, seq_num, length_bytes, body_bytes)
    
    enc_length = encrypted[:4]
    enc_body = encrypted[4:16]
    tag = encrypted[16:]
    
    # Corrupt tag
    corrupt_tag = bytearray(tag)
    corrupt_tag[0] ^= 0x01
    
    import pytest
    from spindlex.exceptions import CryptoException
    
    with pytest.raises(CryptoException, match="Poly1305 authentication failed"):
        backend.chacha20_poly1305_decrypt_body(key, seq_num, enc_length, enc_body, bytes(corrupt_tag))

def test_chacha20_poly1305_wrong_seq():
    backend = CryptographyBackend()
    key = backend.generate_random(64)
    seq_num = 42
    length_bytes = struct.pack(">I", 12)
    body_bytes = b"hello world!"
    
    encrypted = backend.chacha20_poly1305_encrypt(key, seq_num, length_bytes, body_bytes)
    
    enc_length = encrypted[:4]
    enc_body = encrypted[4:16]
    tag = encrypted[16:]
    
    import pytest
    from spindlex.exceptions import CryptoException
    
    # Wrong sequence number should fail verification
    with pytest.raises(CryptoException, match="Poly1305 authentication failed"):
        backend.chacha20_poly1305_decrypt_body(key, seq_num + 1, enc_length, enc_body, tag)
