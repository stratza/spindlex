"""
Tests for SSH cipher suite functionality.

Tests cipher suite algorithm negotiation and cipher information.
"""

import pytest
from ssh_library.crypto.ciphers import CipherSuite
from ssh_library.crypto.backend import CryptographyBackend
from ssh_library.exceptions import CryptoException


class TestCipherSuite:
    """Test CipherSuite implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.cipher_suite = CipherSuite()
    
    def test_initialization(self):
        """Test cipher suite initialization."""
        assert self.cipher_suite.crypto_backend is not None
        assert isinstance(self.cipher_suite.crypto_backend, CryptographyBackend)
        assert self.cipher_suite.negotiated_algorithms == {}
    
    def test_algorithm_lists(self):
        """Test algorithm preference lists."""
        # Test KEX algorithms
        assert "curve25519-sha256" in CipherSuite.KEX_ALGORITHMS
        assert "ecdh-sha2-nistp256" in CipherSuite.KEX_ALGORITHMS
        assert "diffie-hellman-group14-sha256" in CipherSuite.KEX_ALGORITHMS
        
        # Test host key algorithms
        assert "ssh-ed25519" in CipherSuite.HOST_KEY_ALGORITHMS
        assert "ecdsa-sha2-nistp256" in CipherSuite.HOST_KEY_ALGORITHMS
        assert "rsa-sha2-256" in CipherSuite.HOST_KEY_ALGORITHMS
        
        # Test encryption algorithms
        assert "chacha20-poly1305@openssh.com" in CipherSuite.ENCRYPTION_ALGORITHMS
        assert "aes256-gcm@openssh.com" in CipherSuite.ENCRYPTION_ALGORITHMS
        assert "aes128-gcm@openssh.com" in CipherSuite.ENCRYPTION_ALGORITHMS
        assert "aes256-ctr" in CipherSuite.ENCRYPTION_ALGORITHMS
        
        # Test MAC algorithms
        assert "hmac-sha2-256" in CipherSuite.MAC_ALGORITHMS
        assert "hmac-sha2-512" in CipherSuite.MAC_ALGORITHMS
    
    def test_negotiate_algorithms_success(self):
        """Test successful algorithm negotiation."""
        client_algorithms = {
            'kex_algorithms': ['diffie-hellman-group14-sha256', 'curve25519-sha256'],
            'server_host_key_algorithms': ['ssh-ed25519', 'rsa-sha2-256'],
            'encryption_algorithms_client_to_server': ['aes256-ctr', 'chacha20-poly1305@openssh.com'],
            'encryption_algorithms_server_to_client': ['aes256-ctr', 'chacha20-poly1305@openssh.com'],
            'mac_algorithms_client_to_server': ['hmac-sha2-256', 'hmac-sha2-512'],
            'mac_algorithms_server_to_client': ['hmac-sha2-256', 'hmac-sha2-512'],
        }
        
        server_algorithms = {
            'kex_algorithms': ['curve25519-sha256', 'ecdh-sha2-nistp256'],
            'server_host_key_algorithms': ['ssh-ed25519', 'ecdsa-sha2-nistp256'],
            'encryption_algorithms_client_to_server': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
            'encryption_algorithms_server_to_client': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com'],
            'mac_algorithms_client_to_server': ['hmac-sha2-256'],
            'mac_algorithms_server_to_client': ['hmac-sha2-256'],
        }
        
        negotiated = self.cipher_suite.negotiate_algorithms(client_algorithms, server_algorithms)
        
        # Should select highest preference mutually supported algorithms
        assert negotiated['kex'] == 'curve25519-sha256'
        assert negotiated['server_host_key'] == 'ssh-ed25519'
        assert negotiated['encryption_client_to_server'] == 'chacha20-poly1305@openssh.com'
        assert negotiated['encryption_server_to_client'] == 'chacha20-poly1305@openssh.com'
        # AEAD ciphers should set MAC to 'none'
        assert negotiated['mac_client_to_server'] == 'none'
        assert negotiated['mac_server_to_client'] == 'none'
    
    def test_negotiate_algorithms_non_aead(self):
        """Test algorithm negotiation with non-AEAD ciphers."""
        client_algorithms = {
            'kex_algorithms': ['curve25519-sha256'],
            'server_host_key_algorithms': ['ssh-ed25519'],
            'encryption_algorithms_client_to_server': ['aes256-ctr'],
            'encryption_algorithms_server_to_client': ['aes256-ctr'],
            'mac_algorithms_client_to_server': ['hmac-sha2-256'],
            'mac_algorithms_server_to_client': ['hmac-sha2-256'],
        }
        
        server_algorithms = client_algorithms.copy()
        
        negotiated = self.cipher_suite.negotiate_algorithms(client_algorithms, server_algorithms)
        
        # Non-AEAD cipher should keep MAC algorithms
        assert negotiated['encryption_client_to_server'] == 'aes256-ctr'
        assert negotiated['encryption_server_to_client'] == 'aes256-ctr'
        assert negotiated['mac_client_to_server'] == 'hmac-sha2-256'
        assert negotiated['mac_server_to_client'] == 'hmac-sha2-256'
    
    def test_negotiate_algorithms_failure(self):
        """Test algorithm negotiation failure."""
        client_algorithms = {
            'kex_algorithms': ['diffie-hellman-group14-sha256'],
            'server_host_key_algorithms': ['ssh-ed25519'],
            'encryption_algorithms_client_to_server': ['aes256-ctr'],
            'encryption_algorithms_server_to_client': ['aes256-ctr'],
            'mac_algorithms_client_to_server': ['hmac-sha2-256'],
            'mac_algorithms_server_to_client': ['hmac-sha2-256'],
        }
        
        server_algorithms = {
            'kex_algorithms': ['curve25519-sha256'],  # No overlap
            'server_host_key_algorithms': ['ssh-ed25519'],
            'encryption_algorithms_client_to_server': ['aes256-ctr'],
            'encryption_algorithms_server_to_client': ['aes256-ctr'],
            'mac_algorithms_client_to_server': ['hmac-sha2-256'],
            'mac_algorithms_server_to_client': ['hmac-sha2-256'],
        }
        
        with pytest.raises(CryptoException, match="No compatible kex algorithm found"):
            self.cipher_suite.negotiate_algorithms(client_algorithms, server_algorithms)
    
    def test_get_cipher_info(self):
        """Test cipher information retrieval."""
        # Test ChaCha20-Poly1305
        chacha_info = self.cipher_suite.get_cipher_info("chacha20-poly1305@openssh.com")
        assert chacha_info['key_len'] == 64
        assert chacha_info['iv_len'] == 12
        assert chacha_info['aead'] == True
        
        # Test AES-256-GCM
        aes_gcm_info = self.cipher_suite.get_cipher_info("aes256-gcm@openssh.com")
        assert aes_gcm_info['key_len'] == 32
        assert aes_gcm_info['iv_len'] == 12
        assert aes_gcm_info['aead'] == True
        
        # Test AES-128-GCM
        aes128_gcm_info = self.cipher_suite.get_cipher_info("aes128-gcm@openssh.com")
        assert aes128_gcm_info['key_len'] == 16
        assert aes128_gcm_info['iv_len'] == 12
        assert aes128_gcm_info['aead'] == True
        
        # Test AES-256-CTR
        aes_ctr_info = self.cipher_suite.get_cipher_info("aes256-ctr")
        assert aes_ctr_info['key_len'] == 32
        assert aes_ctr_info['iv_len'] == 16
        assert aes_ctr_info['aead'] == False
        
        # Test unsupported cipher
        with pytest.raises(CryptoException):
            self.cipher_suite.get_cipher_info("unsupported-cipher")
    
    def test_get_mac_info(self):
        """Test MAC information retrieval."""
        # Test HMAC-SHA2-256
        mac256_info = self.cipher_suite.get_mac_info("hmac-sha2-256")
        assert mac256_info['key_len'] == 32
        assert mac256_info['digest_len'] == 32
        
        # Test HMAC-SHA2-512
        mac512_info = self.cipher_suite.get_mac_info("hmac-sha2-512")
        assert mac512_info['key_len'] == 64
        assert mac512_info['digest_len'] == 64
        
        # Test unsupported MAC
        with pytest.raises(CryptoException):
            self.cipher_suite.get_mac_info("unsupported-mac")
    
    def test_is_aead_cipher(self):
        """Test AEAD cipher detection."""
        # AEAD ciphers
        assert self.cipher_suite.is_aead_cipher("chacha20-poly1305@openssh.com") == True
        assert self.cipher_suite.is_aead_cipher("aes256-gcm@openssh.com") == True
        assert self.cipher_suite.is_aead_cipher("aes128-gcm@openssh.com") == True
        
        # Non-AEAD cipher
        assert self.cipher_suite.is_aead_cipher("aes256-ctr") == False
    
    def test_custom_crypto_backend(self):
        """Test cipher suite with custom crypto backend."""
        custom_backend = CryptographyBackend()
        cipher_suite = CipherSuite(custom_backend)
        
        assert cipher_suite.crypto_backend is custom_backend
    
    def test_algorithm_preference_order(self):
        """Test that algorithms are in correct preference order."""
        # KEX algorithms should prefer modern curves
        kex_algs = CipherSuite.KEX_ALGORITHMS
        assert kex_algs.index("curve25519-sha256") < kex_algs.index("ecdh-sha2-nistp256")
        assert kex_algs.index("ecdh-sha2-nistp256") < kex_algs.index("diffie-hellman-group14-sha256")
        
        # Host key algorithms should prefer Ed25519
        host_algs = CipherSuite.HOST_KEY_ALGORITHMS
        assert host_algs.index("ssh-ed25519") < host_algs.index("ecdsa-sha2-nistp256")
        assert host_algs.index("ecdsa-sha2-nistp256") < host_algs.index("rsa-sha2-256")
        
        # Encryption algorithms should prefer AEAD ciphers
        enc_algs = CipherSuite.ENCRYPTION_ALGORITHMS
        assert enc_algs.index("chacha20-poly1305@openssh.com") < enc_algs.index("aes256-ctr")
    
    def test_negotiated_algorithms_storage(self):
        """Test that negotiated algorithms are stored correctly."""
        client_algorithms = {
            'kex_algorithms': ['curve25519-sha256'],
            'server_host_key_algorithms': ['ssh-ed25519'],
            'encryption_algorithms_client_to_server': ['chacha20-poly1305@openssh.com'],
            'encryption_algorithms_server_to_client': ['chacha20-poly1305@openssh.com'],
            'mac_algorithms_client_to_server': ['hmac-sha2-256'],
            'mac_algorithms_server_to_client': ['hmac-sha2-256'],
        }
        
        server_algorithms = client_algorithms.copy()
        
        negotiated = self.cipher_suite.negotiate_algorithms(client_algorithms, server_algorithms)
        
        # Check that negotiated algorithms are stored in the instance
        assert self.cipher_suite.negotiated_algorithms == negotiated
        assert self.cipher_suite.negotiated_algorithms['kex'] == 'curve25519-sha256'