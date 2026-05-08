import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from spindlex.client.sftp_client import SFTPClient, SFTPError
from spindlex.client.async_sftp_client import AsyncSFTPClient
from spindlex.protocol.sftp_messages import (
    SFTPAttrsMessage,
    SFTPNameMessage,
    SFTPStatusMessage,
)
from spindlex.protocol.sftp_constants import SSH_FX_OK
from spindlex.crypto.pkey import ECDSAKey
from spindlex.transport.kex import KeyExchange
from spindlex.protocol.constants import (
    KEX_ECDH_SHA2_NISTP384,
    KEX_ECDH_SHA2_NISTP521,
)

# 1. Test SFTP API Parity (Sync)
def test_sftp_sync_parity():
    transport = MagicMock()
    with patch.object(SFTPClient, '_initialize_sftp'):
        client = SFTPClient(transport)
    client._initialized = True
    
    # Mock response for lstat/symlink/readlink
    mock_attrs = MagicMock()
    mock_attrs_msg = SFTPAttrsMessage(request_id=1, attrs=mock_attrs)
    mock_ok_msg = SFTPStatusMessage(request_id=1, status_code=SSH_FX_OK, message="OK")
    mock_name_msg = SFTPNameMessage(request_id=1, names=[("target", "longname", MagicMock())])
    
    with patch.object(SFTPClient, '_send_request_and_wait_response') as mock_send:
        # Test lstat success
        mock_send.return_value = mock_attrs_msg
        res = client.lstat("/path")
        assert res == mock_attrs
        
        # Test lstat failure
        mock_send.return_value = SFTPStatusMessage(request_id=1, status_code=1, message="Fail")
        with pytest.raises(SFTPError, match="\[1\] Fail"):
            client.lstat("/path")
            
        # Test symlink success
        mock_send.return_value = mock_ok_msg
        client.symlink("/target", "/link")
        
        # Test symlink failure
        mock_send.return_value = SFTPStatusMessage(request_id=1, status_code=1, message="Fail")
        with pytest.raises(SFTPError, match="\[1\] Fail"):
            client.symlink("/target", "/link")
        
        # Test readlink success
        mock_send.return_value = mock_name_msg
        res = client.readlink("/link")
        assert res == "target"
        
        # Test readlink failure
        mock_send.return_value = SFTPStatusMessage(request_id=1, status_code=1, message="Fail")
        with pytest.raises(SFTPError, match="\[1\] Fail"):
            client.readlink("/link")

# 2. Test SFTP API Parity (Async)
@pytest.mark.asyncio
async def test_sftp_async_parity():
    channel = AsyncMock()
    client = AsyncSFTPClient(channel)
    client._initialized = True
    
    # Mock response for lstat/symlink/readlink
    mock_attrs = MagicMock()
    mock_attrs_msg = SFTPAttrsMessage(request_id=1, attrs=mock_attrs)
    mock_ok_msg = SFTPStatusMessage(request_id=1, status_code=SSH_FX_OK, message="OK")
    mock_name_msg = SFTPNameMessage(request_id=1, names=[("target", "longname", MagicMock())])
    
    with patch.object(AsyncSFTPClient, '_wait_for_response', new_callable=AsyncMock) as mock_wait:
        # Test lstat success
        mock_wait.return_value = mock_attrs_msg
        res = await client.lstat("/path")
        assert res == mock_attrs
        
        # Test lstat failure
        mock_wait.return_value = SFTPStatusMessage(request_id=1, status_code=1, message="Fail")
        with pytest.raises(SFTPError, match="Lstat failed: Fail"):
            await client.lstat("/path")
            
        # Test symlink success
        mock_wait.return_value = mock_ok_msg
        await client.symlink("/target", "/link")
        
        # Test symlink failure
        mock_wait.return_value = SFTPStatusMessage(request_id=1, status_code=1, message="Fail")
        with pytest.raises(SFTPError, match="Symlink failed: Fail"):
            await client.symlink("/target", "/link")
        
        # Test readlink success
        mock_wait.return_value = mock_name_msg
        res = await client.readlink("/link")
        assert res == "target"
        
        # Test readlink failure
        mock_wait.return_value = SFTPStatusMessage(request_id=1, status_code=1, message="Fail")
        with pytest.raises(SFTPError, match="Readlink failed: Fail"):
            await client.readlink("/link")

# 3. Test ECDSA NIST Curves
def test_ecdsa_nist_curves():
    # P-256 (default)
    key256 = ECDSAKey()
    assert key256.curve_name == "nistp256"
    assert key256.algorithm_name == "ecdsa-sha2-nistp256"
    
    # P-384
    key384 = ECDSAKey(curve_name="nistp384")
    assert key384.curve_name == "nistp384"
    assert key384.algorithm_name == "ecdsa-sha2-nistp384"
    
    # P-521
    key521 = ECDSAKey(curve_name="nistp521")
    assert key521.curve_name == "nistp521"
    assert key521.algorithm_name == "ecdsa-sha2-nistp521"
    
    # Test generation and signing
    for bits in [256, 384, 521]:
        key = ECDSAKey.generate(bits=bits)
        data = b"hello world"
        sig = key.sign(data)
        assert key.verify(sig, data) is True
        
        # Test public key bytes
        pub_bytes = key.get_public_key_bytes()
        key_reloaded = ECDSAKey()
        key_reloaded.load_public_key(pub_bytes)
        assert key_reloaded.curve_name == key.curve_name
        assert key_reloaded.verify(sig, data) is True

# 4. Test KeyExchange Hash Selection
def test_kex_hash_selection():
    transport = MagicMock()
    kex = KeyExchange(transport)
    
    # Mock some state for _generate_session_keys
    kex._encryption_algorithm_c2s = "aes256-ctr"
    kex._encryption_algorithm_s2c = "aes256-ctr"
    kex._mac_algorithm_c2s = "hmac-sha2-256"
    kex._mac_algorithm_s2c = "hmac-sha2-256"
    kex._cipher_suite = MagicMock()
    kex._cipher_suite.get_cipher_info.return_value = {"key_len": 32, "iv_len": 16}
    kex._cipher_suite.get_mac_info.return_value = {"key_len": 32}
    kex._shared_secret = b"secret"
    kex._exchange_hash = b"hash"
    
    with patch('spindlex.crypto.backend.default_crypto_backend.derive_key') as mock_derive:
        # P-384 -> SHA384
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP384
        kex._generate_session_keys()
        # Check first call to derive_key
        assert mock_derive.call_args_list[0][0][0] == "sha384"
        
        mock_derive.reset_mock()
        
        # P-521 -> SHA512
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP521
        kex._generate_session_keys()
        assert mock_derive.call_args_list[0][0][0] == "sha512"
