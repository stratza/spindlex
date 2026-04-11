import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock GSSAPI modules before they are used
mock_gssapi = MagicMock()
sys.modules["gssapi"] = mock_gssapi
sys.modules["gssapi.raw"] = MagicMock()

from spindlex.auth.gssapi import GSSAPIAuth


@pytest.fixture
def mock_transport():
    transport = MagicMock()
    transport.active = True
    transport.authenticated = False
    transport._userauth_service_requested = True
    return transport


def test_gssapi_auth_success(mock_transport):
    with patch("spindlex.auth.gssapi.GSSAPI_AVAILABLE", True):
        # Patch specifically the classes that the module uses
        with patch("spindlex.auth.gssapi.Credentials") as mock_cred_cls:
            with patch("spindlex.auth.gssapi.SecurityContext") as mock_ctx_cls:
                with patch("spindlex.auth.gssapi.Name") as mock_name_cls:
                    mock_ctx = mock_ctx_cls.return_value
                    mock_ctx.complete = True
                    
                    auth = GSSAPIAuth(mock_transport)
                    
                    with patch.object(auth, "_perform_gssapi_exchange", return_value=True):
                        res = auth.authenticate("alice")
                        assert res is True


def test_gssapi_auth_handshake_fail(mock_transport):
    with patch("spindlex.auth.gssapi.GSSAPI_AVAILABLE", True):
        with patch("spindlex.auth.gssapi.Credentials", MagicMock()):
            with patch("spindlex.auth.gssapi.SecurityContext", MagicMock()):
                with patch("spindlex.auth.gssapi.Name", MagicMock()):
                    auth = GSSAPIAuth(mock_transport)
                    with patch.object(auth, "_perform_gssapi_exchange", return_value=False):
                        res = auth.authenticate("alice")
                        assert res is False
