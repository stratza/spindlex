"""
Tests for GSSAPI Authentication

Tests GSSAPI authentication functionality including Kerberos ticket handling
and error scenarios.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest

from ssh_library.auth.gssapi import GSSAPI_AVAILABLE, GSSAPIAuth
from ssh_library.exceptions import AuthenticationException


class TestGSSAPIAuth:
    """Test GSSAPI authentication functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock()
        self.mock_transport.active = True
        self.mock_transport.authenticated = False
        self.mock_transport._userauth_service_requested = False
        self.mock_transport._socket.getpeername.return_value = ("test.example.com", 22)

        # Mock transport methods
        self.mock_transport._request_userauth_service = Mock()
        self.mock_transport._send_message = Mock()
        self.mock_transport._recv_message = Mock()

    def test_gssapi_not_available(self):
        """Test behavior when GSSAPI library is not available."""
        with patch("ssh_library.auth.gssapi.GSSAPI_AVAILABLE", False):
            gssapi_auth = GSSAPIAuth(self.mock_transport)

            with pytest.raises(
                AuthenticationException, match="GSSAPI library not available"
            ):
                gssapi_auth.authenticate("testuser")

    @pytest.mark.skipif(not GSSAPI_AVAILABLE, reason="GSSAPI library not available")
    def test_gssapi_initialization(self):
        """Test GSSAPI authenticator initialization."""
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        assert gssapi_auth._transport == self.mock_transport
        assert gssapi_auth._gss_context is None
        assert gssapi_auth._gss_credentials is None

    @pytest.mark.skipif(not GSSAPI_AVAILABLE, reason="GSSAPI library not available")
    @patch("ssh_library.auth.gssapi.Credentials")
    @patch("ssh_library.auth.gssapi.SecurityContext")
    @patch("ssh_library.auth.gssapi.Name")
    def test_gssapi_context_initialization(self, mock_name, mock_context, mock_creds):
        """Test GSSAPI context initialization."""
        # Setup mocks
        mock_name_instance = Mock()
        mock_name.return_value = mock_name_instance

        mock_creds_instance = Mock()
        mock_creds.return_value = mock_creds_instance

        mock_context_instance = Mock()
        mock_context_instance.complete = False
        mock_context.return_value = mock_context_instance

        gssapi_auth = GSSAPIAuth(self.mock_transport)

        # Test target name creation
        target_name = gssapi_auth._get_target_name(None)
        mock_name.assert_called_once()

        # Test context initialization
        gssapi_auth._init_gss_context(mock_name_instance, False)

        mock_creds.assert_called_once_with(usage="initiate")
        mock_context.assert_called_once()

        assert gssapi_auth._gss_credentials == mock_creds_instance
        assert gssapi_auth._gss_context == mock_context_instance

    def test_transport_not_active(self):
        """Test authentication when transport is not active."""
        self.mock_transport.active = False
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        with pytest.raises(AuthenticationException, match="Transport not active"):
            gssapi_auth.authenticate("testuser")

    def test_already_authenticated(self):
        """Test authentication when already authenticated."""
        self.mock_transport.authenticated = True
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        result = gssapi_auth.authenticate("testuser")
        assert result is True

    @pytest.mark.skipif(not GSSAPI_AVAILABLE, reason="GSSAPI library not available")
    def test_target_name_generation(self):
        """Test GSSAPI target name generation."""
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        # Test with default hostname
        with patch("ssh_library.auth.gssapi.Name") as mock_name:
            gssapi_auth._get_target_name(None)
            mock_name.assert_called_once_with(
                "host@test.example.com",
                name_type=patch.object.__enter__().NameType.hostbased_service,
            )

        # Test with custom hostname
        with patch("ssh_library.auth.gssapi.Name") as mock_name:
            gssapi_auth._get_target_name("custom.example.com")
            mock_name.assert_called_once_with(
                "host@custom.example.com",
                name_type=patch.object.__enter__().NameType.hostbased_service,
            )

    @pytest.mark.skipif(not GSSAPI_AVAILABLE, reason="GSSAPI library not available")
    def test_method_data_building(self):
        """Test GSSAPI method data building."""
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        test_token = b"test_gssapi_token"
        method_data = gssapi_auth._build_gssapi_method_data(test_token)

        # Verify method data contains expected components
        assert isinstance(method_data, bytes)
        assert len(method_data) > 0

        # Should contain OID count, Kerberos OID, and token
        assert test_token in method_data

    def test_cleanup(self):
        """Test GSSAPI resource cleanup."""
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        # Set mock objects
        gssapi_auth._gss_context = Mock()
        gssapi_auth._gss_credentials = Mock()

        # Test cleanup
        gssapi_auth.cleanup()

        assert gssapi_auth._gss_context is None
        assert gssapi_auth._gss_credentials is None

    def test_get_gss_context(self):
        """Test getting GSSAPI context."""
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        # Initially None
        assert gssapi_auth.get_gss_context() is None

        # Set mock context
        mock_context = Mock()
        gssapi_auth._gss_context = mock_context

        assert gssapi_auth.get_gss_context() == mock_context

    def test_get_gss_credentials(self):
        """Test getting GSSAPI credentials."""
        gssapi_auth = GSSAPIAuth(self.mock_transport)

        # Initially None
        assert gssapi_auth.get_gss_credentials() is None

        # Set mock credentials
        mock_creds = Mock()
        gssapi_auth._gss_credentials = mock_creds

        assert gssapi_auth.get_gss_credentials() == mock_creds


class TestGSSAPIIntegration:
    """Test GSSAPI integration with transport."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock()
        self.mock_transport.active = True
        self.mock_transport.authenticated = False
        self.mock_transport._userauth_service_requested = True

    def test_transport_gssapi_auth_method(self):
        """Test transport GSSAPI authentication method."""
        # Test that transport has GSSAPI auth method
        from ssh_library.transport.transport import Transport

        # Check method exists
        assert hasattr(Transport, "auth_gssapi")

        # Test method signature
        import inspect

        sig = inspect.signature(Transport.auth_gssapi)
        expected_params = ["self", "username", "gss_host", "gss_deleg_creds"]
        actual_params = list(sig.parameters.keys())

        assert actual_params == expected_params

    @patch("ssh_library.auth.gssapi.GSSAPIAuth")
    def test_transport_gssapi_auth_call(self, mock_gssapi_class):
        """Test transport calls GSSAPI authenticator correctly."""
        from ssh_library.transport.transport import Transport

        # Setup mock
        mock_gssapi_instance = Mock()
        mock_gssapi_instance.authenticate.return_value = True
        mock_gssapi_class.return_value = mock_gssapi_instance

        # Create transport instance
        transport = Transport(Mock())
        transport._active = True
        transport._authenticated = False
        transport._userauth_service_requested = True

        # Call GSSAPI auth
        result = transport.auth_gssapi("testuser", "test.example.com", True)

        # Verify calls
        mock_gssapi_class.assert_called_once_with(transport)
        mock_gssapi_instance.authenticate.assert_called_once_with(
            "testuser", "test.example.com", True
        )
        mock_gssapi_instance.cleanup.assert_called_once()

        assert result is True
