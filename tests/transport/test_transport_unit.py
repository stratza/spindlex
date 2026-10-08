"""Unit tests for spindlex/transport/transport.py to boost coverage."""

from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import (
    AuthenticationException,
    ProtocolException,
    TransportException,
)
from spindlex.protocol.constants import (
    CHANNEL_SESSION,
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_WINDOW_SIZE,
    MAX_CHANNELS,
    MSG_CHANNEL_CLOSE,
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_OPEN,
    MSG_CHANNEL_SUCCESS,
    MSG_GLOBAL_REQUEST,
    MSG_REQUEST_FAILURE,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_SUCCESS,
    SERVICE_USERAUTH,
)
from spindlex.protocol.messages import (
    ChannelCloseMessage,
    ChannelDataMessage,
    ChannelOpenFailureMessage,
    ChannelOpenMessage,
    ServiceAcceptMessage,
    UserAuthFailureMessage,
    UserAuthSuccessMessage,
)
from spindlex.protocol.utils import (
    write_boolean,
    write_string,
    write_uint32,
)
from spindlex.transport.channel import Channel
from spindlex.transport.transport import Transport


def _make_sock():
    s = MagicMock(spec=socket.socket)
    s.fileno.return_value = 3
    s.gettimeout.return_value = None
    return s


def _make_transport(active=False, authenticated=False, server_mode=False):
    t = Transport(_make_sock())
    t._active = active
    t._authenticated = authenticated
    t._server_mode = server_mode
    return t


# ---- Properties & Simple Methods ----


class TestTransportProperties:
    def test_active(self):
        t = _make_transport(active=True)
        assert t.active is True

    def test_server_mode(self):
        t = _make_transport(server_mode=True)
        assert t.server_mode is True

    def test_authenticated(self):
        t = _make_transport(authenticated=True)
        assert t.authenticated is True

    def test_session_id_none(self):
        t = _make_transport()
        assert t.session_id is None

    def test_session_id_set(self):
        t = _make_transport()
        t._session_id = b"test"
        assert t.session_id == b"test"

    def test_get_timeout(self):
        t = _make_transport()
        t._socket.gettimeout.return_value = 5.0
        assert t.get_timeout() == 5.0

    def test_set_timeout(self):
        t = _make_transport()
        t.set_timeout(10.0)
        assert t._timeout == 10.0
        t._socket.settimeout.assert_called_with(10.0)

    def test_set_rekey_policy(self):
        t = _make_transport()
        t.set_rekey_policy(bytes_limit=100, time_limit=50.0)
        assert t._rekey_bytes_limit == 100
        assert t._rekey_time_limit == 50.0

    def test_context_manager(self):
        t = _make_transport()
        with patch.object(t, "close") as mock_close:
            with t:
                pass
            mock_close.assert_called_once()

    def test_set_get_server_interface(self):
        t = _make_transport()
        iface = MagicMock()
        t.set_server_interface(iface)
        assert t.get_server_interface() is iface

    def test_get_port_forwarding_manager(self):
        t = _make_transport()
        mgr = t.get_port_forwarding_manager()
        assert mgr is not None
        assert t.get_port_forwarding_manager() is mgr


# ---- Auth Methods ----


class TestTransportAuth:
    def test_auth_password_not_active_raises(self):
        t = _make_transport(active=False)
        with pytest.raises(AuthenticationException, match="Transport not active"):
            t.auth_password("u", "p")

    def test_auth_password_already_authenticated(self):
        t = _make_transport(active=True, authenticated=True)
        assert t.auth_password("u", "p") is True

    def test_auth_publickey_not_active_raises(self):
        t = _make_transport(active=False)
        with pytest.raises(AuthenticationException, match="Transport not active"):
            t.auth_publickey("u", MagicMock())

    def test_auth_publickey_already_authenticated(self):
        t = _make_transport(active=True, authenticated=True)
        assert t.auth_publickey("u", MagicMock()) is True

    def test_auth_keyboard_interactive_not_active(self):
        t = _make_transport(active=False)
        with pytest.raises(AuthenticationException, match="Transport not active"):
            t.auth_keyboard_interactive("u", MagicMock())

    def test_auth_keyboard_interactive_already_authenticated(self):
        t = _make_transport(active=True, authenticated=True)
        assert t.auth_keyboard_interactive("u", MagicMock()) is True

    def test_auth_gssapi_not_active(self):
        t = _make_transport(active=False)
        with pytest.raises(AuthenticationException, match="Transport not active"):
            t.auth_gssapi("u")

    def test_auth_gssapi_already_authenticated(self):
        t = _make_transport(active=True, authenticated=True)
        assert t.auth_gssapi("u") is True


# ---- _handle_auth_response_message ----


class TestHandleAuthResponse:
    def test_success_message(self):
        t = _make_transport()
        msg = UserAuthSuccessMessage()
        assert t._handle_auth_response_message(msg) is True
        assert t._authenticated is True

    def test_failure_no_partial(self):
        t = _make_transport()
        msg = UserAuthFailureMessage(["password"], False)
        assert t._handle_auth_response_message(msg) is False

    def test_failure_partial_raises(self):
        t = _make_transport()
        msg = UserAuthFailureMessage(["password"], True)
        with pytest.raises(AuthenticationException, match="Partial success"):
            t._handle_auth_response_message(msg)

    def test_unexpected_msg_raises(self):
        t = _make_transport()
        msg = MagicMock()
        msg.msg_type = 999
        with pytest.raises(AuthenticationException, match="Unexpected"):
            t._handle_auth_response_message(msg)

    def test_success_by_msg_type(self):
        t = _make_transport()
        msg = MagicMock()
        msg.msg_type = MSG_USERAUTH_SUCCESS
        assert t._handle_auth_response_message(msg) is True

    def test_failure_by_msg_type(self):
        t = _make_transport()
        msg = MagicMock()
        msg.msg_type = MSG_USERAUTH_FAILURE
        msg.pack.return_value = UserAuthFailureMessage(["password"], False).pack()
        assert t._handle_auth_response_message(msg) is False


# ---- open_channel ----


class TestOpenChannel:
    def test_not_active_raises(self):
        t = _make_transport(active=False)
        with pytest.raises(TransportException, match="Transport not active"):
            t.open_channel("session")

    def test_not_authenticated_raises(self):
        t = _make_transport(active=True, authenticated=False)
        with pytest.raises(TransportException, match="Transport not authenticated"):
            t.open_channel("session")

    def test_max_channels_raises(self):
        t = _make_transport(active=True, authenticated=True)
        t._channels = {i: MagicMock() for i in range(MAX_CHANNELS)}
        with pytest.raises(TransportException, match="Maximum number"):
            t.open_channel("session")


# ---- _close_channel ----


class TestCloseChannel:
    def test_close_existing_channel(self):
        t = _make_transport()
        t._active = True
        ch = Channel(t, 0)
        ch._remote_channel_id = 99
        t._channels[0] = ch
        with patch.object(t, "_send_message") as send:
            t._close_channel(0)
        sent = send.call_args[0][0]
        assert isinstance(sent, ChannelCloseMessage)
        assert sent.recipient_channel == 99
        # The number stays reserved until the peer's CLOSE arrives.
        assert 0 in t._channels

    def test_channel_close_sends_close_once(self):
        t = _make_transport()
        t._active = True
        ch = Channel(t, 0)
        ch._remote_channel_id = 99
        t._channels[0] = ch
        with patch.object(t, "_send_message") as send:
            ch.close()
            ch.close()
        assert send.call_count == 1

    def test_peer_close_is_answered_and_releases_channel(self):
        t = _make_transport()
        t._active = True
        ch = Channel(t, 0)
        ch._remote_channel_id = 99
        t._channels[0] = ch
        with patch.object(t, "_send_message") as send:
            t._handle_channel_close(ChannelCloseMessage(recipient_channel=0))
        assert send.call_count == 1
        assert isinstance(send.call_args[0][0], ChannelCloseMessage)
        assert ch.closed
        assert 0 not in t._channels

    def test_peer_close_after_local_close_releases_without_resend(self):
        t = _make_transport()
        t._active = True
        ch = Channel(t, 0)
        ch._remote_channel_id = 99
        t._channels[0] = ch
        with patch.object(t, "_send_message") as send:
            ch.close()
            t._handle_channel_close(ChannelCloseMessage(recipient_channel=0))
        assert send.call_count == 1
        assert 0 not in t._channels

    def test_close_during_request_callback_follows_reply(self):
        t = _make_transport()
        t._active = True
        ch = Channel(t, 0)
        ch._remote_channel_id = 99
        t._channels[0] = ch

        def handler(request_type, data):
            ch.close()
            return True

        ch._handle_request = handler
        data = struct.pack(">I", 0) + write_string("exec") + write_boolean(True)
        msg = MagicMock()
        msg._data = data
        with patch.object(t, "_send_message") as send:
            t._handle_channel_request(msg)
        sent_types = [c[0][0].msg_type for c in send.call_args_list]
        assert sent_types == [MSG_CHANNEL_SUCCESS, MSG_CHANNEL_CLOSE]

    def test_close_nonexistent_channel(self):
        t = _make_transport()
        t._close_channel(999)  # should not raise


# ---- _handle_channel_message dispatch ----


class TestHandleChannelMessage:
    def test_channel_open_dispatch(self):
        t = _make_transport()
        msg = MagicMock()
        msg.msg_type = MSG_CHANNEL_OPEN
        with patch.object(t, "_handle_channel_open") as m:
            t._handle_channel_message(msg)
            m.assert_called_once_with(msg)

    def test_global_request_dispatch(self):
        t = _make_transport()
        msg = MagicMock()
        msg.msg_type = MSG_GLOBAL_REQUEST
        with patch.object(t, "_handle_global_request") as m:
            t._handle_channel_message(msg)
            m.assert_called_once_with(msg)

    def test_data_dispatch(self):
        t = _make_transport()
        ch = MagicMock()
        t._channels[0] = ch
        msg = MagicMock()
        msg.msg_type = MSG_CHANNEL_DATA
        msg._data = struct.pack(">I", 0)
        with patch.object(t, "_handle_channel_data") as m:
            t._handle_channel_message(msg)
            m.assert_called_once()

    def test_unknown_channel_logged(self):
        t = _make_transport()
        msg = MagicMock()
        msg.msg_type = MSG_CHANNEL_DATA
        msg._data = struct.pack(">I", 999)
        t._handle_channel_message(msg)  # should not raise


# ---- _handle_channel_open ----


class TestHandleChannelOpen:
    def test_unknown_type_sends_failure(self):
        t = _make_transport()
        msg = ChannelOpenMessage("unknown-type", 0, 1024, 512)
        with patch.object(t, "_send_message") as m:
            t._handle_channel_open(msg)
            sent = m.call_args[0][0]
            assert isinstance(sent, ChannelOpenFailureMessage)

    def test_session_type_accepted(self):
        t = _make_transport()
        msg = ChannelOpenMessage(
            CHANNEL_SESSION, 0, DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE
        )
        with patch.object(t, "_send_message"):
            t._handle_channel_open(msg)
        assert len(t._channels) == 1


# ---- _build_packet ----


class TestBuildPacket:
    def test_build_unencrypted(self):
        t = _make_transport()
        payload = b"\x01" + b"hello"
        pkt = t._build_packet(payload)
        pkt_len = struct.unpack(">I", pkt[:4])[0]
        pad_len = pkt[4]
        assert len(pkt) == 4 + pkt_len
        assert pad_len >= 4

    def test_build_with_cipher(self):
        t = _make_transport()
        t._cipher_out_active = "aes256-ctr"
        payload = b"\x01data"
        pkt = t._build_packet(payload)
        assert len(pkt) % 16 == 0


# ---- _encrypt_packet ----


class TestEncryptPacket:
    def test_no_encryptor_passthrough(self):
        t = _make_transport()
        assert t._encrypt_packet(b"data") == b"data"

    def test_with_encryptor(self):
        t = _make_transport()
        enc = MagicMock()
        enc.update.return_value = b"encrypted"
        t._encryptor_instance = enc
        t._mac_out_active = None
        result = t._encrypt_packet(b"data")
        assert result == b"encrypted"


# ---- close ----


class TestTransportClose:
    def test_close_sets_inactive(self):
        t = _make_transport(active=True)
        t.close()
        assert t._active is False

    def test_close_with_channels(self):
        t = _make_transport(active=True)
        ch = MagicMock()
        t._channels[0] = ch
        t.close()
        ch.close.assert_called_once()
        assert len(t._channels) == 0

    def test_close_socket_errors_ignored(self):
        t = _make_transport(active=True)
        t._socket.shutdown.side_effect = OSError("already closed")
        t._socket.close.side_effect = OSError("already closed")
        t.close()  # should not raise


# ---- _send_channel_data ----


class TestSendChannelData:
    def test_channel_not_found(self):
        t = _make_transport()
        with pytest.raises(TransportException, match="not found"):
            t._send_channel_data(99, b"data")

    def test_window_exceeded(self):
        t = _make_transport()
        ch = Channel(t, 0)
        ch._remote_channel_id = 1
        ch._remote_window_size = 5
        ch._remote_max_packet_size = 1000
        t._channels[0] = ch
        with pytest.raises(TransportException, match="window size exceeded"):
            t._send_channel_data(0, b"x" * 10)

    def test_max_packet_exceeded(self):
        t = _make_transport()
        ch = Channel(t, 0)
        ch._remote_channel_id = 1
        ch._remote_window_size = 100000
        ch._remote_max_packet_size = 5
        t._channels[0] = ch
        with pytest.raises(TransportException, match="max packet size exceeded"):
            t._send_channel_data(0, b"x" * 10)


# ---- _send_channel_window_adjust ----


class TestSendChannelWindowAdjust:
    def test_missing_channel_returns(self):
        t = _make_transport()
        t._send_channel_window_adjust(99, 1024)  # should not raise

    def test_success(self):
        t = _make_transport()
        ch = Channel(t, 0)
        ch._remote_channel_id = 1
        ch._local_window_size = 0
        t._channels[0] = ch
        with patch.object(t, "_send_message"):
            t._send_channel_window_adjust(0, 1024)
        assert ch._local_window_size == 1024


# ---- _send_channel_request ----


class TestSendChannelRequest:
    def test_missing_channel_raises(self):
        t = _make_transport()
        with pytest.raises(TransportException, match="not found"):
            t._send_channel_request(99, "exec", True, b"ls")

    def test_success(self):
        t = _make_transport()
        ch = Channel(t, 0)
        ch._remote_channel_id = 1
        t._channels[0] = ch
        with patch.object(t, "_send_message"):
            t._send_channel_request(0, "exec", True, b"ls")


# ---- _send_channel_eof ----


class TestSendChannelEof:
    def test_missing_channel_returns(self):
        t = _make_transport()
        t._send_channel_eof(99)  # should not raise


# ---- _send_global_request ----


class TestSendGlobalRequest:
    def test_not_active_raises(self):
        t = _make_transport(active=False)
        with pytest.raises(TransportException, match="not active"):
            t._send_global_request("test", True)


# ---- _handle_service_request ----


class TestHandleServiceRequest:
    def test_userauth_service_accepted(self):
        t = _make_transport(server_mode=True)
        data = bytearray()
        data.extend(write_string(SERVICE_USERAUTH))
        msg = MagicMock()
        msg._data = bytes(data)
        with patch.object(t, "_send_message") as m:
            t._handle_service_request(msg)
            sent = m.call_args[0][0]
            assert isinstance(sent, ServiceAcceptMessage)

    def test_unknown_service_logged(self):
        t = _make_transport(server_mode=True)
        data = bytearray()
        data.extend(write_string("ssh-unknown"))
        msg = MagicMock()
        msg._data = bytes(data)
        with patch.object(t, "_send_message"):
            t._handle_service_request(msg)  # should not raise


# ---- _handle_userauth_request ----


class TestHandleUserauthRequest:
    def test_no_server_interface_sends_failure(self):
        t = _make_transport(server_mode=True)
        t._server_interface = None
        msg = MagicMock()
        msg._data = b""
        with patch.object(t, "_send_message") as m:
            t._handle_userauth_request(msg)
            sent = m.call_args[0][0]
            assert isinstance(sent, UserAuthFailureMessage)


# ---- _check_rekey ----


class TestCheckRekey:
    def test_not_active_returns(self):
        t = _make_transport(active=False)
        t._check_rekey()  # should not raise

    def test_already_in_progress_returns(self):
        t = _make_transport(active=True)
        t._kex_in_progress = True
        t._check_rekey()  # should not raise


# ---- get_server_host_key ----


class TestGetServerHostKey:
    def test_no_blob_returns_none(self):
        t = _make_transport()
        assert t.get_server_host_key() is None

    def test_invalid_blob_returns_none(self):
        t = _make_transport()
        t._server_host_key_blob = b"invalid"
        assert t.get_server_host_key() is None


# ---- _handle_channel_data etc ----


class TestChannelHandlers:
    def _transport_with_channel(self):
        t = _make_transport()
        ch = MagicMock(spec=Channel)
        ch._remote_channel_id = 1
        t._channels[0] = ch
        return t, ch

    def test_handle_channel_eof(self):
        t, ch = self._transport_with_channel()
        msg = MagicMock()
        msg._data = struct.pack(">I", 0)
        t._handle_channel_eof(msg)
        ch._handle_eof.assert_called_once()

    def test_handle_channel_window_adjust(self):
        t, ch = self._transport_with_channel()
        msg = MagicMock()
        msg._data = struct.pack(">II", 0, 4096)
        t._handle_channel_window_adjust(msg)
        ch._handle_window_adjust.assert_called_once_with(4096)

    def test_handle_channel_success(self):
        t, ch = self._transport_with_channel()
        msg = MagicMock()
        msg._data = struct.pack(">I", 0)
        t._handle_channel_success(msg)
        ch._handle_request_success.assert_called_once()

    def test_handle_channel_failure(self):
        t, ch = self._transport_with_channel()
        msg = MagicMock()
        msg._data = struct.pack(">I", 0)
        t._handle_channel_failure(msg)
        ch._handle_request_failure.assert_called_once()

    def test_handle_channel_close(self):
        t = _make_transport()
        ch = MagicMock(spec=Channel)
        ch._handling_request = False
        ch._close_sent = True
        ch._close_received = True
        ch._remote_channel_id = 7
        t._channels[5] = ch
        msg = ChannelCloseMessage(recipient_channel=5)
        t._handle_channel_close(msg)
        ch._handle_close.assert_called_once()
        assert 5 not in t._channels

    def test_handle_channel_data(self):
        t = _make_transport()
        ch = MagicMock(spec=Channel)
        t._channels[5] = ch
        msg = ChannelDataMessage(recipient_channel=5, data=b"hello")
        t._handle_channel_data(msg)
        ch._handle_data.assert_called_once_with(b"hello")

    def test_handle_channel_extended_data(self):
        t, ch = self._transport_with_channel()
        data = struct.pack(">II", 0, 1)  # channel 0, type 1 (stderr)
        data += write_string(b"err output")
        msg = MagicMock()
        msg._data = data
        t._handle_channel_extended_data(msg)
        ch._handle_extended_data.assert_called_once()

    def test_handle_channel_request(self):
        t = _make_transport()
        ch = MagicMock(spec=Channel)
        ch._remote_channel_id = 99
        ch._close_deferred = False
        ch._handle_request.return_value = True
        t._channels[0] = ch
        data = struct.pack(">I", 0)
        data += write_string("exec")
        data += write_boolean(True)
        msg = MagicMock()
        msg._data = data
        with patch.object(t, "_send_message"):
            t._handle_channel_request(msg)
        ch._handle_request.assert_called_once()


# ---- _handle_global_request ----


class TestHandleGlobalRequest:
    def test_unknown_request_sends_failure(self):
        t = _make_transport()
        data = write_string("unknown-request")
        data += write_boolean(True)
        msg = MagicMock()
        msg._data = data
        with patch.object(t, "_send_message") as m:
            t._handle_global_request(msg)
            sent = m.call_args[0][0]
            assert sent.msg_type == MSG_REQUEST_FAILURE

    def test_tcpip_forward_no_interface(self):
        t = _make_transport()
        data = write_string("tcpip-forward")
        data += write_boolean(True)
        data += write_string("0.0.0.0")
        data += write_uint32(8080)
        msg = MagicMock()
        msg._data = data
        with patch.object(t, "_send_message") as m:
            t._handle_global_request(msg)
            sent = m.call_args[0][0]
            assert sent.msg_type == MSG_REQUEST_FAILURE


# ---- _handle_tcpip_forward_request ----


class TestHandleTcpipForward:
    def test_no_server_interface_returns_false(self):
        t = _make_transport()
        data = write_string("0.0.0.0") + write_uint32(8080)
        assert t._handle_tcpip_forward_request(data) is False

    def test_with_server_interface(self):
        t = _make_transport(server_mode=True)
        iface = MagicMock()
        iface.check_port_forward_request.return_value = True
        t._server_interface = iface
        data = write_string("0.0.0.0") + write_uint32(8080)
        assert t._handle_tcpip_forward_request(data) is True

    def test_malformed_data_raises(self):
        t = _make_transport()
        with pytest.raises(ProtocolException):
            t._handle_tcpip_forward_request(b"")


# ---- _handle_cancel_tcpip_forward_request ----


class TestHandleCancelTcpipForward:
    def test_no_server_interface_returns_false(self):
        t = _make_transport()
        data = write_string("0.0.0.0") + write_uint32(8080)
        assert t._handle_cancel_tcpip_forward_request(data) is False

    def test_malformed_data_raises(self):
        t = _make_transport()
        with pytest.raises(ProtocolException):
            t._handle_cancel_tcpip_forward_request(b"")


# ---- _activate_outbound_encryption ----


class TestActivateEncryption:
    def test_no_cipher_returns(self):
        t = _make_transport()
        t._activate_outbound_encryption()  # should not raise

    def test_no_iv_raises(self):
        t = _make_transport()
        t._cipher_c2s = "aes256-ctr"
        t._encryption_key_c2s = b"k" * 32
        t._iv_c2s = None
        with pytest.raises(TransportException, match="not fully negotiated"):
            t._activate_outbound_encryption()

    def test_inbound_no_cipher_returns(self):
        t = _make_transport()
        t._activate_inbound_encryption()  # should not raise

    def test_inbound_no_iv_raises(self):
        t = _make_transport()
        t._cipher_s2c = "aes256-ctr"
        t._encryption_key_s2c = b"k" * 32
        t._iv_s2c = None
        with pytest.raises(TransportException, match="not fully negotiated"):
            t._activate_inbound_encryption()


# ---- _build_direct_tcpip_data ----


class TestBuildDirectTcpip:
    def test_success(self):
        t = _make_transport()
        t._socket.getsockname.return_value = ("127.0.0.1", 12345)
        data = t._build_direct_tcpip_data(("remote", 80))
        assert b"remote" in data

    def test_socket_error_fallback(self):
        t = _make_transport()
        t._socket.getsockname.side_effect = OSError("bad")
        data = t._build_direct_tcpip_data(("remote", 80))
        assert b"remote" in data


# ---- _build_keyboard_interactive_data ----


class TestBuildKeyboardInteractiveData:
    def test_returns_bytes(self):
        t = _make_transport()
        data = t._build_keyboard_interactive_data()
        assert isinstance(data, bytes)
        assert len(data) > 0


class TestChannelTransportLockOrder:
    def test_send_does_not_deadlock_with_reader_dispatching_data(self):
        """The reader holds the transport lock and then takes the channel lock
        to deliver data; a concurrent send() must not hold the channel lock
        while waiting for the transport lock (seen live during a rekey)."""
        import threading
        import time

        t = _make_transport()
        t._active = True
        ch = Channel(t, 0)
        ch._remote_channel_id = 9
        ch._remote_window_size = 1 << 20
        ch._remote_max_packet_size = 32768
        t._channels[0] = ch
        reader_holds_lock = threading.Event()

        def reader():
            with t._lock:
                reader_holds_lock.set()
                time.sleep(0.2)  # the sender is now waiting for t._lock
                ch._handle_data(b"incoming")

        th = threading.Thread(target=reader, daemon=True)
        th.start()
        assert reader_holds_lock.wait(2)
        sender = threading.Thread(target=lambda: ch.send(b"outgoing"), daemon=True)
        with patch.object(t, "_send_message"):
            sender.start()
            sender.join(5)
            th.join(5)
        assert not sender.is_alive() and not th.is_alive(), "deadlocked"
        assert ch.recv(100) == b"incoming"


class TestRecvRobustness:
    def test_mid_packet_timeout_keeps_waiting(self):
        """A timeout after part of a packet was consumed must not abandon it."""
        t = _make_transport()
        t._active = True
        t._socket.recv.side_effect = [socket.timeout(), b"rest-of-packet"]
        assert t._recv_bytes(14, mid_packet=True) == b"rest-of-packet"

    def test_timeout_between_packets_still_raises(self):
        t = _make_transport()
        t._active = True
        t._socket.recv.side_effect = socket.timeout()
        with pytest.raises(TransportException, match="Timeout"):
            t._recv_bytes(4)

    def test_mid_packet_timeout_eventually_marks_stream_unusable(self):
        import spindlex.transport.transport as transport_mod

        t = _make_transport()
        t._active = True
        t._socket.recv.side_effect = socket.timeout()
        with patch.object(transport_mod, "_MID_PACKET_TIMEOUT", 0.0):
            with pytest.raises(TransportException, match="middle of a packet"):
                t._recv_bytes(10, mid_packet=True)
        with pytest.raises(TransportException, match="desynchronised"):
            t._recv_packet()

    def test_undecodable_text_is_a_protocol_error(self):
        t = _make_transport()
        t._active = True
        with patch.object(t, "_recv_packet", return_value=b"x" * 16):
            with patch.object(
                t,
                "_dispatch_packet",
                side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"),
            ):
                with pytest.raises(ProtocolException, match="Invalid text"):
                    t._read_message()


class TestUnsolicitedForwardedChannel:
    def _open_data(self, port: int) -> bytes:
        return (
            write_string("127.0.0.1")
            + struct.pack(">I", port)
            + write_string("10.0.0.1")
            + struct.pack(">I", 5555)
        )

    def test_rejected_without_forward_manager(self):
        t = _make_transport()
        with patch.object(t, "_send_message") as send:
            t._handle_forwarded_tcpip_open(7, 1000, 1000, self._open_data(4000))
        sent = send.call_args[0][0]
        assert isinstance(sent, ChannelOpenFailureMessage)
        assert t._channels == {}

    def test_rejected_for_port_not_requested(self):
        t = _make_transport()
        manager = MagicMock()
        manager.has_remote_forward.return_value = False
        t._port_forwarding_manager = manager
        with patch.object(t, "_send_message") as send:
            t._handle_forwarded_tcpip_open(7, 1000, 1000, self._open_data(4000))
        assert isinstance(send.call_args[0][0], ChannelOpenFailureMessage)
        manager.handle_forwarded_connection.assert_not_called()


class TestServerAuthAccounting:
    def _request(self, method: str, method_data: bytes = b"") -> MagicMock:
        msg = MagicMock()
        msg._data = (
            write_string("alice")
            + write_string("ssh-connection")
            + write_string(method)
            + method_data
        )
        return msg

    def _server_transport(self):
        t = _make_transport()
        t._server_mode = True
        t._session_id = b"session"
        t._userauth_service_accepted = True
        iface = MagicMock()
        iface.get_banner.return_value = None
        iface.get_allowed_auths.return_value = ["password"]
        t._server_interface = iface
        return t, iface

    def test_none_probe_is_not_a_failed_attempt(self):
        t, iface = self._server_transport()
        with patch.object(t, "_send_message") as send:
            for _ in range(10):
                t._handle_userauth_request(self._request("none"))
        assert t._auth_failures == 0
        iface.on_authentication_failed.assert_not_called()
        assert isinstance(send.call_args[0][0], UserAuthFailureMessage)

    def test_partial_success_is_reported_and_not_counted(self):
        from spindlex.protocol.constants import AUTH_PARTIAL

        t, iface = self._server_transport()
        iface.check_auth_password.return_value = AUTH_PARTIAL
        data = write_boolean(False) + write_string("pw")
        with patch.object(t, "_send_message") as send:
            t._handle_userauth_request(self._request("password", data))
        reply = send.call_args[0][0]
        assert isinstance(reply, UserAuthFailureMessage) and reply.partial_success
        assert t._auth_failures == 0
        assert not t._authenticated

    def test_banner_sent_once_before_first_reply(self):
        from spindlex.protocol.messages import UserAuthBannerMessage

        t, iface = self._server_transport()
        iface.get_banner.return_value = "hello\n"
        with patch.object(t, "_send_message") as send:
            t._handle_userauth_request(self._request("none"))
            t._handle_userauth_request(self._request("none"))
        sent = [c[0][0] for c in send.call_args_list]
        assert isinstance(sent[0], UserAuthBannerMessage)
        assert sum(isinstance(m, UserAuthBannerMessage) for m in sent) == 1


class TestPreKeyExchangeAndAuthOrdering:
    def _server(self):
        t = _make_transport()
        t._server_mode = True
        t._active = True
        iface = MagicMock()
        iface.get_banner.return_value = None
        iface.get_allowed_auths.return_value = ["password"]
        t._server_interface = iface
        return t, iface

    def _userauth(self, method="password", data=b""):
        msg = MagicMock()
        msg._data = (
            write_string("root")
            + write_string("ssh-connection")
            + write_string(method)
            + data
        )
        return msg

    def test_userauth_before_service_request_disconnects(self):
        t, iface = self._server()
        t._session_id = b"session"  # keys done, but no SERVICE_REQUEST
        data = write_boolean(False) + write_string("guess")
        with patch.object(t, "_disconnect") as disconnect:
            t._handle_userauth_request(self._userauth("password", data))
        disconnect.assert_called_once()
        iface.check_auth_password.assert_not_called()

    def test_userauth_without_session_disconnects(self):
        t, iface = self._server()
        t._userauth_service_accepted = True
        data = write_boolean(False) + write_string("guess")
        with patch.object(t, "_disconnect") as disconnect:
            t._handle_userauth_request(self._userauth("password", data))
        disconnect.assert_called_once()
        iface.check_auth_password.assert_not_called()

    @pytest.mark.parametrize("msg_type", [5, 50, 80, 90, 94])
    def test_non_kex_message_before_newkeys_is_rejected(self, msg_type):
        t = _make_transport()
        payload = bytes([msg_type]) + b"\x00" * 16
        packet = _wrap_packet(payload)
        with pytest.raises(ProtocolException, match="before key exchange"):
            t._dispatch_packet(packet)

    def test_ignore_before_newkeys_allowed_without_strict_kex(self):
        t = _make_transport()
        packet = _wrap_packet(bytes([2]) + write_string(b"x"))
        assert t._dispatch_packet(packet) is None

    def test_ignore_before_newkeys_rejected_with_strict_kex(self):
        t = _make_transport()
        t._strict_kex = True
        packet = _wrap_packet(bytes([2]) + write_string(b"x"))
        with pytest.raises(ProtocolException):
            t._dispatch_packet(packet)


class TestChannelNumberAllocation:
    def test_inbound_session_does_not_reuse_live_channel_number(self):
        t = _make_transport()
        t._server_mode = True
        with patch.object(t, "_send_message"):
            t._handle_session_open(500, 1000, 1000)  # gets number 0
            live = t._channels[0]
            for i in range(MAX_CHANNELS - 1):  # cycle through the rest
                t._handle_session_open(600 + i, 1000, 1000)
                newest = max(k for k in t._channels if k != 0)
                del t._channels[newest]
            t._handle_session_open(999, 1000, 1000)
        assert t._channels[0] is live
        assert len(t._channels) == 2


def _wrap_packet(payload: bytes) -> bytes:
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    length = len(payload) + 1 + padding
    return struct.pack(">IB", length, padding) + payload + b"\x00" * padding
