"""Extended transport.py tests - covering more uncovered lines."""

from __future__ import annotations

import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import (
    TransportException,
)
from spindlex.protocol.constants import (
    AUTH_KEYBOARD_INTERACTIVE,
    MSG_DEBUG,
    MSG_KEXINIT,
)
from spindlex.protocol.messages import (
    DisconnectMessage,
    Message,
    UserAuthRequestMessage,
)
from spindlex.transport.transport import Transport


def _make_sock():
    s = MagicMock(spec=socket.socket)
    s.fileno.return_value = 3
    s.gettimeout.return_value = None
    return s


def _make_transport(**kw):
    t = Transport(_make_sock())
    for k, v in kw.items():
        setattr(t, k, v)
    return t


class TestKeyboardInteractiveAuthExtended:
    def test_auth_ki_success(self):
        t = _make_transport(_active=True, _userauth_service_requested=False)
        handler = MagicMock()
        with patch.object(t, "_request_userauth_service") as req:
            with patch(
                "spindlex.auth.keyboard_interactive.KeyboardInteractiveAuth"
            ) as mock_auth:
                mock_auth.return_value.authenticate.return_value = True
                with patch.object(t, "_send_message") as m:
                    result = t.auth_keyboard_interactive("user", handler)
                    assert result is True
                    req.assert_called_once()
                    sent = m.call_args[0][0]
                    assert isinstance(sent, UserAuthRequestMessage)
                    assert sent.method == AUTH_KEYBOARD_INTERACTIVE


class TestMessageReadingLoops:
    def test_read_message_disconnect(self):
        t = _make_transport(_active=True)
        d_msg = DisconnectMessage(11, "bye", "")
        valid_packet = struct.pack(">IBB", 16, 10, 1) + b"\x00" * 10
        with patch.object(t, "_recv_packet", return_value=valid_packet):
            with patch(
                "spindlex.protocol.utils.extract_message_from_packet",
                return_value=b"\x01...",
            ):
                with patch(
                    "spindlex.protocol.messages.Message.unpack", return_value=d_msg
                ):
                    with patch("spindlex.protocol.utils.validate_packet_structure"):
                        with pytest.raises(
                            TransportException, match="Disconnected: bye"
                        ):
                            t._read_message()

    def test_read_message_kexinit_starts_thread(self):
        t = _make_transport(_active=True, _kex_in_progress=False)
        msg = Message(MSG_KEXINIT)
        valid_packet = struct.pack(">IBB", 16, 10, 20) + b"\x00" * 10
        with patch.object(t, "_recv_packet", return_value=valid_packet):
            with patch(
                "spindlex.protocol.utils.extract_message_from_packet",
                return_value=b"\x14...",
            ):
                with patch(
                    "spindlex.protocol.messages.Message.unpack", return_value=msg
                ):
                    with patch("spindlex.protocol.utils.validate_packet_structure"):
                        with patch("threading.Thread") as th:
                            res = t._read_message(single_pump=True)
                            assert getattr(res, "msg_type", None) == 0
                            assert t._kex_in_progress is True
                            th.assert_called_once()

    def test_pump_reads_new_message(self):
        t = _make_transport()
        msg = Message(MSG_DEBUG)
        with patch.object(t, "_read_message", return_value=msg):
            assert t._pump() is msg

    def test_expect_message_channel_id_mismatch(self):
        t = _make_transport(_active=True)
        msg = MagicMock()
        msg.msg_type = 93
        msg.recipient_channel = 5
        t._message_queue.append(msg)
        with patch.object(t, "_read_message") as mock_read:
            mock_read.side_effect = TransportException("Transport is stopping")
            with pytest.raises(TransportException, match="Transport is stopping"):
                t._expect_message(93, channel_id=6)
