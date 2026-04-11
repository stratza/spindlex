
from spindlex.protocol.sftp_constants import (
    get_message_name,
    get_status_message,
    is_error_status,
    is_success_status,
)


def test_get_status_message():
    assert get_status_message(0) == "Success"
    assert get_status_message(1) == "End of file"
    assert get_status_message(2) == "No such file or directory"
    assert "Unknown status" in get_status_message(99)


def test_get_message_name():
    assert get_message_name(1) == "SSH_FXP_INIT"
    assert get_message_name(101) == "SSH_FXP_STATUS"
    assert "UNKNOWN(255)" in get_message_name(255)


def test_status_checks():
    assert is_success_status(0)
    assert not is_success_status(1)
    assert is_error_status(1)
    assert not is_error_status(0)
