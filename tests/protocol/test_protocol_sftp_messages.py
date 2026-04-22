import stat

import pytest

from spindlex.exceptions import ProtocolException
from spindlex.protocol.sftp_constants import *
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPCloseMessage,
    SFTPDataMessage,
    SFTPExtendedMessage,
    SFTPExtendedReplyMessage,
    SFTPFStatMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPLinkMessage,
    SFTPLStatMessage,
    SFTPMessage,
    SFTPMkdirMessage,
    SFTPNameMessage,
    SFTPOpenDirMessage,
    SFTPOpenMessage,
    SFTPReadDirMessage,
    SFTPReadMessage,
    SFTPRealPathMessage,
    SFTPRemoveMessage,
    SFTPRenameMessage,
    SFTPRmdirMessage,
    SFTPSetStatMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)


def test_sftp_attributes():
    attrs = SFTPAttributes()
    attrs.size = 1234
    attrs.flags |= SSH_FILEXFER_ATTR_SIZE
    attrs.uid = 1000
    attrs.gid = 1000
    attrs.flags |= SSH_FILEXFER_ATTR_UIDGID
    attrs.permissions = stat.S_IFREG | 0o644
    attrs.flags |= SSH_FILEXFER_ATTR_PERMISSIONS
    attrs.atime = 1600000000
    attrs.mtime = 1600000001
    attrs.flags |= SSH_FILEXFER_ATTR_ACMODTIME
    attrs.extended = {"test": "value"}
    attrs.flags |= SSH_FILEXFER_ATTR_EXTENDED

    data = attrs.pack()
    attrs2, offset = SFTPAttributes.unpack(data)

    assert attrs2.size == 1234
    assert attrs2.uid == 1000
    assert attrs2.gid == 1000
    assert attrs2.permissions == (stat.S_IFREG | 0o644)
    assert attrs2.atime == 1600000000
    assert attrs2.mtime == 1600000001
    assert attrs2.extended == {"test": "value"}
    assert attrs2.is_file()
    assert not attrs2.is_dir()
    assert not attrs2.is_symlink()


def test_sftp_attributes_dir():
    attrs = SFTPAttributes()
    attrs.permissions = stat.S_IFDIR | 0o755
    assert attrs.is_dir()
    assert not attrs.is_file()


def test_sftp_attributes_symlink():
    attrs = SFTPAttributes()
    attrs.permissions = stat.S_IFLNK | 0o777
    assert attrs.is_symlink()


def test_sftp_init_message():
    msg = SFTPInitMessage(version=3)
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPInitMessage)
    assert msg2.version == 3


def test_sftp_version_message():
    msg = SFTPVersionMessage(version=3, extensions={"posix-rename@openssh.com": "1"})
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPVersionMessage)
    assert msg2.version == 3
    assert msg2.extensions == {"posix-rename@openssh.com": "1"}


def test_sftp_status_message():
    msg = SFTPStatusMessage(
        request_id=1, status_code=SSH_FX_OK, message="OK", language="en"
    )
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPStatusMessage)
    assert msg2.request_id == 1
    assert msg2.status_code == SSH_FX_OK
    assert msg2.message == "OK"
    assert msg2.language == "en"


def test_sftp_open_message():
    attrs = SFTPAttributes()
    msg = SFTPOpenMessage(
        request_id=1, filename="test.txt", pflags=SSH_FXF_READ, attrs=attrs
    )
    msg.validate()
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPOpenMessage)
    assert msg2.filename == "test.txt"
    assert msg2.pflags == SSH_FXF_READ


def test_sftp_handle_message():
    msg = SFTPHandleMessage(request_id=1, handle=b"handle123")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPHandleMessage)
    assert msg2.handle == b"handle123"


def test_sftp_close_message():
    msg = SFTPCloseMessage(request_id=1, handle=b"handle123")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPCloseMessage)
    assert msg2.handle == b"handle123"


def test_sftp_read_message():
    msg = SFTPReadMessage(request_id=1, handle=b"h", offset=100, length=200)
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPReadMessage)
    assert msg2.offset == 100
    assert msg2.length == 200


def test_sftp_write_message():
    msg = SFTPWriteMessage(request_id=1, handle=b"h", offset=100, data=b"data")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPWriteMessage)
    assert msg2.offset == 100
    assert msg2.data == b"data"


def test_sftp_data_message():
    msg = SFTPDataMessage(request_id=1, data=b"filedata")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPDataMessage)
    assert msg2.data == b"filedata"


def test_sftp_stat_message():
    msg = SFTPStatMessage(request_id=1, path="/tmp/test")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPStatMessage)
    assert msg2.path == "/tmp/test"


def test_sftp_lstat_message():
    msg = SFTPLStatMessage(request_id=1, path="/tmp/test")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPLStatMessage)
    assert msg2.path == "/tmp/test"


def test_sftp_fstat_message():
    msg = SFTPFStatMessage(request_id=1, handle=b"h")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPFStatMessage)
    assert msg2.handle == b"h"


def test_sftp_attrs_message():
    attrs = SFTPAttributes()
    attrs.size = 100
    attrs.flags = SSH_FILEXFER_ATTR_SIZE
    msg = SFTPAttrsMessage(request_id=1, attrs=attrs)
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPAttrsMessage)
    assert msg2.attrs.size == 100


def test_sftp_setstat_message():
    attrs = SFTPAttributes()
    msg = SFTPSetStatMessage(request_id=1, path="p", attrs=attrs)
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPSetStatMessage)
    assert msg2.path == "p"


def test_sftp_opendir_message():
    msg = SFTPOpenDirMessage(request_id=1, path="dir")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPOpenDirMessage)
    assert msg2.path == "dir"


def test_sftp_readdir_message():
    msg = SFTPReadDirMessage(request_id=1, handle=b"h")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPReadDirMessage)
    assert msg2.handle == b"h"


def test_sftp_name_message():
    attrs = SFTPAttributes()
    msg = SFTPNameMessage(request_id=1, names=[("file", "longfile", attrs)])
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPNameMessage)
    assert len(msg2.names) == 1
    assert msg2.names[0][0] == "file"


def test_sftp_remove_message():
    msg = SFTPRemoveMessage(request_id=1, filename="f")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPRemoveMessage)
    assert msg2.filename == "f"


def test_sftp_mkdir_message():
    attrs = SFTPAttributes()
    msg = SFTPMkdirMessage(request_id=1, path="d", attrs=attrs)
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPMkdirMessage)
    assert msg2.path == "d"


def test_sftp_rmdir_message():
    msg = SFTPRmdirMessage(request_id=1, path="d")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPRmdirMessage)
    assert msg2.path == "d"


def test_sftp_realpath_message():
    msg = SFTPRealPathMessage(request_id=1, path=".")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPRealPathMessage)
    assert msg2.path == "."


def test_sftp_rename_message():
    msg = SFTPRenameMessage(request_id=1, oldpath="o", newpath="n")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPRenameMessage)
    assert msg2.oldpath == "o"
    assert msg2.newpath == "n"


def test_sftp_link_message():
    msg = SFTPLinkMessage(request_id=1, linkpath="l", targetpath="t")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPLinkMessage)
    assert msg2.linkpath == "l"
    assert msg2.targetpath == "t"


def test_sftp_extended_message():
    msg = SFTPExtendedMessage(
        request_id=1, extended_request="req", extended_data=b"data"
    )
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPExtendedMessage)
    assert msg2.extended_request == "req"
    assert msg2.extended_data == b"data"


def test_sftp_extended_reply_message():
    msg = SFTPExtendedReplyMessage(request_id=1, extended_data=b"reply")
    data = msg.pack()
    msg2 = SFTPMessage.unpack(data)
    assert isinstance(msg2, SFTPExtendedReplyMessage)
    assert msg2.extended_data == b"reply"


def test_sftp_message_unpack_errors():
    with pytest.raises(ProtocolException):
        SFTPMessage.unpack(b"1234")  # too short

    with pytest.raises(ProtocolException):
        # Length 10, but only 5 bytes provided
        SFTPMessage.unpack(b"\x00\x00\x00\x0a\x01")


def test_sftp_message_invalid_type():
    with pytest.raises(ProtocolException):
        SFTPMessage(255)


def test_sftp_open_validation():
    attrs = SFTPAttributes()
    msg = SFTPOpenMessage(request_id=1, filename="", pflags=SSH_FXF_READ, attrs=attrs)
    with pytest.raises(ProtocolException):
        msg.validate()

    msg.filename = "f"
    msg.pflags = 0  # No read or write
    with pytest.raises(ProtocolException):
        msg.validate()

    msg.pflags = SSH_FXF_READ | 0x100  # Invalid flag
    with pytest.raises(ProtocolException):
        msg.validate()
