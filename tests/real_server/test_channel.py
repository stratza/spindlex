import pytest

from spindlex.exceptions import ChannelException

pytestmark = pytest.mark.real_server


@pytest.fixture
def real_channel(ssh_client):
    transport = ssh_client.get_transport()
    chan = transport.open_channel("session")
    yield chan
    if not chan.closed:
        chan.close()


def test_channel_send_recv(real_channel):
    real_channel.settimeout(2.0)
    real_channel.exec_command("cat")
    data = b"hello spindlex"
    real_channel.send(data)
    # Send EOF so cat flushes its block-buffered stdout and exits
    real_channel.send_eof()

    try:
        received = real_channel.recv(len(data))
        assert data in received
    except ChannelException:
        pytest.fail("Timed out waiting for data in test_channel_send_recv")


def test_channel_exec_command(real_channel):
    real_channel.settimeout(2.0)
    real_channel.exec_command("echo 123")

    out = real_channel.recv(1024)
    assert b"123" in out

    status = real_channel.recv_exit_status()
    assert status == 0


def test_channel_send_stderr(ssh_client):
    transport = ssh_client.get_transport()
    chan = transport.open_channel("session")
    chan.settimeout(2.0)
    # command that writes to stderr
    chan.exec_command("echo 'error' >&2")

    err = chan.recv_stderr(1024)
    assert b"error" in err
    chan.close()


def test_channel_timeout(real_channel):
    real_channel.settimeout(0.5)
    with pytest.raises(ChannelException, match="Timeout"):
        real_channel.recv(1024)


def test_channel_close_behavior(ssh_client):
    transport = ssh_client.get_transport()
    chan = transport.open_channel("session")
    chan.close()
    assert chan.closed
    with pytest.raises(ChannelException, match="closed"):
        chan.send(b"data")


def test_multiple_channels_real(ssh_client):
    transport = ssh_client.get_transport()
    c1 = transport.open_channel("session")
    c2 = transport.open_channel("session")

    c1.settimeout(2.0)
    c2.settimeout(2.0)

    c1.exec_command("echo 1")
    c2.exec_command("echo 2")

    assert b"1" in c1.recv(1024)
    assert b"2" in c2.recv(1024)

    c1.close()
    c2.close()
