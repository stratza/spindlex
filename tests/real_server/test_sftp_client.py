import pytest
from spindlex.exceptions import SFTPError

pytestmark = pytest.mark.real_server


def test_sftp_client_listdir(ssh_client):
    with ssh_client.open_sftp() as sftp:
        files = sftp.listdir(".")
        assert isinstance(files, list)
        assert len(files) >= 0


def test_sftp_client_put_get(ssh_client, tmp_path):
    local_src = tmp_path / "put.txt"
    local_dst = tmp_path / "get.txt"
    content = b"SFTP real test data"
    local_src.write_bytes(content)

    with ssh_client.open_sftp() as sftp:
        remote_path = "spindlex_test_sftp.txt"
        sftp.put(str(local_src), remote_path)
        sftp.get(remote_path, str(local_dst))
        sftp.remove(remote_path)

    assert local_dst.read_bytes() == content


def test_sftp_client_mkdir_rmdir(ssh_client):
    with ssh_client.open_sftp() as sftp:
        dirname = "spindlex_test_dir"
        if dirname in sftp.listdir("."):
            sftp.rmdir(dirname)

        sftp.mkdir(dirname)
        assert dirname in sftp.listdir(".")
        sftp.rmdir(dirname)
        assert dirname not in sftp.listdir(".")


def test_sftp_client_stat(ssh_client, tmp_path):
    local = tmp_path / "stat.txt"
    local.write_bytes(b"12345")

    with ssh_client.open_sftp() as sftp:
        remote = "spindlex_stat.txt"
        sftp.put(str(local), remote)
        attrs = sftp.stat(remote)
        assert attrs.st_size == 5
        sftp.remove(remote)


def test_sftp_client_rename(ssh_client, tmp_path):
    local = tmp_path / "rename.txt"
    local.write_bytes(b"data")

    with ssh_client.open_sftp() as sftp:
        sftp.put(str(local), "old.txt")
        sftp.rename("old.txt", "new.txt")
        assert "new.txt" in sftp.listdir(".")
        assert "old.txt" not in sftp.listdir(".")
        sftp.remove("new.txt")


def test_sftp_file_read_write(ssh_client):
    with ssh_client.open_sftp() as sftp:
        remote = "spindlex_file_test.txt"
        with sftp.open(remote, "w") as f:
            f.write(b"file context manager test")

        with sftp.open(remote, "r") as f:
            assert f.read() == b"file context manager test"

        sftp.remove(remote)


def test_sftp_client_error_handling(ssh_client):
    with ssh_client.open_sftp() as sftp:
        with pytest.raises(SFTPError):
            sftp.stat("this_file_definitely_does_not_exist_12345")
