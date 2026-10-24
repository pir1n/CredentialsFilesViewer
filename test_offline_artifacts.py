from pathlib import Path
from types import SimpleNamespace

import pytest

from offline_artifacts import find_sid_directories, read_offline_credentials


SID = "S-1-5-21-111-222-333-1001"
GUID = "12345678-1234-1234-1234-123456789abc"


def test_offline_artifact_flow(tmp_path, monkeypatch):
    credentials = tmp_path / "Credentials"
    credentials.mkdir()
    (credentials / "AABBCCDD").write_bytes(b"synthetic credential")
    protect = tmp_path / "Protect"
    sid_dir = protect / SID
    sid_dir.mkdir(parents=True)
    (sid_dir / GUID).write_bytes(b"synthetic masterkey")
    (sid_dir / "Preferred").write_bytes(b"ignored")

    class FakeDPAPI:
        def __init__(self):
            self.masterkeys = {}
            self.backupkeys = {}

        def get_prekeys_from_password(self, sid, password):
            assert sid == SID and password == "test password"

        def decrypt_masterkey_file(self, path):
            assert Path(path).name == GUID
            self.masterkeys[GUID] = b"key"

        def decrypt_credential_file(self, path):
            assert Path(path).name == "AABBCCDD"
            return SimpleNamespace(
                target="sample", username="analyst", type=1, persist=2,
                last_written=0, unknown4_raw=b"secret", unknown3_raw=b"extra",
                description="sample description", target_alias="",
            )

    monkeypatch.setattr("pypykatz.dpapi.dpapi.DPAPI", FakeDPAPI)
    assert list(find_sid_directories(protect)) == [SID]
    result = read_offline_credentials(credentials, protect, SID, password="test password")
    assert result.file_count == 1
    assert result.masterkey_count == 1
    assert result.failures == []
    assert result.credentials[0].blob == b"secret"
    assert result.credentials[0].extra_blob == b"extra"
    assert result.credentials[0].source == str(credentials / "AABBCCDD")


def test_offline_requires_key_material(tmp_path):
    credentials = tmp_path / "Credentials"
    credentials.mkdir()
    protect = tmp_path / "Protect"
    (protect / SID).mkdir(parents=True)
    with pytest.raises(ValueError, match="Cần mật khẩu"):
        read_offline_credentials(credentials, protect, SID)
