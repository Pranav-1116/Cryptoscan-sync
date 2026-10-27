"""Native Windows qualification candidates. Skips on Linux are NOT qualification."""

import sys
from datetime import datetime, timedelta, timezone
import pytest
from inventory.host import collect, elevated, _parts, Refused
from shared_models.host_collection import HostManifest, HostInput


@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\file",
        r"\\?\C:\file",
        r"C:\scope\..\file",
        r"C:\scope\file:stream",
        r"C:\scope\NUL",
        r"C:\scope\file.",
        r"C:\scope\file ",
    ],
)
def test_windows_path_contract_refuses_ambiguous_or_remote_inputs(path):
    with pytest.raises(Refused):
        _parts(path, windows=True)


@pytest.mark.skipif(
    sys.platform != "win32", reason="Native Windows user/session required; Linux is not Windows qualification"
)
def test_native_windows_local_file_metadata_and_reparse_refusal(tmp_path):
    if elevated():
        pytest.skip("Unprivileged Windows account required; never disable the privilege guard")
    p = tmp_path / "library.dll"
    p.write_bytes(b"MZsynthetic-header-only")
    m = HostManifest(
        approval_reference="change/windows-test",
        host_id="windows-test",
        environment="test",
        platform="windows",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        inputs=[HostInput(input_id="library", kind="BINARY_METADATA", path=str(p))],
    )
    result = collect(m)
    assert result.receipts[0].status == "PARSED" and result.receipts[0].facts[0].algorithm == "UNKNOWN"
    assert not result.windows_execution_qualified  # One fixture is not OS qualification.
    alias = tmp_path / "reparse.dll"
    try:
        alias.symlink_to(p)
    except OSError:
        pytest.skip("Developer-mode symlink creation unavailable; reparse qualification still open")
    denied = collect(
        m.model_copy(update={"inputs": [HostInput(input_id="library", kind="BINARY_METADATA", path=str(alias))]})
    )
    assert denied.receipts[0].status == "UNSUPPORTED" and not denied.receipts[0].facts
