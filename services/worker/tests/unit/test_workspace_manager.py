from worker.workspace.workspace_manager import WorkspaceManager


def test_create_and_cleanup(tmp_path):
    mgr = WorkspaceManager(str(tmp_path))
    path = mgr.create("abc")
    assert path.exists()
    (path / "x.txt").write_text("ok")
    mgr.cleanup(path)
    assert not path.exists()
