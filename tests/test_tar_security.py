import os
import tarfile
import pytest
import shutil
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main_gui import _safe_tar_extract

def create_evil_tar(path, cases):
    with tarfile.open(path, "w") as tar:
        for name, content in cases:
            # We use a trick to add files with "evil" names 
            # by creating them locally first or using TarInfo
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            import io
            tar.addfile(info, io.BytesIO(content.encode()))

def test_tar_path_traversal_prevented(tmp_path):
    out_dir = tmp_path / "output"
    out_dir.mkdir()
    
    # Cases that SHOULD BE BLOCKED
    evil_cases = [
        ("../evil.txt", "evil"),
        ("../../outside.txt", "outside"),
        ("/abs/path/evil.txt", "absolute"),
        ("../" + os.path.basename(out_dir) + "_evil.txt", "prefix trick evasion"),
    ]
    
    for name, content in evil_cases:
        print(f"Testing blocked case: {name}")
        tar_path = tmp_path / f"evil_{name.replace('/', '_').replace(':', '_').replace('\\', '_')}.tar"
        create_evil_tar(tar_path, [(name, content)])
        
        with tarfile.open(tar_path, "r") as tar:
            with pytest.raises(Exception) as excinfo:
                _safe_tar_extract(tar, str(out_dir))
            actual_msg = str(excinfo.value)
            print(f"Caught expected exception: {actual_msg}")
            assert "Malicious path" in actual_msg or "Forbidden path" in actual_msg
            
    # Case that SHOULD BE ALLOWED
    safe_cases = [
        ("safe.txt", "safe"),
        ("subdir/safe.txt", "safe in subdir"),
    ]
    tar_path = tmp_path / "safe.tar"
    create_evil_tar(tar_path, safe_cases)
    with tarfile.open(tar_path, "r") as tar:
        _safe_tar_extract(tar, str(out_dir))
    
    assert (out_dir / "safe.txt").exists()
    assert (out_dir / "subdir" / "safe.txt").exists()

if __name__ == "__main__":
    # Manual run preparation
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        test_tar_path_traversal_prevented(Path(tmp))
        print("TAR Security Test Passed!")
