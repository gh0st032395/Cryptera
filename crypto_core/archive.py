import os
import tarfile
import shutil
from typing import Callable, Optional, List

from .constants import OperationCancelledError

ProgressCallback = Optional[Callable[[int, int], None]]


def _tar_write_mode(comp: str) -> str:
    return {
        "none": "w",
        "gz": "w:gz",
        "bz2": "w:bz2",
        "xz": "w:xz",
    }[comp]


def _tar_suffix(comp: str) -> str:
    return {
        "none": ".tar",
        "gz": ".tar.gz",
        "bz2": ".tar.bz2",
        "xz": ".tar.xz",
    }[comp]


def _ensure_ext(path: str, ext: str) -> str:
    if not path:
        return path
    _root, cur_ext = os.path.splitext(path)
    if cur_ext == "":
        return path + ext
    return path


def _win_long_path(p: str) -> str:
    if os.name != "nt":
        return p
    p = os.path.abspath(p)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p if len(p) >= 240 else p


def _create_tar_from_folder(
    folder: str,
    tar_path: str,
    comp: str,
    skip_special: bool,
    progress_cb: ProgressCallback = None,
    control_event=None,
    cancel_event=None,
) -> List[str]:
    skipped = []
    base = os.path.abspath(folder)

    total_files = 0
    for _, _, filenames in os.walk(base, followlinks=False):
        total_files += len(filenames)
    total_files = max(1, total_files)

    mode = _tar_write_mode(comp)
    done_cnt = 0
    arcname = os.path.basename(base) or "archive"

    with tarfile.open(tar_path, mode, format=tarfile.PAX_FORMAT) as tar:
        tar.add(base, arcname=arcname, recursive=False)

        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            if cancel_event and cancel_event.is_set():
                raise OperationCancelledError("Operation cancelled.")
            if control_event and not control_event.is_set():
                control_event.wait()

            if skip_special:
                dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
                filenames[:] = [f for f in filenames if not os.path.islink(os.path.join(dirpath, f))]

            rel_path = os.path.relpath(dirpath, base)
            parent_arc = arcname if rel_path == "." else os.path.join(arcname, rel_path)

            for dirname in dirnames:
                full_path = os.path.join(dirpath, dirname)
                arc_path = os.path.join(parent_arc, dirname).replace(os.sep, "/")
                tar.add(full_path, arcname=arc_path, recursive=False)

            for fname in filenames:
                if cancel_event and cancel_event.is_set():
                    raise OperationCancelledError("Operation cancelled.")
                if control_event and not control_event.is_set():
                    control_event.wait()

                full_path = os.path.join(dirpath, fname)
                arc_path = os.path.join(parent_arc, fname).replace(os.sep, "/")

                try:
                    with open(_win_long_path(full_path), "rb") as f:
                        info = tar.gettarinfo(fileobj=f, arcname=arc_path)
                        tar.addfile(info, fileobj=f)
                    done_cnt += 1
                    if progress_cb and done_cnt % 10 == 0:
                        progress_cb(done_cnt, total_files)
                except Exception as e:
                    if skip_special:
                        skipped.append(f"{fname}: {e}")
                    else:
                        raise e

    if progress_cb:
        progress_cb(total_files, total_files)
    return skipped


def _safe_tar_extract(tar: tarfile.TarFile, out_dir: str, progress_cb: ProgressCallback = None):
    """
    Prevent path traversal attacks (ZipSlip), Symlink attacks, and Hardlink attacks.
    """
    out_dir = os.path.abspath(out_dir)
    members = tar.getmembers()
    total = max(1, len(members))

    for i, member in enumerate(members):
        out_dir = os.path.abspath(out_dir)

        if os.path.isabs(member.name):
            raise Exception(f"Malicious path detected (Absolute): {member.name}")

        target_path = os.path.join(out_dir, member.name)
        abs_target = os.path.abspath(target_path)

        try:
            is_inside = os.path.commonpath([out_dir, abs_target]) == out_dir
        except ValueError:
            is_inside = False

        if not is_inside:
            raise Exception(f"Malicious path detected (ZipSlip): {member.name}")

        if member.isfile():
            os.makedirs(os.path.dirname(abs_target), exist_ok=True)
            try:
                fileobj = tar.extractfile(member)
                if fileobj:
                    fd = os.open(abs_target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "wb") as f_out:
                        shutil.copyfileobj(fileobj, f_out)
                    fileobj.close()
            except Exception as e:
                raise Exception(f"Failed to extract {member.name}: {str(e)}")
        elif member.isdir():
            os.makedirs(abs_target, exist_ok=True)
        else:
            continue

        if progress_cb and i % 5 == 0:
            progress_cb(i, total)

    if progress_cb:
        progress_cb(total, total)
