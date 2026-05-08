import os
import json
import re
import time
import tarfile
import tempfile
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import customtkinter as ctk

# Optional: Drag & Drop
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _DND_AVAILABLE = True
except ImportError:
    _DND_AVAILABLE = False
    DND_FILES = None

# Optional: System tray
try:
    import pystray
    from PIL import Image, ImageDraw
    _TRAY_AVAILABLE = True
except ImportError:
    _TRAY_AVAILABLE = False

# Optional: Password strength
try:
    import zxcvbn as _zxcvbn_mod
    _ZXCVBN_AVAILABLE = True
except ImportError:
    _ZXCVBN_AVAILABLE = False

from crypto_core import encrypt_file, decrypt_file, decrypt_file_ex, verify_file, AuditLogger
from crypto_core.constants import PROFILES_SECURITY, PROFILES_INTEGRITY
from crypto_core.header import _read_header_from_start, _parse_header, _read_header_from_end

# -------------------------
# Persistent config
# -------------------------
_CONFIG_PATH = os.path.expanduser("~/.cryptov2_config.json")

def _load_config() -> dict:
    try:
        with open(_CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"theme": "System"}

def _save_config(cfg: dict):
    try:
        with open(_CONFIG_PATH, "w") as f:
            json.dump(cfg, f)
    except Exception:
        pass

# -------------------------
# UI bootstrap
# -------------------------
_config = _load_config()
ctk.set_appearance_mode(_config.get("theme", "System"))
ctk.set_default_color_theme("blue")

# -------------------------
# Constants
# -------------------------
COMP_CHOICES = ["none", "gz", "bz2", "xz"]
FILE_COMP_CHOICES = ["none", "zlib", "lzma"]
_THEME_CYCLE = ["System", "Light", "Dark"]
_THEME_LABELS = {"System": "⚙ System", "Light": "☀ Light", "Dark": "☾ Dark"}

ERROR_MAP = {
    "PASSWORD_INVALID": "Incorrect Password.",
    "CORRUPT_BEYOND_FEC": "File is corrupted beyond recovery.",
    "HEADER_INVALID": "Invalid or incompatible file format.",
    "TRUNCATED": "File appears truncated/incomplete.",
    "PARAMS_OUT_OF_LIMITS": "Security parameters out of safe bounds.",
    "IO_ERROR": "Read/Write error.",
}

# -------------------------
# TAR Helpers
# -------------------------
def _tar_write_mode(comp: str) -> str:
    return {"none": "w", "gz": "w:gz", "bz2": "w:bz2", "xz": "w:xz"}[comp]

def _tar_suffix(comp: str) -> str:
    return {"none": ".tar", "gz": ".tar.gz", "bz2": ".tar.bz2", "xz": ".tar.xz"}[comp]

def _ensure_ext(path: str, ext: str) -> str:
    if not path:
        return path
    _root, cur_ext = os.path.splitext(path)
    return path if cur_ext != "" else path + ext

def _win_long_path(p: str) -> str:
    if os.name != "nt": return p
    p = os.path.abspath(p)
    if p.startswith("\\\\?\\"): return p
    if p.startswith("\\\\"): return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p if len(p) >= 240 else p

def _create_tar_from_folder(folder: str, tar_path: str, comp: str, skip_special: bool, progress_cb=None) -> list:
    skipped = []
    base = os.path.abspath(folder)
    total_files = max(1, sum(len(f) for _, _, f in os.walk(base, followlinks=False)))
    mode = _tar_write_mode(comp)
    done_cnt = 0
    arcname = os.path.basename(base) or "archive"

    with tarfile.open(tar_path, mode, format=tarfile.PAX_FORMAT) as tar:
        tar.add(base, arcname=arcname, recursive=False)
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
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

def _safe_tar_extract(tar: tarfile.TarFile, out_dir: str, progress_cb=None):
    out_dir = os.path.abspath(out_dir)
    members = tar.getmembers()
    total = max(1, len(members))
    for i, member in enumerate(members):
        target_path = os.path.join(out_dir, member.name)
        abs_target = os.path.abspath(target_path)
        if not abs_target.startswith(out_dir):
            raise Exception(f"Malicious path detected (ZipSlip): {member.name}")
        if member.issym() or member.islnk():
            print(f"Skipping link {member.name} -> {member.linkname} (security)")
            continue
        if not (member.isfile() or member.isdir()):
            print(f"Skipping special file {member.name} (type: {member.type})")
            continue
        tar.extract(member, out_dir)
        if progress_cb and i % 5 == 0:
            progress_cb(i, total)
    if progress_cb:
        progress_cb(total, total)

# -------------------------
# DnD helpers
# -------------------------
def _parse_drop_data(data: str) -> list:
    """Parse tkinterdnd2 event.data into a list of file paths."""
    paths = re.findall(r'\{([^}]+)\}|(\S+)', data)
    return [a or b for a, b in paths if (a or b)]

# -------------------------
# Tray icon image
# -------------------------
def _make_tray_image() -> "Image.Image":
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([10, 28, 54, 58], radius=6, fill=(59, 142, 208))
    d.arc([18, 6, 46, 36], start=0, end=180, fill=(59, 142, 208), width=8)
    d.ellipse([27, 37, 37, 47], fill=(255, 255, 255))
    d.rectangle([30, 43, 34, 54], fill=(255, 255, 255))
    return img

# -------------------------
# Password Dialog
# -------------------------
class PasswordDialog(ctk.CTkToplevel):
    """Password entry dialog with optional real-time strength indicator."""

    def __init__(self, parent, title="Enter Password", prompt="Password:", show_strength=False):
        super().__init__(parent)
        self.title(title)
        self.geometry("420x300" if show_strength else "380x160")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        self._show_strength = show_strength

        ctk.CTkLabel(self, text=prompt, font=ctk.CTkFont(size=13, weight="bold")).pack(
            pady=(20, 5), padx=20, anchor="w")

        row_pwd = ctk.CTkFrame(self, fg_color="transparent")
        row_pwd.pack(fill="x", padx=20)
        self._pwd_var = ctk.StringVar()
        self._entry = ctk.CTkEntry(row_pwd, textvariable=self._pwd_var, show="●", width=310)
        self._entry.pack(side="left", fill="x", expand=True)
        ctk.CTkButton(row_pwd, text="👁", width=36, command=self._toggle_show).pack(side="right", padx=(5, 0))

        if show_strength:
            ctk.CTkLabel(self, text="Strength:", font=ctk.CTkFont(size=11)).pack(
                anchor="w", padx=20, pady=(12, 2))
            self._bar = ctk.CTkProgressBar(self)
            self._bar.pack(padx=20, fill="x")
            self._bar.set(0)
            self._lbl_strength = ctk.CTkLabel(
                self, text="Enter a password...", text_color="gray",
                wraplength=380, justify="left", font=ctk.CTkFont(size=11))
            self._lbl_strength.pack(anchor="w", padx=20, pady=(4, 0))
            self._pwd_var.trace_add("write", self._update_strength)

        row_btns = ctk.CTkFrame(self, fg_color="transparent")
        row_btns.pack(pady=20, padx=20, fill="x")
        ctk.CTkButton(row_btns, text="Cancel", width=100, fg_color="#666",
                      command=self._cancel).pack(side="right", padx=(5, 0))
        ctk.CTkButton(row_btns, text="OK", width=100, command=self._confirm).pack(side="right")

        self._entry.focus_set()
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.bind("<Return>", lambda _: self._confirm())
        self.bind("<Escape>", lambda _: self._cancel())

        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - self.winfo_width() // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - self.winfo_height() // 2
        self.geometry(f"+{px}+{py}")

    def _toggle_show(self):
        cur = self._entry.cget("show")
        self._entry.configure(show="" if cur == "●" else "●")

    def _update_strength(self, *_):
        if not _ZXCVBN_AVAILABLE:
            return
        pwd = self._pwd_var.get()
        if not pwd:
            self._bar.set(0)
            self._bar.configure(progress_color="#555")
            self._lbl_strength.configure(text="Enter a password...", text_color="gray")
            return
        res = _zxcvbn_mod.zxcvbn(pwd)
        score = res["score"]
        colors = ["#e74c3c", "#e67e22", "#f39c12", "#2ecc71", "#27ae60"]
        labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        t_colors = ["#e74c3c", "#e67e22", "#b8860b", "#2ecc71", "#27ae60"]
        self._bar.set((score + 1) / 5)
        self._bar.configure(progress_color=colors[score])
        fb = res.get("feedback", {})
        detail = fb.get("warning", "") or (fb.get("suggestions") or [""])[0]
        text = labels[score] + (f" — {detail}" if detail else "")
        self._lbl_strength.configure(text=text, text_color=t_colors[score])

    def _confirm(self):
        self.result = self._pwd_var.get()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

    def get_input(self) -> str | None:
        self.wait_window()
        return self.result


# -------------------------
# Main Application
# -------------------------
class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Enable DnD on this window
        if _DND_AVAILABLE:
            TkinterDnD._require(self)

        self.title("CryptoV2 - Secure Encryptor")
        self.geometry("900x720")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Operation history (in-memory, max 100 entries)
        self._history: list[dict] = []

        # Persistent audit logger
        self._audit = AuditLogger()

        # State
        self._busy = False
        self._control_event = threading.Event()
        self._control_event.set()
        self._paused = False
        self._tray_icon = None
        self._batch_files: list[str] = []

        # Profile vars
        self.profile_sec_var = ctk.StringVar(value="Standard")
        self.profile_int_var = ctk.StringVar(value="High")

        # Theme toggle row
        self._topbar = ctk.CTkFrame(self, height=32, fg_color="transparent")
        self._topbar.pack(fill="x", padx=20, pady=(10, 0))
        cur_theme = _config.get("theme", "System")
        self._btn_theme = ctk.CTkButton(
            self._topbar, text=_THEME_LABELS.get(cur_theme, "⚙ System"),
            width=100, height=26, command=self.toggle_theme)
        self._btn_theme.pack(side="right")

        # Tab view
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(pady=(5, 10), padx=20, fill="both", expand=True)

        self.tab_enc = self.tab_view.add("Encrypt")
        self.tab_dec = self.tab_view.add("Decrypt")
        self.tab_batch = self.tab_view.add("Batch")
        self.tab_history = self.tab_view.add("History")
        self.tab_audit = self.tab_view.add("Audit Log")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_batch_tab()
        self.setup_history_tab()
        self.setup_audit_tab()

        # Status bar
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.pack(fill="x", padx=20, pady=(0, 15), side="bottom")
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready", anchor="w")
        self.status_label.pack(fill="x")
        self.ctrl_frame = ctk.CTkFrame(self.status_frame, fg_color="transparent")
        self.ctrl_frame.pack(fill="x", pady=(5, 0))
        self.btn_pause = ctk.CTkButton(
            self.ctrl_frame, text="Pause", width=60, state="disabled", command=self.toggle_pause)
        self.btn_pause.pack(side="right", padx=(5, 0))
        self.progress_bar = ctk.CTkProgressBar(self.ctrl_frame)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.progress_bar.set(0)

        # Tray
        if _TRAY_AVAILABLE:
            self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -------------------------
    # Theme
    # -------------------------
    def toggle_theme(self):
        cfg = _load_config()
        cur = cfg.get("theme", "System")
        idx = _THEME_CYCLE.index(cur) if cur in _THEME_CYCLE else 0
        nxt = _THEME_CYCLE[(idx + 1) % len(_THEME_CYCLE)]
        cfg["theme"] = nxt
        _save_config(cfg)
        ctk.set_appearance_mode(nxt)
        self._btn_theme.configure(text=_THEME_LABELS[nxt])

    # -------------------------
    # Tray
    # -------------------------
    def _on_close(self):
        if not _TRAY_AVAILABLE:
            self.destroy()
            return
        ans = messagebox.askyesnocancel(
            "CryptoV2",
            "Minimize to system tray?\n\nYes = tray  |  No = exit  |  Cancel = stay open")
        if ans is None:
            return
        if ans:
            self._minimize_to_tray()
        else:
            self._exit_app()

    def _minimize_to_tray(self):
        self.withdraw()
        if self._tray_icon is not None:
            return
        img = _make_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("Open CryptoV2", self._restore_from_tray, default=True),
            pystray.MenuItem("Exit", self._tray_exit),
        )
        self._tray_icon = pystray.Icon("CryptoV2", img, "CryptoV2 - Secure Encryptor", menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _restore_from_tray(self, icon=None, item=None):
        self.after(0, self.deiconify)

    def _tray_exit(self, icon=None, item=None):
        if self._tray_icon:
            self._tray_icon.stop()
        self.after(0, self.destroy)

    def _exit_app(self):
        if self._tray_icon:
            self._tray_icon.stop()
        self.destroy()

    # -------------------------
    # History
    # -------------------------
    def _log_operation(self, op: str, filename: str, status: str, duration: float):
        entry = {
            "ts": datetime.now().strftime("%H:%M:%S"),
            "op": op,
            "file": os.path.basename(filename),
            "status": status,
            "dur": f"{duration:.1f}s",
        }
        self._history.insert(0, entry)
        if len(self._history) > 100:
            self._history.pop()
        self.after(0, self._refresh_history)

    def _refresh_history(self):
        for w in self._hist_frame.winfo_children():
            w.destroy()
        if not self._history:
            ctk.CTkLabel(self._hist_frame, text="No operations yet.",
                         text_color="gray").pack(padx=10, pady=10)
            return
        for e in self._history:
            color = "#2ecc71" if e["status"] == "OK" else "#e74c3c"
            row = ctk.CTkFrame(self._hist_frame, fg_color="transparent")
            row.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(row, text=e["ts"], width=65,
                         font=ctk.CTkFont(family="Consolas", size=11)).pack(side="left")
            ctk.CTkLabel(row, text=e["op"], width=80,
                         font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=4)
            ctk.CTkLabel(row, text=e["file"], anchor="w",
                         font=ctk.CTkFont(family="Consolas", size=11)).pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(row, text=e["status"], width=80, text_color=color,
                         font=ctk.CTkFont(size=11, weight="bold")).pack(side="right")
            ctk.CTkLabel(row, text=e["dur"], width=50,
                         font=ctk.CTkFont(family="Consolas", size=11)).pack(side="right", padx=4)

    # -------------------------
    # Tab: Encrypt
    # -------------------------
    def setup_encrypt_tab(self):
        grp_source = ctk.CTkFrame(self.tab_enc)
        grp_source.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(grp_source, text="Source Selection",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)

        row_file = ctk.CTkFrame(grp_source, fg_color="transparent")
        row_file.pack(fill="x", padx=10, pady=5)
        self.entry_enc_file = ctk.CTkEntry(
            row_file, placeholder_text="Select a file to encrypt (or drag & drop)...")
        self.entry_enc_file.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_file, text="Browse File", width=100,
                      command=self.browse_enc_file).pack(side="right")

        row_folder = ctk.CTkFrame(grp_source, fg_color="transparent")
        row_folder.pack(fill="x", padx=10, pady=5)
        self.entry_enc_folder = ctk.CTkEntry(
            row_folder, placeholder_text="...or select a folder (Auto TAR, drag & drop)")
        self.entry_enc_folder.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_folder, text="Browse Folder", width=100,
                      command=self.browse_enc_folder).pack(side="right")

        # Register DnD on encrypt entries
        if _DND_AVAILABLE:
            self._dnd_register(self.entry_enc_file, self._on_drop_enc_file)
            self._dnd_register(self.entry_enc_folder, self._on_drop_enc_folder)

        grp_opts = ctk.CTkFrame(self.tab_enc)
        grp_opts.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(grp_opts, text="Options",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)

        row_kf = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_kf.pack(fill="x", padx=10)
        self.use_keyfile_var = ctk.BooleanVar(value=False)
        self.chk_keyfile = ctk.CTkCheckBox(row_kf, text="Use Keyfile",
                                            variable=self.use_keyfile_var,
                                            command=self.toggle_keyfile_entry)
        self.chk_keyfile.pack(side="left")
        self.entry_keyfile = ctk.CTkEntry(row_kf, placeholder_text="Select keyfile...",
                                           state="disabled")
        self.entry_keyfile.pack(side="left", fill="x", expand=True, padx=10)
        self.btn_keyfile = ctk.CTkButton(row_kf, text="Browse", width=60, state="disabled",
                                          command=self.browse_keyfile)
        self.btn_keyfile.pack(side="right")

        row_comp = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_comp.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(row_comp, text="Folder Compression:").pack(side="left")
        self.comp_var = ctk.StringVar(value="none")
        ctk.CTkOptionMenu(row_comp, values=COMP_CHOICES, variable=self.comp_var,
                          width=80).pack(side="left", padx=5)
        ctk.CTkLabel(row_comp, text="|").pack(side="left", padx=10)
        ctk.CTkLabel(row_comp, text="File Compression:").pack(side="left")
        self.file_comp_var = ctk.StringVar(value="none")
        ctk.CTkOptionMenu(row_comp, values=FILE_COMP_CHOICES, variable=self.file_comp_var,
                          width=80).pack(side="left", padx=5)
        ctk.CTkLabel(row_comp, text="|").pack(side="left", padx=10)
        self.skip_special_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(row_comp, text="Skip invalid/locked",
                      variable=self.skip_special_var).pack(side="left", padx=5)

        row_opts2 = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_opts2.pack(fill="x", padx=10, pady=(0, 5))
        self.pwchk_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(row_opts2, text="Fast Password Check",
                      variable=self.pwchk_var).pack(side="left", padx=5)

        row_opts3 = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_opts3.pack(fill="x", padx=10, pady=(0, 10))
        self.hide_filename_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(row_opts3, text="Hide original filename (Privacy)",
                      variable=self.hide_filename_var).pack(side="left", padx=5)
        ctk.CTkButton(row_opts3, text="⚙ Advanced", width=80, fg_color="#555",
                      command=self.open_advanced_settings).pack(side="right", padx=5)

        self.btn_enc_action = ctk.CTkButton(
            self.tab_enc, text="Start Encryption", height=40,
            font=ctk.CTkFont(size=16, weight="bold"), command=self.run_encryption)
        self.btn_enc_action.pack(fill="x", padx=10, pady=20)

    # -------------------------
    # Tab: Decrypt
    # -------------------------
    def setup_decrypt_tab(self):
        grp_source = ctk.CTkFrame(self.tab_dec)
        grp_source.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(grp_source, text="Encrypted File",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)

        row_file = ctk.CTkFrame(grp_source, fg_color="transparent")
        row_file.pack(fill="x", padx=10, pady=5)
        self.entry_dec_file = ctk.CTkEntry(
            row_file, placeholder_text="Select .ecf file (or drag & drop)...")
        self.entry_dec_file.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_file, text="Browse", width=100,
                      command=self.browse_dec_file).pack(side="right")

        if _DND_AVAILABLE:
            self._dnd_register(self.entry_dec_file, self._on_drop_dec)

        grp_info = ctk.CTkFrame(self.tab_dec)
        grp_info.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(grp_info, text="Technical Details",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        self.info_text = ctk.CTkTextbox(
            grp_info, height=100, state="disabled",
            font=ctk.CTkFont(family="Consolas", size=11))
        self.info_text.pack(fill="x", padx=10, pady=(0, 10))

        grp_opts = ctk.CTkFrame(self.tab_dec)
        grp_opts.pack(fill="x", padx=10, pady=10)

        row_kf = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_kf.pack(fill="x", padx=10)
        self.dec_use_keyfile_var = ctk.BooleanVar(value=False)
        self.chk_dec_keyfile = ctk.CTkCheckBox(row_kf, text="Use Keyfile",
                                                variable=self.dec_use_keyfile_var,
                                                command=self.toggle_dec_keyfile_entry)
        self.chk_dec_keyfile.pack(side="left")
        self.entry_dec_keyfile = ctk.CTkEntry(
            row_kf, placeholder_text="Select keyfile...", state="disabled")
        self.entry_dec_keyfile.pack(side="left", fill="x", expand=True, padx=10)
        self.btn_dec_keyfile = ctk.CTkButton(
            row_kf, text="Browse", width=60, state="disabled",
            command=self.browse_dec_keyfile)
        self.btn_dec_keyfile.pack(side="right")

        self.keep_tar_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(grp_opts, text="Keep decrypted TAR (if extracting)",
                      variable=self.keep_tar_var).pack(anchor="w", padx=10, pady=10)

        self.btn_dec_file = ctk.CTkButton(
            self.tab_dec, text="Decrypt to File", height=40,
            command=lambda: self.run_decryption(extract=False))
        self.btn_dec_file.pack(fill="x", padx=10, pady=5)

        self.btn_dec_extract = ctk.CTkButton(
            self.tab_dec, text="Decrypt & Extract Project/Folder", height=40,
            fg_color="green", command=lambda: self.run_decryption(extract=True))
        self.btn_dec_extract.pack(fill="x", padx=10, pady=5)

        self.btn_verify = ctk.CTkButton(
            self.tab_dec, text="✔ Verify Integrity (no output)", height=36,
            fg_color="#7B5EA7", command=self.run_verify)
        self.btn_verify.pack(fill="x", padx=10, pady=5)

    # -------------------------
    # Tab: Batch Decrypt
    # -------------------------
    def setup_batch_tab(self):
        grp_top = ctk.CTkFrame(self.tab_batch)
        grp_top.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(grp_top, text="Batch Decrypt",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)

        row_btns = ctk.CTkFrame(grp_top, fg_color="transparent")
        row_btns.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(row_btns, text="+ Add Files", width=110,
                      command=self._batch_add_files).pack(side="left", padx=(0, 5))
        self.btn_batch_remove = ctk.CTkButton(
            row_btns, text="Remove Selected", width=130, fg_color="#666",
            command=self._batch_remove_selected)
        self.btn_batch_remove.pack(side="left", padx=5)
        ctk.CTkButton(row_btns, text="Clear All", width=80, fg_color="#555",
                      command=self._batch_clear).pack(side="left", padx=5)
        self._lbl_batch_count = ctk.CTkLabel(row_btns, text="0 files")
        self._lbl_batch_count.pack(side="right", padx=10)

        # File list
        self._batch_listframe = ctk.CTkScrollableFrame(self.tab_batch, height=200)
        self._batch_listframe.pack(fill="both", expand=True, padx=10, pady=5)
        self._batch_row_vars: list[tuple[ctk.BooleanVar, str]] = []

        # Output folder
        grp_out = ctk.CTkFrame(self.tab_batch)
        grp_out.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(grp_out, text="Output Folder (leave empty = same folder as each file):").pack(
            anchor="w", padx=10, pady=(5, 2))
        row_out = ctk.CTkFrame(grp_out, fg_color="transparent")
        row_out.pack(fill="x", padx=10, pady=(0, 10))
        self.entry_batch_outdir = ctk.CTkEntry(row_out, placeholder_text="(same folder as source)")
        self.entry_batch_outdir.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_out, text="Browse", width=80,
                      command=self._batch_browse_outdir).pack(side="right")

        self.btn_batch_start = ctk.CTkButton(
            self.tab_batch, text="▶ Start Batch Decrypt", height=40,
            font=ctk.CTkFont(size=15, weight="bold"), command=self.run_batch_decrypt)
        self.btn_batch_start.pack(fill="x", padx=10, pady=10)

    # -------------------------
    # Tab: History
    # -------------------------
    def setup_history_tab(self):
        top_row = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        top_row.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(top_row, text="Operation History",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
        ctk.CTkButton(top_row, text="Clear History", width=110, fg_color="#555",
                      command=self._clear_history).pack(side="right", padx=10)

        # Header row
        hdr = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        hdr.pack(fill="x", padx=10)
        for lbl, w in [("Time", 65), ("Op", 80), ("File", 0), ("Status", 80), ("Dur", 50)]:
            ctk.CTkLabel(hdr, text=lbl, width=w if w else None,
                         font=ctk.CTkFont(size=11, weight="bold"),
                         anchor="w" if w == 0 else "center").pack(
                side="left", padx=2, fill="x" if w == 0 else None, expand=(w == 0))

        self._hist_frame = ctk.CTkScrollableFrame(self.tab_history)
        self._hist_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self._refresh_history()

    def _clear_history(self):
        self._history.clear()
        self._refresh_history()

    # -------------------------
    # Tab: Audit Log
    # -------------------------
    def setup_audit_tab(self):
        top_row = ctk.CTkFrame(self.tab_audit, fg_color="transparent")
        top_row.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(top_row, text="Persistent Audit Log",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)

        # Filter
        self._audit_filter_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(top_row, values=["All", "OK", "Error"],
                          variable=self._audit_filter_var, width=80,
                          command=lambda _: self._refresh_audit()).pack(side="right", padx=5)
        ctk.CTkLabel(top_row, text="Filter:").pack(side="right")

        ctk.CTkButton(top_row, text="⟳ Refresh", width=90,
                      command=self._refresh_audit).pack(side="right", padx=5)
        ctk.CTkButton(top_row, text="📂 Open Folder", width=110, fg_color="#555",
                      command=self._open_log_folder).pack(side="right", padx=5)

        # Column headers
        hdr = ctk.CTkFrame(self.tab_audit, fg_color="transparent")
        hdr.pack(fill="x", padx=10)
        _cols = [("Timestamp", 145), ("Op", 90), ("File", 0),
                 ("Size", 65), ("Profile", 80), ("Dur(s)", 55), ("Status", 65)]
        for lbl, w in _cols:
            ctk.CTkLabel(hdr, text=lbl, width=w if w else None,
                         font=ctk.CTkFont(size=11, weight="bold"),
                         anchor="w" if w == 0 else "center").pack(
                side="left", padx=2, fill="x" if w == 0 else None, expand=(w == 0))

        self._audit_frame = ctk.CTkScrollableFrame(self.tab_audit)
        self._audit_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self._lbl_audit_info = ctk.CTkLabel(self.tab_audit, text="",
                                             font=ctk.CTkFont(size=10), text_color="gray")
        self._lbl_audit_info.pack(anchor="w", padx=12, pady=(0, 5))

        self._refresh_audit()

    def _refresh_audit(self):
        entries = self._audit.read_recent(max_entries=500)
        flt = self._audit_filter_var.get()
        if flt != "All":
            entries = [e for e in entries if e.get("status") == flt]

        for w in self._audit_frame.winfo_children():
            w.destroy()

        if not entries:
            ctk.CTkLabel(self._audit_frame, text="No audit entries found.",
                         text_color="gray").pack(padx=10, pady=10)
            self._lbl_audit_info.configure(
                text=f"Log: {self._audit.get_current_log_path() or 'N/A'}")
            return

        for e in entries:
            status = e.get("status", "?")
            color = "#2ecc71" if status == "OK" else "#e74c3c"
            row = ctk.CTkFrame(self._audit_frame, fg_color="transparent")
            row.pack(fill="x", padx=5, pady=1)

            ts = e.get("ts", "")[:19].replace("T", " ")
            op = e.get("op", "")
            fname = e.get("file", "")
            size = f"{e['size_mb']:.2f}" if e.get("size_mb") is not None else "-"
            prof = e.get("profile_sec") or "-"
            dur = f"{e['duration_s']:.1f}" if e.get("duration_s") is not None else "-"

            ctk.CTkLabel(row, text=ts, width=145,
                         font=ctk.CTkFont(family="Consolas", size=10)).pack(side="left")
            ctk.CTkLabel(row, text=op, width=90,
                         font=ctk.CTkFont(size=10, weight="bold")).pack(side="left", padx=2)
            ctk.CTkLabel(row, text=fname, anchor="w",
                         font=ctk.CTkFont(family="Consolas", size=10)).pack(
                side="left", fill="x", expand=True)
            ctk.CTkLabel(row, text=size, width=65,
                         font=ctk.CTkFont(family="Consolas", size=10)).pack(side="right")
            ctk.CTkLabel(row, text=status, width=65, text_color=color,
                         font=ctk.CTkFont(size=10, weight="bold")).pack(side="right", padx=2)
            ctk.CTkLabel(row, text=dur, width=55,
                         font=ctk.CTkFont(family="Consolas", size=10)).pack(side="right")
            ctk.CTkLabel(row, text=prof, width=80,
                         font=ctk.CTkFont(size=10)).pack(side="right", padx=2)

        log_path = self._audit.get_current_log_path() or "N/A"
        self._lbl_audit_info.configure(
            text=f"{len(entries)} entries shown  |  {log_path}")

    def _open_log_folder(self):
        log_dir = self._audit.get_log_dir()
        if os.name == "nt":
            os.startfile(log_dir)
        elif os.name == "posix":
            import subprocess
            subprocess.Popen(["xdg-open", log_dir])

    # -------------------------
    # DnD helpers
    # -------------------------
    def _dnd_register(self, widget: ctk.CTkEntry, callback):
        """Register a drop target on a CTkEntry widget."""
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", callback)
        except Exception:
            pass  # DnD not supported on this widget

    def _on_drop_enc_file(self, event):
        paths = _parse_drop_data(event.data)
        if paths:
            p = paths[0]
            if os.path.isdir(p):
                self.entry_enc_folder.delete(0, "end")
                self.entry_enc_folder.insert(0, p)
                self.entry_enc_file.delete(0, "end")
            else:
                self.entry_enc_file.delete(0, "end")
                self.entry_enc_file.insert(0, p)
                self.entry_enc_folder.delete(0, "end")

    def _on_drop_enc_folder(self, event):
        paths = _parse_drop_data(event.data)
        if paths:
            p = paths[0]
            if os.path.isdir(p):
                self.entry_enc_folder.delete(0, "end")
                self.entry_enc_folder.insert(0, p)
                self.entry_enc_file.delete(0, "end")
            else:
                self.entry_enc_file.delete(0, "end")
                self.entry_enc_file.insert(0, p)
                self.entry_enc_folder.delete(0, "end")

    def _on_drop_dec(self, event):
        paths = _parse_drop_data(event.data)
        if paths:
            p = paths[0]
            self.entry_dec_file.delete(0, "end")
            self.entry_dec_file.insert(0, p)
            self.show_file_info(p)

    # -------------------------
    # Batch helpers
    # -------------------------
    def _batch_add_files(self):
        files = filedialog.askopenfilenames(
            title="Select .ecf files",
            filetypes=[("Encrypted", "*.ecf"), ("All", "*.*")])
        for f in files:
            if f not in self._batch_files:
                self._batch_files.append(f)
        self._refresh_batch_list()

    def _batch_remove_selected(self):
        keep = []
        for var, path in self._batch_row_vars:
            if not var.get():
                keep.append(path)
        self._batch_files = keep
        self._refresh_batch_list()

    def _batch_clear(self):
        self._batch_files.clear()
        self._refresh_batch_list()

    def _batch_browse_outdir(self):
        d = filedialog.askdirectory(title="Select output folder")
        if d:
            self.entry_batch_outdir.delete(0, "end")
            self.entry_batch_outdir.insert(0, d)

    def _refresh_batch_list(self):
        for w in self._batch_listframe.winfo_children():
            w.destroy()
        self._batch_row_vars.clear()
        for path in self._batch_files:
            var = ctk.BooleanVar(value=False)
            self._batch_row_vars.append((var, path))
            row = ctk.CTkFrame(self._batch_listframe, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkCheckBox(row, text="", variable=var, width=20).pack(side="left")
            ctk.CTkLabel(row, text=os.path.basename(path),
                         font=ctk.CTkFont(family="Consolas", size=11),
                         anchor="w").pack(side="left", fill="x", expand=True)
        self._lbl_batch_count.configure(text=f"{len(self._batch_files)} file(s)")

    # -------------------------
    # Browse handlers
    # -------------------------
    def browse_enc_file(self):
        f = filedialog.askopenfilename()
        if f:
            self.entry_enc_file.delete(0, "end"); self.entry_enc_file.insert(0, f)
            self.entry_enc_folder.delete(0, "end")

    def browse_enc_folder(self):
        d = filedialog.askdirectory()
        if d:
            self.entry_enc_folder.delete(0, "end"); self.entry_enc_folder.insert(0, d)
            self.entry_enc_file.delete(0, "end")

    def browse_dec_file(self):
        f = filedialog.askopenfilename(filetypes=[("Encrypted", "*.ecf"), ("All", "*.*")])
        if f:
            self.entry_dec_file.delete(0, "end")
            self.entry_dec_file.insert(0, f)
            self.show_file_info(f)

    def toggle_keyfile_entry(self):
        state = "normal" if self.use_keyfile_var.get() else "disabled"
        self.entry_keyfile.configure(state=state)
        self.btn_keyfile.configure(state=state)

    def browse_keyfile(self):
        f = filedialog.askopenfilename(title="Select Keyfile")
        if f: self.entry_keyfile.delete(0, "end"); self.entry_keyfile.insert(0, f)

    def toggle_dec_keyfile_entry(self):
        state = "normal" if self.dec_use_keyfile_var.get() else "disabled"
        self.entry_dec_keyfile.configure(state=state)
        self.btn_dec_keyfile.configure(state=state)

    def browse_dec_keyfile(self):
        f = filedialog.askopenfilename(title="Select Keyfile")
        if f: self.entry_dec_keyfile.delete(0, "end"); self.entry_dec_keyfile.insert(0, f)

    def toggle_pause(self):
        if not self._busy: return
        if self._paused:
            self._control_event.set()
            self._paused = False
            self.btn_pause.configure(text="Pause", fg_color=["#3B8ED0", "#1F6AA5"])
        else:
            self._control_event.clear()
            self._paused = True
            self.btn_pause.configure(text="Resume", fg_color="orange")

    # -------------------------
    # State helpers
    # -------------------------
    def set_status(self, msg, progress=None):
        self.after(0, lambda: self.status_label.configure(text=msg))
        if progress is not None:
            self.after(0, lambda: self.progress_bar.set(progress))

    def set_busy(self, busy: bool):
        self._busy = busy
        self._paused = False
        self._control_event.set()
        state = "disabled" if busy else "normal"
        for btn in (self.btn_enc_action, self.btn_dec_file, self.btn_dec_extract,
                    self.btn_verify, self.btn_batch_start):
            btn.configure(state=state)
        self.btn_pause.configure(
            state="normal" if busy else "disabled",
            text="Pause", fg_color=["#3B8ED0", "#1F6AA5"])

    def get_keyfile_bytes(self, is_dec=False):
        use = self.dec_use_keyfile_var.get() if is_dec else self.use_keyfile_var.get()
        if not use: return None
        path = self.entry_dec_keyfile.get() if is_dec else self.entry_keyfile.get()
        if not path or not os.path.exists(path):
            return None
        MAX_KEYFILE_SIZE = 1024 * 1024
        try:
            if os.path.getsize(path) > MAX_KEYFILE_SIZE:
                messagebox.showerror("Keyfile Error", "Keyfile too large (max 1 MB).")
                return None
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            messagebox.showerror("Keyfile Error", f"Could not read keyfile: {e}")
            return None

    def show_file_info(self, filepath):
        try:
            with open(filepath, "rb") as f:
                hdr = _read_header_from_start(f) or _read_header_from_end(f)
                if not hdr:
                    self._set_info("Unable to read file header.")
                    return
                params = _parse_header(hdr[0])
                comp_flags = []
                if params['flags'] & 0x02: comp_flags.append("zlib")
                if params['flags'] & 0x08: comp_flags.append("lzma")
                comp_str = ", ".join(comp_flags) or "None"
                file_size_mb = params['file_size'] / (1024 * 1024)
                block_size = params['k'] * params['shard_size']
                num_blocks = ((params['file_size'] + block_size - 1) // block_size
                              if params['file_size'] > 0 else 0)
                overhead_pct = (params['r'] / params['k']) * 100
                info = (
                    f"Version:     {params['version']}\n"
                    f"File Size:   {file_size_mb:.2f} MB ({num_blocks} blocks)\n"
                    f"Integrity:   k={params['k']}, r={params['r']}, "
                    f"shard={params['shard_size']//1024}KB (Overhead: {overhead_pct:.0f}%)\n"
                    f"Security:    Argon2id (t={params['argon2_time']}, "
                    f"m={params['argon2_mem_kib']//1024}MB, p={params['argon2_par']})\n"
                    f"Compression: {comp_str}\n"
                    f"Filename:    {params.get('filename', '(Hidden)')}"
                )
                self._set_info(info)
        except Exception as e:
            self._set_info(f"Error reading file: {e}")

    def _set_info(self, text: str):
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", text)
        self.info_text.configure(state="disabled")

    # -------------------------
    # Advanced settings
    # -------------------------
    def open_advanced_settings(self):
        top = ctk.CTkToplevel(self)
        top.title("Advanced Encryption Settings")
        top.geometry("400x420")
        top.transient(self)
        top.grab_set()

        ctk.CTkLabel(top, text="Security Profile (Argon2)",
                     font=("Arial", 14, "bold")).pack(pady=(20, 5))
        frm_sec = ctk.CTkFrame(top)
        frm_sec.pack(pady=5, padx=20, fill="x")
        for name in PROFILES_SECURITY:
            ctk.CTkRadioButton(frm_sec, text=name, variable=self.profile_sec_var,
                               value=name).pack(anchor="w", padx=20, pady=5)

        ctk.CTkLabel(top, text="Data Integrity / Redundancy",
                     font=("Arial", 14, "bold")).pack(pady=(20, 5))
        frm_int = ctk.CTkFrame(top)
        frm_int.pack(pady=5, padx=20, fill="x")
        for name, val in PROFILES_INTEGRITY.items():
            ratio = (val['r'] / val['k']) * 100
            desc = f"{name}  (Overhead: {ratio:.0f}%, k={val['k']}, r={val['r']})"
            ctk.CTkRadioButton(frm_int, text=desc, variable=self.profile_int_var,
                               value=name).pack(anchor="w", padx=20, pady=5)

        ctk.CTkButton(top, text="Close", command=top.destroy).pack(pady=20)

    # -------------------------
    # Encryption
    # -------------------------
    def run_encryption(self):
        file_path = self.entry_enc_file.get()
        folder_path = self.entry_enc_folder.get()
        if not file_path and not folder_path:
            messagebox.showerror("Error", "Please select a file or folder.")
            return

        dlg = PasswordDialog(self, title="Encryption Password",
                             prompt="Enter Encryption Password:",
                             show_strength=True)
        password = dlg.get_input()
        if not password:
            messagebox.showwarning("Password Required", "Please enter a password to proceed.")
            return

        threading.Thread(
            target=self._encryption_thread,
            args=(file_path, folder_path, password), daemon=True).start()

    def _encryption_thread(self, file_path, folder_path, password):
        self.set_busy(True)
        tmp_tar = None
        t0 = time.time()
        out_path = "?"
        try:
            kf_bytes = self.get_keyfile_bytes(is_dec=False)
            if self.use_keyfile_var.get() and not kf_bytes:
                raise Exception("Keyfile selected but could not be read.")

            compress = self.comp_var.get()
            file_comp = self.file_comp_var.get()
            skip_special = self.skip_special_var.get()
            sec_p = PROFILES_SECURITY[self.profile_sec_var.get()]
            int_p = PROFILES_INTEGRITY[self.profile_int_var.get()]

            input_target = file_path
            original_filename = None

            if folder_path:
                self.set_status("Archiving folder...", 0)
                fd, tmp_tar = tempfile.mkstemp(suffix=_tar_suffix(compress))
                os.close(fd)
                errs = _create_tar_from_folder(
                    folder_path, tmp_tar, compress, skip_special,
                    lambda done, total: self.set_status(
                        f"Archiving: {done}/{total}", done / total if total > 0 else 0))
                if errs:
                    print("Skipped:\n" + "\n".join(errs))
                input_target = tmp_tar
                original_filename = os.path.basename(folder_path) + _tar_suffix(compress)
                out_path = folder_path + ".ecf"
            else:
                original_filename = os.path.basename(input_target)
                out_path = input_target + ".ecf"

            if self.hide_filename_var.get():
                original_filename = ""

            self.set_status("Encrypting...", 0)
            encrypt_file(
                input_file=input_target, output_file=out_path, password=password,
                keyfile=kf_bytes,
                compress_alg=file_comp if file_comp != "none" else None,
                enable_pwchk=self.pwchk_var.get(),
                k=int_p['k'], r=int_p['r'],
                argon2_t=sec_p['t'], argon2_m=sec_p['m'], argon2_p=sec_p['p'],
                control_event=self._control_event,
                progress_cb=lambda stage, done, total: self.set_status(
                    f"{stage.capitalize()}: {int(done / total * 100) if total > 0 else 0}%",
                    done / total if total > 0 else 0),
                original_filename=original_filename,
            )

            dur = time.time() - t0
            self._log_operation("Encrypt", out_path, "OK", dur)
            self._audit.log(
                "encrypt", input_target,
                output_file=out_path,
                file_size_bytes=os.path.getsize(input_target) if os.path.exists(input_target) else None,
                profile_sec=self.profile_sec_var.get(),
                profile_int=self.profile_int_var.get(),
                duration_s=dur, status="OK",
            )
            msg = f"Encryption Complete!\nSaved to: {out_path}"
            self.after(0, lambda: messagebox.showinfo("Success", msg))
        except Exception as e:
            dur = time.time() - t0
            self._log_operation("Encrypt", out_path, "Error", dur)
            self._audit.log(
                "encrypt", file_path or folder_path,
                profile_sec=self.profile_sec_var.get(),
                profile_int=self.profile_int_var.get(),
                duration_s=dur, status="Error", error=str(e),
            )
            err = str(e) or f"{type(e).__name__}"
            self.after(0, lambda: messagebox.showerror("Error", f"Encryption Failed:\n{err}"))
        finally:
            if tmp_tar and os.path.exists(tmp_tar):
                try: os.remove(tmp_tar)
                except Exception: pass
            self.set_busy(False)
            self.set_status("Ready", 0)
            self.after(0, self._refresh_audit)

    # -------------------------
    # Decryption
    # -------------------------
    def run_decryption(self, extract: bool):
        infile = self.entry_dec_file.get()
        if not infile:
            messagebox.showwarning("Input", "Select input file.")
            return

        dlg = PasswordDialog(self, title="Decryption Password",
                             prompt="Enter Decryption Password:", show_strength=False)
        password = dlg.get_input()
        if not password:
            messagebox.showwarning("Password Required", "Please enter a password to proceed.")
            return

        kf_bytes = self.get_keyfile_bytes(is_dec=True)
        if self.dec_use_keyfile_var.get() and not kf_bytes:
            messagebox.showerror("Error", "Keyfile selected but could not be read.")
            return

        metadata = {}
        try:
            with open(infile, "rb") as fq:
                h = _read_header_from_start(fq) or _read_header_from_end(fq)
                if h: metadata = _parse_header(h[0])
        except Exception:
            pass

        suggested_name = metadata.get("filename", "")
        if not suggested_name:
            suggested_name = (os.path.basename(infile)[:-4]
                              if infile.lower().endswith(".ecf")
                              else os.path.basename(infile) + ".decrypted")

        outfile = outdir = None
        if extract:
            outdir = filedialog.askdirectory(title="Extract to folder")
            if not outdir: return
        else:
            outfile = filedialog.asksaveasfilename(
                initialfile=suggested_name, title="Save Decrypted File As")
            if not outfile: return

        threading.Thread(
            target=self._decryption_thread,
            args=(infile, outfile, outdir, password, kf_bytes, extract), daemon=True).start()

    def _decryption_thread(self, f_in, outfile, outdir, password, kf_bytes, extract):
        self.set_busy(True)
        temp_dec = None
        t0 = time.time()
        try:
            self.set_status("Decrypting...", 0.1)
            dest_path = outfile
            if extract:
                fd, temp_dec = tempfile.mkstemp(prefix="dec_", suffix=".tar")
                os.close(fd)
                dest_path = temp_dec

            ok, code, msg, meta = decrypt_file_ex(
                input_file=f_in, output_file=dest_path, password=password,
                keyfile=kf_bytes, control_event=self._control_event,
                progress_cb=lambda stage, done, total: self.set_status(
                    f"{stage.capitalize()}: {int(done / total * 100) if total > 0 else 0}%",
                    done / total if total > 0 else 0))

            if not ok:
                raise Exception(f"{ERROR_MAP.get(code, f'Code {code}')}\nDetails: {msg}")

            if extract:
                self.set_status("Extracting...", 0.9)
                with tarfile.open(dest_path, "r:*") as tar:
                    _safe_tar_extract(
                        tar, outdir,
                        progress_cb=lambda done, total: self.set_status(
                            f"Extracting... {done}/{total}",
                            0.9 + done / total * 0.1 if total > 0 else 0.9))
                if self.keep_tar_var.get():
                    final_name = (meta["filename"] + ".tar" if meta.get("filename")
                                  else os.path.basename(dest_path))
                    shutil.move(dest_path, os.path.join(outdir, final_name))
                else:
                    os.remove(dest_path)

            dur = time.time() - t0
            self._log_operation("Decrypt", f_in, "OK", dur)
            self._audit.log(
                "decrypt", f_in,
                output_file=outfile or outdir,
                file_size_bytes=os.path.getsize(f_in) if os.path.exists(f_in) else None,
                duration_s=dur, status="OK",
            )
            self.after(0, lambda: messagebox.showinfo("Success", "Operation Successful!"))
        except Exception as e:
            dur = time.time() - t0
            self._log_operation("Decrypt", f_in, "Error", dur)
            self._audit.log(
                "decrypt", f_in,
                file_size_bytes=os.path.getsize(f_in) if os.path.exists(f_in) else None,
                duration_s=dur, status="Error", error=str(e),
            )
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            if temp_dec and os.path.exists(temp_dec):
                if not (extract and self.keep_tar_var.get()):
                    try: os.remove(temp_dec)
                    except Exception: pass
            self.set_busy(False)
            self.set_status("Ready", 0)
            self.after(0, self._refresh_audit)

    # -------------------------
    # Verify integrity
    # -------------------------
    def run_verify(self):
        infile = self.entry_dec_file.get()
        if not infile:
            messagebox.showwarning("Input", "Select a .ecf file first.")
            return

        dlg = PasswordDialog(self, title="Verify Integrity",
                             prompt="Enter Password:", show_strength=False)
        password = dlg.get_input()
        if not password:
            return

        kf_bytes = self.get_keyfile_bytes(is_dec=True)
        threading.Thread(
            target=self._verify_thread, args=(infile, password, kf_bytes), daemon=True).start()

    def _verify_thread(self, infile, password, kf_bytes):
        self.set_busy(True)
        t0 = time.time()
        try:
            self.set_status("Verifying...", 0.1)
            ok, code, msg, meta = verify_file(
                input_file=infile, password=password, keyfile=kf_bytes,
                progress_cb=lambda stage, done, total: self.set_status(
                    f"Verifying: {int(done / total * 100) if total > 0 else 0}%",
                    done / total if total > 0 else 0))
            dur = time.time() - t0
            if ok:
                self._log_operation("Verify", infile, "OK", dur)
                self._audit.log(
                    "verify", infile,
                    file_size_bytes=os.path.getsize(infile) if os.path.exists(infile) else None,
                    duration_s=dur, status="OK",
                )
                k, r = meta.get("k", "?"), meta.get("r", "?")
                detail = (f"File: {os.path.basename(infile)}\n"
                          f"All blocks authenticated successfully.\n"
                          f"Integrity profile: k={k}, r={r}\n"
                          f"Elapsed: {dur:.1f}s")
                self.after(0, lambda: messagebox.showinfo("Integrity OK ✔", detail))
            else:
                self._log_operation("Verify", infile, "Error", dur)
                self._audit.log(
                    "verify", infile,
                    file_size_bytes=os.path.getsize(infile) if os.path.exists(infile) else None,
                    duration_s=dur, status="Error", error=ERROR_MAP.get(code, code),
                )
                err_text = ERROR_MAP.get(code, f"Code: {code}")
                self.after(0, lambda: messagebox.showerror(
                    "Integrity Failed ✘", f"{err_text}\n\n{msg}"))
        except Exception as e:
            dur = time.time() - t0
            self._log_operation("Verify", infile, "Error", dur)
            self._audit.log(
                "verify", infile,
                file_size_bytes=os.path.getsize(infile) if os.path.exists(infile) else None,
                duration_s=dur, status="Error", error=str(e),
            )
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.set_busy(False)
            self.set_status("Ready", 0)
            self.after(0, self._refresh_audit)

    # -------------------------
    # Batch decrypt
    # -------------------------
    def run_batch_decrypt(self):
        if not self._batch_files:
            messagebox.showwarning("Batch", "Add at least one .ecf file to the list.")
            return

        dlg = PasswordDialog(self, title="Batch Decrypt",
                             prompt="Enter Password (applies to all files):",
                             show_strength=False)
        password = dlg.get_input()
        if not password:
            return

        outdir = self.entry_batch_outdir.get().strip() or None
        threading.Thread(
            target=self._batch_decrypt_thread,
            args=(list(self._batch_files), password, outdir), daemon=True).start()

    def _batch_decrypt_thread(self, files: list[str], password: str, outdir: str | None):
        self.set_busy(True)
        t0 = time.time()
        successes, failures = [], []

        for i, infile in enumerate(files, 1):
            self.set_status(f"Decrypting {i}/{len(files)}: {os.path.basename(infile)}",
                            (i - 1) / len(files))
            base = os.path.basename(infile)
            stem = base[:-4] if base.lower().endswith(".ecf") else base + ".dec"
            folder = outdir or os.path.dirname(infile) or "."
            outfile = os.path.join(folder, stem)

            # Avoid overwrite: append suffix if needed
            counter = 1
            candidate = outfile
            while os.path.exists(candidate):
                candidate = outfile + f"_{counter}"
                counter += 1
            outfile = candidate

            t1 = time.time()
            try:
                ok, code, msg, _ = decrypt_file_ex(
                    input_file=infile, output_file=outfile,
                    password=password, control_event=self._control_event)
                file_dur = time.time() - t1
                if ok:
                    successes.append(base)
                    self._log_operation("Batch Dec", infile, "OK", file_dur)
                    self._audit.log(
                        "batch_decrypt", infile, output_file=outfile,
                        file_size_bytes=os.path.getsize(infile) if os.path.exists(infile) else None,
                        duration_s=file_dur, status="OK",
                    )
                else:
                    err = ERROR_MAP.get(code, code)
                    failures.append(f"{base}: {err}")
                    self._log_operation("Batch Dec", infile, "Error", file_dur)
                    self._audit.log(
                        "batch_decrypt", infile,
                        file_size_bytes=os.path.getsize(infile) if os.path.exists(infile) else None,
                        duration_s=file_dur, status="Error", error=err,
                    )
                    try: os.remove(outfile)
                    except Exception: pass
            except Exception as e:
                file_dur = time.time() - t1
                failures.append(f"{base}: {e}")
                self._log_operation("Batch Dec", infile, "Error", file_dur)
                self._audit.log(
                    "batch_decrypt", infile,
                    file_size_bytes=os.path.getsize(infile) if os.path.exists(infile) else None,
                    duration_s=file_dur, status="Error", error=str(e),
                )

        dur = time.time() - t0
        self.set_status(f"Batch complete: {len(successes)} ok, {len(failures)} failed", 1.0)

        summary = f"Batch Decrypt Complete ({dur:.1f}s)\n\n"
        summary += f"✔ {len(successes)} succeeded\n"
        summary += f"✘ {len(failures)} failed\n"
        if failures:
            summary += "\nFailed files:\n" + "\n".join(f"  • {e}" for e in failures[:20])

        self.after(0, lambda: messagebox.showinfo("Batch Result", summary))
        self.set_busy(False)
        self.set_status("Ready", 0)
        self.after(0, self._refresh_audit)


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
