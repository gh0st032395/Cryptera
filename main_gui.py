import os
import tarfile
import tempfile
import shutil
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from crypto_core import encrypt_file, decrypt_file, decrypt_file_ex
from crypto_core.constants import PROFILES_SECURITY, PROFILES_INTEGRITY
from crypto_core.header import _read_header_from_start, _parse_header, _read_header_from_end

# -------------------------
# UI Configuration
# -------------------------
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# -------------------------
# Constants
# -------------------------
COMP_CHOICES = ["none", "gz", "bz2", "xz"]
FILE_COMP_CHOICES = ["none", "zlib", "lzma"]

ERROR_MAP = {
    "PASSWORD_INVALID": "Incorrect Password.",
    "CORRUPT_BEYOND_FEC": "File is corrupted beyond recovery.",
    "HEADER_INVALID": "Invalid or incompatible file format.",
    "TRUNCATED": "File appears truncated/incomplete.",
    "PARAMS_OUT_OF_LIMITS": "Security parameters out of safe bounds.",
    "IO_ERROR": "Read/Write error.",
    "DECOMPRESSION_BOMB": "Security alert: output size exceeds expected limit (Decompression Bomb protection).",
}

# -------------------------
# TAR Helpers
# -------------------------
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
    if os.name != "nt": return p
    p = os.path.abspath(p)
    if p.startswith("\\\\?\\"): return p
    if p.startswith("\\\\"): return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p if len(p) >= 240 else p

def _create_tar_from_folder(folder: str, tar_path: str, comp: str, skip_special: bool, progress_cb=None) -> list:
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
    """
    Prevent path traversal attacks (ZipSlip), Symlink attacks, and Hardlink attacks.
    """
    out_dir = os.path.abspath(out_dir)
    members = tar.getmembers()
    total = max(1, len(members))
    
    for i, member in enumerate(members):
        # 1. Path Traversal & Absolute Path Check
        # Normalize to avoid deceptive prefixes
        out_dir = os.path.abspath(out_dir)
        
        # Check if member.name is absolute
        if os.path.isabs(member.name):
            raise Exception(f"Malicious path detected (Absolute): {member.name}")

        target_path = os.path.join(out_dir, member.name)
        abs_target = os.path.abspath(target_path)
        
        # Use commonpath to ensure the target is strictly inside out_dir
        try:
            is_inside = os.path.commonpath([out_dir, abs_target]) == out_dir
        except ValueError:
            # Paths on different drives on Windows will raise ValueError
            is_inside = False
            
        if not is_inside:
            raise Exception(f"Malicious path detected (ZipSlip): {member.name}")
            
        # 2. Secure Extraction Logic
        if member.isfile():
            # Manual extraction with strict permissions (0o600)
            os.makedirs(os.path.dirname(abs_target), exist_ok=True)
            try:
                fileobj = tar.extractfile(member)
                if fileobj:
                    # Open with 0o600 permissions
                    fd = os.open(abs_target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, 'wb') as f_out:
                        import shutil
                        shutil.copyfileobj(fileobj, f_out)
                    fileobj.close()
            except Exception as e:
                raise Exception(f"Failed to extract {member.name}: {str(e)}")
        elif member.isdir():
            os.makedirs(abs_target, exist_ok=True)
        else:
            # Skip symlinks, hardlinks, devices, pipes etc.
            continue

        if progress_cb and i % 5 == 0:
            progress_cb(i, total)
            
    if progress_cb: progress_cb(total, total)


class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CryptoV2 - Secure Encryptor")
        self.geometry("850x650")
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Main Layout
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(pady=20, padx=20, fill="both", expand=True)

        self.tab_enc = self.tab_view.add("Encrypt")
        self.tab_dec = self.tab_view.add("Decrypt")
        
        # Profile Vars
        self.profile_sec_var = ctk.StringVar(value="Standard")
        self.profile_int_var = ctk.StringVar(value="Medium")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        # Status and Progress
        self.status_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.status_frame.pack(fill="x", padx=20, pady=(0, 20), side="bottom")

        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready", anchor="w")
        self.status_label.pack(fill="x")

        # Control Row (Pause/Resume + Progress)
        self.ctrl_frame = ctk.CTkFrame(self.status_frame, fg_color="transparent")
        self.ctrl_frame.pack(fill="x", pady=(5, 0))
        
        self.btn_pause = ctk.CTkButton(self.ctrl_frame, text="Pause", width=60, state="disabled", command=self.toggle_pause)
        self.btn_pause.pack(side="right", padx=(5,0))
        
        self.progress_bar = ctk.CTkProgressBar(self.ctrl_frame)
        self.progress_bar.pack(side="left", fill="x", expand=True)
        self.progress_bar.set(0)

        self._busy = False
        self._control_event = threading.Event()
        self._control_event.set() # Running by default
        self._paused = False

    def setup_encrypt_tab(self):
        # File Source
        grp_source = ctk.CTkFrame(self.tab_enc)
        grp_source.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(grp_source, text="Source Selection", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        # File
        row_file = ctk.CTkFrame(grp_source, fg_color="transparent")
        row_file.pack(fill="x", padx=10, pady=5)
        self.entry_enc_file = ctk.CTkEntry(row_file, placeholder_text="Select a file to encrypt...")
        self.entry_enc_file.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_file, text="Browse File", width=100, command=self.browse_enc_file).pack(side="right")

        # Folder
        row_folder = ctk.CTkFrame(grp_source, fg_color="transparent")
        row_folder.pack(fill="x", padx=10, pady=5)
        self.entry_enc_folder = ctk.CTkEntry(row_folder, placeholder_text="...or select a folder (Auto TAR)")
        self.entry_enc_folder.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_folder, text="Browse Folder", width=100, command=self.browse_enc_folder).pack(side="right")

        # Options
        grp_opts = ctk.CTkFrame(self.tab_enc)
        grp_opts.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(grp_opts, text="Options", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)

        # Keyfile
        row_kf = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_kf.pack(fill="x", padx=10)
        self.use_keyfile_var = ctk.BooleanVar(value=False)
        self.chk_keyfile = ctk.CTkCheckBox(row_kf, text="Use Keyfile", variable=self.use_keyfile_var, command=self.toggle_keyfile_entry)
        self.chk_keyfile.pack(side="left")
        self.entry_keyfile = ctk.CTkEntry(row_kf, placeholder_text="Select keyfile...", state="disabled")
        self.entry_keyfile.pack(side="left", fill="x", expand=True, padx=10)
        self.btn_keyfile = ctk.CTkButton(row_kf, text="Browse", width=60, state="disabled", command=self.browse_keyfile)
        self.btn_keyfile.pack(side="right")

        # Compressions
        row_comp = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_comp.pack(fill="x", padx=10, pady=10)

        # Folder Comp
        ctk.CTkLabel(row_comp, text="Folder Compression:").pack(side="left")
        self.comp_var = ctk.StringVar(value="none")
        self.opt_comp = ctk.CTkOptionMenu(row_comp, values=COMP_CHOICES, variable=self.comp_var, width=80)
        self.opt_comp.pack(side="left", padx=5)
        
        ctk.CTkLabel(row_comp, text="|").pack(side="left", padx=10)

        # File Comp
        ctk.CTkLabel(row_comp, text="Single File Compression:").pack(side="left")
        self.file_comp_var = ctk.StringVar(value="none")
        self.opt_file_comp = ctk.CTkOptionMenu(row_comp, values=FILE_COMP_CHOICES, variable=self.file_comp_var, width=80)
        self.opt_file_comp.pack(side="left", padx=5)

        # Skip
        ctk.CTkLabel(row_comp, text="|").pack(side="left", padx=10)
        self.skip_special_var = ctk.BooleanVar(value=True)
        self.chk_skip = ctk.CTkSwitch(row_comp, text="Skip invalid/locked", variable=self.skip_special_var)
        self.chk_skip.pack(side="left", padx=5)

        # PW Check
        row_opts2 = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_opts2.pack(fill="x", padx=10, pady=(0, 5))
        
        self.pwchk_var = ctk.BooleanVar(value=True)
        self.chk_pwchk = ctk.CTkSwitch(row_opts2, text="Fast Password Check", variable=self.pwchk_var)
        self.chk_pwchk.pack(side="left", padx=5)
        
        # Hide Filename (Privacy)
        row_opts3 = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_opts3.pack(fill="x", padx=10, pady=(0, 10))
        
        self.hide_filename_var = ctk.BooleanVar(value=False)
        self.chk_hide_filename = ctk.CTkSwitch(row_opts3, text="Hide original filename (Privacy)", variable=self.hide_filename_var)
        self.chk_hide_filename.pack(side="left", padx=5)
        
        # Advanced
        self.btn_advanced = ctk.CTkButton(row_opts3, text="⚙️ Advanced", width=80, fg_color="#555", command=self.open_advanced_settings)
        self.btn_advanced.pack(side="right", padx=5)

        # Actions
        self.btn_enc_action = ctk.CTkButton(self.tab_enc, text="Start Encryption", height=40, font=ctk.CTkFont(size=16, weight="bold"), command=self.run_encryption)
        self.btn_enc_action.pack(fill="x", padx=10, pady=20)

    def setup_decrypt_tab(self):
        grp_source = ctk.CTkFrame(self.tab_dec)
        grp_source.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(grp_source, text="Encrypted File", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        row_file = ctk.CTkFrame(grp_source, fg_color="transparent")
        row_file.pack(fill="x", padx=10, pady=5)
        self.entry_dec_file = ctk.CTkEntry(row_file, placeholder_text="Select .ecf file...")
        self.entry_dec_file.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(row_file, text="Browse", width=100, command=self.browse_dec_file).pack(side="right")
        
        # Technical Details Panel
        grp_info = ctk.CTkFrame(self.tab_dec)
        grp_info.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(grp_info, text="Technical Details", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=5)
        
        self.info_text = ctk.CTkTextbox(grp_info, height=100, state="disabled", font=ctk.CTkFont(family="Consolas", size=11))
        self.info_text.pack(fill="x", padx=10, pady=(0, 10))

        # Options
        grp_opts = ctk.CTkFrame(self.tab_dec)
        grp_opts.pack(fill="x", padx=10, pady=10)
        
        # Keyfile Decrypt
        row_kf = ctk.CTkFrame(grp_opts, fg_color="transparent")
        row_kf.pack(fill="x", padx=10)
        self.dec_use_keyfile_var = ctk.BooleanVar(value=False)
        self.chk_dec_keyfile = ctk.CTkCheckBox(row_kf, text="Use Keyfile", variable=self.dec_use_keyfile_var, command=self.toggle_dec_keyfile_entry)
        self.chk_dec_keyfile.pack(side="left")
        self.entry_dec_keyfile = ctk.CTkEntry(row_kf, placeholder_text="Select keyfile...", state="disabled")
        self.entry_dec_keyfile.pack(side="left", fill="x", expand=True, padx=10)
        self.btn_dec_keyfile = ctk.CTkButton(row_kf, text="Browse", width=60, state="disabled", command=self.browse_dec_keyfile)
        self.btn_dec_keyfile.pack(side="right")

        self.keep_tar_var = ctk.BooleanVar(value=False)
        self.chk_keep_tar = ctk.CTkSwitch(grp_opts, text="Keep decrypted TAR (if extracting)", variable=self.keep_tar_var)
        self.chk_keep_tar.pack(anchor="w", padx=10, pady=10)

        # Actions
        self.btn_dec_file = ctk.CTkButton(self.tab_dec, text="Decrypt to File", height=40, command=lambda: self.run_decryption(extract=False))
        self.btn_dec_file.pack(fill="x", padx=10, pady=5)
        
        self.btn_dec_extract = ctk.CTkButton(self.tab_dec, text="Decrypt & Extract Project/Folder", height=40, fg_color="green", command=lambda: self.run_decryption(extract=True))
        self.btn_dec_extract.pack(fill="x", padx=10, pady=5)

    def open_advanced_settings(self):
        top = ctk.CTkToplevel(self)
        top.title("Advanced Encryption Settings")
        top.geometry("400x420")
        top.transient(self) # Keep on top
        top.grab_set()
        
        # Security
        ctk.CTkLabel(top, text="Security Profile (Argon2)", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        frm_sec = ctk.CTkFrame(top)
        frm_sec.pack(pady=5, padx=20, fill="x")
        
        for name in PROFILES_SECURITY.keys():
            ctk.CTkRadioButton(frm_sec, text=name, variable=self.profile_sec_var, value=name).pack(anchor="w", padx=20, pady=5)
            
        # Integrity
        ctk.CTkLabel(top, text="Data Integrity / Redundancy", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        frm_int = ctk.CTkFrame(top)
        frm_int.pack(pady=5, padx=20, fill="x")
        
        for name in PROFILES_INTEGRITY.keys():
            val = PROFILES_INTEGRITY[name]
            # Pretty print info
            ratio = (val['r'] / val['k']) * 100
            desc = f"{name} (Redundancy: {ratio:.0f}%, k={val['k']}, r={val['r']})"
            
            rb = ctk.CTkRadioButton(frm_int, text=desc, variable=self.profile_int_var, value=name)
            rb.pack(anchor="w", padx=20, pady=5)
            
            if name in ["High", "Max"]:
                ctk.CTkLabel(frm_int, text=f"  ⚠️ Warning: High storage overhead!", text_color="orange", font=("Arial", 10)).pack(anchor="w", padx=40)
            
        ctk.CTkButton(top, text="Close", command=top.destroy).pack(pady=20)

    # -------------------------
    # Interactions
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
            self.show_file_info(f)  # Show tech details
    
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
            self.btn_pause.configure(text="Pause", fg_color=["#3B8ED0", "#1F6AA5"]) # Default blue
        else:
            self._control_event.clear()
            self._paused = True
            self.btn_pause.configure(text="Resume", fg_color="orange")

    def set_status(self, msg, progress=None):
        self.after(0, lambda: self.status_label.configure(text=msg))
        if progress is not None:
             self.after(0, lambda: self.progress_bar.set(progress))

    def set_busy(self, busy: bool):
        self._busy = busy
        self._paused = False
        self._control_event.set() # Ensure running
        
        state = "disabled" if busy else "normal"
        self.btn_enc_action.configure(state=state)
        self.btn_dec_file.configure(state=state)
        self.btn_dec_extract.configure(state=state)
        
        # Pause button logic
        self.btn_pause.configure(state="normal" if busy else "disabled", text="Pause", fg_color=["#3B8ED0", "#1F6AA5"])

    def get_keyfile_bytes(self, is_dec=False):
        use = self.dec_use_keyfile_var.get() if is_dec else self.use_keyfile_var.get()
        if not use: return None
        path = self.entry_dec_keyfile.get() if is_dec else self.entry_keyfile.get()
        if not path or not os.path.exists(path):
            return None
        
        MAX_KEYFILE_SIZE = 1024 * 1024  # 1 MB
        try:
            file_size = os.path.getsize(path)
            if file_size > MAX_KEYFILE_SIZE:
                messagebox.showerror("Keyfile Error", 
                                     f"Keyfile too large: {file_size} bytes (max {MAX_KEYFILE_SIZE//1024}KB)")
                return None
            
            with open(path, "rb") as f:
                return f.read()
        except Exception as e:
            messagebox.showerror("Keyfile Error", f"Could not read keyfile: {str(e)}")
            return None

    def ask_password(self):
        return ctk.CTkInputDialog(text="Enter Password:", title="Authentication").get_input()

    def show_file_info(self, filepath):
        """Display technical details of encrypted file in info panel"""
        try:
            with open(filepath, "rb") as f:
                hdr = _read_header_from_start(f) or _read_header_from_end(f)
                if not hdr:
                    self.info_text.configure(state="normal")
                    self.info_text.delete("1.0", "end")
                    self.info_text.insert("1.0", "Unable to read file header")
                    self.info_text.configure(state="disabled")
                    return
                    
                params = _parse_header(hdr[0])
                
                # Compression info
                comp_flags = []
                if params['flags'] & 0x02: comp_flags.append("zlib")
                if params['flags'] & 0x08: comp_flags.append("lzma")
                comp_str = ", ".join(comp_flags) if comp_flags else "None"
                
                # Calculate file size and overhead
                plain_size_mb = params['plain_size'] / (1024 * 1024)
                stored_size_mb = params['stored_size'] / (1024 * 1024)
                
                block_size = params['k'] * params['shard_size']
                num_blocks = (params['stored_size'] + block_size - 1) // block_size if params['stored_size'] > 0 else 0
                overhead_pct = (params['r'] / params['k']) * 100
                
                fname_disp = params.get('filename')
                if not fname_disp or (params['flags'] & HDR_FLAG_HAS_FILENAME == 0):
                    fname_disp = "(Hidden)"

                info = f"""Format Version: {params['version']}
Plain Size:     {plain_size_mb:.2f} MB
Stored Size:    {stored_size_mb:.2f} MB ({num_blocks} blocks)
Integrity:      k={params['k']}, r={params['r']}, shard={params['shard_size']//1024}KB (Overhead: {overhead_pct:.0f}%)
Security:       Argon2id (t={params['argon2_time']}, m={params['argon2_mem_kib']//1024}MB, p={params['argon2_par']})
Compression:    {comp_str}
Filename:       {fname_disp}"""
                
                self.info_text.configure(state="normal")
                self.info_text.delete("1.0", "end")
                self.info_text.insert("1.0", info)
                self.info_text.configure(state="disabled")
        except Exception as e:
            self.info_text.configure(state="normal")
            self.info_text.delete("1.0", "end")
            self.info_text.insert("1.0", f"Error reading file: {str(e)}")
            self.info_text.configure(state="disabled")

    # -------------------------
    # Logic
    # -------------------------
    def run_encryption(self):
        file_path = self.entry_enc_file.get()
        folder_path = self.entry_enc_folder.get()
        
        if not file_path and not folder_path:
             messagebox.showerror("Error", "Please select a file or folder.")
             return

        # Password
        pwd_dialog = ctk.CTkInputDialog(text="Enter Encryption Password:", title="Password")
        password = pwd_dialog.get_input()
        if not password:
            messagebox.showwarning("Password Required", "Please enter a password to proceed.")
            return
        
        # Thread
        threading.Thread(target=self._encryption_thread, args=(file_path, folder_path, password), daemon=True).start()

    def _encryption_thread(self, file_path, folder_path, password):
        self.set_busy(True)
        self.btn_pause.configure(state="normal")
        tmp_tar = None

        try:
            # Inputs
            # Get keyfile bytes if enabled
            kf_bytes = self.get_keyfile_bytes(is_dec=False)
            if self.use_keyfile_var.get() and not kf_bytes:
                 raise Exception("Keyfile selected but could not be read (or empty/missing).")

            compress = self.comp_var.get()     # Folder comp
            file_comp = self.file_comp_var.get() # File comp (can be 'none')
            skip_special = self.skip_special_var.get()
            
            # Profile params
            sec_p = PROFILES_SECURITY[self.profile_sec_var.get()]
            int_p = PROFILES_INTEGRITY[self.profile_int_var.get()]

            input_target = file_path
            original_filename = None
            out_path = None
            
            # 1. Handle Folder -> Tar
            if folder_path:
                self.set_status("Archiving folder...", 0)
                fd, tmp_tar = tempfile.mkstemp(suffix=_tar_suffix(compress))
                os.close(fd)
                
                errs = _create_tar_from_folder(folder_path, tmp_tar, compress, skip_special, 
                                        lambda done, total: self.set_status(f"Archiving: {done}/{total}", done/total if total > 0 else 0))
                
                if errs:
                     print("Skipped items:\n" + "\n".join(errs))
                
                input_target = tmp_tar
                # Suggest output name: foldername.tar.gz
                base_name = os.path.basename(folder_path) + _tar_suffix(compress)
                original_filename = base_name 
                out_path = folder_path + ".ecf" # Default output for folder
            else:
                original_filename = os.path.basename(input_target)
                out_path = input_target + ".ecf"
            
            # Privacy: Hide filename if requested
            if self.hide_filename_var.get():
                original_filename = ""  # Empty = hidden

            self.set_status("Encrypting...", 0)
            
            encrypt_file(
                input_file=input_target,
                output_file=out_path,
                password=password,
                keyfile=kf_bytes,
                compress_alg=file_comp if file_comp != "none" else None,
                enable_pwchk=self.pwchk_var.get(),
                k=int_p['k'], r=int_p['r'],
                argon2_t=sec_p['t'], argon2_m=sec_p['m'], argon2_p=sec_p['p'],
                control_event=self._control_event,
                progress_cb=lambda stage, done, total: self.set_status(f"{stage.capitalize()}: {int(done/total*100) if total > 0 else 0}%", done/total if total > 0 else 0),
                original_filename=original_filename # Pass it!
            )
            
            msg = f"Encryption Complete!\nSaved to: {out_path}"
            if folder_path and tmp_tar: msg += "\n(Temporary archive deleted)"
            
            self.after(0, lambda: messagebox.showinfo("Success", msg))
            
        except Exception as e:
            error_msg = str(e) if str(e) else f"{type(e).__name__}: (no message)"
            self.after(0, lambda: messagebox.showerror("Error", f"Encryption Failed:\n{error_msg}"))
        finally:
            if tmp_tar and os.path.exists(tmp_tar):
                try:
                    os.remove(tmp_tar)
                except Exception as e:
                    print(f"Warning: Could not remove temporary TAR {tmp_tar}: {e}")
            self.set_busy(False)
            self.btn_pause.configure(state="disabled")
            self.set_status("Ready", 0)


    def run_decryption(self, extract: bool):
        infile = self.entry_dec_file.get()
        if not infile:
            messagebox.showwarning("Input", "Select input file.")
            return

        # 1. Password
        pwd_dialog = ctk.CTkInputDialog(text="Enter Decryption Password:", title="Password")
        password = pwd_dialog.get_input()
        if not password:
            messagebox.showwarning("Password Required", "Please enter a password to proceed.")
            return
        
        # 2. Keyfile
        kf_bytes = self.get_keyfile_bytes(is_dec=True)
        if self.dec_use_keyfile_var.get() and not kf_bytes:
             messagebox.showerror("Error", "Keyfile selected but could not be read.")
             return

        # 3. Read Header & Metadata (Main Thread - fast enough)
        # We do this here to get the suggested filename BEFORE asking save location.
        from crypto_core.header import _read_header_from_start, _parse_header, _read_header_from_end
        metadata = {}
        try:
            with open(infile, "rb") as fq:
                 h = _read_header_from_start(fq)
                 if not h: h = _read_header_from_end(fq)
                 if h: metadata = _parse_header(h[0])
        except Exception: 
            pass # Header might be corrupt or encrypted differently, just ignore metadata.

        suggested_name = metadata.get("filename", "")
        if not suggested_name:
            if infile.lower().endswith(".ecf"):
                suggested_name = os.path.basename(infile)[:-4]
            else:
                suggested_name = os.path.basename(infile) + ".decrypted"
        
        # 4. Ask Output Location (Main Thread)
        outfile = None
        outdir = None

        if extract:
            outdir = filedialog.askdirectory(title="Extract to folder")
            if not outdir: return
        else:
            outfile = filedialog.asksaveasfilename(initialfile=suggested_name, title="Save Decrypted File As")
            if not outfile: return

        # 5. Start Thread
        threading.Thread(target=self._decryption_thread, 
                         args=(infile, outfile, outdir, password, kf_bytes, extract), 
                         daemon=True).start()
        
    def _decryption_thread(self, f_in, outfile, outdir, password, kf_bytes, extract):
        self.set_busy(True)
        self.btn_pause.configure(state="normal")
        temp_dec = None
        
        try:
            self.set_status("Decrypting...", 0.1)
            
            dest_path = outfile
            if extract:
                fd, temp_dec = tempfile.mkstemp(prefix="dec_", suffix=".tar")
                os.close(fd)
                dest_path = temp_dec

            # Decrypt
            ok, code, msg, meta = decrypt_file_ex(
                input_file=f_in, 
                output_file=dest_path, 
                password=password,
                keyfile=kf_bytes,
                control_event=self._control_event,
                progress_cb=lambda stage, done, total: self.set_status(f"{stage.capitalize()}: {int(done/total*100) if total > 0 else 0}%", done/total if total > 0 else 0)
            )

            if not ok:
                 err_text = ERROR_MAP.get(code, f"Code {code}")
                 raise Exception(f"{err_text}\nDetails: {msg}")
            
            if extract:
                # Extract TAR
                self.set_status("Extracting...", 0.9)
                try:
                    with tarfile.open(dest_path, "r:*") as tar:
                        # SAFE EXTRACT
                        _safe_tar_extract(tar, outdir, 
                                          progress_cb=lambda done, total: self.set_status(f"Extracting... {done}/{total}", 0.9 + done/total*0.1 if total > 0 else 0.9))
                    
                    if self.keep_tar_var.get():
                        # Use suggested name or generic
                        final_tar_name = os.path.basename(dest_path) 
                        if meta.get("filename"):
                            final_tar_name = meta["filename"] + ".tar"
                        
                        target_tar = os.path.join(outdir, final_tar_name)
                        shutil.move(dest_path, target_tar)
                    else:
                        os.remove(dest_path)
                        
                except Exception as e:
                    raise Exception(f"Extraction failed: {e}")

            self.after(0, lambda: messagebox.showinfo("Success", f"Operation Successful!"))

        except Exception as e:
             self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            if temp_dec and os.path.exists(temp_dec):
                if not (extract and self.keep_tar_var.get()):
                    try: 
                        os.remove(temp_dec)
                    except Exception as e:
                        print(f"Warning: Could not remove temporary file {temp_dec}: {e}")
            self.set_busy(False)
            self.btn_pause.configure(state="disabled")
            self.set_status("Ready", 0)


if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()
