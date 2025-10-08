#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, threading, queue, subprocess, re, ctypes, getpass, difflib, tkinter as tk
from tkinter import ttk, filedialog, messagebox

EXPORT_DEFAULT = "accesschk_filtered_logs.txt"


def is_running_elevated() -> bool:
    """Return True when the process has elevated/admin privileges."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == 0)
    except Exception:
        return False


def current_user_principal() -> str:
    """Best-effort resolution of the current user in DOMAIN\\User format."""
    try:
        user_env = os.environ.get("USERNAME")
    except Exception:
        user_env = None
    try:
        user = user_env or getpass.getuser()
    except Exception:
        user = user_env or ""
    if os.name == "nt":
        domain = os.environ.get("USERDOMAIN")
        if domain and user:
            return f"{domain}\\{user}"
    return user

# Détecte les lignes RW (format accesschk)
LINE_RW_PREFIX = re.compile(r"^\s*RW\s+", re.I)
# Pour coloration rouge (garde l’ancienne heuristique au cas où)
WRITE_REGEX = re.compile(r"(?:^|\s)(rw|w|write|write_data|file_write_data|file_write|:w|W:|WriteData|FILE_WRITE_DATA)\b", re.I)

# Extrait le premier chemin de type Windows/UNC
PATH_EXTRACT = re.compile(r"(?:[A-Za-z]:\\|\\\\[^\\]+\\)[^\r\n]*")
def extract_first_path(s: str):
    m = PATH_EXTRACT.search(s)
    return m.group(0).strip().rstrip('"') if m else None

def bundled_accesschk_path() -> str:
    base = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
    return os.path.join(base, "accesschk.exe")

def decode_bytes_with_fallback(b: bytes) -> str:
    for enc in ("utf-8", "utf-16", "cp850", "cp437", "cp1252", "latin-1"):
        try:
            return b.decode(enc, errors="strict")
        except Exception:
            continue
    return b.decode("latin-1", errors="replace")

def default_targets_string() -> str:
    if os.name == "nt":
        return "C:\\"
    return os.path.sep

class AccessChkGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AccessChk GUI v1.10")
        self.geometry("1100x800"); self.minsize(880, 620)
        self.logs=[]; self.q=queue.Queue(); self.proc=None; self.running=False
        self.BATCH_MAX=250; self._line_count=0; self._isdir_cache={}
        self.current_target = None
        self.current_principal = None
        self.default_principal = current_user_principal()
        base_dir = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
        self.storage_dir = base_dir
        self.base_scan_path = os.path.join(base_dir, "scan_initial.txt")
        self.compare_scan_path = os.path.join(base_dir, "scan_comparatif.txt")
        self.diff_output_path = os.path.join(base_dir, "scan_diff.txt")
        self.scan_mode = None
        for leftover in (self.compare_scan_path, self.diff_output_path):
            try:
                if os.path.isfile(leftover):
                    os.remove(leftover)
            except Exception:
                pass
        self._build_ui()
        self.after(0, self._enforce_standard_user)
        self.after(100, self._poll_queue)

    def _build_ui(self):
        menubar = tk.Menu(self)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Aide sur 'Principal'...", command=self._show_principal_help)
        menubar.add_cascade(label="Aide", menu=helpmenu)
        self.config(menu=menubar)

        ttk.Label(self, text="Cette application doit être lancée avec un utilisateur standard. L'utilisateur courant sera utilisé automatiquement.",
                  foreground="firebrick").pack(side=tk.TOP, fill=tk.X, padx=8, pady=(8, 0))

        frm_top = ttk.Frame(self); frm_top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)
        ttk.Label(frm_top, text="accesschk.exe :").grid(row=0, column=0, sticky=tk.W, padx=4)
        self.entry_accesschk = ttk.Entry(frm_top, width=70); self.entry_accesschk.grid(row=0, column=1, sticky=tk.W)
        self.entry_accesschk.insert(0, bundled_accesschk_path())
        ttk.Button(frm_top, text="Parcourir", command=self._browse_accesschk).grid(row=0, column=2, padx=6)

        ttk.Label(frm_top, text="Utilisateur courant :").grid(row=1, column=0, sticky=tk.W, padx=4, pady=(6,0))
        self.var_principal = tk.StringVar(value=self.default_principal or "(introuvable)")
        ttk.Label(frm_top, textvariable=self.var_principal).grid(row=1, column=1, sticky=tk.W, pady=(6,0))
        btns = ttk.Frame(frm_top); btns.grid(row=1, column=2, padx=6, pady=(6,0))
        self.btn_scan_base = ttk.Button(btns, text="Scan initial", command=lambda: self._on_scan("baseline"))
        self.btn_scan_base.pack(side=tk.LEFT)
        self.btn_scan_compare = ttk.Button(btns, text="Scan comparaison", command=lambda: self._on_scan("compare"))
        self.btn_scan_compare.pack(side=tk.LEFT, padx=(6,0))
        self.btn_stop = ttk.Button(btns, text="Stop", command=self._on_stop, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=(6,0))

        ttk.Label(frm_top, text="Cibles (séparer par ;) :").grid(row=2, column=0, sticky=tk.W, padx=4, pady=(6,0))
        self.entry_target = ttk.Entry(frm_top, width=70); self.entry_target.grid(row=2, column=1, sticky=tk.W, pady=(6,0))
        self.entry_target.insert(0, default_targets_string())
        ttk.Button(frm_top, text="Parcourir", command=self._browse_target_replace).grid(row=2, column=2, padx=6, pady=(6,0))

        frm_filter = ttk.Frame(self); frm_filter.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)
        ttk.Label(frm_filter, text="Filtre (substring, case-insensitive) :").pack(side=tk.LEFT)
        self.var_filter = tk.StringVar()
        ent_filter = ttk.Entry(frm_filter, textvariable=self.var_filter, width=40); ent_filter.pack(side=tk.LEFT, padx=6)
        ent_filter.bind("<KeyRelease>", lambda e: self._render_logs())
        self.var_only_folders = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_filter, text="Only folders", variable=self.var_only_folders, command=self._render_logs).pack(side=tk.LEFT, padx=12)
        ttk.Button(frm_filter, text="Export (filtered)", command=self._export_filtered).pack(side=tk.RIGHT)

        frm_prog = ttk.Frame(self); frm_prog.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0,6))
        self.pbar = ttk.Progressbar(frm_prog, mode="indeterminate"); self.pbar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,8))
        self.status_var = tk.StringVar(value="Prêt"); ttk.Label(frm_prog, textvariable=self.status_var).pack(side=tk.RIGHT)

        frm_logs = ttk.Frame(self); frm_logs.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=(0,8))
        self.txt = tk.Text(frm_logs, wrap=tk.NONE, state=tk.NORMAL); self.txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.txt.tag_configure("write", foreground="red", font=("TkDefaultFont", 10, "bold"))
        self.txt.tag_configure("err", foreground="orange red"); self.txt.tag_configure("normal", foreground="black")
        vscroll = ttk.Scrollbar(frm_logs, orient=tk.VERTICAL, command=self.txt.yview); vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt.config(yscrollcommand=vscroll.set)
        hscroll = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.txt.xview); hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.txt.config(xscrollcommand=hscroll.set)

        self.menu = tk.Menu(self, tearoff=0); self.menu.add_command(label="Copier", command=self._copy_selection)
        self.txt.bind("<Button-3>", self._show_context_menu)
        self._update_compare_state()

    def _show_principal_help(self):
        messagebox.showinfo("Aide — Principal",
            "Le compte utilisé pour le scan correspond automatiquement à l'utilisateur courant non administrateur.\n"
            "Pour exécuter un scan avec un autre compte, relancez l'application en étant connecté avec ce compte standard.")

    def _browse_accesschk(self):
        p = filedialog.askopenfilename(title="Sélectionner accesschk.exe", filetypes=[("Executables","*.exe"), ("All files","*.*")])
        if p: self.entry_accesschk.delete(0, tk.END); self.entry_accesschk.insert(0, p)

    def _browse_target_replace(self):
        p = filedialog.askdirectory(title="Choisir un dossier (remplace la liste actuelle)", mustexist=True)
        if p: self.entry_target.delete(0, tk.END); self.entry_target.insert(0, os.path.normpath(p))

    # ---- core ----
    def _on_scan(self, mode="baseline"):
        if self.proc is not None and self.proc.poll() is None:
            messagebox.showwarning("Scan en cours", "Un scan est déjà en cours."); return
        accesschk = self.entry_accesschk.get().strip()
        if not accesschk or not os.path.isfile(accesschk):
            messagebox.showerror("Erreur", "accesschk.exe introuvable dans le même dossier. Sélectionnez-le."); return
        if mode == "compare" and not os.path.isfile(self.base_scan_path):
            messagebox.showerror("Scan comparaison", "Aucun scan initial trouvé. Lancez d'abord un scan initial."); return
        raw_targets = self.entry_target.get().strip() or default_targets_string()
        targets = [t.strip().strip('"') for t in raw_targets.split(";") if t.strip()]
        principal = self.default_principal.strip() if self.default_principal else ""

        self.logs.clear(); self._line_count=0; self._isdir_cache.clear()
        self.txt.configure(state=tk.NORMAL); self.txt.delete("1.0", tk.END); self.txt.configure(state=tk.DISABLED)
        principal_label = principal or "(introuvable)"
        self.status_var.set(f"Préparation du scan : {principal_label} sur {len(targets)} cible(s). 0 lignes")
        self.running=True
        self.current_target = None
        self.current_principal = None
        self.scan_mode = mode
        self.btn_scan_base.configure(state=tk.DISABLED); self.btn_scan_compare.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL); self.pbar.start(60)

        threading.Thread(target=self._run_accesschk_thread, args=(accesschk, targets, principal), daemon=True).start()

    def _on_stop(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.kill()
                self.status_var.set(f"Arrêt manuel. {self._line_count} lignes.")
        except Exception:
            pass
        finally:
            self.running = False
            self.pbar.stop()
            self.scan_mode = None
            self._update_compare_state()
            self.btn_stop.configure(state=tk.DISABLED)
            self.proc = None
            self.current_target = None
            self.current_principal = None

    def _run_accesschk_thread(self, accesschk, targets, principal):
        try:
            principals = [principal] if principal else ["Utilisateurs", "Users", r"BUILTIN\Users", "S-1-5-32-545"]
            last_rc = 0
            for target in targets:
                for idx, who in enumerate(principals):
                    if not who: continue
                    # RW + récursif + sans bandeau
                    args = [accesschk, "-accepteula", "-nobanner", who, "-w", "-s", target]
                    startupinfo = None
                    creationflags = 0
                    if os.name == "nt":
                        startupinfo = subprocess.STARTUPINFO()
                        startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
                        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

                    self.q.put({"_status": f"Scan de {target} — {who or '(auto)'}"})
                    try:
                        proc = subprocess.Popen(
                            args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            startupinfo=startupinfo,
                            creationflags=creationflags,
                        )
                    except FileNotFoundError:
                        self.q.put({"line": "[ERREUR] accesschk.exe introuvable au lancement.", "write": False, "err": True})
                        self.q.put({"_finished": True, "returncode": -1})
                        return
                    except Exception as ex:
                        self.q.put({"line": f"[ERREUR] Impossible de lancer accesschk.exe : {ex}", "write": False, "err": True})
                        self.q.put({"_finished": True, "returncode": -1})
                        return
                    self.proc = proc
                    self.current_target = target
                    self.current_principal = who

                    invalid = False
                    def reader(stream, is_err=False):
                        nonlocal invalid
                        while True:
                            chunk = stream.readline()
                            if not chunk: break
                            s = decode_bytes_with_fallback(chunk).rstrip("\r\n")
                            if is_err and "Invalid account name" in s: invalid = True
                            has_write = bool(WRITE_REGEX.search(s)) if not is_err else False
                            self.q.put({"line": s, "write": has_write, "err": is_err})
                    t1 = threading.Thread(target=reader, args=(proc.stdout, False), daemon=True)
                    t2 = threading.Thread(target=reader, args=(proc.stderr, True), daemon=True)
                    t1.start(); t2.start(); proc.wait(); t1.join(timeout=1); t2.join(timeout=1)
                    last_rc = proc.returncode
                    if invalid and idx < len(principals)-1:
                        self.q.put({"line": f"[INFO] '{who}' invalide, nouvel essai avec '{principals[idx+1]}'...", "write": False, "err": True}); continue
                    else: break
            self.q.put({"_finished": True, "returncode": last_rc})
        except Exception as ex:
            self.q.put({"line": f"[EXCEPTION] {ex}", "write": False, "err": True})
            self.q.put({"_finished": True, "returncode": -1})

    # ---- queue / UI ----
    def _poll_queue(self):
        processed=0; buf_normal=[]; buf_write=[]; buf_err=[]
        while processed < self.BATCH_MAX:
            try: item = self.q.get_nowait()
            except queue.Empty: break
            if "_status" in item:
                self.status_var.set(item["_status"])
                continue
            if item.get("_finished"):
                rc=item.get("returncode")
                self._finish_scan(rc)
                continue
            self.logs.append(item); self._line_count += 1
            text=item["line"]
            if item["err"]: buf_err.append(text)
            elif item["write"]: buf_write.append(text)
            else: buf_normal.append(text)
            processed += 1

        if buf_normal or buf_write or buf_err:
            self.txt.configure(state=tk.NORMAL)
            if buf_normal: self.txt.insert(tk.END, "\n".join(buf_normal) + "\n", "normal")
            if buf_write:  self.txt.insert(tk.END, "\n".join(buf_write) + "\n", "write")
            if buf_err:    self.txt.insert(tk.END, "\n".join(buf_err) + "\n", "err")
            self.txt.see(tk.END); self.txt.configure(state=tk.DISABLED)

        if self.running:
            target = self.current_target or "(en attente)"
            principal = self.current_principal or "(auto)"
            self.status_var.set(f"Scan en cours — {principal} @ {target} : {self._line_count} lignes")
        self.after(100, self._poll_queue)

    def _finish_scan(self, returncode: int):
        self.proc = None
        self.running = False
        self.pbar.stop()
        self.current_target = None
        self.current_principal = None
        self.status_var.set(f"Terminé (rc={returncode}). {len(self.logs)} lignes.")
        self.btn_stop.configure(state=tk.DISABLED)
        try:
            self._persist_scan_results()
        finally:
            self._update_compare_state()

    # ---- filtering / export ----
    def _is_dir_cached(self, path: str) -> bool:
        key = path.lower()
        if key in self._isdir_cache: return self._isdir_cache[key]
        try: isd = os.path.isdir(path)
        except Exception: isd = False
        self._isdir_cache[key] = isd
        return isd

    def _render_logs(self):
        self.txt.configure(state=tk.NORMAL); self.txt.delete("1.0", tk.END)
        norm, writ, err = [], [], []
        for it in self._filtered_logs():
            text = it["line"]
            if it["err"]:
                err.append(text)
            elif it["write"]:
                writ.append(text)
            else:
                norm.append(text)
        if norm: self.txt.insert(tk.END, "\n".join(norm) + "\n", "normal")
        if writ: self.txt.insert(tk.END, "\n".join(writ) + "\n", "write")
        if err:  self.txt.insert(tk.END, "\n".join(err) + "\n", "err")
        self.txt.see(tk.END); self.txt.configure(state=tk.DISABLED)

    def _filtered_logs(self, filter_text=None, only_dirs=None):
        f = (self.var_filter.get() if filter_text is None else filter_text).strip().lower()
        only_dirs = self.var_only_folders.get() if only_dirs is None else only_dirs
        for it in self.logs:
            text = it["line"]
            if f and f not in text.lower():
                continue
            if only_dirs:
                if it["err"]:
                    continue
                if not LINE_RW_PREFIX.search(text):
                    continue
                p = extract_first_path(text)
                if not p or not self._is_dir_cached(p):
                    continue
            yield it

    def _export_filtered(self):
        if not self.logs: messagebox.showinfo("Export", "Aucun log à exporter."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"), ("All files","*.*")], initialfile=EXPORT_DEFAULT)
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for it in self._filtered_logs():
                    fh.write(it["line"] + "\n")
            messagebox.showinfo("Export", f"Export terminé : {path}")
        except Exception as ex:
            messagebox.showerror("Erreur export", str(ex))

    # ---- misc ----
    def _persist_scan_results(self):
        mode = self.scan_mode
        self.scan_mode = None
        if not mode:
            return
        lines = [it["line"] for it in self.logs]
        target_path = self.base_scan_path if mode == "baseline" else self.compare_scan_path
        try:
            with open(target_path, "w", encoding="utf-8") as fh:
                if lines:
                    fh.write("\n".join(lines))
                    fh.write("\n")
                else:
                    fh.truncate(0)
        except Exception as ex:
            messagebox.showerror("Enregistrement du scan", f"Impossible d'enregistrer le scan : {ex}")
            return

        if mode == "baseline":
            self._safe_remove(self.compare_scan_path)
            self._safe_remove(self.diff_output_path)
            messagebox.showinfo("Scan initial", f"Scan initial enregistré dans : {target_path}")
        else:
            self._handle_compare_diff(lines)

    def _handle_compare_diff(self, current_lines):
        try:
            with open(self.base_scan_path, "r", encoding="utf-8") as fh:
                base_lines = fh.read().splitlines()
        except FileNotFoundError:
            messagebox.showerror("Scan comparaison", "Le scan initial est introuvable pour générer la comparaison.")
            return
        except Exception as ex:
            messagebox.showerror("Scan comparaison", f"Impossible de lire le scan initial : {ex}")
            return

        new_lines = [ln.rstrip("\n") for ln in current_lines]
        diff_lines = list(difflib.unified_diff(base_lines, new_lines,
                                               fromfile=os.path.basename(self.base_scan_path),
                                               tofile=os.path.basename(self.compare_scan_path),
                                               lineterm=""))
        if diff_lines:
            diff_text = "\n".join(diff_lines)
            try:
                with open(self.diff_output_path, "w", encoding="utf-8") as fh:
                    fh.write(diff_text)
                    if not diff_text.endswith("\n"):
                        fh.write("\n")
            except Exception:
                pass
            self._show_diff_window(diff_text)
        else:
            self._safe_remove(self.diff_output_path)
            messagebox.showinfo("Scan comparaison", "Aucune différence détectée entre les scans.")

    def _show_diff_window(self, diff_text: str):
        win = tk.Toplevel(self)
        win.title("Différence entre les scans")
        win.geometry("900x600")
        txt = tk.Text(win, wrap=tk.NONE)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.insert("1.0", diff_text)
        txt.configure(state=tk.DISABLED)
        yscroll = ttk.Scrollbar(win, orient=tk.VERTICAL, command=txt.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt.configure(yscrollcommand=yscroll.set)
        xscroll = ttk.Scrollbar(win, orient=tk.HORIZONTAL, command=txt.xview)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        txt.configure(xscrollcommand=xscroll.set)

    def _update_compare_state(self):
        if self.running:
            self.btn_scan_base.configure(state=tk.DISABLED)
            self.btn_scan_compare.configure(state=tk.DISABLED)
        else:
            self.btn_scan_base.configure(state=tk.NORMAL)
            state_compare = tk.NORMAL if os.path.isfile(self.base_scan_path) else tk.DISABLED
            self.btn_scan_compare.configure(state=state_compare)

    def _safe_remove(self, path: str):
        try:
            if path and os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    def _copy_selection(self):
        try: sel = self.txt.selection_get(); self.clipboard_clear(); self.clipboard_append(sel)
        except Exception: pass
    def _show_context_menu(self, event):
        try: self.menu.tk_popup(event.x_root, event.y_root)
        finally: self.menu.grab_release()

    def _enforce_standard_user(self):
        if is_running_elevated():
            messagebox.showerror("Droits élevés détectés",
                                 "Cette application doit être lancée avec un utilisateur standard.")
            self.after(100, self.on_close)
    def on_close(self):
        try:
            if self.proc and self.proc.poll() is None: self.proc.kill()
        except Exception: pass
        self._cleanup_scan_files()
        self.destroy()

    def _cleanup_scan_files(self):
        for path in (self.base_scan_path, self.compare_scan_path, self.diff_output_path):
            self._safe_remove(path)

def main():
    app=AccessChkGUI(); app.protocol("WM_DELETE_WINDOW", app.on_close); app.mainloop()
if __name__ == "__main__": main()
