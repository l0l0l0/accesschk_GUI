#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, threading, queue, subprocess, re, tkinter as tk
from tkinter import ttk, filedialog, messagebox

EXPORT_DEFAULT = "accesschk_filtered_logs.txt"

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
    paths = []
    pf = os.environ.get("ProgramFiles")
    pf86 = os.environ.get("ProgramFiles(x86)")
    if pf and os.path.isdir(pf): paths.append(os.path.normpath(pf))
    if pf86 and os.path.isdir(pf86) and (pf86.lower() != (pf or "").lower()):
        paths.append(os.path.normpath(pf86))
    if not paths:
        paths = [r"C:\Program Files", r"C:\Program Files (x86)"]
    seen, uniq = set(), []
    for p in paths:
        if p.lower() not in seen:
            seen.add(p.lower()); uniq.append(p)
    return ";".join(uniq)

class AccessChkGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AccessChk GUI v1.10")
        self.geometry("1100x800"); self.minsize(880, 620)
        self.logs=[]; self.q=queue.Queue(); self.proc=None; self.running=False
        self.BATCH_MAX=250; self._line_count=0; self._isdir_cache={}
        self._build_ui()
        self.after(100, self._poll_queue)

    def _build_ui(self):
        menubar = tk.Menu(self)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="Aide sur 'Principal'...", command=self._show_principal_help)
        menubar.add_cascade(label="Aide", menu=helpmenu)
        self.config(menu=menubar)

        frm_top = ttk.Frame(self); frm_top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)
        ttk.Label(frm_top, text="accesschk.exe :").grid(row=0, column=0, sticky=tk.W, padx=4)
        self.entry_accesschk = ttk.Entry(frm_top, width=70); self.entry_accesschk.grid(row=0, column=1, sticky=tk.W)
        self.entry_accesschk.insert(0, bundled_accesschk_path())
        ttk.Button(frm_top, text="Parcourir", command=self._browse_accesschk).grid(row=0, column=2, padx=6)

        ttk.Label(frm_top, text="Principal (compte/groupe) :").grid(row=1, column=0, sticky=tk.W, padx=4, pady=(6,0))
        self.entry_principal = ttk.Entry(frm_top, width=70); self.entry_principal.grid(row=1, column=1, sticky=tk.W, pady=(6,0))
        self.entry_principal.insert(0, "")
        btns = ttk.Frame(frm_top); btns.grid(row=1, column=2, padx=6, pady=(6,0))
        self.btn_scan = ttk.Button(btns, text="Scan", command=self._on_scan); self.btn_scan.pack(side=tk.LEFT)
        self.btn_stop = ttk.Button(btns, text="Stop", command=self._on_stop, state=tk.DISABLED); self.btn_stop.pack(side=tk.LEFT, padx=(6,0))

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
        ttk.Checkbutton(frm_filter, text="Only folders (RW)", variable=self.var_only_folders, command=self._render_logs).pack(side=tk.LEFT, padx=12)
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

    def _show_principal_help(self):
        messagebox.showinfo("Aide — Principal",
            "Entrez le compte/groupe (Users, Utilisateurs, BUILTIN\\Users, DOMAINE\\Groupe, S-1-5-32-545).\n"
            "Vide = essai auto : Utilisateurs → Users → BUILTIN\\Users → SID.\n"
            "Astuce : 'whoami /groups' liste vos groupes.")

    def _browse_accesschk(self):
        p = filedialog.askopenfilename(title="Sélectionner accesschk.exe", filetypes=[("Executables","*.exe"), ("All files","*.*")])
        if p: self.entry_accesschk.delete(0, tk.END); self.entry_accesschk.insert(0, p)

    def _browse_target_replace(self):
        p = filedialog.askdirectory(title="Choisir un dossier (remplace la liste actuelle)", mustexist=True)
        if p: self.entry_target.delete(0, tk.END); self.entry_target.insert(0, os.path.normpath(p))

    # ---- core ----
    def _on_scan(self):
        if self.proc is not None and self.proc.poll() is None:
            messagebox.showwarning("Scan en cours", "Un scan est déjà en cours."); return
        accesschk = self.entry_accesschk.get().strip()
        if not accesschk or not os.path.isfile(accesschk):
            messagebox.showerror("Erreur", "accesschk.exe introuvable dans le même dossier. Sélectionnez-le."); return
        raw_targets = self.entry_target.get().strip() or default_targets_string()
        targets = [t.strip().strip('"') for t in raw_targets.split(";") if t.strip()]
        principal = self.entry_principal.get().strip()

        self.logs.clear(); self._line_count=0; self._isdir_cache.clear()
        self.txt.configure(state=tk.NORMAL); self.txt.delete("1.0", tk.END); self.txt.configure(state=tk.DISABLED)
        self.status_var.set("Lancement... 0 lignes"); self.running=True
        self.btn_scan.configure(state=tk.DISABLED); self.btn_stop.configure(state=tk.NORMAL); self.pbar.start(60)

        threading.Thread(target=self._run_accesschk_thread, args=(accesschk, targets, principal), daemon=True).start()

    def _on_stop(self):
        try:
            if self.proc and self.proc.poll() is None: self.proc.kill()
        except Exception: pass

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

                    proc = subprocess.Popen(
                        args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        startupinfo=startupinfo,
                        creationflags=creationflags,
                    )
                    self.proc = proc

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
            if item.get("_finished"):
                rc=item.get("returncode"); self.status_var.set(f"Terminé (rc={rc}). {len(self.logs)} lignes.")
                self.proc=None; self.running=False; self.pbar.stop()
                self.btn_scan.configure(state=tk.NORMAL); self.btn_stop.configure(state=tk.DISABLED); continue
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

        if self.running: self.status_var.set(f"Scan en cours... {self._line_count} lignes")
        self.after(100, self._poll_queue)

    # ---- filtering / export ----
    def _is_dir_cached(self, path: str) -> bool:
        key = path.lower()
        if key in self._isdir_cache: return self._isdir_cache[key]
        try: isd = os.path.isdir(path)
        except Exception: isd = False
        self._isdir_cache[key] = isd
        return isd

    def _render_logs(self):
        f = self.var_filter.get().strip().lower()
        only_dirs = self.var_only_folders.get()
        self.txt.configure(state=tk.NORMAL); self.txt.delete("1.0", tk.END)
        norm=writ=err=[]
        norm, writ, err = [], [], []
        for it in self.logs:
            text = it["line"]; is_err = it["err"]
            if f and f not in text.lower(): continue
            if only_dirs:
                # exiger 'RW ' au début de la ligne ET que le chemin soit un répertoire réel
                if not LINE_RW_PREFIX.search(text): continue
                p = extract_first_path(text)
                if not p or not self._is_dir_cached(p): continue
            # coloration: rouge si ligne write
            if WRITE_REGEX.search(text) and not is_err: writ.append(text)
            elif is_err: err.append(text)
            else: norm.append(text)
        if norm: self.txt.insert(tk.END, "\n".join(norm) + "\n", "normal")
        if writ: self.txt.insert(tk.END, "\n".join(writ) + "\n", "write")
        if err:  self.txt.insert(tk.END, "\n".join(err) + "\n", "err")
        self.txt.see(tk.END); self.txt.configure(state=tk.DISABLED)

    def _export_filtered(self):
        if not self.logs: messagebox.showinfo("Export", "Aucun log à exporter."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"), ("All files","*.*")], initialfile=EXPORT_DEFAULT)
        if not path: return
        f = self.var_filter.get().strip().lower(); only_dirs = self.var_only_folders.get()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                for it in self.logs:
                    text = it["line"]
                    if f and f not in text.lower(): continue
                    if only_dirs:
                        if not LINE_RW_PREFIX.search(text): continue
                        p = extract_first_path(text)
                        if not p or not self._is_dir_cached(p): continue
                    fh.write(text + "\n")
            messagebox.showinfo("Export", f"Export terminé : {path}")
        except Exception as ex:
            messagebox.showerror("Erreur export", str(ex))

    # ---- misc ----
    def _copy_selection(self):
        try: sel = self.txt.selection_get(); self.clipboard_clear(); self.clipboard_append(sel)
        except Exception: pass
    def _show_context_menu(self, event):
        try: self.menu.tk_popup(event.x_root, event.y_root)
        finally: self.menu.grab_release()
    def on_close(self):
        try:
            if self.proc and self.proc.poll() is None: self.proc.kill()
        except Exception: pass
        self.destroy()

def main():
    app=AccessChkGUI(); app.protocol("WM_DELETE_WINDOW", app.on_close); app.mainloop()
if __name__ == "__main__": main()
