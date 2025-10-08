#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Interface graphique simplifiée pour AccessChk.

Ce module encapsule toute la logique permettant d'exécuter l'outil
``accesschk.exe`` depuis une interface Tkinter, d'afficher les résultats,
et de faciliter leur exportation/comparaison. Toutes les fonctions et
méthodes sont volontairement documentées pour clarifier le rôle de chaque
étape du flux de traitement.
"""

import os
import sys
import threading
import queue
import subprocess
import re
import ctypes
import unicodedata
import getpass
import difflib
import logging
import shlex
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Union
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


class AppConfig:
    """Configuration centralisée de l'application."""
    
    # Performance
    BATCH_SIZE = 100  # Réduit de 250 à 100 pour plus de responsivité
    BATCH_TIMEOUT_MS = 50  # Timeout plus court
    UI_UPDATE_INTERVAL_MS = 75  # Plus fréquent
    MAX_DISPLAYED_LINES = 10000  # Limite pour éviter les ralentissements
    
    # UI
    WINDOW_WIDTH = 1100
    WINDOW_HEIGHT = 800
    MIN_WIDTH = 880
    MIN_HEIGHT = 620
    
    # Fichiers
    EXPORT_DEFAULT = "accesschk_filtered_logs.txt"
    DIFF_EXPORT_DEFAULT = "accesschk_diff.txt"
    LOG_FILE = "accesschk_gui.log"
    
    # Sécurité
    MAX_PATH_LENGTH = 260
    ALLOWED_EXTENSIONS = {'.exe'}
    DANGEROUS_CHARS = ['&', '|', ';', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>']
    
    # AccessChk
    PROGRESS_BAR_SPEED = 30  # Réduit de 60 pour moins de consommation CPU


# Configuration des constantes (héritées pour compatibilité)
EXPORT_DEFAULT = AppConfig.EXPORT_DEFAULT
DIFF_EXPORT_DEFAULT = AppConfig.DIFF_EXPORT_DEFAULT
MAX_PATH_LENGTH = AppConfig.MAX_PATH_LENGTH
ALLOWED_EXTENSIONS = AppConfig.ALLOWED_EXTENSIONS
DANGEROUS_CHARS = AppConfig.DANGEROUS_CHARS


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


def validate_executable_path(path: str) -> Tuple[bool, str]:
    """Validate that the provided path is a safe executable file.
    
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not path or not isinstance(path, str):
        return False, "Le chemin est vide ou invalide"
    
    # Normalize and check path length
    try:
        normalized_path = os.path.normpath(path.strip())
        if len(normalized_path) > MAX_PATH_LENGTH:
            return False, f"Le chemin est trop long (max {MAX_PATH_LENGTH} caractères)"
    except (OSError, ValueError) as e:
        return False, f"Chemin invalide: {str(e)}"
    
    # Check for dangerous characters
    if any(char in normalized_path for char in DANGEROUS_CHARS):
        return False, "Le chemin contient des caractères dangereux"
    
    # Check if file exists
    if not os.path.isfile(normalized_path):
        return False, "Le fichier n'existe pas"
    
    # Check file extension
    file_ext = Path(normalized_path).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension de fichier non autorisée: {file_ext}"
    
    # Check if it's actually accesschk.exe
    filename = Path(normalized_path).name.lower()
    if filename != "accesschk.exe":
        return False, "Le fichier doit être accesschk.exe"
    
    return True, ""


def validate_target_paths(paths_str: str) -> Tuple[bool, str, List[str]]:
    """Validate target paths for scanning.
    
    Returns:
        Tuple[bool, str, List[str]]: (is_valid, error_message, validated_paths)
    """
    if not paths_str or not isinstance(paths_str, str):
        return False, "Aucun chemin spécifié", []
    
    raw_paths = [p.strip().strip('"') for p in paths_str.split(";") if p.strip()]
    if not raw_paths:
        return False, "Aucun chemin valide trouvé", []
    
    validated_paths = []
    for path in raw_paths:
        # Check for dangerous characters
        if any(char in path for char in DANGEROUS_CHARS):
            return False, f"Chemin dangereux détecté: {path}", []
        
        # Normalize path
        try:
            normalized = os.path.normpath(path)
            if len(normalized) > MAX_PATH_LENGTH:
                return False, f"Chemin trop long: {path}", []
        except (OSError, ValueError):
            return False, f"Chemin invalide: {path}", []
        
        # Check if path exists (warning only, not blocking)
        if not os.path.exists(normalized):
            logging.warning(f"Chemin non trouvé (sera ignoré par accesschk): {normalized}")
        
        validated_paths.append(normalized)
    
    return True, "", validated_paths


def sanitize_command_args(args: List[str]) -> List[str]:
    """Sanitize command arguments to prevent injection attacks.
    
    Args:
        args: List of command arguments
    
    Returns:
        List[str]: Sanitized arguments
    """
    sanitized = []
    for arg in args:
        if not isinstance(arg, str):
            continue
        
        # Remove dangerous characters and validate
        if any(char in arg for char in DANGEROUS_CHARS):
            # For paths, we already validated them above
            # For other args, we can safely quote them
            if os.path.exists(arg) or arg.startswith('-') or arg in ['accepteula', 'nobanner']:
                sanitized.append(shlex.quote(arg))
            else:
                logging.warning(f"Argument potentiellement dangereux ignoré: {arg}")
        else:
            sanitized.append(arg)
    
    return sanitized


# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('accesschk_gui.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def current_user_principal() -> str:
    """Best-effort resolution of the current user in DOMAIN\\User format."""
    try:
        user_env = os.environ.get("USERNAME")
    except (KeyError, OSError) as e:
        logger.warning(f"Impossible de récupérer USERNAME depuis l'environnement: {e}")
        user_env = None
    
    try:
        user = user_env or getpass.getuser()
    except (OSError, KeyError, ImportError) as e:
        logger.warning(f"Impossible de récupérer l'utilisateur courant: {e}")
        user = user_env or ""
    
    if os.name == "nt":
        try:
            domain = os.environ.get("USERDOMAIN")
            if domain and user:
                return f"{domain}\\{user}"
        except (KeyError, OSError) as e:
            logger.warning(f"Impossible de récupérer le domaine: {e}")
    
    return user

# Détecte les lignes RW (format accesschk)
LINE_RW_PREFIX = re.compile(r"^\s*RW\s+", re.I)
# Pour coloration rouge (garde l’ancienne heuristique au cas où)
WRITE_REGEX = re.compile(r"(?:^|\s)(rw|w|write|write_data|file_write_data|file_write|:w|W:|WriteData|FILE_WRITE_DATA)\b", re.I)

# Messages d'erreurs verbeux à ignorer (localisés)
SUPPRESSED_ERROR_PATTERNS = (
    re.compile(r"error getting security", re.I),
    re.compile(
        r"la syntaxe du nom de fichier, de r[ée]pertoire ou de volume est incorrecte",
        re.I,
    ),
)

SUPPRESSED_ERROR_FOLDED_SNIPPETS = (
    "error getting security",
    "la syntaxe du nom de fichier, de repertoire ou de volume est incorrecte",
)


def _normalize_for_error_matching(text: str) -> str:
    """Return a lower-cased ASCII approximation of ``text`` for robust matching."""
    try:
        normalized = unicodedata.normalize("NFKD", text)
    except (ValueError, TypeError) as e:
        logger.warning(f"Erreur de normalisation Unicode: {e}")
        normalized = text
    
    try:
        stripped = "".join(ch for ch in normalized if not unicodedata.combining(ch))
        return stripped.casefold()
    except (ValueError, TypeError) as e:
        logger.warning(f"Erreur lors du traitement des caractères: {e}")
        return text.lower()


def matches_suppressed_error(text: str) -> bool:
    """True when ``text`` corresponds to a known noisy AccessChk error message."""

    if any(p.search(text) for p in SUPPRESSED_ERROR_PATTERNS):
        return True
    folded = _normalize_for_error_matching(text)
    return any(snippet in folded for snippet in SUPPRESSED_ERROR_FOLDED_SNIPPETS)

# Extrait le premier chemin de type Windows/UNC
PATH_EXTRACT = re.compile(r"(?:[A-Za-z]:\\|\\\\[^\\]+\\)[^\r\n]*")
def extract_first_path(s: str) -> Optional[str]:
    """Retourne la première occurrence de chemin Windows/UNC trouvée dans ``s``."""
    if not s or not isinstance(s, str):
        return None
    
    try:
        m = PATH_EXTRACT.search(s)
        return m.group(0).strip().rstrip('"') if m else None
    except (AttributeError, IndexError) as e:
        logger.debug(f"Erreur lors de l'extraction du chemin: {e}")
        return None

ASCII_ALNUM = re.compile(r"[A-Za-z0-9]")
CJK_CHARS = re.compile(r"[\u3040-\u30FF\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF\uAC00-\uD7AF]")


def contains_cjk(text: str) -> bool:
    """Indique si ``text`` contient des caractères du bloc CJK (chinois/japonais/etc.)."""

    return bool(CJK_CHARS.search(text))

def bundled_accesschk_path() -> str:
    """Retourne le chemin d'``accesschk.exe`` situé à côté du script ou de l'exécutable."""

    base = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
    return os.path.join(base, "accesschk.exe")

def decode_bytes_with_fallback(b: bytes) -> str:
    """Décode une chaîne d'octets en essayant plusieurs encodages classiques."""
    if not isinstance(b, bytes):
        logger.warning(f"Type inattendu pour le décodage: {type(b)}")
        return str(b)
    
    for enc in ("utf-8", "utf-16", "cp850", "cp437", "cp1252", "latin-1"):
        try:
            return b.decode(enc, errors="strict")
        except (UnicodeDecodeError, LookupError, ValueError) as e:
            logger.debug(f"Échec de décodage avec {enc}: {e}")
            continue
    
    # Fallback final
    try:
        return b.decode("latin-1", errors="replace")
    except (UnicodeDecodeError, LookupError) as e:
        logger.error(f"Échec du décodage de fallback: {e}")
        return str(b, errors="replace")

def default_targets_string() -> str:
    """Valeur par défaut affichée dans le champ des cibles."""
    if os.name == "nt":
        return "C:\\"
    return os.path.sep


class AccessChkRunner:
    """Classe responsable de l'exécution des scans AccessChk."""
    
    def __init__(self, config: AppConfig, queue_handler: queue.Queue):
        self.config = config
        self.queue = queue_handler
        self.current_process = None
        self.is_running = False
    
    def start_scan(self, accesschk_path: str, targets: List[str], principal: str) -> None:
        """Démarre un scan AccessChk dans un thread séparé."""
        if self.is_running:
            raise RuntimeError("Un scan est déjà en cours")
        
        self.is_running = True
        thread = threading.Thread(
            target=self._run_scan,
            args=(accesschk_path, targets, principal),
            daemon=True,
            name="AccessChkRunner"
        )
        thread.start()
    
    def stop_scan(self) -> None:
        """Arrête le scan en cours."""
        try:
            if self.current_process and self.current_process.poll() is None:
                self.current_process.kill()
                logger.info("Scan arrêté par l'utilisateur")
        except (OSError, subprocess.SubprocessError) as e:
            logger.warning(f"Erreur lors de l'arrêt du scan: {e}")
        finally:
            self.is_running = False
            self.current_process = None
    
    def _run_scan(self, accesschk_path: str, targets: List[str], principal: str) -> None:
        """Logique principale d'exécution du scan."""
        try:
            principals = [principal] if principal else ["Utilisateurs", "Users", r"BUILTIN\Users", "S-1-5-32-545"]
            last_rc = 0
            
            for target in targets:
                if not self.is_running:  # Check pour arrêt précoce
                    break
                    
                for idx, who in enumerate(principals):
                    if not who or not self.is_running: 
                        continue
                    
                    # Construction sécurisée des arguments
                    base_args = [accesschk_path, "-accepteula", "-nobanner", who, "-w", "-s", target]
                    args = sanitize_command_args(base_args)
                    
                    self.queue.put({"_status": f"Scan de {target} — {who or '(auto)'}"})
                    
                    try:
                        self.current_process = self._create_process(args)
                        last_rc = self._process_output(self.current_process, who, principals, idx)
                        
                        if last_rc != -2:  # -2 = invalid account, continue with next
                            break
                            
                    except (FileNotFoundError, OSError, subprocess.SubprocessError) as e:
                        error_msg = f"[ERREUR] Impossible de lancer accesschk.exe: {e}"
                        logger.error(error_msg)
                        self.queue.put({"line": error_msg, "write": False, "err": True})
                        self.queue.put({"_finished": True, "returncode": -1})
                        return
            
            self.queue.put({"_finished": True, "returncode": last_rc})
            
        except Exception as ex:
            error_msg = f"[EXCEPTION] Erreur inattendue dans le scan: {ex}"
            logger.exception(error_msg)
            self.queue.put({"line": error_msg, "write": False, "err": True})
            self.queue.put({"_finished": True, "returncode": -1})
        finally:
            self.is_running = False
            self.current_process = None
    
    def _create_process(self, args: List[str]) -> subprocess.Popen:
        """Crée un processus subprocess pour AccessChk."""
        startupinfo = None
        creationflags = 0
        
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        return subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
    
    def _process_output(self, proc: subprocess.Popen, who: str, principals: List[str], idx: int) -> int:
        """Traite la sortie du processus AccessChk."""
        invalid = False
        
        def reader(stream, is_err=False):
            """Lit un flux AccessChk et pousse les lignes dans la file d'attente."""
            nonlocal invalid
            try:
                while True:
                    chunk = stream.readline()
                    if not chunk: 
                        break
                    
                    s = decode_bytes_with_fallback(chunk).rstrip("\r\n")
                    
                    if not is_err and contains_cjk(s):
                        continue
                    
                    if is_err and "Invalid account name" in s: 
                        invalid = True
                    
                    has_write = bool(WRITE_REGEX.search(s)) if not is_err else False
                    self.queue.put({"line": s, "write": has_write, "err": is_err})
            except (UnicodeError, IOError) as e:
                logger.warning(f"Erreur lors de la lecture du flux: {e}")
        
        # Threads de lecture des flux
        t1 = threading.Thread(target=reader, args=(proc.stdout, False), daemon=True, name="StdoutReader")
        t2 = threading.Thread(target=reader, args=(proc.stderr, True), daemon=True, name="StderrReader")
        
        t1.start()
        t2.start()
        
        try:
            proc.wait()
        except KeyboardInterrupt:
            logger.info("Interruption du scan par l'utilisateur")
            proc.kill()
            return -1
        
        # Attente des threads de lecture
        t1.join(timeout=2)
        t2.join(timeout=2)
        
        # Gestion des comptes invalides
        if invalid and idx < len(principals) - 1:
            info_msg = f"[INFO] '{who}' invalide, nouvel essai avec '{principals[idx+1]}'..."
            logger.info(info_msg)
            self.queue.put({"line": info_msg, "write": False, "err": True})
            return -2  # Code spécial pour compte invalide
        
        return proc.returncode


class AccessChkGUI(tk.Tk):
    """Fenêtre principale gérant l'intégralité des interactions utilisateur."""

    def __init__(self):
        """Initialise l'interface et les structures de stockage en mémoire."""
        super().__init__()
        self.title("AccessChk GUI v1.10")
        self.geometry(f"{AppConfig.WINDOW_WIDTH}x{AppConfig.WINDOW_HEIGHT}")
        self.minsize(AppConfig.MIN_WIDTH, AppConfig.MIN_HEIGHT)
        
        # Configuration et composants
        self.app_config = AppConfig()
        self.q = queue.Queue()
        self.runner = AccessChkRunner(self.app_config, self.q)
        
        # État de l'application
        self.logs = []
        self.running = False
        
        # Métriques et cache
        self._line_count = 0
        self._write_count = 0
        self._isdir_cache = {}
        self._suppressed_errors = 0
        self._pending_path = None
        self._ui_buffer = []  # Buffer pour optimiser les mises à jour UI
        
        # État du scan
        self.current_target = None
        self.current_principal = None
        self.default_principal = current_user_principal()
        self.scan_mode = None
        
        # Chemins de fichiers
        base_dir = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
        self.storage_dir = base_dir
        self.base_scan_path = os.path.join(base_dir, "scan_initial.txt")
        self.compare_scan_path = os.path.join(base_dir, "scan_comparatif.txt")
        self.diff_output_path = os.path.join(base_dir, "scan_diff.txt")
        
        # Nettoyage des fichiers temporaires
        for leftover in (self.compare_scan_path, self.diff_output_path):
            try:
                if os.path.isfile(leftover):
                    os.remove(leftover)
            except (OSError, IOError) as e:
                logger.warning(f"Impossible de supprimer {leftover}: {e}")
        
        self._build_ui()
        self.after(0, self._enforce_standard_user)
        self.after(self.app_config.UI_UPDATE_INTERVAL_MS, self._poll_queue)

    def _build_ui(self) -> None:
        """Construit tous les widgets de la fenêtre principale."""

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

    def _show_principal_help(self) -> None:
        """Affiche une boîte d'information détaillant l'utilisation du champ 'Principal'."""

        messagebox.showinfo("Aide — Principal",
            "Le compte utilisé pour le scan correspond automatiquement à l'utilisateur courant non administrateur.\n"
            "Pour exécuter un scan avec un autre compte, relancez l'application en étant connecté avec ce compte standard.")

    def _browse_accesschk(self):
        """Ouvre un sélecteur de fichier pour choisir ``accesschk.exe``."""

        p = filedialog.askopenfilename(title="Sélectionner accesschk.exe", filetypes=[("Executables","*.exe"), ("All files","*.*")])
        if p: self.entry_accesschk.delete(0, tk.END); self.entry_accesschk.insert(0, p)

    def _browse_target_replace(self):
        """Ouvre un sélecteur de dossier qui remplace la liste de cibles actuelle."""

        p = filedialog.askdirectory(title="Choisir un dossier (remplace la liste actuelle)", mustexist=True)
        if p: self.entry_target.delete(0, tk.END); self.entry_target.insert(0, os.path.normpath(p))

    # ---- core ----
    def _on_scan(self, mode: str = "baseline"):
        """Démarre un scan AccessChk dans un thread en fonction du ``mode`` sélectionné."""
        if self.runner.is_running:
            messagebox.showwarning("Scan en cours", "Un scan est déjà en cours.")
            return
        
        # Validation sécurisée de l'exécutable
        accesschk = self.entry_accesschk.get().strip()
        is_valid, error_msg = validate_executable_path(accesschk)
        if not is_valid:
            messagebox.showerror("Erreur", f"Erreur avec accesschk.exe: {error_msg}")
            return
        
        # Vérification du mode comparaison
        if mode == "compare" and not os.path.isfile(self.base_scan_path):
            messagebox.showerror("Scan comparaison", "Aucun scan initial trouvé. Lancez d'abord un scan initial.")
            return
        
        # Validation des cibles
        raw_targets = self.entry_target.get().strip() or default_targets_string()
        is_valid, error_msg, targets = validate_target_paths(raw_targets)
        if not is_valid:
            messagebox.showerror("Erreur", f"Erreur avec les cibles: {error_msg}")
            return
        
        principal = self.default_principal.strip() if self.default_principal else ""

        # Réinitialisation de l'état
        self.logs.clear()
        self._line_count = 0
        self._write_count = 0
        self._isdir_cache.clear()
        self._suppressed_errors = 0
        self._pending_path = None
        
        # Mise à jour de l'UI
        self.txt.configure(state=tk.NORMAL)
        self.txt.delete("1.0", tk.END)
        self.txt.configure(state=tk.DISABLED)
        
        principal_label = principal or "(introuvable)"
        self.status_var.set(f"Préparation du scan : {principal_label} sur {len(targets)} cible(s). 0 lignes (0 RW)")
        
        # État du scan
        self.running = True
        self.current_target = None
        self.current_principal = None
        self.scan_mode = mode
        
        # État des boutons
        self.btn_scan_base.configure(state=tk.DISABLED)
        self.btn_scan_compare.configure(state=tk.DISABLED)
        self.btn_stop.configure(state=tk.NORMAL)
        self.pbar.start(self.app_config.PROGRESS_BAR_SPEED)

        # Lancement du scan via le runner
        try:
            self.runner.start_scan(accesschk, targets, principal)
        except RuntimeError as e:
            messagebox.showerror("Erreur", str(e))
            self._on_stop()

    def _on_stop(self) -> None:
        """Arrête le scan en cours (si un processus est actif)."""
        try:
            self.runner.stop_scan()
            self.status_var.set(f"Arrêt manuel. {self._line_count} lignes ({self._write_count} RW).")
        except Exception as e:
            logger.warning(f"Erreur lors de l'arrêt: {e}")
        finally:
            self.running = False
            self.pbar.stop()
            self.scan_mode = None
            self._update_compare_state()
            self.btn_stop.configure(state=tk.DISABLED)
            self.current_target = None
            self.current_principal = None

    def _poll_queue(self) -> None:
        """Récupère les éléments de la file d'attente et met à jour l'affichage."""
        start_time = time.time()
        processed = 0
        buf_normal, buf_write, buf_err = [], [], []
        
        # Traitement par batch avec limite de temps
        while processed < self.app_config.BATCH_SIZE and (time.time() - start_time) < (self.app_config.BATCH_TIMEOUT_MS / 1000):
            try: 
                item = self.q.get_nowait()
            except queue.Empty: 
                break
            
            if "_status" in item:
                self.status_var.set(item["_status"])
                continue
                
            if item.get("_finished"):
                rc = item.get("returncode")
                self._finish_scan(rc)
                continue
            
            text = item["line"]
            if not text.strip():
                self._pending_path = None
                processed += 1
                continue
            
            # Traitement optimisé des lignes
            if not item["err"]:
                path = extract_first_path(text)
                if not item["write"]:
                    if path and text.strip() == path.strip():
                        self._pending_path = path.strip()
                        processed += 1
                        continue
                    else:
                        self._pending_path = None
                else:
                    if (not path) and self._pending_path:
                        text = f"{text.strip()} — {self._pending_path}"
                        item = dict(item)
                        item["line"] = text
                        path = extract_first_path(text)
                    self._pending_path = None
            else:
                if self._pending_path and not extract_first_path(text):
                    text = f"{self._pending_path} — {text.strip()}"
                    item = dict(item)
                    item["line"] = text
                self._pending_path = None
            
            # Gestion des erreurs supprimées
            if matches_suppressed_error(text):
                self._suppressed_errors += 1
                self._suppress_error_sequence(buf_normal, buf_write, buf_err)
                processed += 1
                continue
            
            # Limitation du nombre de lignes pour éviter les ralentissements
            if len(self.logs) >= self.app_config.MAX_DISPLAYED_LINES:
                # Supprime les anciennes lignes (FIFO)
                removed_items = self.logs[:self.app_config.BATCH_SIZE]
                self.logs = self.logs[self.app_config.BATCH_SIZE:]
                self._line_count = len(self.logs)
                self._write_count = sum(1 for item in self.logs if item["write"] and not item["err"])
                
                # Met à jour l'affichage
                self.txt.configure(state=tk.NORMAL)
                self.txt.delete("1.0", f"{self.app_config.BATCH_SIZE}.0")
                self.txt.configure(state=tk.DISABLED)
            
            # Ajout de la ligne
            self.logs.append(item)
            self._line_count += 1
            if item["write"] and not item["err"]:
                self._write_count += 1
            
            # Buffering pour l'affichage
            if item["err"]: 
                buf_err.append(text)
            elif item["write"]: 
                buf_write.append(text)
            else: 
                buf_normal.append(text)
            
            processed += 1

        # Mise à jour de l'affichage par batch
        if buf_normal or buf_write or buf_err:
            self._update_display_batch(buf_normal, buf_write, buf_err)

        # Mise à jour du statut
        if self.running:
            target = self.current_target or "(en attente)"
            principal = self.current_principal or "(auto)"
            suppressed = f", {self._suppressed_errors} erreurs ignorées" if self._suppressed_errors else ""
            self.status_var.set(
                f"Scan en cours — {principal} @ {target} : {self._line_count} lignes ({self._write_count} RW{suppressed})"
            )
        
        # Planifier la prochaine vérification
        self.after(self.app_config.UI_UPDATE_INTERVAL_MS, self._poll_queue)
    
    def _update_display_batch(self, buf_normal: List[str], buf_write: List[str], buf_err: List[str]):
        """Met à jour l'affichage par batch pour de meilleures performances."""
        self.txt.configure(state=tk.NORMAL)
        
        if buf_normal: 
            self.txt.insert(tk.END, "\n".join(buf_normal) + "\n", "normal")
        if buf_write:  
            self.txt.insert(tk.END, "\n".join(buf_write) + "\n", "write")
        if buf_err:    
            self.txt.insert(tk.END, "\n".join(buf_err) + "\n", "err")
        
        # Défilement intelligent - seulement si on est près du bas
        try:
            visible_end = float(self.txt.index("@0,%d" % self.txt.winfo_height()))
            total_lines = float(self.txt.index(tk.END))
            if (total_lines - visible_end) < 5:  # Si on est dans les 5 dernières lignes visibles
                self.txt.see(tk.END)
        except (tk.TclError, ValueError):
            pass  # En cas d'erreur, on ignore le défilement
        
        self.txt.configure(state=tk.DISABLED)

    def _finish_scan(self, returncode: int):
        """Finalise un scan : mise à jour du statut et sauvegarde éventuelle."""
        self.running = False
        self.runner.is_running = False
        self.pbar.stop()
        self.current_target = None
        self.current_principal = None
        
        suppressed = f", {self._suppressed_errors} erreurs ignorées" if self._suppressed_errors else ""
        self.status_var.set(
            f"Terminé (rc={returncode}). {len(self.logs)} lignes ({self._write_count} RW{suppressed})."
        )
        self.btn_stop.configure(state=tk.DISABLED)
        
        try:
            self._persist_scan_results()
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde: {e}")
            messagebox.showerror("Erreur", f"Impossible de sauvegarder les résultats: {e}")
        finally:
            self._update_compare_state()

    def _remove_last_log_entry(self, buf_normal, buf_write, buf_err):
        """Supprime la dernière ligne stockée pour synchroniser les tampons d'affichage."""

        if not self.logs:
            return False
        last = self.logs.pop()
        self._line_count = max(0, self._line_count - 1)
        if last["write"] and not last["err"] and self._write_count:
            self._write_count -= 1
        target_buf = buf_err if last["err"] else (buf_write if last["write"] else buf_normal)
        for idx in range(len(target_buf) - 1, -1, -1):
            if target_buf[idx] == last["line"]:
                target_buf.pop(idx)
                break
        return True

    def _suppress_error_sequence(self, buf_normal, buf_write, buf_err):
        """Nettoie les lignes de bruit qui suivent un message d'erreur AccessChk."""

        removed = False

        def remove_last_if(predicate):
            nonlocal removed
            if self.logs and predicate(self.logs[-1]):
                if self._remove_last_log_entry(buf_normal, buf_write, buf_err):
                    removed = True
                return True
            return False

        remove_last_if(
            lambda it: not it["err"]
            and not LINE_RW_PREFIX.search(it["line"])
            and bool(extract_first_path(it["line"]))
        )
        # Remove leftover unreadable noise (ex: garbled wide-char sequences)
        while remove_last_if(
            lambda it: not it["err"]
            and not it["write"]
            and not LINE_RW_PREFIX.search(it["line"])
            and (contains_cjk(it["line"]) or not ASCII_ALNUM.search(it["line"]))
        ):
            pass
        return removed

    # ---- filtering / export ----
    def _is_dir_cached(self, path: str) -> bool:
        """Teste si ``path`` est un dossier en mémorisant le résultat."""
        if not path or not isinstance(path, str):
            return False
            
        key = path.lower()
        if key in self._isdir_cache: 
            return self._isdir_cache[key]
        
        try: 
            isd = os.path.isdir(path)
        except (OSError, ValueError, TypeError) as e:
            logger.debug(f"Erreur lors de la vérification du dossier {path}: {e}")
            isd = False
        
        self._isdir_cache[key] = isd
        return isd

    def _render_logs(self) -> None:
        """Ré-affiche le contenu filtré des journaux dans la zone de texte."""

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
        """Génère les lignes filtrées selon la saisie utilisateur."""

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

    def _filter_lines_for_diff(self, lines):
        """Prépare une liste de lignes comparables pour la génération d'un diff."""

        filtered = []
        for line in lines:
            if not line:
                continue
            lower = line.lower()
            if "[erreur]" in lower or "[info]" in lower or "[exception]" in lower:
                continue
            if not LINE_RW_PREFIX.search(line):
                continue
            path = extract_first_path(line)
            if not path:
                continue
            if not self._is_dir_cached(path):
                continue
            filtered.append(line)
        return filtered

    def _export_filtered(self) -> None:
        """Exporte les lignes actuellement visibles vers un fichier texte."""

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
    def _persist_scan_results(self) -> None:
        """Sauvegarde les résultats d'un scan dans un fichier temporaire."""

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
        """Compare le scan courant au scan initial puis affiche/enregistre le diff."""

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
        base_filtered = self._filter_lines_for_diff(base_lines)
        new_filtered = self._filter_lines_for_diff(new_lines)
        diff_lines = [
            line for line in difflib.unified_diff(
                base_filtered,
                new_filtered,
                fromfile="",
                tofile="",
                lineterm="",
            )
            if line and not line.startswith("---") and not line.startswith("+++")
        ]
        if diff_lines:
            diff_text = "\n".join(diff_lines)
            try:
                with open(self.diff_output_path, "w", encoding="utf-8") as fh:
                    fh.write(diff_text)
                    if not diff_text.endswith("\n"):
                        fh.write("\n")
            except Exception:
                pass
            self._show_diff_window(diff_lines)
        else:
            self._safe_remove(self.diff_output_path)
            messagebox.showinfo("Scan comparaison", "Aucune différence RW détectée entre les scans.")

    def _show_diff_window(self, diff_lines):
        """Ouvre une fenêtre contenant le diff généré entre deux scans."""

        win = tk.Toplevel(self)
        win.title("Différence entre les scans")
        win.geometry("900x600")
        txt_content = "\n".join(diff_lines)
        if txt_content and not txt_content.endswith("\n"):
            txt_content += "\n"

        frm_actions = ttk.Frame(win)
        frm_actions.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        def _export_diff():
            path = filedialog.asksaveasfilename(
                title="Exporter la comparaison",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=DIFF_EXPORT_DEFAULT,
            )
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(txt_content)
                messagebox.showinfo("Export diff", f"Export terminé : {path}")
            except Exception as ex:
                messagebox.showerror("Export diff", str(ex))

        ttk.Button(frm_actions, text="Exporter", command=_export_diff).pack(side=tk.RIGHT)

        txt = tk.Text(win, wrap=tk.NONE)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.insert("1.0", txt_content)
        txt.configure(state=tk.DISABLED)
        yscroll = ttk.Scrollbar(win, orient=tk.VERTICAL, command=txt.yview)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        txt.configure(yscrollcommand=yscroll.set)
        xscroll = ttk.Scrollbar(win, orient=tk.HORIZONTAL, command=txt.xview)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        txt.configure(xscrollcommand=xscroll.set)

    def _update_compare_state(self) -> None:
        """Active/désactive les boutons de scan selon l'état courant."""

        if self.running:
            self.btn_scan_base.configure(state=tk.DISABLED)
            self.btn_scan_compare.configure(state=tk.DISABLED)
        else:
            self.btn_scan_base.configure(state=tk.NORMAL)
            state_compare = tk.NORMAL if os.path.isfile(self.base_scan_path) else tk.DISABLED
            self.btn_scan_compare.configure(state=state_compare)

    def _safe_remove(self, path: str):
        """Supprime silencieusement un fichier (utilisé pour les fichiers temporaires)."""

        try:
            if path and os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    def _copy_selection(self):
        """Copie la sélection actuelle de la zone de texte dans le presse-papiers."""

        try: sel = self.txt.selection_get(); self.clipboard_clear(); self.clipboard_append(sel)
        except Exception: pass

    def _show_context_menu(self, event):
        """Affiche le menu contextuel personnalisé du widget texte."""

        try: self.menu.tk_popup(event.x_root, event.y_root)
        finally: self.menu.grab_release()

    def _enforce_standard_user(self):
        """Vérifie que l'application n'est pas exécutée avec des privilèges élevés."""

        if is_running_elevated():
            messagebox.showerror("Droits élevés détectés",
                                 "Cette application doit être lancée avec un utilisateur standard.")
            self.after(100, self.on_close)
    def on_close(self) -> None:
        """Ferme proprement la fenêtre principale en stoppant les processus éventuels."""
        try:
            self.runner.stop_scan()
        except Exception as e:
            logger.warning(f"Erreur lors de l'arrêt du runner: {e}")
        
        self._cleanup_scan_files()
        self.destroy()

    def _cleanup_scan_files(self):
        """Supprime les fichiers temporaires de scan générés par l'application."""

        for path in (self.base_scan_path, self.compare_scan_path, self.diff_output_path):
            self._safe_remove(path)

def main():
    """Point d'entrée : instancie la fenêtre principale et lance la boucle Tk."""

    app=AccessChkGUI(); app.protocol("WM_DELETE_WINDOW", app.on_close); app.mainloop()
if __name__ == "__main__": main()
