#!/usr/bin/env python3
"""
Test de la regex d'extraction de chemin
"""

import re

PATH_EXTRACT = re.compile(r"(?:[A-Za-z]:\\|\\\\[^\\]+\\)[^\r\n]*")

def extract_first_path(s: str):
    """Test de la fonction d'extraction de chemin."""
    if not s or not isinstance(s, str):
        return None
    
    try:
        m = PATH_EXTRACT.search(s)
        return m.group(0).strip().rstrip('"') if m else None
    except (AttributeError, IndexError) as e:
        print(f"Erreur lors de l'extraction du chemin: {e}")
        return None

def test_path_extraction():
    """Test de l'extraction de chemins."""
    
    test_lines = [
        "  RW BUILTIN\\Users  C:\\Program Files\\Common Files\\test.txt",
        "  RW BUILTIN\\Users  C:\\Program Files (x86)\\Microsoft\\test.txt",
        "  R  BUILTIN\\Users  C:\\Windows\\System32\\test.txt",
        "C:\\Program Files\\7-Zip",
        "C:\\Program Files (x86)\\Adobe",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW AUTORITE NT\\Système",
        "Error getting security: AccÞs refusÚ."
    ]
    
    print("🧪 Test d'extraction de chemins")
    print("=" * 50)
    
    for line in test_lines:
        path = extract_first_path(line)
        print(f"Ligne: {line[:60]}")
        print(f"  → Chemin extrait: {path}")
        print()

if __name__ == "__main__":
    test_path_extraction()