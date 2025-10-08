#!/usr/bin/env python3
"""
Test de la fonction de filtrage pour la comparaison
"""

import os
import re

# Régex utilisées dans l'application
LINE_RW_PREFIX = re.compile(r"^\s*RW\s+", re.I)
PATH_EXTRACT = re.compile(r"(?:[A-Za-z]:\\|\\\\[^\\]+\\)[^\r\n]*")

def extract_first_path(s: str):
    """Extrait le premier chemin d'une ligne."""
    if not s or not isinstance(s, str):
        return None
    
    try:
        m = PATH_EXTRACT.search(s)
        return m.group(0).strip().rstrip('"') if m else None
    except (AttributeError, IndexError) as e:
        print(f"Erreur lors de l'extraction du chemin: {e}")
        return None

def _is_dir_cached(path: str, cache: dict) -> bool:
    """Version simplifiée du cache de répertoires."""
    if not path or not isinstance(path, str):
        return False
        
    key = path.lower()
    if key in cache: 
        return cache[key]
    
    try: 
        isd = os.path.isdir(path)
    except (OSError, ValueError, TypeError) as e:
        print(f"Erreur lors de la vérification du dossier {path}: {e}")
        isd = False
    
    cache[key] = isd
    return isd

def filter_lines_for_diff(lines, cache):
    """Simule la nouvelle fonction _filter_lines_for_diff de l'application."""
    
    filtered = []
    for i, line in enumerate(lines):
        print(f"\nLigne {i+1}: '{line}'")
        
        if not line:
            print("  -> Ligne vide")
            continue
            
        lower = line.lower()
        if "[erreur]" in lower or "[info]" in lower or "[exception]" in lower:
            print("  -> Contient [erreur], [info] ou [exception]")
            continue
        
        # Deux cas à traiter :
        # 1. Lignes de répertoires (commencent par un chemin)
        # 2. Lignes de permissions RW (indentées, commencent par RW)
        
        path = extract_first_path(line)
        if path:
            # Ligne de répertoire - la garder si c'est effectivement un répertoire
            print(f"  -> Chemin trouve: {path}")
            if _is_dir_cached(path, cache):
                print("  -> Est un repertoire -> CONSERVEE!")
                filtered.append(line)
            else:
                print("  -> N'est pas un repertoire")
        elif LINE_RW_PREFIX.search(line):
            # Ligne de permission RW sans chemin - la garder pour la comparaison
            print("  -> Ligne de permission RW -> CONSERVEE!")
            filtered.append(line)
        else:
            print("  -> Ni chemin ni permission RW")
            
    return filtered

def test_filtering():
    """Test du filtrage des lignes."""
    
    print("Test de filtrage des lignes pour la comparaison")
    print("=" * 50)
    
    # Vraies lignes provenant d'AccessChk
    test_lines = [
        "C:\\Program Files\\7-Zip",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW AUTORITE NT\\Système", 
        "  RW BUILTIN\\Administrateurs",
        "  R  BUILTIN\\Utilisateurs",
        "  R  AUTORITE DE PACKAGE D'APPLICATION\\TOUS LES PACKAGES D'APPLICATION",
        "C:\\Program Files (x86)\\Adobe",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW AUTORITE NT\\Système",
        "  RW BUILTIN\\Administrateurs",
        "  R  BUILTIN\\Utilisateurs",
        "C:\\Program Files\\Common Files",
        "  RW NT SERVICE\\TrustedInstaller",
        "C:\\Program Files (x86)\\Common Files",
        "  RW NT SERVICE\\TrustedInstaller",
        "C:\\fichier_inexistant.txt",
        "  RW BUILTIN\\Users",
        "[ERREUR] Quelque chose",
        "[INFO] Information"
    ]
    
    cache = {}
    print(f"📄 Lignes à traiter: {len(test_lines)}")
    
    for i, line in enumerate(test_lines):
        print(f"{i+1:2d}: {line}")
    
    print("\n🔍 Filtrage en cours...")
    filtered = filter_lines_for_diff(test_lines, cache)
    
    print(f"\n📊 Résultats:")
    print(f"✅ Lignes filtrées: {len(filtered)}")
    print(f"❌ Lignes supprimées: {len(test_lines) - len(filtered)}")
    
    print(f"\n📝 Lignes conservées:")
    for i, line in enumerate(filtered):
        print(f"  {i+1}: {line}")
    
    print(f"\n💾 Cache des répertoires:")
    for path, is_dir in cache.items():
        status = "✅ DIR" if is_dir else "❌ FILE/MISSING"
        print(f"  {path} → {status}")

if __name__ == "__main__":
    test_filtering()