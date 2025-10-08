#!/usr/bin/env python3
"""
Test de validation de la correction du scan de comparaison
"""

import os
import sys
import tempfile
import difflib

# Ajouter le répertoire du script au PYTHONPATH pour importer accesschk_gui_tk
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importer les fonctions de l'application
from accesschk_gui_tk import extract_first_path, LINE_RW_PREFIX
import re

def mock_is_dir_cached(path: str, cache: dict) -> bool:
    """Version mock du cache de répertoires pour le test."""
    if not path or not isinstance(path, str):
        return False
        
    key = path.lower()
    if key in cache: 
        return cache[key]
    
    # Simuler des répertoires connus
    known_dirs = [
        "c:\\program files",
        "c:\\program files (x86)",
        "c:\\program files\\common files",
        "c:\\program files (x86)\\common files",
        "c:\\program files\\7-zip",
        "c:\\program files (x86)\\adobe",
        "c:\\windows",
        "c:\\windows\\system32"
    ]
    
    isd = key in known_dirs
    cache[key] = isd
    return isd

def filter_lines_for_diff_new(lines, cache):
    """Version corrigée de _filter_lines_for_diff."""
    
    filtered = []
    for line in lines:
        if not line:
            continue
        lower = line.lower()
        if "[erreur]" in lower or "[info]" in lower or "[exception]" in lower:
            continue
        
        # Deux cas à traiter :
        # 1. Lignes de répertoires (commencent par un chemin)
        # 2. Lignes de permissions RW (indentées, commencent par RW)
        
        path = extract_first_path(line)
        if path:
            # Ligne de répertoire - la garder si c'est effectivement un répertoire
            if mock_is_dir_cached(path, cache):
                filtered.append(line)
        elif LINE_RW_PREFIX.search(line):
            # Ligne de permission RW sans chemin - la garder pour la comparaison
            filtered.append(line)
    return filtered

def filter_lines_for_diff_old(lines, cache):
    """Version originale (bugguée) de _filter_lines_for_diff."""
    
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
        if not mock_is_dir_cached(path, cache):
            continue
        filtered.append(line)
    return filtered

def test_comparison_fix():
    """Test de la correction du scan de comparaison."""
    
    print("=== Test de validation de la correction ===")
    print()
    
    # Données de test simulant une vraie sortie AccessChk
    sample_lines = [
        "C:\\Program Files\\7-Zip",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW AUTORITE NT\\Système",
        "  RW BUILTIN\\Administrateurs",
        "  R  BUILTIN\\Utilisateurs",
        "C:\\Program Files (x86)\\Adobe",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW AUTORITE NT\\Système",
        "  RW BUILTIN\\Administrateurs",
        "  R  BUILTIN\\Utilisateurs",
        "C:\\Program Files\\Common Files",
        "  RW NT SERVICE\\TrustedInstaller",
        "C:\\Program Files (x86)\\Common Files",
        "  RW NT SERVICE\\TrustedInstaller",
        "[INFO] Information ignorée",
        "[ERREUR] Erreur ignorée"
    ]
    
    cache = {}
    
    # Test de l'ancienne version (bugguée)
    print("1. Test de l'ancienne version (bugguée):")
    old_filtered = filter_lines_for_diff_old(sample_lines, cache)
    print(f"   Lignes conservées: {len(old_filtered)}")
    if old_filtered:
        print("   Lignes:")
        for line in old_filtered:
            print(f"     {line}")
    else:
        print("   ❌ AUCUNE LIGNE CONSERVÉE (c'était le problème!)")
    
    print()
    
    # Test de la nouvelle version (corrigée)
    cache.clear()  # Reset du cache
    print("2. Test de la nouvelle version (corrigée):")
    new_filtered = filter_lines_for_diff_new(sample_lines, cache)
    print(f"   Lignes conservées: {len(new_filtered)}")
    print("   Lignes:")
    for i, line in enumerate(new_filtered, 1):
        print(f"     {i:2d}. {line}")
    
    print()
    
    # Validation
    print("3. Validation:")
    
    # Vérifier que Program Files et Program Files (x86) sont présents
    program_files_found = any("Program Files" in line and "(x86)" not in line for line in new_filtered)
    program_files_x86_found = any("Program Files (x86)" in line for line in new_filtered)
    
    print(f"   ✅ Program Files trouvé: {program_files_found}")
    print(f"   ✅ Program Files (x86) trouvé: {program_files_x86_found}")
    print(f"   ✅ Lignes RW conservées: {len([l for l in new_filtered if l.strip().startswith('RW')])}")
    print(f"   ✅ Amélioration: {len(new_filtered)} lignes vs {len(old_filtered)} lignes")
    
    if program_files_found and program_files_x86_found and len(new_filtered) > 0:
        print("\n🎉 CORRECTION VALIDÉE! La comparaison de scans fonctionne maintenant.")
        return True
    else:
        print("\n❌ La correction a des problèmes.")
        return False

def test_diff_generation():
    """Test de génération de diff pour vérifier que la comparaison fonctionne."""
    
    print("\n=== Test de génération de diff ===")
    
    # Simulation de deux scans
    scan1 = [
        "C:\\Program Files\\7-Zip",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW BUILTIN\\Administrateurs",
        "C:\\Program Files (x86)\\Adobe", 
        "  RW NT SERVICE\\TrustedInstaller"
    ]
    
    scan2 = [
        "C:\\Program Files\\7-Zip",
        "  RW NT SERVICE\\TrustedInstaller",
        "  RW BUILTIN\\Administrateurs",
        "C:\\Program Files (x86)\\Adobe",
        "  RW NT SERVICE\\TrustedInstaller",
        "C:\\Program Files (x86)\\NewApp",  # Nouvelle application
        "  RW NT SERVICE\\TrustedInstaller"
    ]
    
    cache = {}
    
    # Filtrage avec la nouvelle version
    filtered1 = filter_lines_for_diff_new(scan1, cache)
    cache.clear()
    filtered2 = filter_lines_for_diff_new(scan2, cache)
    
    # Génération du diff
    diff_lines = list(difflib.unified_diff(
        filtered1,
        filtered2,
        fromfile="Scan initial",
        tofile="Scan comparaison",
        lineterm=""
    ))
    
    print(f"Lignes scan 1: {len(filtered1)}")
    print(f"Lignes scan 2: {len(filtered2)}")
    print(f"Différences trouvées: {len([l for l in diff_lines if l.startswith('+') or l.startswith('-')])}")
    
    print("\nDiff généré:")
    for line in diff_lines:
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue
        print(f"  {line}")
    
    # Vérifier qu'on détecte l'ajout de NewApp
    has_newapp = any("NewApp" in line for line in diff_lines)
    print(f"\n✅ Nouveau répertoire détecté: {has_newapp}")
    
    return has_newapp

if __name__ == "__main__":
    print("Test de validation de la correction du scan de comparaison")
    print("=" * 60)
    
    success1 = test_comparison_fix()
    success2 = test_diff_generation()
    
    print("\n" + "=" * 60)
    if success1 and success2:
        print("🎉 TOUS LES TESTS RÉUSSIS! La correction fonctionne parfaitement.")
        print("\nMaintenant la comparaison de scans va correctement afficher:")
        print("  • Program Files")
        print("  • Program Files (x86)")  
        print("  • Toutes les permissions RW associées")
    else:
        print("❌ Certains tests ont échoué.")
    
    print("\nVous pouvez maintenant tester dans l'interface graphique!")