#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Test de validation des chemins avec parenthèses."""

import sys
import os

# Ajouter le dossier parent au path pour pouvoir importer le module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import accesschk_gui_tk
    
    # Test avec des chemins contenant des parenthèses (valides)
    test_paths = [
        "C:\\Program Files (x86)",
        "C:\\Program Files (x86)\\Microsoft",
        "D:\\Test [Folder]\\subfolder",
        "E:\\Data {backup}\\files"
    ]
    
    for path in test_paths:
        is_valid, error_msg, validated = accesschk_gui_tk.validate_target_paths(path)
        print(f"Chemin: {path}")
        print(f"  Résultat: {'✅ Valide' if is_valid else '❌ Invalide'}")
        if not is_valid:
            print(f"  Erreur: {error_msg}")
        print()
    
    # Test avec des chemins vraiment dangereux
    dangerous_paths = [
        "C:\\test & echo dangerous",
        "C:\\test | echo pipe",
        "C:\\test ; echo semicolon",
        "C:\\test $ echo variable"
    ]
    
    print("=== Tests avec chemins dangereux ===")
    for path in dangerous_paths:
        is_valid, error_msg, validated = accesschk_gui_tk.validate_target_paths(path)
        print(f"Chemin: {path}")
        print(f"  Résultat: {'✅ Valide' if is_valid else '❌ Invalide (attendu)'}")
        if not is_valid:
            print(f"  Erreur: {error_msg}")
        print()

except Exception as e:
    print(f"❌ Erreur: {e}")
    import traceback
    traceback.print_exc()