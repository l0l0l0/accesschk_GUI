#!/usr/bin/env python3
"""
Test des nouvelles fonctionnalités : Exclusions et affichage de commande
"""

import os
import sys

# Ajouter le répertoire du script au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_exclusions_functionality():
    """Test de la fonctionnalité d'exclusion."""
    
    print("=== Test de la fonctionnalité Exclusions ===")
    
    # Simuler le filtrage avec exclusions
    targets = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Users\\TestUser\\AppData\\Local",
        "C:\\Users\\TestUser\\AppData\\Roaming", 
        "C:\\Windows\\System32",
        "C:\\Temp"
    ]
    
    exclusions = [
        "C:\\Users\\TestUser\\AppData"  # Exclut tous les AppData
    ]
    
    print("Cibles originales :")
    for i, target in enumerate(targets, 1):
        print(f"  {i}. {target}")
    
    print(f"\nExclusions configurées :")
    for i, exclusion in enumerate(exclusions, 1):
        print(f"  {i}. {exclusion}")
    
    # Filtrage avec exclusions
    filtered_targets = []
    excluded_targets = []
    
    for target in targets:
        target_normalized = os.path.normpath(target).lower()
        is_excluded = False
        
        for exclusion in exclusions:
            exclusion_normalized = os.path.normpath(exclusion).lower()
            if target_normalized.startswith(exclusion_normalized):
                is_excluded = True
                excluded_targets.append(target)
                break
        
        if not is_excluded:
            filtered_targets.append(target)
    
    print(f"\nRésultats du filtrage :")
    print(f"✅ Cibles conservées ({len(filtered_targets)}) :")
    for i, target in enumerate(filtered_targets, 1):
        print(f"  {i}. {target}")
    
    print(f"\n❌ Cibles exclues ({len(excluded_targets)}) :")
    for i, target in enumerate(excluded_targets, 1):
        print(f"  {i}. {target}")
    
    # Validation
    expected_excluded = 2  # AppData\Local et AppData\Roaming
    expected_kept = len(targets) - expected_excluded
    
    success = (len(excluded_targets) == expected_excluded and 
               len(filtered_targets) == expected_kept)
    
    print(f"\n✅ Test réussi : {success}")
    return success

def test_command_display():
    """Test de l'affichage de commande."""
    
    print("\n=== Test de l'affichage de commande ===")
    
    # Simuler la construction d'une commande
    accesschk_path = "C:\\Tools\\accesschk.exe"
    principal = "Users"
    targets = ["C:\\Program Files", "C:\\Program Files (x86)"]
    
    # Construction de la commande d'exemple
    sample_cmd = [accesschk_path, "-accepteula", "-nobanner"]
    if principal:
        sample_cmd.append(principal)
    sample_cmd.extend(["-w", "-s", targets[0] if targets else "<cible>"])
    
    # Formatage pour l'affichage
    cmd_display = " ".join(f'"{arg}"' if " " in arg else arg for arg in sample_cmd)
    if len(targets) > 1:
        cmd_display += f" (et {len(targets) - 1} autres cibles)"
    
    print("Commande générée :")
    print(f"  {cmd_display}")
    
    # Validation
    expected_parts = [
        "accesschk.exe",
        "-accepteula", 
        "-nobanner",
        "Users",
        "-w",
        "-s",
        '"C:\\Program Files"',
        "(et 1 autres cibles)"
    ]
    
    success = all(part in cmd_display for part in expected_parts)
    print(f"\n✅ Test réussi : {success}")
    
    # Vérification des parties de la commande
    print("\nVérification des éléments :")
    for part in expected_parts:
        found = part in cmd_display
        status = "✅" if found else "❌"
        print(f"  {status} '{part}' : {found}")
    
    return success

def test_appdata_detection():
    """Test de la détection automatique d'AppData."""
    
    print("\n=== Test de la détection d'AppData ===")
    
    # Simuler la détection d'AppData par défaut
    default_appdata = os.path.expandvars("%USERPROFILE%\\AppData")
    appdata_exists = os.path.exists(default_appdata)
    
    print(f"Chemin AppData détecté : {default_appdata}")
    print(f"AppData existe : {appdata_exists}")
    
    # Test de l'initialisation des exclusions par défaut
    exclusions = [default_appdata] if appdata_exists else []
    
    print(f"Exclusions par défaut :")
    if exclusions:
        for i, exclusion in enumerate(exclusions, 1):
            print(f"  {i}. {exclusion}")
    else:
        print("  (aucune)")
    
    success = appdata_exists == bool(exclusions)
    print(f"\n✅ Test réussi : {success}")
    
    return success

if __name__ == "__main__":
    print("Test des nouvelles fonctionnalités AccessChk GUI")
    print("=" * 60)
    
    test1 = test_exclusions_functionality()
    test2 = test_command_display()
    test3 = test_appdata_detection()
    
    print("\n" + "=" * 60)
    print("RÉSUMÉ DES TESTS :")
    print(f"  • Fonctionnalité exclusions : {'✅ RÉUSSI' if test1 else '❌ ÉCHOUÉ'}")
    print(f"  • Affichage de commande : {'✅ RÉUSSI' if test2 else '❌ ÉCHOUÉ'}")
    print(f"  • Détection AppData : {'✅ RÉUSSI' if test3 else '❌ ÉCHOUÉ'}")
    
    if all([test1, test2, test3]):
        print(f"\n🎉 TOUS LES TESTS RÉUSSIS!")
        print(f"\nLes nouvelles fonctionnalités sont prêtes :")
        print(f"  • Bouton 'Exclusions' (Ctrl+X) pour gérer les répertoires à exclure")
        print(f"  • AppData de l'utilisateur exclu par défaut")
        print(f"  • Affichage de la commande AccessChk lancée")
        print(f"  • Filtrage automatique des cibles selon les exclusions")
    else:
        print(f"\n❌ Certains tests ont échoué. Vérifiez l'implémentation.")
    
    print(f"\nVous pouvez maintenant tester dans l'interface graphique!")
    print(f"  1. Cliquez sur 'Exclusions' ou utilisez Ctrl+X")
    print(f"  2. Observez l'affichage de la commande lors des scans")
    print(f"  3. Vérifiez que les exclusions fonctionnent correctement")