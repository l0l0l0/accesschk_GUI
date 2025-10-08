#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Test de diagnostic pour les scans de comparaison."""

import os
import sys
import subprocess
import tempfile
import difflib

def test_accesschk_behavior():
    """Test le comportement d'AccessChk sur Program Files."""
    
    print("🔍 Diagnostic du comportement AccessChk")
    print("="*50)
    
    # Vérifier si accesschk.exe existe
    accesschk_path = os.path.join(os.path.dirname(__file__), "accesschk.exe")
    if not os.path.exists(accesschk_path):
        print("❌ accesschk.exe non trouvé dans le dossier courant")
        return False
    
    print(f"✅ AccessChk trouvé: {accesschk_path}")
    
    # Test sur Program Files
    test_paths = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Windows\\System32",
        "C:\\Users"
    ]
    
    for path in test_paths:
        if not os.path.exists(path):
            print(f"⚠️  Chemin non trouvé: {path}")
            continue
            
        print(f"\n📁 Test sur: {path}")
        
        # Tester avec différents utilisateurs
        users = ["Users", "BUILTIN\\Users", "S-1-5-32-545"]
        
        for user in users:
            try:
                print(f"  👤 Test avec utilisateur: {user}")
                
                # Commande AccessChk
                cmd = [accesschk_path, "-accepteula", "-nobanner", user, "-w", "-s", path]
                
                # Créer le processus
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.CREATE_NO_WINDOW
                
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    startupinfo=startupinfo,
                    creationflags=creationflags
                )
                
                stdout, stderr = proc.communicate()
                
                # Décoder la sortie
                try:
                    stdout_text = stdout.decode('utf-8', errors='replace')
                    stderr_text = stderr.decode('utf-8', errors='replace')
                except:
                    stdout_text = str(stdout)
                    stderr_text = str(stderr)
                
                print(f"    📤 Code de retour: {proc.returncode}")
                
                if stdout_text.strip():
                    lines = stdout_text.strip().split('\n')
                    print(f"    📝 Lignes stdout: {len(lines)}")
                    
                    # Compter les permissions en écriture
                    write_lines = [line for line in lines if 'RW' in line or 'W' in line]
                    print(f"    ✍️  Lignes avec permissions d'écriture: {len(write_lines)}")
                    
                    # Afficher quelques exemples
                    if write_lines:
                        print("    🔍 Exemples de permissions d'écriture:")
                        for i, line in enumerate(write_lines[:3]):
                            print(f"      {i+1}. {line.strip()}")
                        if len(write_lines) > 3:
                            print(f"      ... et {len(write_lines)-3} autres")
                else:
                    print("    📭 Aucune sortie stdout")
                
                if stderr_text.strip():
                    print(f"    ⚠️  Stderr: {stderr_text.strip()[:200]}...")
                
                # Tester si ce user fonctionne
                if proc.returncode == 0 and stdout_text.strip():
                    print(f"    ✅ Utilisateur '{user}' fonctionne bien")
                    break
                else:
                    print(f"    ❌ Utilisateur '{user}' ne fonctionne pas")
                    
            except Exception as e:
                print(f"    💥 Erreur pour utilisateur '{user}': {e}")
        
        print()  # Ligne vide entre les paths
    
    return True

def test_comparison_logic():
    """Test la logique de comparaison."""
    
    print("\n🔄 Test de la logique de comparaison")
    print("="*40)
    
    # Simuler deux scans
    scan1_lines = [
        "RW BUILTIN\\Users  C:\\Program Files\\Common Files\\test1.txt",
        "RW BUILTIN\\Users  C:\\Program Files (x86)\\Microsoft\\test2.txt", 
        "R  BUILTIN\\Users  C:\\Windows\\System32\\test3.txt"
    ]
    
    scan2_lines = [
        "RW BUILTIN\\Users  C:\\Program Files\\Common Files\\test1.txt",
        "RW BUILTIN\\Users  C:\\Program Files (x86)\\Microsoft\\test2.txt",
        "RW BUILTIN\\Users  C:\\Program Files (x86)\\Microsoft\\NEW_FILE.txt",  # Nouveau fichier
        "R  BUILTIN\\Users  C:\\Windows\\System32\\test3.txt"
    ]
    
    print("📄 Scan 1 (baseline):")
    for line in scan1_lines:
        print(f"  {line}")
    
    print("\n📄 Scan 2 (comparaison):")
    for line in scan2_lines:
        print(f"  {line}")
    
    # Générer le diff
    diff_lines = list(difflib.unified_diff(
        scan1_lines,
        scan2_lines,
        fromfile="scan_initial",
        tofile="scan_comparaison",
        lineterm=""
    ))
    
    print(f"\n🔍 Différences détectées ({len(diff_lines)} lignes):")
    for line in diff_lines:
        if line.startswith('+++') or line.startswith('---'):
            continue
        if line.startswith('+'):
            print(f"  ➕ AJOUTÉ: {line[1:]}")
        elif line.startswith('-'):
            print(f"  ➖ SUPPRIMÉ: {line[1:]}")
        elif line.startswith('@@'):
            print(f"  📍 CONTEXTE: {line}")
    
    if not any(line.startswith(('+', '-')) and not line.startswith(('+++', '---')) for line in diff_lines):
        print("  ⚠️  Aucune différence trouvée (problème potentiel!)")
    
    return len(diff_lines) > 0

if __name__ == "__main__":
    print("🧪 Diagnostic AccessChk GUI - Scan de comparaison")
    print("="*60)
    
    # Test 1: Comportement AccessChk
    print("1️⃣  Test du comportement AccessChk...")
    accesschk_ok = test_accesschk_behavior()
    
    # Test 2: Logique de comparaison
    print("2️⃣  Test de la logique de comparaison...")
    comparison_ok = test_comparison_logic()
    
    # Résumé
    print("\n📊 RÉSUMÉ DU DIAGNOSTIC")
    print("="*30)
    print(f"AccessChk fonctionne: {'✅' if accesschk_ok else '❌'}")
    print(f"Logique de comparaison: {'✅' if comparison_ok else '❌'}")
    
    if accesschk_ok and comparison_ok:
        print("\n💡 RECOMMANDATIONS:")
        print("• Vérifiez que le scan initial contient bien des données")
        print("• Assurez-vous que les deux scans utilisent le même utilisateur")
        print("• Vérifiez que les cibles sont identiques entre les scans")
        print("• Regardez dans les logs de l'application (accesschk_gui.log)")
    else:
        print("\n🚨 PROBLÈMES DÉTECTÉS:")
        if not accesschk_ok:
            print("• AccessChk ne fonctionne pas correctement")
        if not comparison_ok:
            print("• La logique de comparaison a des problèmes")