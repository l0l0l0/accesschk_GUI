#!/usr/bin/env python3
"""
Test spécifique pour le problème Program Files
"""

import os
import sys
import subprocess
import shlex
from typing import List

def sanitize_command_args(args: List[str]) -> List[str]:
    """Version simplifiée de la fonction de sanitization."""
    DANGEROUS_CHARS = ['&', '|', ';', '$', '`', '<', '>']
    
    sanitized = []
    for arg in args:
        if not isinstance(arg, str):
            continue
        
        # Check for really dangerous characters
        dangerous_found = [char for char in DANGEROUS_CHARS if char in arg]
        if dangerous_found:
            if os.path.exists(arg) or arg.startswith('-') or arg in ['accepteula', 'nobanner']:
                sanitized.append(shlex.quote(arg))
            else:
                print(f"⚠️  Argument potentiellement dangereux ignoré: {arg} (caractères: {', '.join(dangerous_found)})")
        else:
            sanitized.append(arg)
    
    return sanitized

def test_accesschk_command(accesschk_path: str, target: str, principal: str = ""):
    """Test d'une commande AccessChk comme dans l'application."""
    
    print(f"\n🧪 Test AccessChk: {target}")
    print(f"📁 Cible: {target}")
    print(f"👤 Principal: {principal or '(auto)'}")
    
    # Construction de la commande comme dans l'application
    if principal:
        base_args = [accesschk_path, "-accepteula", "-nobanner", principal, "-w", target]
    else:
        base_args = [accesschk_path, "-accepteula", "-nobanner", "-w", target]
    
    print(f"🔧 Arguments bruts: {base_args}")
    
    # Sanitization
    args = sanitize_command_args(base_args)
    print(f"🧹 Arguments sanitized: {args}")
    
    # Vérification que tous les arguments sont présents
    if len(args) != len(base_args):
        print(f"❌ PROBLÈME: {len(base_args) - len(args)} arguments supprimés!")
        return False
    
    # Exécution
    try:
        print(f"▶️  Exécution: {' '.join(args)}")
        
        startupinfo = None
        creationflags = 0
        if os.name == 'nt':  # Windows
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
        
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=creationflags,
            text=True
        )
        
        stdout, stderr = proc.communicate()
        
        print(f"📤 Code de retour: {proc.returncode}")
        print(f"📝 Lignes stdout: {len(stdout.splitlines()) if stdout else 0}")
        print(f"⚠️  Lignes stderr: {len(stderr.splitlines()) if stderr else 0}")
        
        if proc.returncode == 0 and stdout.strip():
            print(f"✅ SUCCÈS!")
            lines_with_write = sum(1 for line in stdout.splitlines() if 'W' in line[:3])
            print(f"✍️  Lignes avec permissions d'écriture: {lines_with_write}")
            
            # Montrer les 5 premières lignes
            lines = stdout.splitlines()[:5]
            for i, line in enumerate(lines):
                print(f"   {i+1}: {line[:100]}")
            if len(stdout.splitlines()) > 5:
                print(f"   ... et {len(stdout.splitlines()) - 5} lignes de plus")
        else:
            print(f"❌ ÉCHEC!")
            if stderr.strip():
                print(f"   Stderr: {stderr.strip()[:200]}")
        
        return proc.returncode == 0 and stdout.strip()
        
    except Exception as e:
        print(f"💥 Erreur: {e}")
        return False

def main():
    print("🧪 Test spécifique Program Files")
    print("=" * 50)
    
    # Chemin vers AccessChk
    accesschk_path = os.path.join(os.path.dirname(__file__), "accesschk.exe")
    if not os.path.exists(accesschk_path):
        print(f"❌ AccessChk non trouvé: {accesschk_path}")
        return
    
    print(f"✅ AccessChk trouvé: {accesschk_path}")
    
    # Tests avec différentes cibles
    targets = [
        "C:\\Program Files",
        "C:\\Program Files (x86)"
    ]
    
    principals = [
        "Users"
    ]
    
    success_count = 0
    total_tests = 0
    
    for target in targets:
        if not os.path.exists(target):
            print(f"⏭️  Ignorer {target} (n'existe pas)")
            continue
            
        for principal in principals:
            total_tests += 1
            if test_accesschk_command(accesschk_path, target, principal):
                success_count += 1
    
    print(f"\n📊 RÉSULTATS FINAUX")
    print(f"✅ Réussis: {success_count}/{total_tests}")
    print(f"❌ Échoués: {total_tests - success_count}/{total_tests}")
    
    if success_count < total_tests:
        print(f"🚨 Des tests ont échoué! Vérifiez les arguments ou les permissions.")
    else:
        print(f"🎉 Tous les tests réussis!")

if __name__ == "__main__":
    main()