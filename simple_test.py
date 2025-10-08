#!/usr/bin/env python3
"""
Test ultra-simple pour Program Files
"""

import os
import subprocess

def simple_test():
    print("🧪 Test ultra-simple AccessChk")
    
    accesschk_path = os.path.join(os.path.dirname(__file__), "accesschk.exe")
    if not os.path.exists(accesschk_path):
        print(f"❌ AccessChk non trouvé: {accesschk_path}")
        return
    
    # Test simple sans principal spécifique
    cmd = [accesschk_path, "-accepteula", "-nobanner", "C:\\Program Files"]
    
    print(f"🔧 Commande: {' '.join(cmd)}")
    
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        
        print(f"📤 Code de retour: {proc.returncode}")
        print(f"📝 Lignes stdout: {len(proc.stdout.splitlines()) if proc.stdout else 0}")
        print(f"⚠️  Lignes stderr: {len(proc.stderr.splitlines()) if proc.stderr else 0}")
        
        if proc.returncode == 0 and proc.stdout.strip():
            print("✅ Program Files accessible!")
            # Montrer quelques lignes
            lines = proc.stdout.splitlines()[:3]
            for line in lines:
                print(f"   {line}")
        else:
            print("❌ Problème avec Program Files")
            if proc.stderr:
                print(f"   Error: {proc.stderr.strip()}")
                
    except subprocess.TimeoutExpired:
        print("⏰ Timeout - trop long")
    except Exception as e:
        print(f"💥 Erreur: {e}")

if __name__ == "__main__":
    simple_test()