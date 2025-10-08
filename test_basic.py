#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Test basique pour vérifier que le module AccessChk GUI se charge correctement."""

import sys
import os

# Ajouter le dossier parent au path pour pouvoir importer le module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Test d'import du module principal
    import accesschk_gui_tk
    print("✅ Import du module principal: OK")
    
    # Test de création de la classe AppConfig
    config = accesschk_gui_tk.AppConfig()
    print("✅ Création de AppConfig: OK")
    
    # Test des constantes de configuration
    assert hasattr(config, 'BATCH_SIZE')
    assert hasattr(config, 'WINDOW_WIDTH')
    assert hasattr(config, 'PROGRESS_BAR_SPEED')
    print("✅ Constantes de configuration: OK")
    
    # Test des fonctions de validation
    is_valid, msg = accesschk_gui_tk.validate_executable_path("test.exe")
    print(f"✅ Fonction de validation: OK (retour: {is_valid})")
    
    # Test des fonctions utilitaires
    principal = accesschk_gui_tk.current_user_principal()
    print(f"✅ Utilisateur principal détecté: {principal}")
    
    print("\n🎉 Tous les tests de base sont passés avec succès!")
    print("L'application AccessChk GUI est prête à être utilisée.")

except ImportError as e:
    print(f"❌ Erreur d'import: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Erreur inattendue: {e}")
    sys.exit(1)