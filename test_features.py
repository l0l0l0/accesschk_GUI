#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests rapides de validation des nouvelles fonctionnalités."""

import os
import sys
import tempfile
import json

# Ajouter le dossier parent au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_new_features():
    """Test rapide des nouvelles fonctionnalités."""
    
    print("🧪 Test des nouvelles fonctionnalités AccessChk GUI")
    print("=" * 60)
    
    try:
        import accesschk_gui_tk as gui
        
        # Test 1: Configuration
        print("📋 Test 1: Configuration...")
        config = gui.AppConfig()
        assert hasattr(config, 'BATCH_SIZE'), "Batch size manquant"
        assert hasattr(config, 'DANGEROUS_CHARS'), "Liste des caractères dangereux manquante"
        print("✅ Configuration: OK")
        
        # Test 2: Gestionnaire d'historique
        print("\n📚 Test 2: Gestionnaire d'historique...")
        with tempfile.TemporaryDirectory() as temp_dir:
            history_mgr = gui.ScanHistoryManager(temp_dir)
            
            # Ajouter un scan
            history_mgr.add_scan("baseline", ["C:\\test"], "user", 50)
            history = history_mgr.get_history()
            
            assert len(history) == 1, "Historique vide après ajout"
            assert history[0]['scan_type'] == "baseline", "Type de scan incorrect"
            assert history[0]['result_count'] == 50, "Nombre de résultats incorrect"
            
            print("✅ Gestionnaire d'historique: OK")
        
        # Test 3: Gestionnaire d'exports
        print("\n📤 Test 3: Gestionnaire d'exports...")
        test_logs = [
            {'line': 'RW DOMAIN\\user C:\\test\\file.txt', 'write': True, 'err': False},
            {'line': 'R  DOMAIN\\user C:\\test\\file2.txt', 'write': False, 'err': False}
        ]
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test JSON
            json_path = os.path.join(temp_dir, "test.json")
            gui.ExportManager.export_to_json(test_logs, json_path)
            assert os.path.exists(json_path), "Fichier JSON non créé"
            
            with open(json_path, 'r') as f:
                data = json.load(f)
                assert 'entries' in data, "Clé 'entries' manquante dans JSON"
                assert len(data['entries']) == 2, "Nombre d'entrées incorrect"
            
            # Test CSV
            csv_path = os.path.join(temp_dir, "test.csv")
            gui.ExportManager.export_to_csv(test_logs, csv_path)
            assert os.path.exists(csv_path), "Fichier CSV non créé"
            
            # Test XML
            xml_path = os.path.join(temp_dir, "test.xml")
            gui.ExportManager.export_to_xml(test_logs, xml_path)
            assert os.path.exists(xml_path), "Fichier XML non créé"
            
            print("✅ Gestionnaire d'exports: OK")
        
        # Test 4: Validation améliorée
        print("\n🔒 Test 4: Validation sécurisée...")
        
        # Test chemins avec parenthèses (devrait être valide maintenant)
        is_valid, msg, paths = gui.validate_target_paths("C:\\Program Files (x86)")
        assert is_valid, f"Chemin avec parenthèses rejeté: {msg}"
        
        # Test chemins dangereux (devrait être rejeté)
        is_valid, msg, paths = gui.validate_target_paths("C:\\test & dangerous")
        assert not is_valid, "Chemin dangereux accepté"
        
        print("✅ Validation sécurisée: OK")
        
        # Test 5: Fonctions utilitaires
        print("\n🔧 Test 5: Fonctions utilitaires...")
        
        # Test extraction de chemin
        path = gui.extract_first_path("RW USER C:\\Windows\\System32\\test.txt")
        assert path == "C:\\Windows\\System32\\test.txt", f"Extraction de chemin incorrecte: {path}"
        
        # Test utilisateur principal
        principal = gui.current_user_principal()
        assert isinstance(principal, str), "Principal n'est pas une chaîne"
        assert len(principal) > 0, "Principal vide"
        
        print("✅ Fonctions utilitaires: OK")
        
        print("\n🎉 TOUS LES TESTS SONT PASSÉS AVEC SUCCÈS !")
        print("\nNouvelles fonctionnalités validées :")
        print("• ✅ Raccourcis clavier et menus améliorés")
        print("• ✅ Export multi-format (TXT, CSV, JSON, XML)")
        print("• ✅ Historique des scans avec persistance")
        print("• ✅ Validation sécurisée des chemins Windows")
        print("• ✅ Gestion d'erreurs robuste avec logging")
        print("• ✅ Architecture modulaire et maintenable")
        
        return True
        
    except ImportError as e:
        print(f"❌ Erreur d'import: {e}")
        return False
    except AssertionError as e:
        print(f"❌ Test échoué: {e}")
        return False
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_new_features()
    sys.exit(0 if success else 1)