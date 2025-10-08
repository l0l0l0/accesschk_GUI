#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Suite de tests unitaires pour AccessChk GUI."""

import unittest
import tempfile
import os
import json
import sys
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Ajouter le dossier parent au path pour pouvoir importer le module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import accesschk_gui_tk as gui


class TestAppConfig(unittest.TestCase):
    """Tests pour la classe AppConfig."""
    
    def test_config_constants(self):
        """Test que toutes les constantes sont définies."""
        config = gui.AppConfig()
        
        # Vérifier les constantes de performance
        self.assertIsInstance(config.BATCH_SIZE, int)
        self.assertGreater(config.BATCH_SIZE, 0)
        
        # Vérifier les constantes UI
        self.assertIsInstance(config.WINDOW_WIDTH, int)
        self.assertIsInstance(config.WINDOW_HEIGHT, int)
        
        # Vérifier les constantes de sécurité
        self.assertIsInstance(config.DANGEROUS_CHARS, list)
        self.assertIn('&', config.DANGEROUS_CHARS)
        self.assertIn('|', config.DANGEROUS_CHARS)


class TestValidationFunctions(unittest.TestCase):
    """Tests pour les fonctions de validation."""
    
    def test_validate_executable_path_valid(self):
        """Test de validation d'un chemin d'exécutable valide."""
        # Créer un fichier temporaire .exe
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
            tmp.write(b'fake exe')
            tmp_path = tmp.name
        
        try:
            # Renommer pour que ce soit accesschk.exe
            exe_path = os.path.join(os.path.dirname(tmp_path), 'accesschk.exe')
            os.rename(tmp_path, exe_path)
            
            is_valid, msg = gui.validate_executable_path(exe_path)
            self.assertTrue(is_valid)
            self.assertEqual(msg, "")
        finally:
            try:
                os.unlink(exe_path)
            except FileNotFoundError:
                pass
    
    def test_validate_executable_path_invalid(self):
        """Test de validation d'un chemin d'exécutable invalide."""
        # Fichier inexistant
        is_valid, msg = gui.validate_executable_path("nonexistent.exe")
        self.assertFalse(is_valid)
        self.assertIn("n'existe pas", msg)
        
        # Mauvaise extension
        is_valid, msg = gui.validate_executable_path("test.txt")
        self.assertFalse(is_valid)
        self.assertIn("Extension", msg)
        
        # Caractères dangereux
        is_valid, msg = gui.validate_executable_path("test&dangerous.exe")
        self.assertFalse(is_valid)
        self.assertIn("dangereux", msg)
    
    def test_validate_target_paths(self):
        """Test de validation des chemins cibles."""
        # Chemins valides
        is_valid, msg, paths = gui.validate_target_paths("C:\\Windows;C:\\Program Files (x86)")
        self.assertTrue(is_valid)
        self.assertEqual(len(paths), 2)
        
        # Chemins avec caractères dangereux
        is_valid, msg, paths = gui.validate_target_paths("C:\\test & dangerous")
        self.assertFalse(is_valid)
        self.assertIn("dangereux", msg)
        
        # Chemin vide
        is_valid, msg, paths = gui.validate_target_paths("")
        self.assertFalse(is_valid)
        self.assertIn("Aucun chemin", msg)
    
    def test_sanitize_command_args(self):
        """Test de la fonction de nettoyage des arguments."""
        # Arguments normaux
        args = ["accesschk.exe", "-accepteula", "-nobanner", "Users"]
        sanitized = gui.sanitize_command_args(args)
        self.assertEqual(len(sanitized), 4)
        
        # Arguments avec caractères dangereux
        args = ["accesschk.exe", "user&dangerous"]
        sanitized = gui.sanitize_command_args(args)
        self.assertEqual(len(sanitized), 1)  # Le dangereux devrait être filtré


class TestScanHistoryManager(unittest.TestCase):
    """Tests pour le gestionnaire d'historique."""
    
    def setUp(self):
        """Prépare un répertoire temporaire pour les tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.history_manager = gui.ScanHistoryManager(self.temp_dir)
    
    def tearDown(self):
        """Nettoie le répertoire temporaire."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_add_and_get_scan(self):
        """Test d'ajout et récupération d'un scan."""
        # Ajouter un scan
        self.history_manager.add_scan(
            "baseline", 
            ["C:\\Windows"], 
            "test_user", 
            100
        )
        
        # Récupérer l'historique
        history = self.history_manager.get_history()
        self.assertEqual(len(history), 1)
        
        entry = history[0]
        self.assertEqual(entry['scan_type'], "baseline")
        self.assertEqual(entry['targets'], ["C:\\Windows"])
        self.assertEqual(entry['principal'], "test_user")
        self.assertEqual(entry['result_count'], 100)
        self.assertIn('timestamp', entry)
    
    def test_history_limit(self):
        """Test de la limite de l'historique."""
        # Ajouter plus que la limite
        for i in range(25):
            self.history_manager.add_scan(
                f"scan_{i}", 
                [f"C:\\test{i}"], 
                "user", 
                i
            )
        
        # Vérifier que la limite est respectée
        history = self.history_manager.get_history()
        self.assertLessEqual(len(history), self.history_manager.max_history)
    
    def test_clear_history(self):
        """Test d'effacement de l'historique."""
        # Ajouter des scans
        self.history_manager.add_scan("test", ["C:\\test"], "user", 10)
        
        # Vérifier qu'il y a des données
        history = self.history_manager.get_history()
        self.assertGreater(len(history), 0)
        
        # Effacer
        self.history_manager.clear_history()
        
        # Vérifier que c'est vide
        history = self.history_manager.get_history()
        self.assertEqual(len(history), 0)


class TestExportManager(unittest.TestCase):
    """Tests pour le gestionnaire d'exports."""
    
    def setUp(self):
        """Prépare des données de test."""
        self.test_logs = [
            {'line': 'RW DOMAIN\\user C:\\test\\file1.txt', 'write': True, 'err': False},
            {'line': 'R  DOMAIN\\user C:\\test\\file2.txt', 'write': False, 'err': False},
            {'line': 'Error: Access denied', 'write': False, 'err': True}
        ]
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Nettoie le répertoire temporaire."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_export_to_json(self):
        """Test d'export JSON."""
        filepath = os.path.join(self.temp_dir, "test.json")
        gui.ExportManager.export_to_json(self.test_logs, filepath)
        
        # Vérifier que le fichier existe
        self.assertTrue(os.path.exists(filepath))
        
        # Vérifier le contenu
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.assertIn('export_timestamp', data)
        self.assertEqual(data['total_entries'], 3)
        self.assertEqual(len(data['entries']), 3)
    
    def test_export_to_csv(self):
        """Test d'export CSV."""
        filepath = os.path.join(self.temp_dir, "test.csv")
        gui.ExportManager.export_to_csv(self.test_logs, filepath)
        
        # Vérifier que le fichier existe
        self.assertTrue(os.path.exists(filepath))
        
        # Vérifier qu'il y a du contenu
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn('timestamp,type,permissions,path,user', content)
        self.assertIn('write', content)
    
    def test_export_to_xml(self):
        """Test d'export XML."""
        filepath = os.path.join(self.temp_dir, "test.xml")
        gui.ExportManager.export_to_xml(self.test_logs, filepath)
        
        # Vérifier que le fichier existe
        self.assertTrue(os.path.exists(filepath))
        
        # Vérifier qu'il y a du contenu XML
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn('<?xml', content)
        self.assertIn('<accesschk_scan', content)
        self.assertIn('<entry', content)


class TestUtilityFunctions(unittest.TestCase):
    """Tests pour les fonctions utilitaires."""
    
    def test_extract_first_path(self):
        """Test d'extraction de chemin."""
        # Chemin Windows valide
        path = gui.extract_first_path("RW DOMAIN\\user C:\\Windows\\System32\\file.txt")
        self.assertEqual(path, "C:\\Windows\\System32\\file.txt")
        
        # Chemin UNC
        path = gui.extract_first_path("RW user \\\\server\\share\\file.txt")
        self.assertEqual(path, "\\\\server\\share\\file.txt")
        
        # Pas de chemin
        path = gui.extract_first_path("No path here")
        self.assertIsNone(path)
    
    def test_decode_bytes_with_fallback(self):
        """Test de décodage d'octets."""
        # UTF-8 valide
        result = gui.decode_bytes_with_fallback(b"Hello World")
        self.assertEqual(result, "Hello World")
        
        # Octets invalides
        result = gui.decode_bytes_with_fallback(b"\x80\x81\x82")
        self.assertIsInstance(result, str)  # Doit retourner quelque chose
    
    def test_current_user_principal(self):
        """Test de récupération de l'utilisateur principal."""
        principal = gui.current_user_principal()
        self.assertIsInstance(principal, str)
        # Sur Windows, devrait contenir un backslash pour DOMAIN\User
        if os.name == "nt":
            self.assertTrue('\\' in principal or len(principal) > 0)


class TestAccessChkRunner(unittest.TestCase):
    """Tests pour la classe AccessChkRunner."""
    
    def setUp(self):
        """Prépare les objets de test."""
        self.config = gui.AppConfig()
        self.queue = Mock()
        self.runner = gui.AccessChkRunner(self.config, self.queue)
    
    def test_runner_initialization(self):
        """Test d'initialisation du runner."""
        self.assertEqual(self.runner.config, self.config)
        self.assertEqual(self.runner.queue, self.queue)
        self.assertFalse(self.runner.is_running)
        self.assertIsNone(self.runner.current_process)
    
    def test_stop_scan(self):
        """Test d'arrêt de scan."""
        # Test sans processus actif
        self.runner.stop_scan()
        self.assertFalse(self.runner.is_running)
        
        # Test avec processus mock
        mock_process = Mock()
        mock_process.poll.return_value = None  # Processus en cours
        self.runner.current_process = mock_process
        self.runner.is_running = True
        
        self.runner.stop_scan()
        mock_process.kill.assert_called_once()
        self.assertFalse(self.runner.is_running)


def run_tests():
    """Lance tous les tests."""
    # Créer la suite de tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Ajouter toutes les classes de test
    test_classes = [
        TestAppConfig,
        TestValidationFunctions,
        TestScanHistoryManager,
        TestExportManager,
        TestUtilityFunctions,
        TestAccessChkRunner
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Lancer les tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Afficher le résumé
    print(f"\n{'='*50}")
    print(f"RÉSUMÉ DES TESTS")
    print(f"{'='*50}")
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    
    if result.failures:
        print(f"\nÉCHECS:")
        for test, trace in result.failures:
            print(f"- {test}: {trace.split(chr(10))[-2]}")
    
    if result.errors:
        print(f"\nERREURS:")
        for test, trace in result.errors:
            print(f"- {test}: {trace.split(chr(10))[-2]}")
    
    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\nTaux de réussite: {success_rate:.1f}%")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)