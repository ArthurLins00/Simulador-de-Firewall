"""
Script para executar todos os testes do projeto
Uso: python run_tests.py
"""

import sys
import os
import unittest

project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

if __name__ == '__main__':
    print("=" * 60)
    print("Executando testes do Firewall Simulator")
    print("=" * 60)
    print()
    
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print()
    print("=" * 60)
    if result.wasSuccessful():
        print(f"SUCESSO! Todos os {result.testsRun} testes passaram.")
    else:
        print(f"FALHAS ENCONTRADAS!")
        print(f"  Testes executados: {result.testsRun}")
        print(f"  Falhas: {len(result.failures)}")
        print(f"  Erros: {len(result.errors)}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)

