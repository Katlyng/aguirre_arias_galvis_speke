import subprocess
import time
import threading
import socket
import json
from aguirre_arias_galvis_speke import *
import hmac
import hashlib

test_cases = [
    ("SecurePass123", "SecurePass123", True, "Caso 1: Contraseñas idénticas"),
    ("SecurePass123", "SecurePass124", False, "Caso 2: Contraseñas diferentes"),
    ("Admin2024", "Admin2024", True, "Caso 3: Contraseña común"),
    ("Test", "test", False, "Caso 4: Sensibilidad mayúsculas/minúsculas"),
    ("Complex!@#Pass$%^", "Complex!@#Pass$%^", True, "Caso 5: Contraseña compleja")
]

class TestSPEKE:
    def __init__(self):
        self.results = []
    
    def simulate_key_exchange(self, alice_password, bob_password):
        """Simula el intercambio de claves SPEKE entre Alice y Bob"""
        # Alice
        alice_g = derive_generator(alice_password)
        alice_private = generate_private_exponent("alice")
        alice_public = compute_public_value(alice_g, alice_private, p)
        
        # Bob
        bob_g = derive_generator(bob_password)
        bob_private = generate_private_exponent("bob")
        bob_public = compute_public_value(bob_g, bob_private, p)
        
        # Cálculo de claves compartidas
        alice_shared = compute_shared_key(bob_public, alice_private, p)
        bob_shared = compute_shared_key(alice_public, bob_private, p)
        
        return alice_shared, bob_shared
    
    def test_authentication(self, alice_password, bob_password):
        """Prueba el proceso completo de autenticación"""
        alice_key, bob_key = self.simulate_key_exchange(alice_password, bob_password)
        
        # Verificar si las claves compartidas coinciden
        keys_match = (alice_key == bob_key)
        
        return keys_match, alice_key, bob_key

def run_test_case(case_num, alice_pass, bob_pass, should_succeed, description):
    print(f"\n--- {description} ---")
    print(f"Alice password: '{alice_pass}'")
    print(f"Bob password: '{bob_pass}'")
    print(f"Expected result: {'SUCCESS' if should_succeed else 'FAILURE'}")
    
    # Medir tiempo de ejecución
    start_time = time.perf_counter()
    
    tester = TestSPEKE()
    success, alice_key, bob_key = tester.test_authentication(alice_pass, bob_pass)
    
    end_time = time.perf_counter()
    elapsed_ms = (end_time - start_time) * 1000  # Convertir a milisegundos
    
    result = "PASSED" if (success == should_succeed) else "FAILED"
    
    print(f"Keys match: {success}")
    print(f"Test result: {result}")
    print(f"Tiempo de ejecución: {elapsed_ms:.2f} ms")
    
    if success:
        print(f"Shared key: {str(alice_key)[:50]}...")
    
    return result == "PASSED"

def main():
    print("=== SPEKE Protocol Test Suite ===")
    passed = 0
    total = len(test_cases)
    execution_times = []
    
    for i, (alice_pass, bob_pass, expected, description) in enumerate(test_cases, 1):
        start = time.perf_counter()
        if run_test_case(i, alice_pass, bob_pass, expected, description):
            passed += 1
        end = time.perf_counter()
        execution_times.append((description, (end - start) * 1000))
    
    print(f"\n=== Results ===")
    print(f"Passed: {passed}/{total}")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    
    print(f"\n=== Tiempos de ejecución ===")
    total_time = 0
    for description, elapsed_ms in execution_times:
        print(f"{description}: {elapsed_ms:.2f} ms")
        total_time += elapsed_ms
    print(f"Tiempo total: {total_time:.2f} ms")

if __name__ == "__main__":
    main()