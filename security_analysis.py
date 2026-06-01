import hashlib
import time
import itertools
from aguirre_arias_galvis_speke import *

class SecurityAnalyzer:
    def __init__(self):
        self.common_passwords = [
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "admin", "123123", "qwerty", "abc123"
        ]
    
    def simulate_dictionary_attack(self, alice_public_value, bob_public_value, target_shared_key):
        """
        Simula un ataque de diccionario offline realista
        El atacante intenta reconstruir la clave compartida usando contraseñas candidatas
        """
        print("=== Simulación de Ataque de Diccionario Offline (Realista) ===")
        start_time = time.time()
        attempts = 0
        
        for password in self.common_passwords:
            attempts += 1
            candidate_g = derive_generator(password)
            attacker_private = generate_private_exponent()
            candidate_shared_key = compute_shared_key(bob_public_value, attacker_private, p)
            
            if candidate_shared_key == target_shared_key:
                print(f"¡Contraseña encontrada: {password}")
                print(f"Intentos realizados: {attempts}")
                print(f"Tiempo transcurrido: {time.time() - start_time:.2f}s")
                return password, attempts
        
        print("Contraseña no encontrada en el diccionario")
        print(f"Intentos totales: {attempts}")
        print(f"Tiempo total: {time.time() - start_time:.2f}s")
        return None, attempts
    
    def analyze_private_key_reuse(self):
        """
        Analiza el impacto de reutilizar exponentes privados
        """
        print("\n=== Análisis de Reutilización de Exponentes Privados ===")
        
        password = "TestPassword123"
        g = derive_generator(password)
        fixed_private_key = generate_private_exponent()
        
        public_values = []
        for i in range(3):
            public_val = compute_public_value(g, fixed_private_key, p)
            public_values.append(public_val)
            print(f"Sesión {i+1} - Valor público: {str(public_val)[:50]}...")
        
        all_same = all(val == public_values[0] for val in public_values)
        
        if all_same:
            print("⚠️  VULNERABILIDAD: Los valores públicos son idénticos")
            print("    Esto permite ataques de correlación entre sesiones")
        else:
            print("✓ Los valores públicos son diferentes (comportamiento esperado)")

def main():
    analyzer = SecurityAnalyzer()
    
    test_password = "admin"
    
    g_alice = derive_generator(test_password)
    alice_private = generate_private_exponent()
    alice_public = compute_public_value(g_alice, alice_private, p)
    
    g_bob = derive_generator(test_password)
    bob_private = generate_private_exponent()
    bob_public = compute_public_value(g_bob, bob_private, p)
    
    shared_key = compute_shared_key(bob_public, alice_private, p)
    
    analyzer.simulate_dictionary_attack(alice_public, bob_public, shared_key)
    analyzer.analyze_private_key_reuse()

if __name__ == "__main__":
    main()
