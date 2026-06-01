"""
================================================================================
SUITE DE PRUEBAS PARA EL PROTOCOLO SPEKE
================================================================================
Este módulo contiene pruebas unitarias exhaustivas del protocolo SPEKE.

CASOS DE PRUEBA INCLUIDOS:

1. Caso 1: Contraseñas idénticas - ESPERADO: ÉXITO
   - Alice y Bob tienen la MISMA contraseña
   - Deben derivar el mismo generador
   - Deben calcular la MISMA clave compartida
   - Autenticación debe ser exitosa

2. Caso 2: Contraseñas diferentes - ESPERADO: FALLO
   - Alice y Bob tienen contraseñas DIFERENTES
   - Derivarán generadores DIFERENTES
   - Calcularán claves compartidas DIFERENTES
   - Autenticación debe fallar

3. Caso 3: Contraseña común - ESPERADO: ÉXITO
   - Contraseña simple pero correcta
   - Verifica que el protocolo funciona con contraseñas comunes

4. Caso 4: Sensibilidad de mayúsculas/minúsculas - ESPERADO: FALLO
   - "Test" vs "test"
   - El hashing es sensible a mayúsculas
   - Las contraseñas diferentes deben producir fallos

5. Caso 5: Contraseña compleja - ESPERADO: ÉXITO
   - Contraseña con caracteres especiales, números, letras
   - Verifica que el protocolo maneja caracteres especiales

MÉTRICAS MEDIDAS:
- Tiempo de ejecución de cada caso
- Número de intentos exitosos vs fallidos
- Tasa de éxito general
- Performance del protocolo
"""

import subprocess
import time
import threading
import socket
import json
from aguirre_arias_galvis_speke import *
import hmac
import hashlib

# Definición de casos de prueba
# Formato: (contraseña_alice, contraseña_bob, resultado_esperado, descripción)
test_cases = [
    ("SecurePass123", "SecurePass123", True, "Caso 1: Contraseñas idénticas"),
    ("SecurePass123", "SecurePass124", False, "Caso 2: Contraseñas diferentes"),
    ("Admin2024", "Admin2024", True, "Caso 3: Contraseña común"),
    ("Test", "test", False, "Caso 4: Sensibilidad mayúsculas/minúsculas"),
    ("Complex!@#Pass$%^", "Complex!@#Pass$%^", True, "Caso 5: Contraseña compleja")
]

class TestSPEKE:
    """
    Clase de pruebas para validar el protocolo SPEKE.
    
    RESPONSABILIDADES:
    1. Simular intercambios SPEKE entre Alice y Bob
    2. Verificar que las claves compartidas coinciden cuando deben
    3. Almacenar resultados de pruebas
    """
    
    def __init__(self):
        """Inicializa el probador con lista vacía de resultados."""
        self.results = []
    
    def simulate_key_exchange(self, alice_password, bob_password):
        """
        Simula un intercambio completo de claves SPEKE.
        
        PROCESO:
        1. Alice:
           - Derivar generador ga de su contraseña
           - Generar exponente privado aleatorio a
           - Calcular valor público A = ga^a mod p
           
        2. Bob:
           - Derivar generador gb de su contraseña
           - Generar exponente privado aleatorio b
           - Calcular valor público B = gb^b mod p
           
        3. Intercambio (inseguro, puede ser observado):
           - Alice obtiene B
           - Bob obtiene A
           
        4. Cálculo de claves compartidas:
           - Alice calcula: Ka = B^a mod p
           - Bob calcula: Kb = A^b mod p
           
        5. Verificación:
           - Si contraseñas son iguales: ga = gb, por lo que Ka = Kb ✓
           - Si contraseñas son diferentes: ga ≠ gb, por lo que Ka ≠ Kb ✗
        
        PARÁMETROS:
            alice_password (str): Contraseña de Alice
            bob_password (str): Contraseña de Bob
        
        RETORNA:
            tuple: (clave_compartida_alice, clave_compartida_bob)
        """
        # ALICE: Fase 1
        alice_g = derive_generator(alice_password)
        alice_private = generate_private_exponent("alice")
        alice_public = compute_public_value(alice_g, alice_private, p)
        
        # BOB: Fase 1
        bob_g = derive_generator(bob_password)
        bob_private = generate_private_exponent("bob")
        bob_public = compute_public_value(bob_g, bob_private, p)
        
        # FASE 2: Intercambio de valores públicos (puede ser observado)
        # A → B, B → A (transmisión insegura, atacante puede capturar)
        
        # FASE 3: Cálculo de claves compartidas
        # Alice: Ka = B^a mod p
        alice_shared = compute_shared_key(bob_public, alice_private, p)
        # Bob: Kb = A^b mod p
        bob_shared = compute_shared_key(alice_public, bob_private, p)
        
        return alice_shared, bob_shared
    
    def test_authentication(self, alice_password, bob_password):
        """
        Prueba el proceso de autenticación completo.
        
        Realiza un intercambio SPEKE y verifica si las claves coinciden.
        Si coinciden: ambas partes tienen la contraseña correcta
        Si no coinciden: al menos una parte tiene contraseña incorrecta
        
        PARÁMETROS:
            alice_password (str): Contraseña de Alice
            bob_password (str): Contraseña de Bob
        
        RETORNA:
            tuple: (claves_coinciden, clave_alice, clave_bob)
        """
        alice_key, bob_key = self.simulate_key_exchange(alice_password, bob_password)
        
        # Verificar si las claves compartidas coinciden
        keys_match = (alice_key == bob_key)
        
        return keys_match, alice_key, bob_key

def run_test_case(case_num, alice_pass, bob_pass, should_succeed, description):
    """
    Ejecuta una prueba individual del protocolo SPEKE.
    
    PROCESO:
    1. Mostrar información del caso de prueba
    2. Medir tiempo de ejecución
    3. Simular intercambio SPEKE
    4. Comparar resultado actual con resultado esperado
    5. Registrar si la prueba pasó
    
    PARÁMETROS:
        case_num (int): Número del caso (para referencia)
        alice_pass (str): Contraseña de Alice
        bob_pass (str): Contraseña de Bob
        should_succeed (bool): ¿Las claves deben coincidir?
        description (str): Descripción del caso
    
    RETORNA:
        bool: True si el caso pasó (resultado ≈ esperado), False si falló
    """
    print(f"\n--- {description} ---")
    print(f"Alice password: '{alice_pass}'")
    print(f"Bob password: '{bob_pass}'")
    print(f"Expected result: {'SUCCESS' if should_succeed else 'FAILURE'}")
    
    # Medir tiempo de ejecución (más preciso con perf_counter)
    start_time = time.perf_counter()
    
    # Crear probador y ejecutar autenticación
    tester = TestSPEKE()
    success, alice_key, bob_key = tester.test_authentication(alice_pass, bob_pass)
    
    # Fin de medición de tiempo
    end_time = time.perf_counter()
    elapsed_ms = (end_time - start_time) * 1000  # Convertir a milisegundos
    
    # Verificar si el resultado fue el esperado
    result = "PASSED" if (success == should_succeed) else "FAILED"
    
    # Mostrar resultados
    print(f"Keys match: {success}")
    print(f"Test result: {result}")
    print(f"Tiempo de ejecución: {elapsed_ms:.2f} ms")
    
    # Mostrar clave compartida si coinciden
    if success:
        print(f"Shared key: {str(alice_key)[:50]}...")
    
    return result == "PASSED"

def main():
    """
    Función principal de la suite de pruebas.
    
    FLUJO:
    1. Mostrar encabezado de la suite de pruebas
    2. Ejecutar cada caso de prueba en orden
    3. Medir tiempo de cada caso
    4. Contar casos exitosos y fallidos
    5. Mostrar resumen de resultados
    6. Mostrar estadísticas de rendimiento
    
    MÉTRICAS MOSTRADAS:
    - Número de pruebas pasadas/totales
    - Porcentaje de éxito
    - Tiempo de ejecución por prueba
    - Tiempo total de todas las pruebas
    """
    print("=== SPEKE Protocol Test Suite ===")
    print("=" * 50)
    
    # Variables para tracking de resultados
    passed = 0
    total = len(test_cases)
    execution_times = []
    
    # Ejecutar cada caso de prueba
    for i, (alice_pass, bob_pass, expected, description) in enumerate(test_cases, 1):
        # Medir tiempo del caso
        start = time.perf_counter()
        
        # Ejecutar prueba
        if run_test_case(i, alice_pass, bob_pass, expected, description):
            passed += 1
        
        # Registrar tiempo
        end = time.perf_counter()
        execution_times.append((description, (end - start) * 1000))
    
    # ========== RESUMEN DE RESULTADOS ==========
    print("\n" + "=" * 50)
    print("=== RESUMEN DE RESULTADOS ===")
    print("=" * 50)
    print(f"Passed: {passed}/{total}")
    print(f"Success rate: {(passed/total)*100:.1f}%")
    
    # ========== ANÁLISIS DE RENDIMIENTO ==========
    print(f"\n=== Tiempos de ejecución ===")
    total_time = 0
    for description, elapsed_ms in execution_times:
        print(f"{description}: {elapsed_ms:.2f} ms")
        total_time += elapsed_ms
    print(f"Tiempo total: {total_time:.2f} ms")
    print(f"Tiempo promedio por prueba: {total_time/total:.2f} ms")
    
    # ========== CONCLUSIONES ==========
    print("\n" + "=" * 50)
    if passed == total:
        print("✓ TODAS LAS PRUEBAS PASARON CORRECTAMENTE")
    else:
        print(f"✗ {total - passed} prueba(s) fallaron")
    print("=" * 50)

if __name__ == "__main__":
    main()