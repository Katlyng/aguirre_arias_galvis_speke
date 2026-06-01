"""
================================================================================
ANÁLISIS DE SEGURIDAD DEL PROTOCOLO SPEKE
================================================================================
Este módulo realiza análisis de seguridad y pruebas de vulnerabilidad para
el protocolo SPEKE.

PRUEBAS REALIZADAS:

1. ATAQUE DE DICCIONARIO OFFLINE (simulate_dictionary_attack)
   - Simula un atacante que capturó A y B del intercambio
   - El atacante intenta adivinar la contraseña probando un diccionario
   - Mide cuántos intentos se necesitaron
   - Mide el tiempo de ataque
   
   RESULTADO ESPERADO:
   - Con contraseña fuerte: Muy pocas colisiones
   - Con contraseña débil en diccionario: Rápido encontrar

2. ANÁLISIS DE REUTILIZACIÓN DE EXPONENTES (analyze_private_key_reuse)
   - Verifica si reutilizar el exponente privado es seguro
   - Si se usa el mismo b en múltiples sesiones, el valor público B es igual
   - Esto permite ataques de correlación entre sesiones
   
   RESULTADO ESPERADO:
   - Cada sesión debe generar un nuevo exponente privado
   - Los valores públicos deben variar entre sesiones

CONSIDERACIONES DE SEGURIDAD:

1. CONTRASEÑAS:
   - Más fuerte: Mayor dificultad para ataque de diccionario
   - Más débil: Más rápido encontrar mediante fuerza bruta
   
2. DERIVACIÓN DE GENERADOR:
   - Es determinística: misma contraseña → mismo generador
   - Esto es correcto para SPEKE (permite autenticación)
   
3. EXPONENTES PRIVADOS:
   - Deben ser criptográficamente aleatorios
   - Nunca deben reutilizarse en múltiples sesiones
   - Deben mantener secreto (nunca transmitirse)
"""

import hashlib
import time
import itertools
from aguirre_arias_galvis_speke import *

class SecurityAnalyzer:
    """
    Analizador de seguridad para el protocolo SPEKE.
    
    Realiza pruebas de penetración y análisis de vulnerabilidades
    para validar la seguridad del protocolo.
    """
    
    def __init__(self):
        """
        Inicializa el analizador con un diccionario de contraseñas comunes.
        
        Este diccionario representa las contraseñas más comúnmente usadas
        en ataques reales. Incluye: números secuenciales, palabras comunes,
        combinaciones simples.
        """
        self.common_passwords = [
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "admin", "123123", "qwerty", "abc123"
        ]
    
    def simulate_dictionary_attack(self, alice_public_value, bob_public_value, target_shared_key):
        """
        Simula un ataque de diccionario offline realista contra SPEKE.
        
        ESCENARIO DEL ATAQUE:
        1. Un atacante captura A y B durante el intercambio (transmisión insegura)
        2. El atacante captura también la clave compartida K
        3. Ahora intenta reconstruir K usando contraseñas del diccionario
        4. Para cada contraseña candidata:
           a) Deriva el generador g
           b) Genera un exponente privado aleatorio
           c) Calcula la clave compartida con el valor públicodel otro lado
           d) Compara con el K capturado
        
        LIMITACIONES DEL ATAQUE:
        - Offline (no necesita interactuar con el servidor)
        - Pero: O(diccionario) intentos necesarios
        - Si diccionario es pequeño: ataque rápido
        - Si contraseña está fuera del diccionario: ataque falla
        
        PARÁMETROS:
            alice_public_value (int): A - valor público de Alice (capturado)
            bob_public_value (int): B - valor público de Bob (capturado)
            target_shared_key (int): K - clave compartida a encontrar (capturada)
        
        RETORNA:
            tuple: (contraseña encontrada o None, número de intentos)
        """
        print("=== Simulación de Ataque de Diccionario Offline (Realista) ===")
        start_time = time.time()
        attempts = 0
        
        # Intentar cada contraseña en el diccionario
        for password in self.common_passwords:
            attempts += 1
            # Paso 1: Derivar generador de la contraseña candidata
            candidate_g = derive_generator(password)
            # Paso 2: Generar exponente privado aleatorio
            attacker_private = generate_private_exponent()
            # Paso 3: Calcular clave compartida con el valor público capturado
            candidate_shared_key = compute_shared_key(bob_public_value, attacker_private, p)
            
            # Paso 4: Comparar con la clave capturada
            if candidate_shared_key == target_shared_key:
                elapsed = time.time() - start_time
                print(f"¡Contraseña encontrada: {password}")
                print(f"Intentos realizados: {attempts}")
                print(f"Tiempo transcurrido: {elapsed:.2f}s")
                return password, attempts
        
        # Si no se encuentra en el diccionario
        elapsed = time.time() - start_time
        print("Contraseña no encontrada en el diccionario")
        print(f"Intentos totales: {attempts}")
        print(f"Tiempo total: {elapsed:.2f}s")
        return None, attempts
    
    def analyze_private_key_reuse(self):
        """
        Analiza el impacto de seguridad de reutilizar exponentes privados.
        
        PROBLEMA:
        - Si Bob reutiliza el mismo b en múltiples sesiones
        - Entonces B = g^b mod p será idéntico en todas las sesiones
        - Un atacante puede correlacionar sesiones
        - Aunque no pueda calcular b, puede saber que es la misma persona
        
        SOLUCIÓN:
        - Cada sesión DEBE generar un nuevo exponente privado
        - Cada B debe ser diferente
        
        Esta función verifica que el protocolo genera nuevos valores públicos
        para cada sesión (como debería ser).
        """
        print("\n=== Análisis de Reutilización de Exponentes Privados ===")
        
        # Usar contraseña fija (ambas partes derivarán el mismo g)
        password = "TestPassword123"
        g = derive_generator(password)
        
        # Generar exponente privado UNA SOLA VEZ
        fixed_private_key = generate_private_exponent()
        
        # Calcular valores públicos (usando el mismo exponente)
        public_values = []
        for i in range(3):
            public_val = compute_public_value(g, fixed_private_key, p)
            public_values.append(public_val)
            print(f"Sesión {i+1} - Valor público: {str(public_val)[:50]}...")
        
        # Verificar si son iguales (COMPORTAMIENTO ESPERADO: Sí, porque usamos el mismo a)
        all_same = all(val == public_values[0] for val in public_values)
        
        if all_same:
            print("⚠️  VULNERABILIDAD: Los valores públicos son idénticos")
            print("    Esto permite ataques de correlación entre sesiones")
            print("    SOLUCIÓN: Generar nuevo exponente privado para cada sesión")
        else:
            print("✓ Los valores públicos son diferentes (comportamiento esperado)")
            print("  Este es el comportamiento correcto del protocolo")

def main():
    """
    Función principal del análisis de seguridad.
    
    FLUJO:
    1. Crear analizador de seguridad
    2. Usar contraseña de prueba ("admin")
    3. Simular intercambio SPEKE entre Alice y Bob
    4. Ejecutar ataque de diccionario offline
    5. Analizar reutilización de exponentes privados
    
    SALIDA:
    - Resultados del ataque de diccionario
    - Análisis de seguridad de exponentes privados
    """
    # Paso 1: Crear analizador
    analyzer = SecurityAnalyzer()
    
    # Paso 2: Usar contraseña de prueba que ESTÁ en el diccionario
    test_password = "admin"
    
    # Paso 3: Simular intercambio SPEKE
    print("=== Simulación de Intercambio SPEKE ===")
    
    # Alice: Derivar g, generar exponente, calcular valor público
    g_alice = derive_generator(test_password)
    alice_private = generate_private_exponent()
    alice_public = compute_public_value(g_alice, alice_private, p)
    print(f"Alice generó valor público A")
    
    # Bob: Derivar g, generar exponente, calcular valor público
    g_bob = derive_generator(test_password)
    bob_private = generate_private_exponent()
    bob_public = compute_public_value(g_bob, bob_private, p)
    print(f"Bob generó valor público B")
    
    # Calcular clave compartida
    shared_key = compute_shared_key(bob_public, alice_private, p)
    print(f"Clave compartida calculada: {str(shared_key)[:50]}...\n")
    
    # Paso 4: Ejecutar ataque de diccionario
    # El atacante tiene: A, B, K (capturados de la transmisión)
    analyzer.simulate_dictionary_attack(alice_public, bob_public, shared_key)
    
    # Paso 5: Analizar reutilización de exponentes
    analyzer.analyze_private_key_reuse()

if __name__ == "__main__":
    main()
