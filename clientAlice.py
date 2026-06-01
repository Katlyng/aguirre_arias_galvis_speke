"""
================================================================================
CLIENTE ALICE - PROTOCOLO SPEKE (Strongly Password Encrypted Key Exchange)
================================================================================
Este módulo implementa el lado del CLIENTE (Alice) del protocolo SPEKE.

FLUJO DEL CLIENTE ALICE:
1. Recibir contraseña del usuario
2. Crear instancia SPEKEClient (derivar g, generar exponente privado, calcular A)
3. Conectar al servidor Bob
4. Enviar valor público A a Bob
5. Recibir valor público B de Bob
6. Calcular clave compartida: K = B^a mod p
7. Recibir K de Bob para verificación
8. Comparar claves: Si son iguales, autenticación exitosa

NOTAS IMPORTANTES:
- La contraseña NUNCA se transmite por la red
- Solo se intercambian A y B (valores públicos)
- Ambas partes cálculan la MISMA clave compartida K
- Si las claves coinciden, significa que ambas tenían la contraseña correcta

REQUISITOS:
- El servidor Bob debe estar escuchando en HOST:8080
- Ambas partes deben tener la MISMA contraseña
"""

import socket
import json
from aguirre_arias_galvis_speke import *

class SPEKEClient:
    """
    Cliente SPEKE que implementa el lado de Alice en el protocolo.
    
    RESPONSABILIDADES:
    1. Derivar el generador g de la contraseña
    2. Generar exponente privado aleatorio
    3. Calcular el valor público A
    4. Comunicarse con el servidor
    5. Calcular la clave compartida final
    """
    
    def __init__(self, password):
        """
        Inicializa el cliente SPEKE con una contraseña compartida.
        
        PROCESO:
        1. Almacenar la contraseña
        2. Derivar el generador g a partir de la contraseña
        3. Generar un exponente privado aleatorio (a)
        4. Calcular el valor público A = g^a mod p
        
        PARÁMETROS:
            password (str): La contraseña compartida con Bob
        
        ATRIBUTOS:
            self.password: La contraseña
            self.g: El generador derivado de la contraseña
            self.private_key: El exponente privado (a) - DEBE GUARDARSE EN SECRETO
            self.public_value: El valor público A = g^a mod p (PUEDE COMPARTIRSE)
        """
        self.password = password
        # Paso 1: Derivar el generador a partir de la contraseña
        self.g = derive_generator(password)
        # Paso 2: Generar exponente privado aleatorio
        self.private_key = generate_private_exponent("alice")
        # Paso 3: Calcular valor público para intercambiar
        self.public_value = compute_public_value(self.g, self.private_key, p)
        
    def compute_shared_secret(self, other_public_value):
        """
        Calcula la clave compartida a partir del valor público de Bob.
        
        FÓRMULA: K = B^a mod p
        
        PARÁMETROS:
            other_public_value (int): El valor público B recibido de Bob
        
        RETORNA:
            int: La clave compartida K
        
        NOTA: Si Bob también tiene la contraseña correcta, su cálculo de K
              será idéntico al nuestro, permitiendo verificar autenticación
        """
        shared_secret = compute_shared_key(other_public_value, self.private_key, p)
        return shared_secret

def main():
    """
    Función principal del cliente Alice.
    
    FLUJO DETALLADO:
    1. Solicitar contraseña al usuario
    2. Crear cliente SPEKE (se derivan valores criptográficos)
    3. Establecer conexión TCP con el servidor Bob
    4. Enviar valor público A a Bob
    5. Recibir valor público B de Bob
    6. Calcular clave compartida K = B^a mod p
    7. Recibir clave compartida de Bob para comparar
    8. Verificar autenticación comparando claves
    
    SEGURIDAD:
    - La contraseña se solicita localmente y NUNCA se transmite
    - Solo se intercambian valores públicos (A y B)
    - Las claves privadas (a y b) nunca se comparten
    
    FLUJO DE MENSAJES JSON:
    
    ALICE → BOB:
    {
        "type": "public_value",
        "value": <valor público A>,
        "client": "Alice"
    }
    
    BOB → ALICE:
    {
        "type": "public_value",
        "value": <valor público B>,
        "client": "Bob"
    }
    
    BOB → ALICE (Verificación):
    {
        "status": "ready",
        "shared_key": <clave compartida de Bob>
    }
    """
    # Paso 1: Solicitar contraseña al usuario
    password = input("Ingresa la contraseña: ")
    
    # Paso 2: Crear cliente SPEKE (genera valores criptográficos)
    client = SPEKEClient(password)
    
    # Paso 3: Conectar al servidor Bob
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    HOST = socket.gethostbyname(socket.gethostname())
    print(f"Conectando a {HOST}:8080...")
    sock.connect((HOST, 8080))
    
    try:
        # Paso 4: Enviar valor público A a Bob
        print("Enviando valor público A a Bob...")
        message = {
            "type": "public_value",
            "value": client.public_value,
            "client": "Alice"
        }
        sock.sendall(json.dumps(message).encode())
        
        # Paso 5: Recibir valor público B de Bob
        print("Esperando valor público B de Bob...")
        response = sock.recv(4096)
        bob_data = json.loads(response.decode())
        bob_public_value = bob_data["value"]
        print(f"Valor público B recibido")
        
        # Paso 6: Calcular clave compartida local
        print("Calculando clave compartida...")
        shared_key = client.compute_shared_secret(bob_public_value)
        print(f"Clave de llave publica computada (Alice): {shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big').hex()[:16]}...")
        
        # Paso 7: Recibir clave compartida de Bob para verificación
        print("Esperando clave compartida de Bob para verificación...")
        auth_response = sock.recv(1024)
        bob_result = json.loads(auth_response.decode())
        bob_shared_key = bob_result["shared_key"]
        
        # Paso 8: Verificar autenticación comparando claves
        print("\nVERIFICANDO AUTENTICACIÓN...")
        print(f"Clave compartida de Alice: {shared_key}")
        print(f"Clave compartida de Bob:   {bob_shared_key}")
        
        if shared_key == bob_shared_key:
            print(f"✓ Autenticación EXITOSA: Las claves coinciden!")
            print("✓ Ambas partes tienen la contraseña correcta")
        else:
            print(f"✗ Autenticación FALLIDA: Las claves no coinciden")
            print("✗ Las contraseñas no son idénticas")
        
    finally:
        sock.close()
        print("Conexión cerrada")

if __name__ == "__main__":
    main()