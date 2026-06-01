"""
================================================================================
SERVIDOR BOB - PROTOCOLO SPEKE (Strongly Password Encrypted Key Exchange)
================================================================================
Este módulo implementa el lado del SERVIDOR (Bob) del protocolo SPEKE.

FLUJO DEL SERVIDOR BOB:
1. Recibir contraseña del usuario
2. Escuchar conexiones de clientes (Alice)
3. Para cada cliente:
   - Crear instancia SPEKEServer (derivar g, generar exponente privado, calcular B)
   - Recibir valor público A de Alice
   - Enviar valor público B a Alice
   - Calcular clave compartida: K = A^b mod p
   - Enviar K a Alice para verificación
   - Si K coincide, autenticación exitosa

NOTAS IMPORTANTES:
- El servidor espera conexiones en HOST:8080
- Para cada conexión, se genera un nuevo exponente privado (b)
- La contraseña NUNCA se transmite
- La autenticación se verifica comparando claves compartidas

DIFERENCIA CON ALICE:
- Bob es PASIVO (espera conexión de Alice)
- Alice es ACTIVO (inicia la conexión)
- Matemáticamente, el protocolo es simétrico
"""

import socket
import json
from aguirre_arias_galvis_speke import *

class SPEKEServer:
    """
    Servidor SPEKE que implementa el lado de Bob en el protocolo.
    
    RESPONSABILIDADES:
    1. Derivar el generador g de la contraseña
    2. Generar exponente privado aleatorio por cada sesión
    3. Calcular el valor público B
    4. Recibir comunicaciones de clientes (Alice)
    5. Calcular la clave compartida final
    """
    
    def __init__(self, password):
        """
        Inicializa el servidor SPEKE con una contraseña compartida.
        
        PROCESO:
        1. Almacenar la contraseña
        2. Derivar el generador g a partir de la contraseña
        3. Generar un exponente privado aleatorio (b)
        4. Calcular el valor público B = g^b mod p
        
        PARÁMETROS:
            password (str): La contraseña compartida con Alice
        
        ATRIBUTOS:
            self.password: La contraseña
            self.g: El generador derivado de la contraseña
            self.private_key: El exponente privado (b) - DEBE GUARDARSE EN SECRETO
            self.public_value: El valor público B = g^b mod p (PUEDE COMPARTIRSE)
            self.shared_key: La clave compartida (se calcula después de recibir A)
        """
        self.password = password
        # Paso 1: Derivar el generador a partir de la contraseña
        self.g = derive_generator(password)
        # Paso 2: Generar exponente privado aleatorio
        self.private_key = generate_private_exponent("bob")
        # Paso 3: Calcular valor público para intercambiar
        self.public_value = compute_public_value(self.g, self.private_key, p)
        
    def compute_shared_secret(self, other_public_value):
        """
        Calcula la clave compartida a partir del valor público de Alice.
        
        FÓRMULA: K = A^b mod p
        
        PARÁMETROS:
            other_public_value (int): El valor público A recibido de Alice
        
        RETORNA:
            int: La clave compartida K
        
        NOTA: Si Alice también tiene la contraseña correcta, su cálculo de K
              será idéntico al nuestro, permitiendo verificar autenticación
        """
        shared_secret = compute_shared_key(other_public_value, self.private_key, p)
        self.shared_key = shared_secret
        return self.shared_key

def handle_client(conn, addr, password):
    """
    Maneja una conexión de cliente (Alice) individual.
    
    PROCESO DETALLADO:
    1. Aceptar conexión y mostrar información
    2. Crear instancia SPEKEServer para esta sesión
    3. Recibir valor público A de Alice
    4. Enviar valor público B a Alice
    5. Calcular clave compartida K = A^b mod p
    6. Enviar K a Alice para que verifique
    7. Registrar resultado de autenticación
    
    FLUJO DE MENSAJES:
    
    ALICE → BOB (Paso 3):
    {
        "type": "public_value",
        "value": <valor público A>,
        "client": "Alice"
    }
    
    BOB → ALICE (Paso 4):
    {
        "type": "public_value",
        "value": <valor público B>,
        "client": "Bob"
    }
    
    BOB → ALICE (Paso 6):
    {
        "status": "ready",
        "shared_key": <clave compartida de Bob>
    }
    
    PARÁMETROS:
        conn: Socket de conexión con el cliente
        addr: Tupla (host, puerto) del cliente
        password: La contraseña compartida
    """
    print(f"Conexión con {addr}")
    
    # Paso 2: Crear servidor SPEKE para esta sesión específica
    server = SPEKEServer(password)
    
    try:
        # Paso 3: Recibir valor público A de Alice
        print(f"  Esperando valor público A de Alice...")
        data = conn.recv(4096)
        alice_data = json.loads(data.decode())
        alice_public_value = alice_data["value"]
        print(f"  ✓ Valor público A recibido")
        
        # Paso 4: Enviar valor público B a Alice
        print(f"  Enviando valor público B a Alice...")
        response = {
            "type": "public_value",
            "value": server.public_value,
            "client": "Bob"
        }
        conn.sendall(json.dumps(response).encode())
        
        # Paso 5: Calcular clave compartida
        print(f"  Calculando clave compartida...")
        shared_key = server.compute_shared_secret(alice_public_value)
        print(f"  Llave K de bob (Bob): {shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big').hex()[:16]}...")
        
        # Paso 6: Enviar la clave compartida a Alice para verificación
        print(f"  Enviando clave compartida a Alice...")
        result = {
            "status": "ready",
            "shared_key": shared_key
        }
        conn.sendall(json.dumps(result).encode())
        print(f"  ✓ Clave compartida enviada a Alice para verificación")
        print(f"  Sesión completada para {addr}")

    except Exception as e:
        print(f"  ✗ Error: {e}")
    finally:
        conn.close()
        print(f"  Conexión cerrada para {addr}")

def main():
    """
    Función principal del servidor Bob.
    
    FLUJO:
    1. Solicitar contraseña al usuario
    2. Crear socket de servidor TCP
    3. Configurar socket para reutilizar puerto (SO_REUSEADDR)
    4. Vincular a HOST:8080
    5. Escuchar conexiones entrantes
    6. Para cada conexión, manejarla en handle_client
    7. Repetir indefinidamente
    
    CONFIGURACIÓN:
    - HOST: IP local del servidor
    - PUERTO: 8080
    - SO_REUSEADDR: Permite reiniciar el servidor rápidamente
    
    NOTA: El servidor permanece ejecutándose indefinidamente.
          Para detenerlo, presionar Ctrl+C
    """
    # Paso 1: Solicitar contraseña del usuario
    password = input("Ingresa la contraseña: ")
    
    # Paso 2-5: Crear y configurar socket de servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Permitir reutilizar puerto inmediatamente
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Obtener IP local
        HOST = socket.gethostbyname(socket.gethostname())
        
        # Vincular socket a puerto
        s.bind((HOST, 8080))
        
        # Comenzar a escuchar conexiones
        s.listen(5)
        print(f"SPEKE Server listening on {HOST}:8080")
        print("Esperando conexiones de Alice...")
        print("Presionar Ctrl+C para detener\n")
        
        # Paso 6-7: Aceptar conexiones indefinidamente
        try:
            while True:
                # Esperar conexión de cliente
                conn, addr = s.accept()
                # Manejar la conexión
                handle_client(conn, addr, password)
        except KeyboardInterrupt:
            print("\nServidor detenido por el usuario")

if __name__ == "__main__":
    main()