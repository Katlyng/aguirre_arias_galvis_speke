import socket
import json
from aguirre_arias_galvis_speke import *

class SPEKEClient:
    def __init__(self, password):
        self.password = password
        self.g = derive_generator(password)
        self.private_key = generate_private_exponent("alice")
        self.public_value = compute_public_value(self.g, self.private_key, p)
        
    def compute_shared_secret(self, other_public_value):
        shared_secret = compute_shared_key(other_public_value, self.private_key, p)
        return shared_secret

def main():
    password = input("Ingresa la contraseña: ")
    client = SPEKEClient(password)
    
    # Conectar al servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    HOST = socket.gethostbyname(socket.gethostname())
    sock.connect((HOST, 8080))
    
    try:
        # Enviar valor público
        message = {
            "type": "public_value",
            "value": client.public_value,
            "client": "Alice"
        }
        #print("json enviado:", json.dumps(message))
        sock.sendall(json.dumps(message).encode())
        
        # Recibir valor público de Bob
        response = sock.recv(4096)
        bob_data = json.loads(response.decode())
        bob_public_value = bob_data["value"]
        
        # Calcular clave compartida
        shared_key = client.compute_shared_secret(bob_public_value)
        print(f"Clave de llave publica computada (Alice): {shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big').hex()[:16]}...")
        
        # Recibir clave compartida de Bob para verificación
        auth_response = sock.recv(1024)
        bob_result = json.loads(auth_response.decode())
        bob_shared_key = bob_result["shared_key"]
        
        # Comparar claves
        if shared_key == bob_shared_key:
            print(f"✓ Autenticación EXITOSA: Las claves coinciden!")
        else:
            print(f"✗ Autenticación FALLIDA: Las claves no coinciden")
        
    finally:
        sock.close()

if __name__ == "__main__":
    main()