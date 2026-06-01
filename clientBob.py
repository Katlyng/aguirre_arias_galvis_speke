import socket
import json
from aguirre_arias_galvis_speke import *

class SPEKEServer:
    def __init__(self, password):
        self.password = password
        self.g = derive_generator(password)
        self.private_key = generate_private_exponent("bob")
        self.public_value = compute_public_value(self.g, self.private_key, p)
        
    def compute_shared_secret(self, other_public_value):
        shared_secret = compute_shared_key(other_public_value, self.private_key, p)
        self.shared_key = shared_secret
        return self.shared_key

def handle_client(conn, addr, password):
    print(f"Conexión con {addr}")
    server = SPEKEServer(password)
    
    try:
        # Recibir valor público de Alice
        data = conn.recv(4096)
        alice_data = json.loads(data.decode())
        alice_public_value = alice_data["value"]
        
        # Enviar valor público a Alice
        response = {
            "type": "public_value",
            "value": server.public_value,
            "client": "Bob"
        }
        conn.sendall(json.dumps(response).encode())
        
        # Calcular clave compartida
        shared_key = server.compute_shared_secret(alice_public_value)
        print(f"Llave K de bob (Bob): {shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big').hex()[:16]}...")
        
        # Enviar la clave compartida a Alice para verificación
        result = {
            "status": "ready",
            "shared_key": shared_key
        }
        conn.sendall(json.dumps(result).encode())
        print(f"Clave compartida enviada a Alice para verificación")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def main():
    password = input("Ingresa la contraseña: ")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        HOST = socket.gethostbyname(socket.gethostname())
        s.bind((HOST, 8080))
        s.listen(5)
        print(f"SPEKE Server listening on {HOST}:8080")
        
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, password)

if __name__ == "__main__":
    main()