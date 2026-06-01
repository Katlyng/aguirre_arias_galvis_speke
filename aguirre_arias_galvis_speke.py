import hashlib
import secrets
import logging

# Configurar logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


"""
Valor primo de 2048 bits extraído wolframalfa ejecutando: NextPrime[2^2048 + 2^217]
"""
p = 32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389647960126939249806625440700685819469589938384356951833568218188663

def validate_password(password):
    """
    Valida que la contraseña cumple requisitos mínimos
    Que sea mayor a 8 caracteres
    Que no esté vacía
    """
    if not password:
        raise ValueError("La contraseña no puede estar vacía")
    if len(password) < 8:
        logger.warning("Contraseña corta detectada (< 8 caracteres)")
    return True

def derive_generator(password):
    """
    Deriva el generador g a partir de la contraseña usando SHA-256
    """
    validate_password(password)    
    password_hash = hashlib.sha256(password.encode()).digest()
    """
     Convierta el hash en un entero y reduzca módulo p
    """
    g = int.from_bytes(password_hash, byteorder='big') %p
    if g <= 1:
        g = 2
    
    logger.debug(f"Generador derivado: {g.to_bytes((g.bit_length() + 7) // 8, 'big').hex()[:16]}...")
    return g

def generate_private_exponent(value="b"):
    """
    Genera exponente privado aleatorio de 256 bits
    """
    private_exp = secrets.randbits(256)
    logger.debug("Nuevo exponente privado generado el valor de %s es: %s", value, str(private_exp.to_bytes(32, 'big').hex())[:16])
    return private_exp

def compute_public_value(g, private_exp, p):
    """
    Calcula valor público: g^private_exp mod p
    """
    if g <= 1 or g >= p:
        raise ValueError("Generador inválido")
    if private_exp <= 0:
        raise ValueError("Exponente privado inválido")
    
    public_val = pow(g, private_exp, p)
    logger.debug(f"Valor público calculado: {public_val.to_bytes((public_val.bit_length() + 7) // 8, 'big').hex()[:16]}...")
    return public_val

def compute_shared_key(public_value, private_exp, p):
    """Calcula la clave compartida: K = B^a mod p (o A^b mod p)"""
    if public_value <= 1 or public_value >= p:
        raise ValueError("Valor público inválido")
    if private_exp <= 0:
        raise ValueError("Exponente privado inválido")
    
    shared_key = pow(public_value, private_exp, p)
    logger.debug("Clave compartida calculada")
    print(f"Llave: {shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big').hex()[:16]}...")
    return shared_key

def verify_prime_parameters():
    """Verifica que los parámetros del primo son adecuados"""
    bit_length = p.bit_length()
    if bit_length < 2048:
        raise ValueError(f"Primo insuficientemente grande: {bit_length} bits")
    
    logger.info(f"Parámetros verificados: primo de {bit_length} bits")
    return True