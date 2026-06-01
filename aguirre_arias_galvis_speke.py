"""
================================================================================
IMPLEMENTACIÓN DEL PROTOCOLO SPEKE (Strongly Password Encrypted Key Exchange)
================================================================================
Este módulo implementa el protocolo SPEKE, un método de autenticación y
intercambio de claves basado en contraseñas. El protocolo permite que dos
partes autentiquen una contraseña compartida de forma segura sin exponerla.

COMPONENTES PRINCIPALES:
1. Parámetro primo grande (p): Base matemática del protocolo
2. Generador derivado (g): Generado a partir de la contraseña
3. Exponentes privados: Claves privadas generadas aleatoriamente
4. Valores públicos: Calculados para el intercambio
5. Clave compartida: Resultado final del protocolo

FLUJO DEL PROTOCOLO:
1. Alice y Bob comparten una contraseña (nunca se transmite)
2. Cada uno deriva el generador g de la contraseña
3. Cada uno genera un exponente privado aleatorio
4. Cada uno calcula su valor público: A = g^a mod p, B = g^b mod p
5. Intercambian valores públicos (puede ser interceptado)
6. Cada uno calcula la clave compartida: K = B^a mod p = A^b mod p
================================================================================
"""

import hashlib
import secrets
import logging

# Configurar logging con formato detallado
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# PARÁMETRO PRIMO GRANDE (2048 bits)
# Este primo es esencial para la seguridad del protocolo
# Se extrajo usando: NextPrime[2^2048 + 2^217] en Wolfram Alpha
# Un primo más grande aumenta la dificultad de ataques de fuerza bruta
p = 32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389647960126939249806625440700685819469589938384356951833568218188663

def validate_password(password):
    """
    Valida que la contraseña cumple con los requisitos mínimos de seguridad.
    
    REQUISITOS:
    - No puede estar vacía
    - Debe tener al menos 8 caracteres (recomendación de seguridad)
    
    PARÁMETROS:
        password (str): La contraseña a validar
    
    RETORNA:
        bool: True si la contraseña es válida
    
    EXCEPCIONES:
        ValueError: Si la contraseña está vacía
    
    NOTA: Si la contraseña es más corta de 8 caracteres, se registra una
          advertencia pero se acepta (para permitir pruebas con contraseñas cortas)
    """
    if not password:
        raise ValueError("La contraseña no puede estar vacía")
    if len(password) < 8:
        logger.warning("Contraseña corta detectada (< 8 caracteres)")
    return True

def derive_generator(password):
    """
    Deriva el generador g a partir de la contraseña usando hashing SHA-256.
    
    Este paso es CRÍTICO en SPEKE. El generador se derive de manera determinística
    a partir de la contraseña, lo que significa:
    - Misma contraseña → Mismo generador
    - Diferente contraseña → Diferente generador
    
    PROCESO:
    1. Validar que la contraseña sea válida
    2. Aplicar SHA-256 para obtener un hash de 256 bits
    3. Convertir el hash a un entero grande
    4. Reducir módulo p para obtener un valor en el rango válido
    5. Asegurar que g > 1 (si no, usar g = 2)
    
    PARÁMETROS:
        password (str): La contraseña compartida entre Alice y Bob
    
    RETORNA:
        int: El generador g derivado de la contraseña
    
    IMPORTANCIA:
    - Ambas partes (Alice y Bob) deben derivar el MISMO generador
    - Si uno tiene contraseña incorrecta, derivará un g diferente
    - Esto causará que los valores públicos difieran en lo que resultan
    """
    validate_password(password)
    
    # Generar hash SHA-256 de la contraseña (256 bits = 32 bytes)
    password_hash = hashlib.sha256(password.encode()).digest()
    
    # Convertir hash a entero grande y reducir módulo p
    # El resultado es un entero entre 0 y p-1
    g = int.from_bytes(password_hash, byteorder='big') % p
    
    # Asegurar que g es un generador válido (no puede ser 0 o 1)
    if g <= 1:
        g = 2
    
    logger.debug(f"Generador derivado: {g.to_bytes((g.bit_length() + 7) // 8, 'big').hex()[:16]}...")
    return g

def generate_private_exponent(value="b"):
    """
    Genera un exponente privado aleatorio de 256 bits.
    
    IMPORTANCIA:
    - Cada sesión debe tener un exponente privado DIFERENTE
    - Nunca debe reutilizarse el mismo exponente privado en múltiples sesiones
    - Debe ser criptográficamente aleatorio (se usa secrets, no random)
    
    PROCESO:
    1. Generar 256 bits aleatorios criptográficos
    2. Convertir a entero grande
    3. Registrar en el log para auditoría
    
    PARÁMETROS:
        value (str): Identificador para logging ('alice' o 'bob'). Por defecto 'b'
    
    RETORNA:
        int: Entero aleatorio de 256 bits
    
    SEGURIDAD:
    - Usa secrets.randbits() que es seguro para criptografía
    - No usa random.random() que sería vulnerable
    """
    # Generar 256 bits aleatorios (número entre 0 y 2^256 - 1)
    private_exp = secrets.randbits(256)
    logger.debug("Nuevo exponente privado generado el valor de %s es: %s", value, str(private_exp.to_bytes(32, 'big').hex())[:16])
    return private_exp

def compute_public_value(g, private_exp, p):
    """
    Calcula el valor público a partir del generador, exponente privado y módulo.
    
    FÓRMULA: A = g^a mod p (para Alice) o B = g^b mod p (para Bob)
    
    PROCESO:
    1. Validar que el generador g es válido (1 < g < p)
    2. Validar que el exponente privado es válido (> 0)
    3. Calcular g elevado a la potencia del exponente, módulo p
    4. Usar pow() con 3 argumentos para exponenciación modular eficiente
    
    PARÁMETROS:
        g (int): El generador (derivado de la contraseña)
        private_exp (int): El exponente privado aleatorio
        p (int): El módulo primo (2048 bits)
    
    RETORNA:
        int: El valor público que será intercambiado con la otra parte
    
    SEGURIDAD:
    - Este valor SE PUEDE intercambiar de forma insegura (puede ser interceptado)
    - NO permite recuperar el exponente privado ni el generador
    - Dos partes con la misma contraseña derivarán el mismo g pero diferentes
      valores públicos (porque tienen exponentes privados diferentes)
    
    NOTA: Es matemáticamente imposible calcular a partir de g^a mod p
          los valores de g o a por separado
    """
    # Validar parámetros de entrada
    if g <= 1 or g >= p:
        raise ValueError("Generador inválido")
    if private_exp <= 0:
        raise ValueError("Exponente privado inválido")
    
    # Calcular g^private_exp mod p de forma eficiente
    public_val = pow(g, private_exp, p)
    logger.debug(f"Valor público calculado: {public_val.to_bytes((public_val.bit_length() + 7) // 8, 'big').hex()[:16]}...")
    return public_val

def compute_shared_key(public_value, private_exp, p):
    """
    Calcula la clave compartida final del protocolo SPEKE.
    
    FÓRMULA: K = B^a mod p (para Alice) o K = A^b mod p (para Bob)
    
    Este es el paso final del protocolo donde ambas partes generan
    la MISMA clave compartida (si ambas tienen la contraseña correcta)
    sin nunca transmitirla por la red.
    
    PROCESO:
    1. Validar que el valor público es válido
    2. Validar que el exponente privado es válido
    3. Calcular: valor_público^exponente_privado mod p
    4. El resultado es la clave compartida
    
    PARÁMETROS:
        public_value (int): El valor público recibido de la otra parte (A o B)
        private_exp (int): Nuestro exponente privado privado (a o b)
        p (int): El módulo primo
    
    RETORNA:
        int: La clave compartida K (misma para ambas partes si contraseña es igual)
    
    PROPIEDAD MATEMÁTICA CRUCIAL:
    - Alice calcula: K = B^a mod p
    - Bob calcula:   K = A^b mod p
    - Ambas son IGUALES por la propiedad: (g^b)^a ≡ (g^a)^b ≡ g^(ab) (mod p)
    
    SEGURIDAD:
    - Aunque A y B se transmiten por red insegura, K permanece secreto
    - Solo alguien con g (derivado de la contraseña) podría calcular K
    - Un atacante con contraseña diferente derivará g diferente
    - Esto resultará en una clave compartida completamente diferente
    
    AUTENTICACIÓN:
    - Si ambas partes calculan la MISMA K, ambas tienen la contraseña correcta
    - Si K es diferente, la contraseña no coincide
    """
    # Validar parámetros de entrada
    if public_value <= 1 or public_value >= p:
        raise ValueError("Valor público inválido")
    if private_exp <= 0:
        raise ValueError("Exponente privado inválido")
    
    # Calcular la clave compartida: public_value^private_exp mod p
    shared_key = pow(public_value, private_exp, p)
    logger.debug("Clave compartida calculada")
    print(f"Llave: {shared_key.to_bytes((shared_key.bit_length() + 7) // 8, 'big').hex()[:16]}...")
    return shared_key

def verify_prime_parameters():
    """
    Verifica que los parámetros primos del protocolo son adecuados para seguridad.
    
    VALIDACIONES:
    1. El primo p debe tener al menos 2048 bits
    2. Un primo de 2048 bits proporciona seguridad equivalente a clave RSA 2048
    
    PARÁMETROS TEÓRICOS DE SEGURIDAD:
    - 1024 bits: Considerado débil (vulnerable a ataques modernos)
    - 2048 bits: Seguridad razonable para usos generales hasta ~2030
    - 4096 bits: Mayor seguridad, pero más lento
    - 8192 bits: Seguridad a largo plazo
    
    RETORNA:
        bool: True si los parámetros son válidos
    
    EXCEPCIONES:
        ValueError: Si el primo es demasiado pequeño
    
    NOTA: Esta verificación debe ejecutarse una vez al iniciar el programa
    """
    # Obtener el número de bits del primo p
    bit_length = p.bit_length()
    
    # Verificar que tiene suficientes bits para seguridad
    if bit_length < 2048:
        raise ValueError(f"Primo insuficientemente grande: {bit_length} bits")
    
    # Registrar confirmación de seguridad
    logger.info(f"Parámetros verificados: primo de {bit_length} bits")
    return True