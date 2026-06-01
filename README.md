# SPEKE Protocol Implementation

Implementación del protocolo de autenticación **SPEKE (Simple Password Exponential Key Exchange)** en Python.

## Integrantes
- Diego Fernando Aguirre Tenjo
- Camilo Andres Arias Tenjo
- Katlyn Jennelis Galvis Rodriguez

## Descripción

SPEKE es un protocolo de intercambio de claves autenticado por contraseña que permite a dos partes (Alice y Bob) establecer una clave compartida de forma segura usando solo una contraseña común, sin necesidad de infraestructura de clave pública.

## Estructura del Proyecto

```
taller2/
├── speke.py              # Implementación core del protocolo SPEKE
├── clientAlice.py        # Cliente Alice (iniciador)
├── clientBob.py          # Servidor Bob (receptor)
├── security_analysis.py  # Análisis de seguridad y vulnerabilidades
├── test_cases.py         # Pruebas solicitadas
└── largePrimeNumber.txt  # Número primo de 2048 bits
```

## Requisitos

- Python 3.7 o superior
- Librerías estándar (no requiere dependencias externas)

## Cómo Ejecutar

### 1. Ejecución del Protocolo SPEKE (Intercambio de Claves)

#### Terminal 1 - Iniciar el Servidor (Bob)

```bash
python3 clientBob.py
```

Se pedirá que ingreses una contraseña. **Anota esta contraseña**, ya que debe ser idéntica en Alice.

```
Ingresa la contraseña: SecurePass123
SPEKE Server listening on 192.168.x.x:8080
```

#### Terminal 2 - Ejecutar el Cliente (Alice)

En otra terminal, ejecuta:

```bash
python3 clientAlice.py
```

Ingresa la **misma contraseña** que usaste en Bob:

```
Ingresa la contraseña: SecurePass123
Clave de llave publica computada (Alice): 123456789...
✓ Autenticación EXITOSA: Las claves coinciden!
```

**Resultado esperado:**
- Si las contraseñas coinciden: `✓ Autenticación EXITOSA`
- Si las contraseñas son diferentes: `✗ Autenticación FALLIDA`

### 2. Ejecutar la Suite de Pruebas

Para validar el protocolo con múltiples casos de prueba:

```bash
python3 test_cases.py
```

Esto ejecutará 5 casos de prueba:
- **Caso 1:** Contraseñas idénticas → Éxito
- **Caso 2:** Contraseñas diferentes → Fallo
- **Caso 3:** Contraseña común → Éxito
- **Caso 4:** Sensibilidad mayúsculas/minúsculas → Fallo
- **Caso 5:** Contraseña compleja → Éxito

**Ejemplo de salida:**

```
=== Results ===
Passed: 5/5
Success rate: 100.0%
```

### 3. Ejecutar Análisis de Seguridad

Para ver análisis de vulnerabilidades y estrategias de mitigación:

```bash
python3 security_analysis.py
```

Esto muestra intentos ataques:
- Simulación de ataque de diccionario
- Análisis de reutilización de exponentes privados


## Parámetros de Seguridad

- **Número primo (p):** 2048 bits
- **Longitud de exponente privado:** 256 bits
- **Función hash:** SHA-256 (para derivar generador)
- **Algoritmo:** Exponenciación modular (g^x mod p)

### indicaciones a resaltar
1. **Contraseñas idénticas:** El protocolo solo funciona si ambas partes usan exactamente la misma contraseña.

2. **Diferenciación mayúsculas/minúsculas:** `Password123` ≠ `password123`

3. **Longitud mínima:** Se recomienda contraseñas de al menos 8 caracteres.

4. **Red local:** Por defecto, se conecta a través de `localhost` (127.0.0.1). Para conectarse desde máquinas diferentes, cambia `HOST` en los clientes.

## Referencias

- RFC 5054 - SPEKE Protocol
- RFC 3526 - Prime Numbers for Diffie-Hellman
- NIST Guidelines for Cryptographic Key Generation

---

**Autor:** Taller 2 de Seguridad Computacional - Ingeniería de Sistemas  
**Periodo:** 2026-I
