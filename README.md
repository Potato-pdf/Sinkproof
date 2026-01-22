# Sinkproof Password Hashing System

Sistema de hashing de contraseñas personalizado usando multi-threading, operaciones intensivas de memoria y encriptación.

## Características

- ✅ Generación de salt aleatorio (32 bytes)
- ✅ Procesamiento multi-hilo configurable
- ✅ Operaciones intensivas de memoria (memory-hard)
- ✅ Encriptación AES-256-GCM
- ✅ Formato de almacenamiento estructurado
- ✅ Verificación segura de contraseñas

## Instalación

```bash
cargo build --release
```

## Uso

### Como Librería

```rust
use sinkproof::{hash_password, verify_password};

// Generar hash
let password = "mi_contraseña_segura";
let hash = hash_password(password, 4, 50)?; // 4 hilos, 50 MB
let stored = hash.to_string();

// Verificar contraseña
let is_valid = verify_password(password, &stored)?;
```

### Programa Demo

```bash
cargo run --release
```

## Formato de Almacenamiento

```
Sinkproof:v1:hilos:memoria_mb:salt_base64:frase_encriptada_base64
```

**Ejemplo:**
```
Sinkproof:v1:4:50:4KZUOXIHfgKa3fTedRHG5ZH0gOUdKPmIjefg5qIL4II=:XX+ZA1mirZw8qSFrar6RZJTdMTwHS0J93Du95DTHKCoi+OkSJ3itHSW1w14jVfdbNXxsMhs=
```

## Algoritmo

1. **Generación de salt**: Salt aleatorio de 32 bytes
2. **Procesamiento multi-hilo**: Cada hilo procesa `contraseña || salt || índice_hilo`
3. **Llenado de memoria**: Operaciones SHA-256 en cadena con mezclas XOR y rotaciones
4. **Derivación de llave**: Últimos 512 bytes de cada hilo se combinan
5. **Encriptación**: Frase "No vendo cigarros sueltos" se encripta con AES-256-GCM
6. **Almacenamiento**: Formato estructurado con todos los parámetros

## Verificación

La verificación re-ejecuta el mismo proceso con los parámetros almacenados. Si la contraseña es correcta, la llave derivada desencriptará la frase correctamente.

## Tests

```bash
cargo test -- --nocapture
```

**Resultados**: 22 tests pasados exitosamente

## Rendimiento

| Hilos | Memoria (MB) | Tiempo (ms) |
|-------|--------------|-------------|
| 2     | 10           | ~40         |
| 4     | 25           | ~130        |
| 8     | 50           | ~330        |

*Tiempos medidos en modo release*

## Seguridad

- **Salt único**: Cada hash usa un salt diferente
- **Memory-hard**: Resistente a ataques con GPUs
- **Multi-threading**: Aumenta el costo computacional
- **AES-256-GCM**: Encriptación autenticada estándar industrial

## Estructura del Proyecto

```
src/
├── lib.rs         - API pública
├── hasher.rs      - Motor de hashing
├── encryption.rs  - Encriptación AES-256-GCM
├── storage.rs     - Formato de almacenamiento
├── verifier.rs    - Verificación de contraseñas
└── main.rs        - Programa de demostración
```

## Licencia

Este proyecto es un sistema de hashing personalizado para uso educativo y de producción.
