# jwt-tool

**[CodeStrux Tech](https://codestrux.tech)**

CLI en Rust para inspeccionar y validar JSON Web Tokens (JWT) desde la línea de comandos.

## Características

- **`decode`**: decodifica el header y el payload de un JWT (base64url + JSON), sin verificar la firma.
- **`verify`**: valida la firma de un JWT contra un secreto (HMAC) o una clave pública PEM (RSA/EC/EdDSA).
  - El algoritmo esperado se indica explícitamente con `--alg`, en vez de confiar en el `alg` del propio token, para evitar ataques de confusión de algoritmo (p. ej. downgrade de RS256 a HS256).
  - El código de salida refleja el resultado: `0` si la firma es válida, `1` si es inválida o el token está malformado.
- Salida en texto legible (con colores en terminal) o en JSON con `--format json`, para integrarse con otras herramientas.
- El token siempre se recibe por **stdin**, nunca como argumento en texto plano (evita que quede expuesto en el historial de shell o en `ps`).

## Compilación

Requiere el toolchain de Rust (rustc/cargo). Se puede instalar con [rustup](https://rustup.rs/).

```bash
git clone <url-del-repositorio>
cd jwt-tool
cargo build --release
```

El binario queda en `target/release/jwt-tool`.

Para verificar que compila y correr los tests (si los hubiera):

```bash
cargo check
cargo test
```

## Instalación

Para instalar el binario en `~/.cargo/bin` (debe estar en el `PATH`):

```bash
cargo install --path .
```

Luego se puede invocar directamente como `jwt-tool` desde cualquier directorio.

## Uso

### Decodificar un token

```bash
echo -n "$TOKEN" | jwt-tool decode -
```

Salida en JSON:

```bash
echo -n "$TOKEN" | jwt-tool decode - --format json
```

Decodificando un token copiado al portapapeles (macOS) y filtrando el JSON con `jq`:

```bash
pbpaste | jwt-tool decode --format json - | jq
```

### Verificar la firma

Con secreto compartido (algoritmos HS256/HS384/HS512):

```bash
echo -n "$TOKEN" | jwt-tool verify - --alg HS256 --secret "mi-secreto"
```

Con clave pública PEM (algoritmos RS256/RS384/RS512, ES256/ES384, PS256/PS384/PS512, EdDSA):

```bash
echo -n "$TOKEN" | jwt-tool verify - --alg RS256 --public-key ./public.pem
```

### Flags disponibles

| Comando  | Flag                    | Descripción                                                              |
|----------|--------------------------|---------------------------------------------------------------------------|
| decode   | `--format <text\|json>`  | Formato de salida (por defecto `text`)                                    |
| verify   | `--alg <ALG>`             | Algoritmo esperado (requerido): `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256`, `PS384`, `PS512`, `EdDSA` |
| verify   | `--secret <STRING>`       | Secreto compartido, para algoritmos HMAC                                  |
| verify   | `--public-key <PATH>`     | Ruta a una clave pública PEM, para RSA/EC/EdDSA                           |
| verify   | `--format <text\|json>`  | Formato de salida (por defecto `text`)                                    |

Nota: `verify` valida únicamente la firma, no reclamaciones como `exp` o `nbf`.

Los colores de la salida en texto se desactivan automáticamente si la salida no es una terminal, si se define la variable `NO_COLOR`, o siempre que se use `--format json`.

---

Desarrollado por [CodeStrux Tech](https://codestrux.tech).
