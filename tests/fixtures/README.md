# Fixtures de prueba

Material de prueba **publico** del SAT (descargado originalmente por el SAT
para desarrolladores, vendoreado por la comunidad phpcfdi) mas un par
sintetico generado localmente. **Aqui nunca se committean llaves reales de
usuarios**; todo lo que hay en este directorio es de dominio publico o
generado desde cero solo para pruebas.

## Origen

Clonado (shallow) desde `https://github.com/phpcfdi/credentials` (commit
`fe9f96b`, rama `main`).

> Nota de discovery: el diseno original de este proyecto asumia el RFC de
> pruebas `EKU9003173C9` (ESCUELA KEMPER URGATE), que es el que documenta la
> guia de OpenSSL del propio SAT. El layout actual del repo phpcfdi/credentials
> vendorea en cambio el RFC de pruebas **`AAA010101AAA`** (ACCEM SERVICIOS
> EMPRESARIALES SC), descargado por ese proyecto directamente del sitio del
> SAT (`tests/_files/README.md` del repo fuente cita
> `http://omawww.sat.gob.mx/.../Cert_Sellos.zip`, carpeta `/aaa010101aaa_FIEL/`).
> Es igualmente material publico de pruebas emitido por el SAT, solo que un
> RFC distinto al que se anticipaba. Los tests de tareas posteriores deben
> usar el RFC y la contrasena documentados aqui, no los del brief original.

| Fixture destino | Archivo origen (en phpcfdi/credentials) |
|---|---|
| `fiel.cer` | `tests/_files/FIEL_AAA010101AAA/certificate.cer` |
| `fiel.key` | `tests/_files/FIEL_AAA010101AAA/private_key.key` |
| `csd.cer`  | `tests/_files/CSD01_AAA010101AAA/certificate.cer` |
| `csd.key`  | `tests/_files/CSD01_AAA010101AAA/private_key.key` |

Ambos pares estan en DER (binario), tal como los distribuye el SAT.

## RFC de pruebas y contrasenas

- RFC de pruebas: **`AAA010101AAA`** (razon social "ACCEM SERVICIOS
  EMPRESARIALES SC"). Aparece en el subject como
  `x500UniqueIdentifier=AAA010101AAA / HEGT7610034S2` (el segundo RFC es el
  del representante legal que firma el tramite; asi lo emite el SAT en estos
  certificados de prueba).
- Contrasena de `fiel.key`: **`12345678a`**
- Contrasena de `csd.key`: **`12345678a`**
- Contrasena de `sintetica.key`: **`sintetica123`**

La contrasena viene documentada en `password.txt` dentro de cada carpeta del
repo origen y coincide con el valor que uso el propio repo phpcfdi en sus
tests unitarios (`tests/Unit/PrivateKeyConstructTest.php`,
`tests/Unit/CredentialTest.php`).

## Heuristica de OU (para Tarea 5)

Confirmado sobre los certificados ya copiados a este directorio:

- `fiel.cer` (e.firma/FIEL): el subject **no** trae `OU`.
  ```
  subject= /CN=ACCEM SERVICIOS EMPRESARIALES SC/name=ACCEM SERVICIOS EMPRESARIALES SC/O=ACCEM SERVICIOS EMPRESARIALES SC/C=MX/emailAddress=FactElect@sat.gob.mx/x500UniqueIdentifier=AAA010101AAA / HEGT7610034S2/serialNumber= / HEGT761003MDFRNN09
  ```
- `csd.cer` (CSD): el subject **si** trae `OU` (nombre/identificador de la
  sucursal que emitio el CSD):
  ```
  subject= /CN=ACCEM SERVICIOS EMPRESARIALES SC/name=ACCEM SERVICIOS EMPRESARIALES SC/O=ACCEM SERVICIOS EMPRESARIALES SC/x500UniqueIdentifier=AAA010101AAA / HEGT7610034S2/serialNumber= / HEGT761003MDFRNN09/OU=CSD01_AAA010101AAA
  ```

La heuristica "FIEL sin OU / CSD con OU" **se sostiene** en este par de
fixtures.

## Vigencia de los certificados reales

Los certificados reales del SAT (`fiel.cer`, `csd.cer`) son de 2017 y ya
**vencieron**:

- `fiel.cer`: `notBefore=May 16 2017` — `notAfter=May 15 2021`
- `csd.cer`: `notBefore=May 18 2017` — `notAfter=May 18 2021`

Son utiles para parseo, verificacion de firma/llave-certificado y para casos
de prueba de "certificado vencido". Para casos "vigente" / "por vencer" con
fechas relativas a hoy, generar certificados sinteticos con
`openssl req ... -days N` (ver `generate.sh` como base) en vez de depender de
estas fechas fijas.

## Par sintetico (`sintetica.cer` / `sintetica.key`)

Generado localmente con `generate.sh` (no es material del SAT). Imita el
cifrado legacy del SAT: PKCS#8 con PBE-SHA1-3DES (`-v1 PBE-SHA1-3DES`), en
DER. Subject: `/CN=PRUEBA SINTETICA/x500UniqueIdentifier=XAXX010101000`.
Contrasena: `sintetica123`.

### Regenerar

```bash
tests/fixtures/generate.sh
```

Es re-ejecutable: sobrescribe `sintetica.cer` y `sintetica.key` y limpia sus
archivos temporales (usa `mktemp` + `trap` para la llave plana intermedia).

En este equipo (macOS) tanto la LibreSSL 3.3.6 del sistema como OpenSSL 3.6.3
(`brew install openssl@3`) aceptan `-v1 PBE-SHA1-3DES` sin problema, asi que
no fue necesario el fallback a `-v2 des3` que menciona el script. Si tu
OpenSSL/LibreSSL local rechaza `-v1 PBE-SHA1-3DES`, cambia esa linea por
`-v2 des3` en `generate.sh` y anota aqui el cambio.

## Verificacion (comandos y resultado)

```bash
openssl x509 -inform DER -in tests/fixtures/fiel.cer -noout -subject -dates
openssl x509 -inform DER -in tests/fixtures/csd.cer  -noout -subject -dates
openssl x509 -inform DER -in tests/fixtures/sintetica.cer -noout -subject
```

Los tres imprimen el subject esperado (ver arriba) sin error, con la LibreSSL
del sistema.

### Gap de verificacion conocido: `openssl pkcs8 ... -nocrypt`

El comando sugerido en el brief para verificar la contrasena de las llaves,

```bash
openssl pkcs8 -inform DER -in tests/fixtures/fiel.key -passin pass:12345678a -nocrypt
```

**falla** en este equipo tanto con la LibreSSL 3.3.6 del sistema como con
OpenSSL 3.6.3 de `brew install openssl@3`, con `error decrypting key` /
`asn1 encoding routines ... wrong tag`. Se investigo a fondo antes de asumir
que la fixture o la contrasena estuvieran mal:

- El mismo error ocurre con `fiel.key`, `csd.key` **y** con una llave PKCS#8
  generada localmente en el momento (tanto con `-v1 PBE-SHA1-3DES` como con
  `-v2 des3`), es decir, el subcomando `openssl pkcs8` en modo
  descifrado/`-nocrypt` esta roto en este equipo para *cualquier* PKCS#8
  cifrado, no solo para las fixtures del SAT — no es un problema de las
  fixtures.
- El subcomando **`openssl pkey`** (mas moderno, mismo binario de
  `brew install openssl@3`) descifra las tres llaves sin problema:
  ```bash
  /opt/homebrew/opt/openssl@3/bin/openssl pkey -inform DER \
    -in tests/fixtures/fiel.key -passin pass:12345678a
  # -> imprime "-----BEGIN PRIVATE KEY-----"
  ```
  Igual para `csd.key` (contrasena `12345678a`) y `sintetica.key` (contrasena
  `sintetica123`).
- Se confirmo independientemente con el `crypto` de Node.js
  (`crypto.createPrivateKey({ key, format: 'der', type: 'pkcs8', passphrase })`),
  que descifra las tres llaves correctamente y ademas se verifico que la
  llave publica de cada `.key` coincide con la del `.cer` correspondiente
  (`fiel.key`↔`fiel.cer`, `csd.key`↔`csd.cer`), confirmando que son pares
  correctos.

**Conclusion:** las contrasenas documentadas arriba son correctas y estan
verificadas por dos vias independientes (`openssl pkey` y Node `crypto`); lo
que no funciona en este equipo es especificamente el subcomando
`openssl pkcs8` al descifrar. Si en tu equipo `openssl pkcs8 ... -nocrypt`
si funciona, deberia dar el mismo resultado (`-----BEGIN PRIVATE KEY-----`).

## Advertencia

Material de prueba publico del SAT (RFC de pruebas `AAA010101AAA`) mas un par
sintetico generado con OpenSSL. **Aqui nunca se committean llaves reales.**
No uses estos archivos fuera de pruebas automatizadas.
