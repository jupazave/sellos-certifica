# Formato `.sdg`, subject del CSR y certificado del SAT

Documento de referencia para las Tareas 7 (cifrado del `.key`), 8 (CSR: subject + digest)
y 9 (ensobretado). Resuelve los 5 valores marcados `[CONFIRMAR-T3]` en el plan.

> **Regla de lectura:** cada sección declara **Valor**, **Fuente** y **Confianza**
> (`confirmado` = leído directamente del código oficial del SAT y/o corroborado contra
> certificados reales emitidos por el SAT; `hipótesis` = inferencia razonada sin
> evidencia directa). Nada aquí marcado `confirmado` depende de una sola fuente débil.

---

## 0. Método y procedencia de las fuentes

La fuente primaria es **la propia aplicación Certifica del SAT**, descargada del portal
oficial y descompilada para lograr interoperabilidad con el formato propietario del SAT
(uso legítimo del contribuyente sobre su propio trámite fiscal).

| Artefacto | Origen | SHA-256 |
|---|---|---|
| `Certifica.jar` v4.335 (2024-07-18) | `https://portalsat.plataforma.sat.gob.mx/certifica/imagenes/64/Certifica.jar` | `4ef53c3798778f51db0b9c75c5e73a890857f3dbb79a7e496dbf76b1bfcb45a6` |
| `Cert_Prod.zip` (certificados raíz SAT) | `http://omawww.sat.gob.mx/tramitesyservicios/Paginas/documentos/Cert_Prod.zip`, enlazado desde `http://omawww.sat.gob.mx/tramitesyservicios/Paginas/certificado_sello_digital.htm` | `c58f3fe92e23d1c82cee46e8b2356b69b0e216b23bbec86eefdc280822ad6af7` |

Certifica está ofuscado (clases renombradas a `a`, `b`, `c`…), pero **conserva el atributo
`SourceFile`**, lo que permite recuperar los nombres originales. Mapeo relevante:

| Clase ofuscada | Archivo fuente original | Rol |
|---|---|---|
| `mx/a/a/a/f` | (base de los `CRequerimiento*`) | Construye el CSR PKCS#10 |
| `mx/a/a/a/h` | `CRequerimientoSello.java` | Subclase, pasa el modo `"SELLO"` |
| `mx/a/a/a/g` | `CRequerimientoFIEL.java` | Subclase, modo `"FIEL"` |
| `mx/a/a/a/b` | `CEnsobretado.java` | Ensobretado (firma CMS) |
| `mx/a/a/a/i` | `CSolicitudSellos.java` | ZIP + ensobretado (ruta del CSD) |
| `mx/a/a/a/d` | `CLlavePrivada.java` | Escribe el `.key` cifrado (PKCS#8) |
| `mx/a/a/a/c` | `CGeneracionLlave.java` | Genera el par de llaves RSA |
| `mx/a/a/a/a/a/c` | (sin `SourceFile`) | Envoltura de `CMSSignedDataStreamGenerator` |
| `mx/sat/gob/b/f` | `PGeneracionLlaves.java` | Orquesta la generación por sucursal |
| `mx/sat/gob/a/c` | `CSDListener.java` | Ensambla y escribe el `.sdg` en disco |
| `mx/sat/gob/b` | `Contribuyente.java` | Holder de identidad (RFC, CURP, razón social) |

Certifica usa **BouncyCastle** (versión antigua, ~1.4x) empaquetado en el mismo JAR; las
constantes de BC citadas abajo se leyeron del propio JAR, no de documentación externa.

**Corroboración independiente:** los valores de las secciones 1 y 2 se contrastaron
contra certificados CSD **reales emitidos por el SAT** incluidos como fixtures en
[`phpcfdi/credentials`](https://github.com/phpcfdi/credentials)
(`tests/_files/CSD01_AAA010101AAA/certificate.cer` y
`tests/_files/00001000000413053762.cer`). Ambos coinciden con lo que produce el código.

---

## 1. Subject del CSR de CSD

**Confianza: `confirmado`**

**Fuente:** `mx/a/a/a/f.java` (`CRequerimiento*`), rama `if (this.a.compareTo("SELLO") == 0)`,
líneas de construcción del `X509Name`; y `mx/sat/gob/b/f.java` método `b()`, que llena el
holder de datos. Corroborado contra los dos certificados CSD reales citados arriba.

### 1.1 Estructura y orden

El subject es un `RDNSequence` de **exactamente 4 RDN**, cada uno con **un solo atributo**,
en este orden (el orden importa: es el orden de inserción en el `ASN1EncodableVector`):

| # | OID | Atributo | Tipo ASN.1 | Valor |
|---|---|---|---|---|
| 1 | `2.5.4.45` | `x500UniqueIdentifier` | **PrintableString** | RFC (ver 1.2) |
| 2 | `2.5.4.5` | `serialNumber` | **PrintableString** | CURP (ver 1.2) |
| 3 | `2.5.4.3` **o** `2.5.4.10` | `CN` **o** `O` | **UTF8String** | Razón social / nombre |
| 4 | `2.5.4.11` | `OU` | **UTF8String** | Nombre de la sucursal |

> **Ojo (trampa para la Tarea 8):** el *certificado emitido* por el SAT trae más atributos
> (`CN`, `name` 2.5.4.41, `O`, `OU`, …) y con otros tipos ASN.1 (`PrintableString` /
> `T61String`). Eso lo produce la **CA del SAT al re-codificar**, no el CSR. **No** hay que
> imitar el certificado emitido: hay que imitar el CSR de Certifica, que es lo de arriba.

### 1.2 Cómo se calculan los valores 1 y 2

De `mx/sat/gob/b/f.java` método `b()`. Sea `RFC` = RFC del titular,
`RFC_RL` / `CURP_RL` = del representante legal, `CURP` = CURP del titular:

```
si (hay representante legal):
    x500UniqueIdentifier = RFC + " / " + RFC_RL
    si (RFC.length == 12)                       # persona moral
        serialNumber = " / " + CURP_RL          # ← nótese el espacio inicial literal
    si no                                       # persona física
        serialNumber = CURP + " / " + CURP_RL
si no:
    x500UniqueIdentifier = RFC
    serialNumber = CURP
```

Verificación contra certificados reales del SAT (ambos personas morales con RL):

| Certificado | `x500UniqueIdentifier` | `serialNumber` |
|---|---|---|
| `CSD01_AAA010101AAA` | `AAA010101AAA / HEGT7610034S2` | `" / HEGT761003MDFRNN09"` |
| `00001000000413053762` | `SMA0112284B2 / GOCA741120HY0` | `" / GOCA741120HVZMNR00"` |

Ambos casos coinciden exactamente con la regla `RFC.length == 12 → " / " + CURP_RL`.

### 1.3 `CN` vs `O` — la regla no obvia

El atributo #3 **no siempre es `CN`**. Certifica elige según la longitud del RFC del titular:

```java
// mx/a/a/a/f.java  (valor = el mismo string del x500UniqueIdentifier)
boolean esPersonaFisica = false;
if (valor.length() == 13)              esPersonaFisica = true;   // RFC solo, 13 chars
else if (valor.length() > 12) {
    if (valor.split("/")[0].trim().length() == 13) esPersonaFisica = true;
}
if (esPersonaFisica) add(X509Name.CN);   // 2.5.4.3
else                 add(X509Name.O);    // 2.5.4.10
```

- **Persona física** (RFC de 13 caracteres) → `CN` (`2.5.4.3`)
- **Persona moral** (RFC de 12 caracteres) → `O` (`2.5.4.10`)

> La hipótesis por defecto del plan (`CN=<razón social>` siempre) **es incorrecta para
> personas morales**.

### 1.4 Atributo `challengePassword` (obligatorio)

El CSR lleva **un atributo** en el campo `attributes`:

- OID `1.2.840.113549.1.9.7` (`pkcs-9-at-challengePassword`)
- valor: `SET { PrintableString(...) }`

El valor es un **doble SHA-1 en Base64**. Sea `X` = el string del `x500UniqueIdentifier`
(sección 1.2) — Certifica pasa el mismo valor como "password" (`a2.c(object2)` con
`object2 == a2.a()`):

```
interno  = Base64( SHA1( X + X ) )
challengePassword = Base64( SHA1( X + interno ) )
```

`Base64` estándar (alfabeto `+/=`), todos caracteres válidos en `PrintableString`.
`SHA1` sobre los bytes ASCII del string concatenado.

### 1.5 Encodificación de la razón social — advertencia

Certifica hace `new DERUTF8String(new String(razonSocial.getBytes("ISO-8859-1")))`.
Eso es un round-trip Latin-1 → charset por defecto de la JVM: **identidad** cuando el
valor es ASCII puro (el caso normal: el SAT usa mayúsculas sin acentos) y **mojibake** en
JVM modernas con acentos/`Ñ`. Es un bug heredado, no una especificación.

**Instrucción para la Tarea 8:** codificar la razón social como **UTF-8 dentro de un
`UTF8String`**, que es la intención evidente. Mismo tratamiento para `OU` (sucursal).

### 1.6 Traducción a node-forge

`forge.pki.createCertificationRequest()`; `csr.setSubject([...])` acepta por entrada
`{ type: '<OID>', value: '<valor>', valueTagClass: forge.asn1.Type.<TIPO> }`.
Forge respeta el orden del arreglo y emite un RDN por entrada.

```js
csr.setSubject([
  { type: '2.5.4.45', value: x500uid,     valueTagClass: forge.asn1.Type.PRINTABLESTRING },
  { type: '2.5.4.5',  value: serialNumber,valueTagClass: forge.asn1.Type.PRINTABLESTRING },
  { type: esPersonaFisica ? '2.5.4.3' : '2.5.4.10',
                      value: razonSocial, valueTagClass: forge.asn1.Type.UTF8 },
  { type: '2.5.4.11', value: sucursal,    valueTagClass: forge.asn1.Type.UTF8 },
]);
```

Para el `challengePassword`:

```js
csr.setAttributes([
  { type: '1.2.840.113549.1.9.7', value: challengePassword,
    valueTagClass: forge.asn1.Type.PRINTABLESTRING },
]);
```

**Verificado contra `node_modules/node-forge/lib/x509.js` (v1.4.0):**

- `_dnToAsn1` (línea ~1860) emite **un RDN `SET` por cada entrada del arreglo**, en el orden
  del arreglo, y respeta `valueTagClass`. El default es `PRINTABLESTRING`, así que los
  atributos 3 y 4 **requieren** `valueTagClass: forge.asn1.Type.UTF8` explícito.
- La ruta de atributos del CSR (línea ~2360) emite exactamente
  `SEQUENCE { OID, SET { valor } }`. Su default es **`UTF8`**, así que el
  `challengePassword` **requiere** `valueTagClass: PRINTABLESTRING` explícito.

### 1.7 Restricciones de captura (validaciones de Certifica)

De `mx/sat/gob/recursos/solcedi_mensajes.properties`:

- Sucursal: **máx. 64 caracteres**, no puede contener `/ \ : * ? " < > $ |` (`ERR_M12`).
- No se permiten dos sucursales con el mismo nombre (`ERR_M13`).
- **Máximo 30 sucursales por petición** (`ERR_M14`) — ver sección 3.
- Contraseña de la clave privada: **mín. 8, máx. 256** caracteres (`ERR_M10`).

---

## 2. Digest de la firma

**Confianza: `confirmado`**

### 2.1 Firma del CSR: **SHA-1**

**Fuente:** `mx/a/a/a/f.java`:

```java
new PKCS10CertificationRequest("SHA1withRSA", subject, publicKey, attributes, privateKey);
```

→ `signatureAlgorithm` = **`sha1WithRSAEncryption`, OID `1.2.840.113549.1.1.5`**.

El string `"SHA1withRSA"` está literalmente en el bytecode, así que este valor no depende
de inferencia. (`mx/sat/gob/recursos/solcediv2.properties` también trae `algoritmo_dig=SHA1`,
pero esa clave **no se referencia en ningún lado** del código descompilado: es coherente,
no es evidencia.)

> **La hipótesis del plan (SHA-256 para el CSR) es incorrecta.** En node-forge:
> `csr.sign(privateKey, forge.md.sha1.create())` — **no** `sha256`.

### 2.2 Firma del SignedData (`.sdg`): **SHA-1**

**Fuente:** `mx/a/a/a/a/a/c.java`:

```java
gen.addSigner(privateKey, signerCert, CMSSignedGenerator.DIGEST_SHA1, "BC");
```

y en el BouncyCastle empaquetado,
`CMSSignedGenerator.DIGEST_SHA1 = OIWObjectIdentifiers.idSHA1.getId()`.

→ `digestAlgorithm` = **`sha1`, OID `1.3.14.3.2.26`**
→ `digestEncryptionAlgorithm` = **`rsaEncryption`, OID `1.2.840.113549.1.1.1`**

### 2.3 Tamaño de llave

`tam_llave_sellos=2048` (`solcediv2.properties`) → **RSA 2048** para el CSD.
(`tam_llave=2048` para e.firma.)

---

## 3. Estructura del `.sdg`

**Confianza: `confirmado`**

> ### ⚠ Hallazgo que invalida la hipótesis del plan
>
> El plan hipotetizaba `ContentInfo(EnvelopedData)` conteniendo un `SignedData`.
> **Eso es falso.** El "ensobretado" del SAT **no cifra nada**: no hay `EnvelopedData`,
> no hay cifrado simétrico y **no hay certificado destinatario**. Es únicamente una
> **firma CMS/PKCS#7 SignedData** con el contenido adjunto.
>
> Además el contenido firmado **no es el CSR directamente**: es un **archivo ZIP** que
> contiene uno o más `.req`. Esto es así **incluso cuando hay una sola sucursal**.

### 3.1 Cadena de llamadas (evidencia)

`mx/sat/gob/a/c.java` (ensamblado del `.sdg`) — siempre usa la ruta ZIP:

```java
a2.a(1, new ByteArrayInputStream(SolcediV2.a));           // cert de la e.firma (.cer)
c2.a(new ByteArrayInputStream(SolcediV2.d), SolcediV2.e.getBytes());  // .key + contraseña
mx.a.a.a.i i2 = new mx.a.a.a.i();                          // ← ZIP + ensobretado
HashMap<String, ByteArrayInputStream> hashMap = ...;       // nombre .req → DER del CSR
for (cada sucursal) { hashMap.put(d2.g, new ByteArrayInputStream(d2.f)); ... }
i2.a(a2, c2, hashMap, fileOutputStream);
```

`mx/a/a/a/i.java` — comprime el `HashMap` y delega al ensobretado:

```java
ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(baos));
for (...) { zos.putNextEntry(new ZipEntry(nombre)); zos.write(contenidoDER); }
zos.close();
i.a(cert, key, new ByteArrayInputStream(baos.toByteArray()), out);   // → CEnsobretado
```

`mx/a/a/a/a/a/c.java` — el ensobretado real:

```java
CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
gen.addSigner(privKeyEfirma, certEfirma, CMSSignedGenerator.DIGEST_SHA1, "BC");
gen.addCertificatesAndCRLs(certStore);        // certStore contiene el cert de la e.firma
OutputStream os = gen.open(outputStream, true);   // true = encapsulate (contenido adjunto)
Streams.pipeAll(inputStream, os);                 // inputStream = el ZIP
os.close();
```

### 3.2 Estructura resultante

```
ContentInfo ::= SEQUENCE {
  contentType  OID 1.2.840.113549.1.7.2          -- signedData
  content [0] EXPLICIT SignedData ::= SEQUENCE {
      version              INTEGER 1
      digestAlgorithms     SET { AlgorithmIdentifier { 1.3.14.3.2.26 (sha1), NULL } }
      encapContentInfo     SEQUENCE {
          eContentType     OID 1.2.840.113549.1.7.1   -- data
          eContent [0]     OCTET STRING = <bytes del ZIP>   -- ADJUNTO
      }
      certificates [0] IMPLICIT SET { <certificado X.509 de la e.firma> }
      -- sin CRLs
      signerInfos          SET { SignerInfo {
          version                      INTEGER 1
          sid                          IssuerAndSerialNumber (del cert de la e.firma)
          digestAlgorithm              1.3.14.3.2.26 (sha1)
          signedAttrs [0] IMPLICIT SET {
              contentType    1.2.840.113549.1.9.3 = 1.2.840.113549.1.7.1 (data)
              signingTime    1.2.840.113549.1.9.5 = UTCTime
              messageDigest  1.2.840.113549.1.9.4 = SHA1(eContent)
          }
          signatureAlgorithm           1.2.840.113549.1.1.1 (rsaEncryption)
          signature                    RSA( SHA1( DER de signedAttrs ) )
      } }
  }
}
```

**Los `signedAttrs` SÍ están presentes.** Evidencia: la sobrecarga
`addSigner(PrivateKey, X509Certificate, String, String provider)` de
`CMSSignedDataStreamGenerator` delega en
`addSigner(..., new DefaultSignedAttributeTableGenerator(), null, ...)`, que añade
`contentType`, `signingTime` y `messageDigest`. Como manda CMS, la firma se calcula sobre
la codificación **DER del `SET` de `signedAttrs`** (con tag `SET`, no `[0]`), no sobre el
contenido.

### 3.3 Contenido del ZIP

- Una entrada por sucursal; cada entrada es el **DER crudo del CSR PKCS#10** (`.req`).
- Nombre de entrada:
  `CSD_<sucursal>_<RFC>_<yyyyMMdd>_<HHmmss>s.req`
  (nótese la **`s` literal** entre la hora y `.req`).
- La `<sucursal>` en el nombre va **sin acentos** (`mx/sat/gob/f/m.java` método `e()`
  reemplaza `ÀÁÂÃÄÅ→A`, `àáâãäå→a`, `Ò…Ø→O`, `Ì…Ï→I`, `È…Ë→E`, `Ù…Ü→U`, `Çç→C`, etc.)
  y con **espacios convertidos a `_`**. El valor `OU` del CSR conserva el nombre original.
- `ZipOutputStream` por defecto → método **DEFLATE**, sin contraseña.
- Formato de fecha: `yyyyMMdd` y `HHmmss` (`com/sun/a/h.a(int, Date)`).

### 3.4 Nombres de archivo de salida

| Archivo | Patrón |
|---|---|
| `.sdg` | `CSD_<RFC>_<yyyyMMdd>_<HHmmss>.sdg` |
| `.key` | `CSD_<sucursal>_<RFC>_<yyyyMMdd>_<HHmmss>.key` |
| `.req` (dentro del ZIP) | `CSD_<sucursal>_<RFC>_<yyyyMMdd>_<HHmmss>s.req` |

### 3.5 Encabezado / pie textual

**No hay ninguno.** El `.sdg` es DER/BER binario puro, sin cabeceras PEM ni texto.

### 3.6 DER vs BER — único riesgo residual

Certifica usa el generador **streaming** de BC, que emite **BER con longitudes
indefinidas** (`BERSequenceGenerator`, `CMSUtils.createBEROctetOutputStream`): el
`eContent` sale como `OCTET STRING` constructed troceado.

node-forge emite **DER con longitudes definidas**. DER es un subconjunto válido de BER y
un `SignedData` en DER es CMS conforme, por lo que cualquier parser correcto (incluido
BouncyCastle, que es lo que casi seguro corre del lado de CertiSAT) lo acepta.

`hipótesis` (bajo riesgo): que CertiSAT acepte DER. Se valida con la **prueba E2E manual
del usuario contra CertiSAT Web**. Si fuera rechazado, es lo primero a revisar en `sdg.ts`.

### 3.7 Traducción a node-forge

`forge.pkcs7.createSignedData()`:

```js
const p7 = forge.pkcs7.createSignedData();
p7.content = forge.util.createBuffer(zipBytes);      // el ZIP, binario
p7.addCertificate(certEfirma);                        // certificates [0]
p7.addSigner({
  key: privateKeyEfirma,
  certificate: certEfirma,
  digestAlgorithm: forge.pki.oids.sha1,               // 1.3.14.3.2.26
  authenticatedAttributes: [
    { type: forge.pki.oids.contentType,   value: forge.pki.oids.data },
    { type: forge.pki.oids.messageDigest },           // forge lo calcula
    { type: forge.pki.oids.signingTime,   value: new Date() },
  ],
});
p7.sign({ detached: false });                         // contenido ADJUNTO
const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
```

**Verificado contra `node_modules/node-forge/lib/pkcs7.js` (v1.4.0):**

- `sign()` (línea ~528) hace `asn1.toDer(attrsAsn1)` sobre un `SET` universal —
  **no** sobre el `[0] IMPLICIT`— y firma ese digest. Es lo que exige CMS y lo mismo que
  hace BouncyCastle, así que la firma es interoperable.
- `messageDigest` y `signingTime` se autocompletan (líneas ~511–518); basta declararlos
  sin valor.
- `detached: false` (el default) deja el contenido **adjunto** en `contentInfo`, que es lo
  que necesitamos.

Para el ZIP en el navegador: cualquier librería que produzca un ZIP DEFLATE estándar
(p. ej. `fflate`) sirve; no se requiere nada especial.

---

## 4. Formato del `.key` de salida

**Confianza: `confirmado`**

**Fuente:** `mx/a/a/a/d.java` método `a(keypair, password, OutputStream)`; el selector de
algoritmo se fija en `mx/sat/gob/b/f.java` con `new mx.a.a.a.d(mx.a.a.a.d.a)` donde el
campo estático `d.a == 1` → rama `DESedeEngine` / `PKCSObjectIdentifiers.des_EDE3_CBC`.

> **La hipótesis del plan (`pbeWithSHAAnd3-KeyTripleDES-CBC`, PBE de PKCS#12) es
> incorrecta.** Certifica usa **PBES2**.

### 4.1 Estructura

```
EncryptedPrivateKeyInfo ::= SEQUENCE {
  encryptionAlgorithm SEQUENCE {
     OID 1.2.840.113549.1.5.13                    -- id-PBES2
     PBES2-params ::= SEQUENCE {
        keyDerivationFunc SEQUENCE {
           OID 1.2.840.113549.1.5.12              -- id-PBKDF2
           PBKDF2-params ::= SEQUENCE {
              salt           OCTET STRING (8 bytes)
              iterationCount INTEGER 2048
              -- sin keyLength, sin prf  → prf por defecto = hmacWithSHA1
           }
        }
        encryptionScheme SEQUENCE {
           OID 1.2.840.113549.3.7                 -- des-EDE3-CBC
           iv  OCTET STRING (8 bytes)
        }
     }
  }
  encryptedData OCTET STRING
}
```

- KDF: **PBKDF2-HMAC-SHA1**, **2048 iteraciones**, llave derivada de **192 bits**
  (`generateDerivedParameters(192)`).
- Cifrado: **3DES-EDE-CBC**, padding **PKCS#5/7** (`PaddedBufferedBlockCipher`).
- Texto plano: el **PKCS#8 `PrivateKeyInfo` DER sin cifrar** de la llave RSA
  (`privateKey.getEncoded()` de Java).

El `iterationCount` es `2048` porque proviene de `keypair.a()`, que Certifica fija al
tamaño de llave (`tam_llave_sellos=2048`); es el mismo número, no una coincidencia de
diseño.

### 4.2 Quirks de Certifica que NO hay que copiar

Certifica deriva `salt` e `iv` **del propio texto plano**:

```java
System.arraycopy(plaintextPkcs8, 30, salt, 0, 8);   // salt = bytes [30..38) del PKCS#8
System.arraycopy(plaintextPkcs8,  0, iv,   0, 8);   // iv   = bytes [0..8)  del PKCS#8
```

Los primeros 8 bytes de un PKCS#8 DER son casi constantes (`30 82 04 BE 02 01 00 30`…),
así que el **IV es prácticamente fijo** — criptográficamente malo.

**Instrucción para la Tarea 7:** generar `salt` e `iv` con **CSPRNG** (`crypto.getRandomValues`).
Nada en el formato exige los valores derivados: `salt` e `iv` viajan explícitos en el
`EncryptedPrivateKeyInfo`, así que cualquier valor aleatorio se descifra igual. Esto es
una mejora segura y no afecta la interoperabilidad.

### 4.3 Nota: el `.key` de **entrada** (e.firma) usa otros algoritmos

`mx/a/a/a/a/c.java` (lector de llave privada) acepta solo:

- **PBES1**: `1.2.840.113549.1.5.3` (`pbeWithMD5AndDES`) y
  `1.2.840.113549.1.5.1` (`pbeWithMD2AndDES`)
- **PBES2** (`1.2.840.113549.1.5.13`) con PBKDF2 + `des` (`1.3.14.3.2.7`),
  `des-EDE3` (`1.3.14.3.2.17` o `1.2.840.113549.3.7`),
  `aes256-CBC` (`2.16.840.1.101.3.4.1.42`) o `RC2` (`1.2.840.113549.3.2`)

La Tarea 7 debe **descifrar** el `.key` de la e.firma soportando al menos PBES1
`pbeWithMD5AndDES` (histórico, muy común en e.firmas antiguas) y PBES2/PBKDF2+3DES.
node-forge cubre ambos con `forge.pki.decryptPrivateKeyInfo` /
`forge.pki.encryptedPrivateKeyFromPem`; verificar el soporte de `pbeWithMD5AndDES`.

### 4.4 Traducción a node-forge — **trampa verificada**

> **`forge.pki.encryptPrivateKeyInfo` NO puede producir PBES2 + 3DES.** Verificado leyendo
> `node_modules/node-forge/lib/pbe.js` (v1.4.0, la que ya está en el proyecto), líneas
> 234–334:
>
> - `algorithm: '3des'` → **PKCS#12 PBE** (`pbeWithSHAAnd3-KeyTripleDES-CBC`,
>   `1.2.840.113549.1.12.1.3`), **no** PBES2. (Nombre correcto: `'3des'`, no `'des3'`.)
> - La rama PBES2 (`if algorithm.indexOf('aes') === 0 || algorithm === 'des'`) solo admite
>   `aes128` / `aes192` / `aes256` / `des` (DES simple). **3DES no está en esa rama.**
>
> Es decir: el helper de forge no da el formato de Certifica. Hay dos salidas.

**Opción A (recomendada) — construir el `EncryptedPrivateKeyInfo` a mano.**
Es ~25 líneas: replicar la rama PBES2 de forge pero con el OID y tamaños de 3DES.

```js
const salt = forge.random.getBytesSync(8);
const iv   = forge.random.getBytesSync(8);
const count = 2048;
const dk = forge.pkcs5.pbkdf2(password, salt, count, 24, forge.md.sha1.create()); // 192 bits
const cipher = forge.des.createEncryptionCipher(dk);   // clave de 24 bytes ⇒ 3DES-EDE
cipher.start(iv);
cipher.update(forge.util.createBuffer(forge.asn1.toDer(pkcs8Asn1)));
cipher.finish();                                        // padding PKCS#5/7
// luego armar a mano el SEQUENCE de la sección 4.1 con forge.asn1.create(),
// usando oids['pkcs5PBES2'], oids['pkcs5PBKDF2'] y oids['des-EDE3-CBC'].
```

Los defaults de forge ya coinciden con Certifica (`saltSize: 8`, `count: 2048`,
`prfAlgorithm: 'sha1'`), así que solo cambian el OID de cifrado, `dkLen = 24` e `ivLen = 8`.
Para las `PBKDF2-params`, omitir `keyLength` y `prf` reproduce exactamente a Certifica
(BouncyCastle no los escribe); incluirlos también es válido y más explícito.

**Opción B (más simple, ligeramente distinta) — `algorithm: 'aes256'`.**
Produce PBES2 + `aes256-CBC` (`2.16.840.1.101.3.4.1.42`), que el propio lector de llaves de
Certifica acepta (sección 4.3) y que OpenSSL/PHP/.NET leen sin problema. Solo se aparta del
byte-a-byte de Certifica en el algoritmo simétrico.

> Recomendación: **Opción A**, para no apostar a que toda la cadena de software fiscal del
> usuario (PACs, sistemas de facturación heredados) soporte PBES2+AES. 3DES es el formato
> que esos sistemas llevan décadas leyendo.

**Verificación obligatoria en la Tarea 7** — el `.key` generado debe abrirse con:

```bash
openssl pkcs8 -inform DER -in salida.key -passin pass:<contraseña> -nocrypt
```

y `openssl asn1parse -inform DER -in salida.key` debe mostrar
`1.2.840.113549.1.5.13`, `1.2.840.113549.1.5.12`, `:2048` y `1.2.840.113549.3.7`.

---

## 5. Certificado destinatario del sobre

**Confianza: `confirmado` (que NO existe tal certificado) / el archivo vendorizado es un
`hipótesis` en cuanto a su utilidad**

### 5.1 Conclusión principal: no hay destinatario

**El `.sdg` no tiene destinatario criptográfico.** Como se demuestra en la sección 3, el
ensobretado es un `SignedData` sin cifrado alguno: no hay `EnvelopedData`, no hay
`RecipientInfo`, no hay clave simétrica y por tanto **no se usa ningún certificado público
del SAT** para construir el `.sdg`.

El término "ensobretado" es histórico (heredado de SOLCEDI) y describe el empaquetado
lógico —CSR(s) → ZIP → firma con la e.firma—, no un sobre digital cifrado.

**Instrucción para la Tarea 9: no implementar cifrado ni cargar un certificado
destinatario.** Hacerlo produciría un archivo que CertiSAT rechazaría.

### 5.2 Qué se vendorizó y para qué

Aun así se incluye `docs/reference/certificado-sat.cer` (requisito del plan y útil por
otra razón): es el **certificado de la Autoridad Certificadora vigente del SAT**, que
sirve como **ancla de confianza** para validar que el `.cer` que sube el usuario es una
e.firma realmente emitida por el SAT antes de firmar con ella.

- **Archivo:** `docs/reference/certificado-sat.cer` (DER, 2263 bytes)
- **Origen:** `AC7.crt` dentro de `Cert_Prod.zip`, descargado de
  `http://omawww.sat.gob.mx/tramitesyservicios/Paginas/documentos/Cert_Prod.zip`,
  enlazado desde la página oficial del SAT
  `http://omawww.sat.gob.mx/tramitesyservicios/Paginas/certificado_sello_digital.htm`
  bajo la leyenda *"Certificados para validar la cadena de confianza de los certificados
  de producción — Certificados raíz de los certificados que emite el SAT"*.
- **Conversión:** `openssl x509 -in AC7.crt -inform PEM -outform DER -out certificado-sat.cer`
- **SHA-256 del DER:** `6d1d1f871f0d69233fc94526fecf826bee67181782d6b7e5320b279c97e8dac7`

Verificación (ejecutada con el `openssl` del sistema, LibreSSL; salida real):

```
$ openssl x509 -inform DER -in docs/reference/certificado-sat.cer -noout -subject -dates
subject= /CN=AC DEL SERVICIO DE ADMINISTRACION TRIBUTARIA/O=SERVICIO DE ADMINISTRACION TRIBUTARIA/OU=SAT-IES Authority/emailAddress=serviciosalcontribuyente@sat.gob.mx/street=Av. Hidalgo 77, Col. Guerrero/postalCode=06300/C=MX/ST=CDMX/L=CUAUHTEMOC/x500UniqueIdentifier=SAT970701NN3/unstructuredName=responsable: ADMINISTRACION CENTRAL DE SERVICIOS TRIBUTARIOS AL CONTRIBUYENTE
notBefore=May 23 22:24:10 2023 GMT
notAfter=May 23 22:24:10 2031 GMT
```

Es del SAT (`x500UniqueIdentifier=SAT970701NN3`, el RFC del SAT) y está **vigente**
(2023-05-23 → 2031-05-23; hoy 2026-08-29).

`AC7` **no es autofirmado**: lo emite `CN=AGENCIA REGISTRADORA CENTRAL, O=BANCO DE MEXICO`
(la IES/Infraestructura Extendida de Seguridad de Banxico). La raíz correspondiente es
`ARC7_IES.crt`, en el mismo ZIP.

### 5.3 Otras ACs del SAT en el mismo ZIP oficial

Si la Tarea 9 (o el front) quiere validar e.firmas más antiguas, hacen falta varias ACs.
Vigentes hoy (2026-08-29):

| Archivo | Subject CN | Vigencia |
|---|---|---|
| `AC7.crt` ← vendorizado | `AC DEL SERVICIO DE ADMINISTRACION TRIBUTARIA` | 2023-05-23 → 2031-05-23 |
| `AC6_SAT.crt` | `A.C. del Servicio de Administración Tributaria` | 2023-03-24 → 2031-03-24 |
| `AC5_SAT.cer` / `.crt` | `AUTORIDAD CERTIFICADORA` | 2019-05-03 → 2027-05-03 |

Caducadas (solo para validar certificados históricos): `AC0`–`AC4`.

> **Nota:** si el objetivo es solo *generar* el `.sdg`, **ninguna** de estas es necesaria.
> Validar la cadena de la e.firma es opcional y no lo hace Certifica al ensobretar
> (Certifica sí valida vigencia del `.cer` y que el `.key` corresponda al `.cer`,
> mensajes `ERR_M01` / `ERR_M06`, pero no la cadena).

---

## 6. Resumen ejecutable para las Tareas 7 / 8 / 9

| # | Valor | Confianza |
|---|---|---|
| 1 | Subject = 4 RDN en orden: `2.5.4.45` (PrintableString), `2.5.4.5` (PrintableString), `CN` **o** `O` según RFC de 13/12 chars (UTF8String), `OU` (UTF8String). Más atributo `challengePassword` = doble SHA-1/Base64. | confirmado |
| 2 | **SHA-1** en ambos: CSR (`sha1WithRSAEncryption`, `1.2.840.113549.1.1.5`) y SignedData (`sha1`, `1.3.14.3.2.26` + `rsaEncryption`). RSA 2048. | confirmado |
| 3 | `.sdg` = `ContentInfo(SignedData)` **con contenido adjunto** = **ZIP** de los `.req` DER; firmado con la e.firma, SHA-1, con `signedAttrs` y el cert de la e.firma incluido. **Sin EnvelopedData, sin cifrado.** | confirmado |
| 4 | `.key` = PKCS#8 `EncryptedPrivateKeyInfo` con **PBES2** (`1.2.840.113549.1.5.13`) + **PBKDF2-HMAC-SHA1** 2048 iteraciones, salt 8 bytes + **des-EDE3-CBC** (`1.2.840.113549.3.7`), IV 8 bytes. | confirmado |
| 5 | **No existe certificado destinatario** (no hay sobre cifrado): `confirmado`. Se vendoriza `certificado-sat.cer` (AC7 del SAT, vigente, fuente oficial) como ancla de confianza **opcional**; que valga la pena usarlo así es `hipótesis`. | mixto (ver 5.1/5.2) |

### Puntos abiertos (a validar con la prueba E2E manual contra CertiSAT Web)

1. **DER vs BER** (sección 3.6): Certifica emite BER indefinido; forge emitirá DER.
   Esperamos que CertiSAT lo acepte, pero es lo primero a revisar si rechaza el archivo.
2. **`signingTime`**: Certifica usa la hora local de la máquina. Se asume que CertiSAT no
   la valida estrictamente; usar la hora actual del navegador.
3. **ZIP con una sola entrada**: confirmado que Certifica siempre comprime, incluso con una
   sucursal. Si CertiSAT rechazara, la alternativa a probar sería firmar el `.req` DER
   directamente (ruta `CEnsobretado` sin ZIP, que existe en el código pero el flujo CSD
   no usa).
4. **Metadatos del ZIP**: no se replicaron marcas de tiempo/orden de entradas de
   Certifica. Se asume irrelevante.
