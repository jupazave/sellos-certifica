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

#### De dónde saca la Tarea 8 estos valores (importante)

**No hay que reimplementar el algoritmo de arriba.** Certifica lo necesita porque pide RFC,
CURP y datos del representante legal en formularios; nuestra app no: recibe el `.cer` de la
e.firma, **que ya trae los dos atributos ensamblados por la propia CA del SAT**.

> **Instrucción: copiar los valores de `2.5.4.45` y `2.5.4.5` **verbatim** del subject del
> `.cer` de la e.firma que sube el usuario, sin re-derivarlos ni normalizarlos.**

Es exacto por construcción: el SAT emitió la e.firma con exactamente el mismo par
`(x500UniqueIdentifier, serialNumber)` que espera en el requerimiento de CSD. Comprobado con
el fixture del repo `tests/fixtures/fiel.cer`, que ya los trae listos:

```
x500UniqueIdentifier = PRINTABLESTRING: AAA010101AAA / HEGT7610034S2
serialNumber         = PRINTABLESTRING:  / HEGT761003MDFRNN09
```

— idénticos a los del CSD emitido para ese mismo contribuyente (tabla de arriba). Copiar
verbatim también preserva el espacio inicial de `" / CURP_RL"`, que es fácil de perder al
`trim()`ear. El algoritmo de §1.2 queda documentado solo para entender **por qué** los
valores tienen esa forma, y para validar lo que se leyó.

#### Caso borde: la rama `si no` (sin representante legal)

En esa rama `serialNumber = CURP` del titular, lo que solo tiene sentido para **personas
físicas**; una persona moral no tiene CURP. Dos cosas confirmadas en el código:

- **La RDN nunca se omite.** En `mx/a/a/a/f.java` los `add` del subject son incondicionales
  (`vector.add(dERSet3); vector.add(dERSet4);`), así que el atributo `2.5.4.5` siempre está.
  Si el valor viniera vacío se emitiría un **`PrintableString` de longitud 0**, no se
  eliminaría la RDN.
- **Certifica exige RL para personas morales**: el validador `Contribuyente.q()`
  (`mx/sat/gob/b.java`) devuelve `false` si el RFC del titular tiene 13 caracteres y, para
  los de 12, exige RFC de RL válido de 13 caracteres. O sea, la combinación "persona moral
  sin RL" no llega a generarse por la UI.

Con la instrucción de copiar verbatim del `.cer`, **este borde no se puede dar**: sea cual
sea el caso, el valor ya viene resuelto en el certificado.

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

**Confianza: `confirmado (fuente única)`** — el resto de §1 tiene doble fuente (código +
certificados reales del SAT); esto **no se puede corroborar contra un certificado emitido**,
porque los atributos del CSR no se copian al certificado. La derivación de abajo es
literal del bytecode descompilado, pero descansa solo en esa lectura. Lo separo del
`confirmado` pleno de §1.1–§1.3 por honestidad, no porque dude de la lectura.

El CSR lleva **un atributo** en el campo `attributes`:

- OID `1.2.840.113549.1.9.7` (`pkcs-9-at-challengePassword`)
- valor: `SET { PrintableString(...) }`

Código descompilado, `mx/a/a/a/f.java` (base de `CRequerimientoSello`) — helper de digest:

```java
private static String a(String string, String object) {   // = Base64(SHA1(s1 + s2))
    string = string + (String)object;
    object = new SHA1Digest();
    ((GeneralDigest)object).update(string.getBytes(), 0, string.length());
    Object object2 = new byte[((SHA1Digest)object).getDigestSize()];
    ((SHA1Digest)object).doFinal((byte[])object2, 0);
    return new String(Base64.encode(object2));
}
```

y su uso en el mismo archivo (`object2` es el holder `mx/a/a/a/a`):

```java
if ((object5 = ((a)object2).c()) == null) {
    ... 21 bytes aleatorios en Base64 ...          // rama muerta en el flujo de CSD
} else {
    object5 = f.a(((a)object2).a(), ((a)object2).c());     // interno = B64(SHA1(a + c))
}
...
((DEREncodableVector)object3).add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
((DEREncodableVector)object3).add(
    new DERSet(new DERPrintableString(f.a(((a)object2).a(), (String)object5))));
```

La rama `null` **no aplica al CSD**: `PGeneracionLlaves.b()` (`mx/sat/gob/b/f.java`) hace
`a2.a(object2)` y `a2.c(object2)` con el **mismo** `object2`, de modo que
`holder.a() == holder.c() ==` el string del `x500UniqueIdentifier`. Llamando `X` a ese valor:

```
interno            = Base64( SHA1( X + X ) )
challengePassword  = Base64( SHA1( X + interno ) )
```

`Base64` estándar (alfabeto `+/=`); `+`, `/` y `=` son válidos en `PrintableString`.
El digest va sobre los bytes ASCII del string concatenado — nótese que Certifica usa
`string.getBytes()` (charset por defecto) con `string.length()` (número de *chars*): para
ASCII coinciden, y `X` siempre es ASCII (RFC/CURP/Base64), así que es inocuo aquí.

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

#### Orden de los `signedAttrs` — importa, y no es el orden por OID

`CMSSignedGenerator.getAttributeSet()` hace `new DERSet(attributeTable.toASN1EncodableVector())`,
y `DERSet(DEREncodableVector)` llama a `sort()`. O sea: **BouncyCastle ordena el `SET` en
orden canónico DER** antes de firmar y de emitir. `ASN1Set.lessThanOrEqual` compara las
**codificaciones DER completas byte a byte, incluyendo el tag y el octeto de longitud**
(y, a igualdad de prefijo, la más corta va primero).

Como el octeto de longitud va en la posición 1 —**antes** de los bytes del OID— es la
longitud, no el OID, la que domina la comparación. Con SHA-1 (digest de 20 B) y `UTCTime`
(13 B) las tres codificaciones empiezan así:

| Atributo | OID | Bytes iniciales | Longitud total |
|---|---|---|---|
| `contentType` | …1.9.**3** | `30 18 06 09` | 26 B |
| `signingTime` | …1.9.**5** | `30 1c 06 09` | 30 B |
| `messageDigest` | …1.9.**4** | `30 23 06 09` | 37 B |

→ El orden canónico DER es **`contentType`, `signingTime`, `messageDigest`**, que es el que
aparece en el esquema de §3.2. **No** es el orden por OID (`9.3 < 9.4 < 9.5`); confundir
ambos es fácil porque coinciden en el primer elemento pero no en los otros dos.

Verificado empíricamente reimplementando `ASN1Set.lessThanOrEqual` sobre las codificaciones
DER que produce forge (script en §7). Consecuencia feliz: **no hay conflicto** entre
"imitar a Certifica" y "ser canónico en DER" — son el mismo orden, así que un verificador
que re-codifique canónicamente tampoco tiene de qué quejarse. Por eso esto **no** entra en
la lista de riesgos residuales.

> Ojo: el orden es consecuencia de las longitudes codificadas. Vale para SHA-1 + `UTCTime`
> (nuestro caso). Con otro digest o `GeneralizedTime` habría que recalcularlo.

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
- El `<RFC>` de este patrón y de los tres de §3.4 es el **RFC plano** del titular
  (`efirma.datos.rfc`), *no* el compuesto `RFC + " / " + RFC_RL` que sí lleva el
  `x500UniqueIdentifier` del subject del CSR (§1.2) — implementación en
  `src/crypto/sdg.ts` (`nombreEntradaReq`, líneas 150-151).

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
  // ⚠ EL ORDEN DE ESTE ARREGLO ES EL ORDEN EN EL ARCHIVO. Ver §3.2 y "Orden de los
  // signedAttrs": contentType, signingTime, messageDigest (canónico DER con SHA-1).
  authenticatedAttributes: [
    { type: forge.pki.oids.contentType,   value: forge.pki.oids.data },
    { type: forge.pki.oids.signingTime },             // forge lo autocompleta
    { type: forge.pki.oids.messageDigest },           // forge lo calcula
  ],
});
p7.sign({ detached: false });                         // contenido ADJUNTO
const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
```

**Verificado contra `node_modules/node-forge/lib/pkcs7.js` (v1.4.0):**

- **forge NO ordena el `SET`.** No hay una sola llamada a `.sort(` en `pkcs7.js` ni en
  `asn1.js`: `sign()` recorre `authenticatedAttributes` y hace `push` en el orden del
  arreglo, tanto en el `SET` que firma como en el `[0] IMPLICIT` que emite. **El orden que
  se escriba en el arreglo es literalmente el orden en el `.sdg`**, así que hay que escribirlo
  ya ordenado (a diferencia de BouncyCastle, que ordena solo).
- `sign()` (línea ~528) hace `asn1.toDer(attrsAsn1)` sobre un `SET` universal —
  **no** sobre el `[0] IMPLICIT`— y firma ese digest. Es lo que exige CMS y lo mismo que
  hace BouncyCastle, así que la firma es interoperable.
- `messageDigest` y `signingTime` se autocompletan (líneas ~511–518); basta declararlos
  sin valor.
- `detached: false` (el default) deja el contenido **adjunto** en `contentInfo`, que es lo
  que necesitamos.

Para el ZIP en el navegador: la implementación **no** usa una librería de terceros como
`fflate` — instrucción del controlador de esta tarea, para no sumar una dependencia de
compresión solo para empaquetar archivos de unos KB (la única dependencia de runtime del
proyecto es `node-forge`). En su lugar, `src/crypto/zip.ts` escribe a mano un ZIP **método
STORE** (sin comprimir); es un riesgo residual documentado que CertiSAT acepte STORE igual
que el DEFLATE que usa Certifica — ver README, sección "Estado del formato `.sdg`".

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
- **Contraseña → bytes: UTF-8.** Certifica hace `string.getBytes()` (charset por defecto de
  la JVM) en `mx/a/a/a/d.java`, pero el estándar de facto —y lo que hacen OpenSSL, Node y el
  resto de la cadena fiscal— es **UTF-8**. Ver §4.5: no explicitarlo produce llaves que nadie
  más puede abrir.

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

**node-forge NO cubre los dos.** Verificado en `node_modules/node-forge/lib/pbe.js`:
`pki.pbe.getCipher` (L754) solo despacha tres OID —

```js
case pki.oids['pkcs5PBES2']:                      // 1.2.840.113549.1.5.13  ✔
case pki.oids['pbeWithSHAAnd3-KeyTripleDES-CBC']: // 1.2.840.113549.1.12.1.3 ✔
case pki.oids['pbewithSHAAnd40BitRC2-CBC']:       // 1.2.840.113549.1.12.1.6 ✔
default: throw new Error('Cannot read encrypted PBE data block. Unsupported OID.');
```

— así que **PBES1 `pbeWithMD5AndDES` (`1.2.840.113549.1.5.3`) lanza excepción**; lo mismo
`pbeWithMD2AndDES`. (La versión anterior de este documento afirmaba lo contrario; era falso.)

Consecuencia para la Tarea 7:

- **Camino común, soportado:** las e.firma actuales que entrega el SAT vienen en
  **PBES2 + PBKDF2 + 3DES**, que forge sí lee vía `forge.pki.decryptPrivateKeyInfo`.
- **Limitación conocida:** los `.key` **PBES1 heredados** (`pbeWithMD5AndDES`) **no se
  pueden abrir con forge tal cual**. Hay que detectar ese OID al leer el
  `EncryptedPrivateKeyInfo` y **fallar con un mensaje claro** ("tu archivo de llave usa un
  formato antiguo; vuelve a descargar tu e.firma del SAT"), en vez de reventar con un error
  de ASN.1 incomprensible. Si más adelante hiciera falta soportarlos, PBES1-MD5-DES es
  trivial de implementar a mano (MD5 iterado sobre `password+salt`, DES-CBC), pero **no
  asumir que forge lo hace**.

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
const pwBytes = forge.util.encodeUtf8(password);   // ⚠ OBLIGATORIO — ver §4.5
const salt = forge.random.getBytesSync(8);
const iv   = forge.random.getBytesSync(8);
const count = 2048;
const dk = forge.pkcs5.pbkdf2(pwBytes, salt, count, 24, forge.md.sha1.create()); // 192 bits
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

**Verificación obligatoria en la Tarea 7.** Comandos probados contra un `.key` generado con
la receta de arriba (LibreSSL del sistema y OpenSSL 3, misma salida en ambos):

```bash
# descifra e imprime el PKCS#8 en PEM  → exit 0
openssl pkcs8 -inform DER -in salida.key -passin pass:'<contraseña>'
# o, equivalente y más escueto        → "Key is valid", exit 0
openssl pkey -inform DER -in salida.key -passin pass:'<contraseña>' -noout -check
```

> **No usar `-nocrypt`.** Esa bandera declara que la *entrada* viene sin cifrar, así que
> falla precisamente cuando el `.key` es correcto:
> `Error decrypting key … asn1_check_tlen:wrong tag … Field=version, Type=PKCS8_PRIV_KEY_INFO`.
> (La versión anterior de este documento traía ese comando; era un falso negativo garantizado.)

Y `openssl asn1parse -inform DER -in salida.key` debe rendir así — nótese que OpenSSL
imprime los OID **por nombre**, y el `iterationCount` en **hexadecimal** (`0x800 = 2048`):

```
    0:d=0  hl=4 l=1294 cons: SEQUENCE
    4:d=1  hl=2 l=  64 cons: SEQUENCE
    6:d=2  hl=2 l=   9 prim: OBJECT            :PBES2
   17:d=2  hl=2 l=  51 cons: SEQUENCE
   19:d=3  hl=2 l=  27 cons: SEQUENCE
   21:d=4  hl=2 l=   9 prim: OBJECT            :PBKDF2
   32:d=4  hl=2 l=  14 cons: SEQUENCE
   34:d=5  hl=2 l=   8 prim: OCTET STRING      [HEX DUMP]:D77D3019A9DE6B69
   44:d=5  hl=2 l=   2 prim: INTEGER           :0800
   48:d=3  hl=2 l=  20 cons: SEQUENCE
   50:d=4  hl=2 l=   8 prim: OBJECT            :des-ede3-cbc
   60:d=4  hl=2 l=   8 prim: OCTET STRING      [HEX DUMP]:EC05CA8953612679
   70:d=1  hl=4 l=1224 prim: OCTET STRING      [HEX DUMP]:…
```

Es decir: buscar `:PBES2`, `:PBKDF2`, `INTEGER :0800` y `:des-ede3-cbc` — **no** los OID
numéricos ni `:2048`.

### 4.5 Codificación de la contraseña: **UTF-8, siempre**

PBKDF2 deriva de **bytes**, no de caracteres, así que el `.key` solo se puede abrir si quien
lo cifró y quien lo descifra convierten la contraseña a bytes igual. **Hay que usar UTF-8.**

En node-forge esto es una trampa real: las funciones de bajo nivel tratan un `string` de JS
como **binario/Latin-1** (un byte por code unit), así que una contraseña con `ñ`, `á` o
cualquier carácter fuera de ASCII produce **bytes distintos** a los que usarán OpenSSL, Node
o el software del PAC. El resultado es una llave que *parece* correcta y que **nadie más
puede abrir**, incluida la propia app en otra sesión si ahí se codifica distinto.

```js
const pwBytes = forge.util.encodeUtf8(password);   // ← siempre, al cifrar Y al descifrar
```

Comprobado empíricamente (§7) con la contraseña `contrañseña`:

| Vía | Resultado |
|---|---|
| Cifrar y descifrar con `forge.util.encodeUtf8(password)` | **OK** (y `openssl pkcs8`/`pkey` la abren) |
| Cifrar con `encodeUtf8` y descifrar pasando el string JS crudo | **falla** |

Aplica igual al **descifrado** del `.key` de la e.firma (§4.3): pasar `pwBytes`, no el string.
Para contraseñas ASCII puras —la mayoría— ambas rutas coinciden, y por eso el bug se escapa
en pruebas y aparece con el primer usuario que use `ñ`.

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
| 1 | Subject = 4 RDN en orden: `2.5.4.45` (PrintableString), `2.5.4.5` (PrintableString), `CN` **o** `O` según RFC de 13/12 chars (UTF8String), `OU` (UTF8String). Los dos primeros se **copian verbatim del `.cer` de la e.firma** (§1.2). | confirmado |
| 1b | Atributo `challengePassword` = `B64(SHA1(X + B64(SHA1(X+X))))`, PrintableString. | confirmado (fuente única — §1.4) |
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

> El orden de los `signedAttrs` **no** está en esta lista: se comprobó que el orden de
> Certifica coincide con el canónico DER (§3.2), así que no hay riesgo por ese lado.

---

## 7. Cómo reproducir las verificaciones

Dos afirmaciones de este documento se verificaron ejecutando código, no leyendo. Se pueden
reproducir con el `node-forge` ya instalado en el repo:

**(A) Orden canónico DER de los `signedAttrs`** (§3.2). Se construyen los tres atributos con
forge, se codifican a DER y se ordenan reimplementando literalmente
`org.bouncycastle.asn1.ASN1Set.lessThanOrEqual` (comparación byte a byte de las
codificaciones completas; a igualdad de prefijo gana la más corta). Salida obtenida:

```
contentType   (…1.9.3)  len=26  head=30 18 06 09
messageDigest (…1.9.4)  len=37  head=30 23 06 09
signingTime   (…1.9.5)  len=30  head=30 1c 06 09
→ orden canónico: contentType, signingTime, messageDigest
```

**(B) `.key` PBES2+3DES y contraseña UTF-8** (§4.4, §4.5). Se genera un PKCS#8 en claro con
`openssl genrsa | openssl pkcs8 -topk8 -nocrypt`, se cifra con la receta de §4.4 usando la
contraseña no-ASCII `contrañseña`, y se comprueba que:

- `forge.pki.decryptPrivateKeyInfo(..., forge.util.encodeUtf8(password))` → **OK**
- lo mismo pasando el string JS crudo → **falla**
- `openssl pkcs8 -inform DER -in salida.key -passin pass:'contrañseña'` → **exit 0**
- `openssl pkey ... -noout -check` → **"Key is valid"**
- el mismo comando **con `-nocrypt`** → **falla** (`Error decrypting key`), que es por lo que
  se corrigió §4.4

Ambos comprobados con LibreSSL (el `openssl` del sistema en macOS) y con OpenSSL 3
(`brew --prefix openssl@3`), con idéntico resultado.
