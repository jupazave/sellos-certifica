# Sellos — Generador de CSD: Plan de Implementación

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** App estática en navegador que genera solicitudes de CSD (.key + .sdg) a partir de una e.firma del SAT y valida archivos .cer/.key, sin ninguna conexión de red en runtime.

**Architecture:** Vite + TypeScript sin framework. Módulos criptográficos puros (sin DOM) sobre node-forge, con WebCrypto solo para generar la llave RSA-2048. La UI (dos vistas: Generar y Validar) solo orquesta. El build produce un único `index.html` autocontenido (vite-plugin-singlefile) con CSP estricta que bloquea toda conexión saliente.

**Tech Stack:** Vite, TypeScript (strict), node-forge ^1.3.1 (única dependencia de runtime), Vitest + happy-dom, vite-plugin-singlefile.

**Spec:** `docs/superpowers/specs/2026-08-29-sellos-csd-design.md`

## Global Constraints

- Node ≥ 20 (WebCrypto global en tests).
- Única dependencia de runtime: `node-forge@^1.3.1`. Cero CDNs, cero fuentes externas.
- Todo texto de UI y mensajes de error **en español**. Identificadores de código en español sin acentos (`descifrarLlave`, no `descífrarLlave`).
- Archivos de salida en **DER binario** (no PEM): así los produce/espera el ecosistema SAT.
- Nombres de salida: `CSD_<sucursal>_<RFC>_<AAAAMMDD>.key` / `.sdg`.
- Contraseña nueva del CSD: mínimo 8 caracteres, con confirmación.
- CSP inyectada **solo en build** (el dev server necesita websockets para HMR): `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'`.
- Nunca committear llaves reales de ningún usuario. Fixtures: solo material de prueba público del SAT o sintético generado con OpenSSL.
- Nunca loggear (console.log) contraseñas, llaves ni buffers de material sensible.
- TDD en cada tarea; commit al final de cada tarea como mínimo. Mensajes de commit terminan con `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Los valores criptográficos marcados como **[CONFIRMAR-T3]** (subject del CSR, digest, cifrado del sobre, PBE del .key de salida, certificado del SAT) tienen un valor por defecto hipotético que la Tarea 3 confirma o corrige en `docs/reference/sdg-format.md`. Las tareas 7–9 leen ese documento antes de implementar.

---

### Task 1: Scaffold del proyecto

**Files:**
- Create: `package.json`, `tsconfig.json`, `vite.config.ts`, `index.html`, `src/main.ts`, `src/style.css`, `tests/sanity.test.ts`, `.gitignore`

**Interfaces:**
- Consumes: nada.
- Produces: proyecto compilable (`npm run build`) y testeable (`npm test`); `index.html` con marcador `<!--CSP-->` y `<div id="app">`; alias de import `node-forge` funcionando en tests y build.

- [ ] **Step 1: Crear package.json**

```json
{
  "name": "sellos",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "engines": { "node": ">=20" },
  "scripts": {
    "dev": "vite",
    "build": "tsc --noEmit && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest"
  }
}
```

- [ ] **Step 2: Instalar dependencias (pineadas por npm en package-lock)**

```bash
npm install node-forge@^1.3.1
npm install -D vite typescript vitest happy-dom @types/node-forge vite-plugin-singlefile
```

- [ ] **Step 3: Crear tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noEmit": true,
    "skipLibCheck": true,
    "types": ["vite/client"]
  },
  "include": ["src", "tests"]
}
```

- [ ] **Step 4: Crear vite.config.ts** (singlefile + CSP solo en build + config de vitest)

```ts
/// <reference types="vitest" />
import { defineConfig, type Plugin } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

const CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src data:; font-src data:; connect-src 'none'; base-uri 'none'; " +
  "form-action 'none'; object-src 'none'";

function inyectarCsp(): Plugin {
  return {
    name: 'inyectar-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<!--CSP-->',
        `<meta http-equiv="Content-Security-Policy" content="${CSP}">`,
      );
    },
  };
}

export default defineConfig({
  plugins: [viteSingleFile(), inyectarCsp()],
  build: { target: 'es2022' },
  test: { environment: 'node' },
});
```

- [ ] **Step 5: Crear index.html**

```html
<!doctype html>
<html lang="es">
  <head>
    <meta charset="UTF-8" />
    <!--CSP-->
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Sellos — Generador de CSD</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

- [ ] **Step 6: Crear src/style.css y src/main.ts mínimos**

`src/style.css`:

```css
:root {
  font-family: system-ui, sans-serif;
  color-scheme: light dark;
}
body {
  margin: 0 auto;
  max-width: 720px;
  padding: 1rem;
}
```

`src/main.ts`:

```ts
import './style.css';

const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = '<h1>Sellos — Generador de CSD</h1>';
```

- [ ] **Step 7: Crear .gitignore**

```
node_modules/
dist/
```

- [ ] **Step 8: Test de sanidad que prueba el wiring de forge**

`tests/sanity.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import forge from 'node-forge';

describe('wiring del proyecto', () => {
  it('node-forge carga y calcula sha256', () => {
    const hex = forge.md.sha256.create().update('sellos').digest().toHex();
    expect(hex).toHaveLength(64);
  });
});
```

- [ ] **Step 9: Verificar que test y build pasan**

Run: `npm test` → Expected: 1 passed.
Run: `npm run build` → Expected: sale sin error y `dist/index.html` existe.
Run: `grep -c "Content-Security-Policy" dist/index.html` → Expected: `1`.

- [ ] **Step 10: Commit**

```bash
git add package.json package-lock.json tsconfig.json vite.config.ts index.html src/ tests/ .gitignore
git commit -m "feat: scaffold Vite+TS con singlefile, CSP de build y Vitest

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Fixtures de prueba (e.firma/CSD públicas del SAT + sintéticas)

**Files:**
- Create: `tests/fixtures/generate.sh`, `tests/fixtures/README.md`
- Create (copiados/generados): `tests/fixtures/fiel.cer`, `tests/fixtures/fiel.key`, `tests/fixtures/csd.cer`, `tests/fixtures/csd.key`, `tests/fixtures/sintetica.cer`, `tests/fixtures/sintetica.key`

**Interfaces:**
- Consumes: nada.
- Produces: pares .cer/.key de FIEL y CSD de prueba en DER con su contraseña documentada en `tests/fixtures/README.md`; par sintético con contraseña `sintetica123`. Las tareas 5, 7, 8, 9 y 11 los leen con `readFileSync`.

- [ ] **Step 1: Obtener las fixtures públicas del SAT**

El SAT publica material de prueba para desarrolladores (RFC de pruebas tipo `EKU9003173C9` — ESCUELA KEMPER URGATE). La fuente más práctica es el repositorio de la comunidad phpcfdi, que las vendorea para sus propios tests:

```bash
git clone --depth 1 https://github.com/phpcfdi/credentials /tmp/phpcfdi-credentials
find /tmp/phpcfdi-credentials/tests -name '*.cer' -o -name '*.key' | sort
```

Identificar un par FIEL (e.firma) y un par CSD del mismo RFC de pruebas (los tests del repo distinguen ambos tipos; revisar nombres de carpeta/archivo y el código de tests para localizar la contraseña, buscando `grep -ri "passphrase\|password" /tmp/phpcfdi-credentials/tests --include='*.php' | head -30`; históricamente es `12345678a` para el material EKU9003173C9). Copiarlos:

```bash
mkdir -p tests/fixtures
cp <ruta-fiel>.cer tests/fixtures/fiel.cer
cp <ruta-fiel>.key tests/fixtures/fiel.key
cp <ruta-csd>.cer tests/fixtures/csd.cer
cp <ruta-csd>.key tests/fixtures/csd.key
```

Si el clone no es posible (sin red), detenerse y reportarlo: las fixtures reales son necesarias para las tareas 5+.

- [ ] **Step 2: Verificar las fixtures con OpenSSL**

```bash
openssl x509 -inform DER -in tests/fixtures/fiel.cer -noout -subject -dates
openssl x509 -inform DER -in tests/fixtures/csd.cer -noout -subject -dates
openssl pkcs8 -inform DER -in tests/fixtures/fiel.key -passin pass:<contraseña> -nocrypt 2>/dev/null | head -1
```

Expected: los dos primeros imprimen subject con el RFC de pruebas en `x500UniqueIdentifier` (OID 2.5.4.45); el tercero imprime `-----BEGIN PRIVATE KEY-----` (la contraseña descifra). Anotar: el subject exacto del CSD (si trae `OU` con nombre de sucursal) y del FIEL (sin `OU`), para los tests de la Tarea 5.

- [ ] **Step 3: Crear tests/fixtures/generate.sh (par sintético)**

```bash
#!/usr/bin/env bash
# Regenera el par sintético usado en tests (NO es material del SAT).
# Imita el cifrado legacy del SAT: PKCS#8 con PBE-SHA1-3DES, en DER.
set -euo pipefail
cd "$(dirname "$0")"

PASS="sintetica123"

openssl genrsa -out /tmp/sintetica-plain.pem 2048
openssl req -new -x509 -key /tmp/sintetica-plain.pem -days 3650 \
  -subj "/CN=PRUEBA SINTETICA/x500UniqueIdentifier=XAXX010101000" \
  -outform DER -out sintetica.cer
openssl pkcs8 -topk8 -inform PEM -in /tmp/sintetica-plain.pem \
  -outform DER -out sintetica.key -v1 PBE-SHA1-3DES -passout "pass:${PASS}"
rm /tmp/sintetica-plain.pem
echo "OK: sintetica.cer / sintetica.key (contraseña: ${PASS})"
```

- [ ] **Step 4: Ejecutarlo y verificar**

```bash
chmod +x tests/fixtures/generate.sh && tests/fixtures/generate.sh
openssl x509 -inform DER -in tests/fixtures/sintetica.cer -noout -subject
```

Expected: imprime el subject sintético. Si la versión local de OpenSSL/LibreSSL rechaza `-v1 PBE-SHA1-3DES`, usar `-v2 des3` y anotar el cambio en el README de fixtures.

- [ ] **Step 5: Crear tests/fixtures/README.md**

Documentar: origen de cada archivo (repo/carpeta de donde se copió), RFC de pruebas, contraseña de fiel.key/csd.key, contraseña `sintetica123`, y cómo regenerar las sintéticas. Dejar explícito: "Material de prueba público del SAT; aquí nunca se committean llaves reales".

- [ ] **Step 6: Commit**

```bash
git add tests/fixtures/
git commit -m "test: fixtures publicas del SAT (FIEL/CSD de prueba) y par sintetico

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Investigación — formato .sdg, subject del CSR y certificado del SAT

**Files:**
- Create: `docs/reference/sdg-format.md`, `docs/reference/certificado-sat.cer` (DER)

**Interfaces:**
- Consumes: nada.
- Produces: `docs/reference/sdg-format.md` con los 5 valores **[CONFIRMAR-T3]** resueltos (o marcados explícitamente como hipótesis) que las tareas 7, 8 y 9 leen antes de implementar; `docs/reference/certificado-sat.cer` que la Tarea 9 vendorea.

Esta tarea es de investigación: su entregable es un documento, no código. El formato .sdg no está documentado oficialmente; hay que fijarlo con fuentes de la comunidad.

- [ ] **Step 1: Buscar implementaciones y documentación existentes**

Con WebSearch/WebFetch, buscar (en este orden de confiabilidad):
1. Implementaciones open-source del "ensobretado" SOLCEDI/Certifica: términos como `"ensobretado" SAT SOLCEDI github`, `"sdg" "certifica" CSR SAT site:github.com`, `SAT CSD requerimiento PKCS7 EnvelopedData`.
2. La documentación técnica histórica de SOLCEDI ("Especificaciones técnicas de ensobretado digital") citada en foros/repos CFDI.
3. El propio Certifica: es una app Java descargable del portal SAT; si los pasos 1–2 no bastan, descargar el JAR y revisar las clases de generación de requerimiento (interoperabilidad con formato propio del SAT para uso legítimo del contribuyente).

- [ ] **Step 2: Resolver y documentar los 5 valores [CONFIRMAR-T3]**

Escribir `docs/reference/sdg-format.md` con secciones fijas, cada una con el valor confirmado, la fuente (URL/archivo/clase Java), y nivel de confianza (confirmado / hipótesis):

1. **Subject del CSR de CSD.** Hipótesis por defecto: `CN=<razón social>`, `OU=<sucursal>`, `2.5.4.45 (x500UniqueIdentifier)=<RFC>`. Registrar el orden y tipo ASN.1 (UTF8String vs PrintableString) de cada atributo.
2. **Digest de la firma** (del CSR y del SignedData): SHA-1 o SHA-256. Hipótesis: SHA-256 para el CSR; el SignedData según fuente.
3. **Estructura del .sdg**: hipótesis: `ContentInfo(EnvelopedData)` cuyo contenido cifrado es `ContentInfo(SignedData)` que firma el CSR DER con la e.firma. Confirmar: orden sign→envelope, cifrado simétrico del sobre (des-EDE3-CBC vs RC4 vs AES), si el SignedData incluye el certificado de la e.firma, y si el archivo lleva algún encabezado/pie textual además del DER.
4. **Formato del .key de salida**: hipótesis: PKCS#8 `EncryptedPrivateKeyInfo` DER con `pbeWithSHAAnd3-KeyTripleDES-CBC` (igual que las llaves que entrega el SAT).
5. **Certificado destinatario del sobre**: cuál certificado público del SAT usa CertiSAT hoy. Descargarlo de fuente oficial del SAT (o extraerlo del propio Certifica) y guardarlo como `docs/reference/certificado-sat.cer`; verificar con `openssl x509 -inform DER -in docs/reference/certificado-sat.cer -noout -subject -dates` que es del SAT y está vigente.

- [ ] **Step 3: Regla de cierre**

Si tras la investigación algún valor queda como hipótesis, dejarlo marcado así en el documento con el plan de verificación: "se valida con la prueba E2E manual del usuario contra CertiSAT". No bloquear el resto del plan por esto — `sdg.ts` queda aislado justo para absorber correcciones.

- [ ] **Step 4: Commit**

```bash
git add docs/reference/
git commit -m "docs: formato .sdg, subject CSR y certificado SAT (investigacion T3)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Utilidades — errores tipados, bytes y archivos

**Files:**
- Create: `src/util/errors.ts`, `src/util/bytes.ts`, `src/util/files.ts`
- Test: `tests/util.test.ts`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `errors.ts`: `class SellosError extends Error { constructor(mensaje: string) }` y subclases `ArchivoInvalidoError`, `ContrasenaIncorrectaError`, `ParejaInvalidaError`, `TipoCertificadoError` (todas sin parámetros extra, con mensaje por defecto en español sobreescribible).
  - `bytes.ts`: `aBinario(bytes: Uint8Array): string` (string binario para forge) y `aBytes(binario: string): Uint8Array`.
  - `files.ts`: `leerArchivo(archivo: File): Promise<Uint8Array>`, `descargarArchivo(nombre: string, bytes: Uint8Array): void`, `nombreBase(sucursal: string, rfc: string, fecha: Date): string` → `CSD_<sucursal saneada>_<RFC>_<AAAAMMDD>`.

- [ ] **Step 1: Escribir tests que fallan**

`tests/util.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import {
  ArchivoInvalidoError,
  ContrasenaIncorrectaError,
  SellosError,
} from '../src/util/errors';
import { aBinario, aBytes } from '../src/util/bytes';
import { nombreBase } from '../src/util/files';

describe('errores tipados', () => {
  it('tienen mensaje en español por defecto y son SellosError', () => {
    const err = new ContrasenaIncorrectaError();
    expect(err).toBeInstanceOf(SellosError);
    expect(err.message).toBe('La contraseña no descifra esta llave privada.');
    expect(new ArchivoInvalidoError('otro mensaje').message).toBe('otro mensaje');
  });
});

describe('bytes', () => {
  it('aBinario/aBytes hacen round-trip', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    expect(aBytes(aBinario(original))).toEqual(original);
  });
});

describe('nombreBase', () => {
  it('arma CSD_<sucursal>_<RFC>_<AAAAMMDD> saneando la sucursal', () => {
    const fecha = new Date(2026, 7, 29); // 29-ago-2026
    expect(nombreBase('Matriz Centro', 'EKU9003173C9', fecha)).toBe(
      'CSD_Matriz_Centro_EKU9003173C9_20260829',
    );
  });
});
```

- [ ] **Step 2: Verificar que fallan**

Run: `npm test` → Expected: FAIL por módulos inexistentes.

- [ ] **Step 3: Implementar**

`src/util/errors.ts`:

```ts
export class SellosError extends Error {}

export class ArchivoInvalidoError extends SellosError {
  constructor(mensaje = 'El archivo no parece ser un .cer/.key del SAT (formato DER).') {
    super(mensaje);
  }
}

export class ContrasenaIncorrectaError extends SellosError {
  constructor(mensaje = 'La contraseña no descifra esta llave privada.') {
    super(mensaje);
  }
}

export class ParejaInvalidaError extends SellosError {
  constructor(mensaje = 'Esta llave privada no corresponde a este certificado.') {
    super(mensaje);
  }
}

export class TipoCertificadoError extends SellosError {
  constructor(
    mensaje = 'Este certificado es un CSD; para generar sellos necesitas tu e.firma (FIEL).',
  ) {
    super(mensaje);
  }
}
```

`src/util/bytes.ts`:

```ts
export function aBinario(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return out;
}

export function aBytes(binario: string): Uint8Array {
  const out = new Uint8Array(binario.length);
  for (let i = 0; i < binario.length; i++) out[i] = binario.charCodeAt(i) & 0xff;
  return out;
}
```

`src/util/files.ts`:

```ts
export async function leerArchivo(archivo: File): Promise<Uint8Array> {
  return new Uint8Array(await archivo.arrayBuffer());
}

export function descargarArchivo(nombre: string, bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = nombre;
  a.click();
  URL.revokeObjectURL(url);
}

export function nombreBase(sucursal: string, rfc: string, fecha: Date): string {
  const saneada = sucursal.trim().replace(/[^A-Za-z0-9ÁÉÍÓÚÑáéíóúñ]+/g, '_');
  const aaaa = fecha.getFullYear();
  const mm = String(fecha.getMonth() + 1).padStart(2, '0');
  const dd = String(fecha.getDate()).padStart(2, '0');
  return `CSD_${saneada}_${rfc.toUpperCase()}_${aaaa}${mm}${dd}`;
}
```

- [ ] **Step 4: Verificar que pasan**

Run: `npm test` → Expected: PASS (util + sanity).

- [ ] **Step 5: Commit**

```bash
git add src/util/ tests/util.test.ts
git commit -m "feat: errores tipados y utilidades de bytes/archivos

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: crypto/efirma.ts — parseo, descifrado, pareja, tipo y vigencia

**Files:**
- Create: `src/crypto/efirma.ts`
- Test: `tests/efirma.test.ts`

**Interfaces:**
- Consumes: `aBinario` de `src/util/bytes.ts`; errores de `src/util/errors.ts`; fixtures de la Tarea 2.
- Produces (lo que usan las tareas 9, 10 y 11):

```ts
export type TipoCertificado = 'FIEL' | 'CSD';
export type EstadoVigencia = 'vigente' | 'por_vencer' | 'vencido';

export interface DatosCertificado {
  tipo: TipoCertificado;
  rfc: string;
  razonSocial: string;
  numeroSerie: string; // decodificado a ASCII, ej. "30001000000400002434"
  validoDesde: Date;
  validoHasta: Date;
  certificado: forge.pki.Certificate;
}

export interface Efirma {
  datos: DatosCertificado;
  llave: forge.pki.rsa.PrivateKey;
}

export function parsearCertificado(der: Uint8Array): DatosCertificado; // ArchivoInvalidoError
export function descifrarLlave(der: Uint8Array, contrasena: string): forge.pki.rsa.PrivateKey; // ArchivoInvalidoError | ContrasenaIncorrectaError
export function sonPareja(cert: forge.pki.Certificate, llave: forge.pki.rsa.PrivateKey): boolean;
export function estadoVigencia(datos: DatosCertificado, ahora: Date): EstadoVigencia; // por_vencer = faltan ≤90 días
export function cargarEfirma(cer: Uint8Array, key: Uint8Array, contrasena: string): Efirma; // + TipoCertificadoError | ParejaInvalidaError
```

- [ ] **Step 1: Inspeccionar las fixtures para fijar valores esperados**

```bash
openssl x509 -inform DER -in tests/fixtures/fiel.cer -noout -subject -serial -dates -nameopt oneline,show_type
openssl x509 -inform DER -in tests/fixtures/csd.cer -noout -subject -serial -dates -nameopt oneline,show_type
```

Anotar de la salida real: RFC (en el atributo OID 2.5.4.45; si trae formato `RFC1 / RFC2`, el RFC del titular es el primero), razón social (CN), presencia de `OU` en el CSD (heurística de clasificación: **con OU ⇒ CSD, sin OU ⇒ FIEL** — si la salida contradice esto, usar la diferencia observable que sí distinga a los dos y documentarla en un comentario del módulo), y el serial hex (decodificado por pares hex→ASCII da el número de serie que muestra el SAT).

- [ ] **Step 2: Escribir tests que fallan** (sustituir las constantes `ESPERADO_*` con los valores reales del Step 1)

`tests/efirma.test.ts`:

```ts
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  cargarEfirma,
  descifrarLlave,
  estadoVigencia,
  parsearCertificado,
  sonPareja,
  type DatosCertificado,
} from '../src/crypto/efirma';
import {
  ArchivoInvalidoError,
  ContrasenaIncorrectaError,
  ParejaInvalidaError,
  TipoCertificadoError,
} from '../src/util/errors';

const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const csdCer = new Uint8Array(readFileSync('tests/fixtures/csd.cer'));
const sinteticaKey = new Uint8Array(readFileSync('tests/fixtures/sintetica.key'));

const CONTRASENA = '12345678a'; // la documentada en tests/fixtures/README.md
const ESPERADO_RFC = 'EKU9003173C9'; // ajustar al valor real del Step 1
const ESPERADO_RAZON = 'ESCUELA KEMPER URGATE'; // ajustar (prefijo del CN real)

describe('parsearCertificado', () => {
  it('extrae RFC, razón social, serie y vigencia de la FIEL', () => {
    const datos = parsearCertificado(fielCer);
    expect(datos.rfc).toBe(ESPERADO_RFC);
    expect(datos.razonSocial).toContain(ESPERADO_RAZON);
    expect(datos.tipo).toBe('FIEL');
    expect(datos.numeroSerie).toMatch(/^[0-9]{20}$/);
    expect(datos.validoHasta.getTime()).toBeGreaterThan(datos.validoDesde.getTime());
  });

  it('clasifica el CSD como CSD', () => {
    expect(parsearCertificado(csdCer).tipo).toBe('CSD');
  });

  it('rechaza bytes que no son un certificado DER', () => {
    expect(() => parsearCertificado(new Uint8Array([1, 2, 3]))).toThrow(ArchivoInvalidoError);
  });
});

describe('descifrarLlave', () => {
  it('descifra con la contraseña correcta', () => {
    const llave = descifrarLlave(fielKey, CONTRASENA);
    expect(llave.n.bitLength()).toBeGreaterThanOrEqual(2048);
  });

  it('rechaza contraseña incorrecta', () => {
    expect(() => descifrarLlave(fielKey, 'incorrecta')).toThrow(ContrasenaIncorrectaError);
  });

  it('rechaza bytes que no son una llave DER', () => {
    expect(() => descifrarLlave(new Uint8Array([9, 9]), CONTRASENA)).toThrow(ArchivoInvalidoError);
  });
});

describe('sonPareja', () => {
  it('acepta la pareja real y rechaza una llave ajena', () => {
    const datos = parsearCertificado(fielCer);
    expect(sonPareja(datos.certificado, descifrarLlave(fielKey, CONTRASENA))).toBe(true);
    expect(sonPareja(datos.certificado, descifrarLlave(sinteticaKey, 'sintetica123'))).toBe(false);
  });
});

describe('estadoVigencia', () => {
  const base = (hasta: Date): DatosCertificado =>
    ({ ...parsearCertificado(fielCer), validoDesde: new Date(2020, 0, 1), validoHasta: hasta });

  it('vigente / por_vencer / vencido según fecha de referencia', () => {
    const hasta = new Date(2030, 0, 1);
    expect(estadoVigencia(base(hasta), new Date(2029, 0, 1))).toBe('vigente');
    expect(estadoVigencia(base(hasta), new Date(2029, 11, 1))).toBe('por_vencer');
    expect(estadoVigencia(base(hasta), new Date(2030, 5, 1))).toBe('vencido');
  });
});

describe('cargarEfirma', () => {
  it('carga una e.firma completa', () => {
    const efirma = cargarEfirma(fielCer, fielKey, CONTRASENA);
    expect(efirma.datos.rfc).toBe(ESPERADO_RFC);
  });

  it('rechaza un CSD como e.firma', () => {
    expect(() => cargarEfirma(csdCer, fielKey, CONTRASENA)).toThrow(TipoCertificadoError);
  });

  it('rechaza llave que no es pareja del certificado', () => {
    expect(() => cargarEfirma(fielCer, sinteticaKey, 'sintetica123')).toThrow(ParejaInvalidaError);
  });
});
```

Nota: si el .key CSD de la fixture usa otra contraseña que el FIEL, ajustar constantes según `tests/fixtures/README.md`.

- [ ] **Step 3: Verificar que fallan**

Run: `npm test tests/efirma.test.ts` → Expected: FAIL (módulo inexistente).

- [ ] **Step 4: Implementar src/crypto/efirma.ts**

```ts
import forge from 'node-forge';
import { aBinario } from '../util/bytes';
import {
  ArchivoInvalidoError,
  ContrasenaIncorrectaError,
  ParejaInvalidaError,
  TipoCertificadoError,
} from '../util/errors';

export type TipoCertificado = 'FIEL' | 'CSD';
export type EstadoVigencia = 'vigente' | 'por_vencer' | 'vencido';

export interface DatosCertificado {
  tipo: TipoCertificado;
  rfc: string;
  razonSocial: string;
  numeroSerie: string;
  validoDesde: Date;
  validoHasta: Date;
  certificado: forge.pki.Certificate;
}

export interface Efirma {
  datos: DatosCertificado;
  llave: forge.pki.rsa.PrivateKey;
}

const OID_RFC = '2.5.4.45'; // x500UniqueIdentifier

const DIAS_POR_VENCER = 90;

export function parsearCertificado(der: Uint8Array): DatosCertificado {
  let cert: forge.pki.Certificate;
  try {
    cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(aBinario(der)));
  } catch {
    throw new ArchivoInvalidoError('El archivo no parece ser un certificado .cer del SAT (DER).');
  }

  const attrs = cert.subject.attributes;
  const rfcCrudo = String(attrs.find((a) => a.type === OID_RFC)?.value ?? '');
  const rfc = rfcCrudo.split('/')[0]?.trim().toUpperCase() ?? '';
  const razonSocial = String(attrs.find((a) => a.shortName === 'CN')?.value ?? '');
  // Heurística SAT: los CSD llevan el nombre de sucursal en OU; la e.firma no.
  const tipo: TipoCertificado = attrs.some((a) => a.shortName === 'OU') ? 'CSD' : 'FIEL';

  const serieHex = cert.serialNumber.replace(/^0+/, '');
  const numeroSerie = serieHex.match(/.{2}/g)?.map((h) => String.fromCharCode(parseInt(h, 16))).join('') ?? serieHex;

  return {
    tipo,
    rfc,
    razonSocial,
    numeroSerie,
    validoDesde: cert.validity.notBefore,
    validoHasta: cert.validity.notAfter,
    certificado: cert,
  };
}

export function descifrarLlave(der: Uint8Array, contrasena: string): forge.pki.rsa.PrivateKey {
  let epki: forge.asn1.Asn1;
  try {
    epki = forge.asn1.fromDer(aBinario(der));
  } catch {
    throw new ArchivoInvalidoError('El archivo no parece ser una llave .key del SAT (DER).');
  }
  let pki: forge.asn1.Asn1 | null;
  try {
    pki = forge.pki.decryptPrivateKeyInfo(epki, contrasena);
  } catch {
    pki = null;
  }
  if (!pki) throw new ContrasenaIncorrectaError();
  try {
    return forge.pki.privateKeyFromAsn1(pki) as forge.pki.rsa.PrivateKey;
  } catch {
    throw new ArchivoInvalidoError('La llave descifrada no es una llave RSA válida.');
  }
}

export function sonPareja(cert: forge.pki.Certificate, llave: forge.pki.rsa.PrivateKey): boolean {
  const publica = cert.publicKey as forge.pki.rsa.PublicKey;
  return publica.n.compareTo(llave.n) === 0;
}

export function estadoVigencia(datos: DatosCertificado, ahora: Date): EstadoVigencia {
  if (ahora.getTime() > datos.validoHasta.getTime()) return 'vencido';
  const msRestantes = datos.validoHasta.getTime() - ahora.getTime();
  if (msRestantes <= DIAS_POR_VENCER * 24 * 60 * 60 * 1000) return 'por_vencer';
  return 'vigente';
}

export function cargarEfirma(cer: Uint8Array, key: Uint8Array, contrasena: string): Efirma {
  const datos = parsearCertificado(cer);
  if (datos.tipo !== 'FIEL') throw new TipoCertificadoError();
  const llave = descifrarLlave(key, contrasena);
  if (!sonPareja(datos.certificado, llave)) throw new ParejaInvalidaError();
  return { datos, llave };
}
```

Nota para el implementador: si `forge.pki.decryptPrivateKeyInfo` no descifra la fixture real (algoritmo PBE no soportado), imprimir el OID del algoritmo (`openssl asn1parse -inform DER -in tests/fixtures/fiel.key | head`) y reportarlo antes de improvisar — puede requerir mapear PBES2 con parámetros específicos.

- [ ] **Step 5: Verificar que pasan**

Run: `npm test tests/efirma.test.ts` → Expected: PASS completo.

- [ ] **Step 6: Commit**

```bash
git add src/crypto/efirma.ts tests/efirma.test.ts
git commit -m "feat: carga y validacion de e.firma (parseo, descifrado, pareja, vigencia)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: crypto/keygen.ts — par RSA-2048 vía WebCrypto

**Files:**
- Create: `src/crypto/keygen.ts`
- Test: `tests/keygen.test.ts`

**Interfaces:**
- Consumes: `aBinario` de `src/util/bytes.ts`.
- Produces: `export async function generarParCSD(): Promise<{ privada: forge.pki.rsa.PrivateKey; publica: forge.pki.rsa.PublicKey }>` — usado por tareas 7, 8 y 11.

- [ ] **Step 1: Escribir test que falla**

`tests/keygen.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { generarParCSD } from '../src/crypto/keygen';

describe('generarParCSD', () => {
  it('genera un par RSA-2048 cuyas mitades coinciden', async () => {
    const { privada, publica } = await generarParCSD();
    expect(privada.n.bitLength()).toBe(2048);
    expect(publica.n.compareTo(privada.n)).toBe(0);
    expect(publica.e.toString(16)).toBe('10001');
  }, 20_000);
});
```

- [ ] **Step 2: Verificar que falla**

Run: `npm test tests/keygen.test.ts` → Expected: FAIL (módulo inexistente).

- [ ] **Step 3: Implementar src/crypto/keygen.ts**

```ts
import forge from 'node-forge';
import { aBinario } from '../util/bytes';

export async function generarParCSD(): Promise<{
  privada: forge.pki.rsa.PrivateKey;
  publica: forge.pki.rsa.PublicKey;
}> {
  const par = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', par.privateKey));
  const privada = forge.pki.privateKeyFromAsn1(
    forge.asn1.fromDer(aBinario(pkcs8)),
  ) as forge.pki.rsa.PrivateKey;
  const publica = forge.pki.setRsaPublicKey(privada.n, privada.e);
  return { privada, publica };
}
```

- [ ] **Step 4: Verificar que pasa**

Run: `npm test tests/keygen.test.ts` → Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/keygen.ts tests/keygen.test.ts
git commit -m "feat: generacion de par RSA-2048 con WebCrypto importado a forge

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: crypto/keyfile.ts — cifrar la llave nueva en formato .key del SAT

**Files:**
- Create: `src/crypto/keyfile.ts`
- Test: `tests/keyfile.test.ts`

**Interfaces:**
- Consumes: `generarParCSD` (Tarea 6); `descifrarLlave` (Tarea 5) como oráculo del round-trip; `aBinario`/`aBytes`; **[CONFIRMAR-T3]** algoritmo PBE en `docs/reference/sdg-format.md` (sección 4).
- Produces: `export function cifrarLlaveCSD(privada: forge.pki.rsa.PrivateKey, contrasena: string): Uint8Array` (DER `EncryptedPrivateKeyInfo`) — usado por Tarea 11.

Antes de implementar: leer `docs/reference/sdg-format.md` sección 4. El código de abajo usa el valor por defecto (`3des` en forge = `pbeWithSHAAnd3-KeyTripleDES-CBC`); si T3 concluyó otro algoritmo, sustituirlo.

- [ ] **Step 1: Escribir test que falla**

`tests/keyfile.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { generarParCSD } from '../src/crypto/keygen';
import { cifrarLlaveCSD } from '../src/crypto/keyfile';
import { descifrarLlave } from '../src/crypto/efirma';
import { ContrasenaIncorrectaError } from '../src/util/errors';

describe('cifrarLlaveCSD', () => {
  it('produce DER que descifrarLlave abre con la misma contraseña (round-trip)', async () => {
    const { privada } = await generarParCSD();
    const der = cifrarLlaveCSD(privada, 'MiContrasena123');
    expect(der[0]).toBe(0x30); // SEQUENCE: es DER, no PEM
    const recuperada = descifrarLlave(der, 'MiContrasena123');
    expect(recuperada.n.compareTo(privada.n)).toBe(0);
  }, 20_000);

  it('la contraseña incorrecta no la abre', async () => {
    const { privada } = await generarParCSD();
    const der = cifrarLlaveCSD(privada, 'MiContrasena123');
    expect(() => descifrarLlave(der, 'otra')).toThrow(ContrasenaIncorrectaError);
  }, 20_000);
});
```

- [ ] **Step 2: Verificar que falla**

Run: `npm test tests/keyfile.test.ts` → Expected: FAIL (módulo inexistente).

- [ ] **Step 3: Implementar src/crypto/keyfile.ts**

```ts
import forge from 'node-forge';
import { aBytes } from '../util/bytes';

// Algoritmo por defecto confirmado/corregido por docs/reference/sdg-format.md (T3):
// '3des' en forge produce pbeWithSHAAnd3-KeyTripleDES-CBC, el PBE legacy del SAT.
const ALGORITMO_PBE = '3des';

export function cifrarLlaveCSD(privada: forge.pki.rsa.PrivateKey, contrasena: string): Uint8Array {
  const pki = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(privada));
  const epki = forge.pki.encryptPrivateKeyInfo(pki, contrasena, {
    algorithm: ALGORITMO_PBE,
    count: 2048,
    saltSize: 8,
  });
  return aBytes(forge.asn1.toDer(epki).getBytes());
}
```

- [ ] **Step 4: Verificar que pasa + cross-check con OpenSSL**

Run: `npm test tests/keyfile.test.ts` → Expected: PASS.

Cross-check manual (opcional pero recomendado — escribir un DER de ejemplo a `/tmp` desde un test temporal o script node y correr):

```bash
openssl pkcs8 -inform DER -in /tmp/ejemplo-csd.key -passin pass:MiContrasena123 -nocrypt | head -1
```

Expected: `-----BEGIN PRIVATE KEY-----` (en OpenSSL 3 puede requerir `-provider legacy -provider default` por el PBE SHA1/3DES; anotar el resultado en el commit).

- [ ] **Step 5: Commit**

```bash
git add src/crypto/keyfile.ts tests/keyfile.test.ts
git commit -m "feat: cifrado de la llave CSD en formato PKCS#8 legacy del SAT

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: crypto/csr.ts — CSR PKCS#10 con subject del SAT

**Files:**
- Create: `src/crypto/csr.ts`
- Test: `tests/csr.test.ts`

**Interfaces:**
- Consumes: `generarParCSD` (Tarea 6); `aBinario`/`aBytes`; **[CONFIRMAR-T3]** subject y digest en `docs/reference/sdg-format.md` (secciones 1–2).
- Produces: `export function generarCSR(entrada: { privada: forge.pki.rsa.PrivateKey; publica: forge.pki.rsa.PublicKey; rfc: string; razonSocial: string; sucursal: string }): Uint8Array` (DER PKCS#10) — usado por tareas 9 y 11.

Antes de implementar: leer `docs/reference/sdg-format.md` secciones 1–2 y ajustar `SUBJECT`/digest si difieren del default.

- [ ] **Step 1: Escribir test que falla**

`tests/csr.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { generarParCSD } from '../src/crypto/keygen';
import { generarCSR } from '../src/crypto/csr';
import { aBinario } from '../src/util/bytes';

describe('generarCSR', () => {
  it('produce un PKCS#10 verificable con el subject del SAT', async () => {
    const par = await generarParCSD();
    const der = generarCSR({
      ...par,
      rfc: 'EKU9003173C9',
      razonSocial: 'ESCUELA KEMPER URGATE SA DE CV',
      sucursal: 'Matriz',
    });
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));
    expect(csr.verify()).toBe(true);

    const attrs = csr.subject.attributes;
    expect(String(attrs.find((a) => a.shortName === 'CN')?.value)).toBe(
      'ESCUELA KEMPER URGATE SA DE CV',
    );
    expect(String(attrs.find((a) => a.shortName === 'OU')?.value)).toBe('Matriz');
    expect(String(attrs.find((a) => a.type === '2.5.4.45')?.value)).toBe('EKU9003173C9');
  }, 20_000);
});
```

- [ ] **Step 2: Verificar que falla**

Run: `npm test tests/csr.test.ts` → Expected: FAIL (módulo inexistente).

- [ ] **Step 3: Implementar src/crypto/csr.ts**

```ts
import forge from 'node-forge';
import { aBytes } from '../util/bytes';

export interface EntradaCSR {
  privada: forge.pki.rsa.PrivateKey;
  publica: forge.pki.rsa.PublicKey;
  rfc: string;
  razonSocial: string;
  sucursal: string;
}

// Subject y digest según docs/reference/sdg-format.md (T3, secciones 1-2).
export function generarCSR(entrada: EntradaCSR): Uint8Array {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = entrada.publica;
  csr.setSubject([
    { name: 'commonName', value: entrada.razonSocial, valueTagClass: forge.asn1.Type.UTF8 },
    { name: 'organizationalUnitName', value: entrada.sucursal, valueTagClass: forge.asn1.Type.UTF8 },
    { type: '2.5.4.45', value: entrada.rfc.toUpperCase(), valueTagClass: forge.asn1.Type.UTF8 },
  ]);
  csr.sign(entrada.privada, forge.md.sha256.create());
  return aBytes(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes());
}
```

- [ ] **Step 4: Verificar que pasa + cross-check OpenSSL**

Run: `npm test tests/csr.test.ts` → Expected: PASS.

Cross-check (desde un script/test temporal escribir un CSR a `/tmp/ejemplo.csr`):

```bash
openssl req -inform DER -in /tmp/ejemplo.csr -noout -verify -subject
```

Expected: `verify OK` y el subject con CN/OU/x500UniqueIdentifier.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/csr.ts tests/csr.test.ts
git commit -m "feat: CSR PKCS#10 con subject de CSD del SAT

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: crypto/sat-cert.ts + crypto/sdg.ts — ensobretado .sdg

**Files:**
- Create: `src/crypto/sat-cert.ts`, `src/crypto/sdg.ts`
- Test: `tests/sdg.test.ts`

**Interfaces:**
- Consumes: `Efirma` y `cargarEfirma` (Tarea 5); `generarCSR` (Tarea 8); `docs/reference/certificado-sat.cer` y **[CONFIRMAR-T3]** estructura/cifrado (sección 3 de `docs/reference/sdg-format.md`).
- Produces:
  - `sat-cert.ts`: `export function certificadoSAT(): forge.pki.Certificate` (cert embebido como base64).
  - `sdg.ts`: `export function generarSDG(csrDer: Uint8Array, efirma: Efirma): Uint8Array` — usado por Tarea 11.

Antes de implementar: leer completo `docs/reference/sdg-format.md`. El código de abajo implementa la hipótesis por defecto (SignedData con la e.firma → EnvelopedData hacia el SAT con des-EDE3-CBC). Si T3 documentó otra estructura, seguir el documento — los tests estructurales se ajustan igual.

- [ ] **Step 1: Vendorear el certificado del SAT**

```bash
base64 -i docs/reference/certificado-sat.cer | tr -d '\n' > /tmp/sat-cert-b64.txt
wc -c /tmp/sat-cert-b64.txt
```

Crear `src/crypto/sat-cert.ts` pegando el base64 (una sola línea larga es aceptable aquí):

```ts
import forge from 'node-forge';
import { aBinario } from '../util/bytes';

// Certificado público del SAT para el ensobretado (fuente: docs/reference/sdg-format.md, sección 5).
const SAT_CERT_B64 = '<PEGAR AQUÍ el contenido de /tmp/sat-cert-b64.txt>';

export function certificadoSAT(): forge.pki.Certificate {
  const der = Uint8Array.from(atob(SAT_CERT_B64), (c) => c.charCodeAt(0));
  return forge.pki.certificateFromAsn1(forge.asn1.fromDer(aBinario(der)));
}
```

- [ ] **Step 2: Escribir tests que fallan**

`tests/sdg.test.ts`:

```ts
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { cargarEfirma } from '../src/crypto/efirma';
import { generarParCSD } from '../src/crypto/keygen';
import { generarCSR } from '../src/crypto/csr';
import { certificadoSAT } from '../src/crypto/sat-cert';
import { generarSDG } from '../src/crypto/sdg';
import { aBinario } from '../src/util/bytes';

const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md

describe('certificadoSAT', () => {
  it('parsea y es un certificado con llave RSA', () => {
    const cert = certificadoSAT();
    expect((cert.publicKey as forge.pki.rsa.PublicKey).n.bitLength()).toBeGreaterThanOrEqual(2048);
  });
});

describe('generarSDG', () => {
  it('produce un EnvelopedData dirigido al SAT', async () => {
    const efirma = cargarEfirma(fielCer, fielKey, CONTRASENA);
    const par = await generarParCSD();
    const csr = generarCSR({
      ...par,
      rfc: efirma.datos.rfc,
      razonSocial: efirma.datos.razonSocial,
      sucursal: 'Matriz',
    });

    const sdg = generarSDG(csr, efirma);
    const asn1 = forge.asn1.fromDer(aBinario(sdg));
    const msg = forge.pkcs7.messageFromAsn1(asn1) as forge.pkcs7.PkcsEnvelopedData;

    expect(msg.type).toBe(forge.pki.oids.envelopedData);
    const destinatario = certificadoSAT();
    expect(msg.recipients[0]?.serialNumber).toBe(destinatario.serialNumber);
  }, 30_000);
});
```

- [ ] **Step 3: Verificar que fallan**

Run: `npm test tests/sdg.test.ts` → Expected: FAIL (módulos inexistentes / base64 sin pegar).

- [ ] **Step 4: Implementar src/crypto/sdg.ts**

```ts
import forge from 'node-forge';
import { aBinario, aBytes } from '../util/bytes';
import type { Efirma } from './efirma';
import { certificadoSAT } from './sat-cert';

// Estructura según docs/reference/sdg-format.md (T3, sección 3):
// 1) SignedData: el CSR DER firmado con la e.firma (incluye su certificado).
// 2) EnvelopedData: el SignedData cifrado hacia el certificado del SAT.
export function generarSDG(csrDer: Uint8Array, efirma: Efirma): Uint8Array {
  const firmado = forge.pkcs7.createSignedData();
  firmado.content = forge.util.createBuffer(aBinario(csrDer));
  firmado.addCertificate(efirma.datos.certificado);
  firmado.addSigner({
    key: efirma.llave,
    certificate: efirma.datos.certificado,
    digestAlgorithm: forge.pki.oids.sha256, // ajustar si T3 concluyó SHA-1
  });
  firmado.sign();
  const firmadoDer = forge.asn1.toDer(firmado.toAsn1()).getBytes();

  const sobre = forge.pkcs7.createEnvelopedData();
  sobre.addRecipient(certificadoSAT());
  sobre.content = forge.util.createBuffer(firmadoDer);
  sobre.encrypt(undefined, forge.pki.oids['des-EDE3-CBC']); // ajustar si T3 concluyó otro cifrado
  return aBytes(forge.asn1.toDer(sobre.toAsn1()).getBytes());
}
```

- [ ] **Step 5: Verificar que pasan**

Run: `npm test tests/sdg.test.ts` → Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/crypto/sat-cert.ts src/crypto/sdg.ts tests/sdg.test.ts
git commit -m "feat: ensobretado .sdg (SignedData + EnvelopedData hacia el SAT)

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: UI — componentes y vista Validar

**Files:**
- Create: `src/ui/components.ts`, `src/ui/validar-view.ts`
- Test: `tests/validar-view.test.ts`

**Interfaces:**
- Consumes: todo `src/crypto/efirma.ts`; `leerArchivo` de `src/util/files.ts`; `SellosError`.
- Produces:
  - `components.ts`: `selectorArchivo(etiqueta: string, onBytes: (bytes: Uint8Array, nombre: string) => void): HTMLElement`; `alerta(tipo: 'ok' | 'aviso' | 'error', mensaje: string): HTMLElement`; `campoTexto(etiqueta: string, opciones?: { tipo?: 'text' | 'password'; valor?: string }): { raiz: HTMLElement; input: HTMLInputElement }`.
  - `validar-view.ts`: `validar(entrada: { cer?: Uint8Array; key?: Uint8Array; contrasena?: string }): ResultadoValidacion` (lógica pura, exportada para tests) y `vistaValidar(): HTMLElement` (DOM). `ResultadoValidacion = { certificado?: DatosCertificado; vigencia?: EstadoVigencia; contrasenaCorrecta?: boolean; pareja?: boolean; error?: string }`.

- [ ] **Step 1: Escribir tests que fallan** (la lógica pura con environment node; el DOM con happy-dom)

`tests/validar-view.test.ts`:

```ts
// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { validar, vistaValidar } from '../src/ui/validar-view';

const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const sinteticaKey = new Uint8Array(readFileSync('tests/fixtures/sintetica.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md

describe('validar (lógica pura)', () => {
  it('con .cer reporta datos y vigencia', () => {
    const r = validar({ cer: fielCer });
    expect(r.certificado?.rfc).toMatch(/^[A-ZÑ&0-9]{12,13}$/);
    expect(r.vigencia).toMatch(/^(vigente|por_vencer|vencido)$/);
  });

  it('con .key y contraseña reporta si es correcta', () => {
    expect(validar({ key: fielKey, contrasena: CONTRASENA }).contrasenaCorrecta).toBe(true);
    expect(validar({ key: fielKey, contrasena: 'mala' }).contrasenaCorrecta).toBe(false);
  });

  it('con ambos reporta pareja', () => {
    expect(validar({ cer: fielCer, key: fielKey, contrasena: CONTRASENA }).pareja).toBe(true);
    expect(
      validar({ cer: fielCer, key: sinteticaKey, contrasena: 'sintetica123' }).pareja,
    ).toBe(false);
  });

  it('con bytes basura reporta error en español', () => {
    const r = validar({ cer: new Uint8Array([1, 2, 3]) });
    expect(r.error).toContain('certificado');
  });
});

describe('vistaValidar (DOM)', () => {
  it('renderiza los dos selectores de archivo y el campo de contraseña', () => {
    const vista = vistaValidar();
    expect(vista.querySelectorAll('input[type="file"]').length).toBe(2);
    expect(vista.querySelector('input[type="password"]')).not.toBeNull();
  });
});
```

- [ ] **Step 2: Verificar que fallan**

Run: `npm test tests/validar-view.test.ts` → Expected: FAIL (módulos inexistentes).

- [ ] **Step 3: Implementar src/ui/components.ts**

```ts
export function selectorArchivo(
  etiqueta: string,
  onBytes: (bytes: Uint8Array, nombre: string) => void,
): HTMLElement {
  const raiz = document.createElement('label');
  raiz.className = 'selector-archivo';
  const texto = document.createElement('span');
  texto.textContent = etiqueta;
  const input = document.createElement('input');
  input.type = 'file';
  input.addEventListener('change', async () => {
    const archivo = input.files?.[0];
    if (!archivo) return;
    onBytes(new Uint8Array(await archivo.arrayBuffer()), archivo.name);
  });
  raiz.append(texto, input);
  return raiz;
}

export function alerta(tipo: 'ok' | 'aviso' | 'error', mensaje: string): HTMLElement {
  const div = document.createElement('div');
  div.className = `alerta alerta-${tipo}`;
  div.setAttribute('role', tipo === 'error' ? 'alert' : 'status');
  div.textContent = mensaje;
  return div;
}

export function campoTexto(
  etiqueta: string,
  opciones: { tipo?: 'text' | 'password'; valor?: string } = {},
): { raiz: HTMLElement; input: HTMLInputElement } {
  const raiz = document.createElement('label');
  raiz.className = 'campo-texto';
  const texto = document.createElement('span');
  texto.textContent = etiqueta;
  const input = document.createElement('input');
  input.type = opciones.tipo ?? 'text';
  input.value = opciones.valor ?? '';
  raiz.append(texto, input);
  return { raiz, input };
}
```

- [ ] **Step 4: Implementar src/ui/validar-view.ts**

```ts
import {
  descifrarLlave,
  estadoVigencia,
  parsearCertificado,
  sonPareja,
  type DatosCertificado,
  type EstadoVigencia,
} from '../crypto/efirma';
import { ContrasenaIncorrectaError, SellosError } from '../util/errors';
import { alerta, campoTexto, selectorArchivo } from './components';

export interface ResultadoValidacion {
  certificado?: DatosCertificado;
  vigencia?: EstadoVigencia;
  contrasenaCorrecta?: boolean;
  pareja?: boolean;
  error?: string;
}

export function validar(entrada: {
  cer?: Uint8Array;
  key?: Uint8Array;
  contrasena?: string;
}): ResultadoValidacion {
  const r: ResultadoValidacion = {};
  try {
    if (entrada.cer) {
      r.certificado = parsearCertificado(entrada.cer);
      r.vigencia = estadoVigencia(r.certificado, new Date());
    }
    if (entrada.key && entrada.contrasena !== undefined) {
      try {
        const llave = descifrarLlave(entrada.key, entrada.contrasena);
        r.contrasenaCorrecta = true;
        if (r.certificado) r.pareja = sonPareja(r.certificado.certificado, llave);
      } catch (e) {
        if (e instanceof ContrasenaIncorrectaError) r.contrasenaCorrecta = false;
        else throw e;
      }
    }
  } catch (e) {
    r.error = e instanceof SellosError ? e.message : 'Ocurrió un error inesperado al procesar los archivos.';
  }
  return r;
}

const ETIQUETA_VIGENCIA: Record<EstadoVigencia, { tipo: 'ok' | 'aviso' | 'error'; texto: string }> = {
  vigente: { tipo: 'ok', texto: '🟢 Vigente' },
  por_vencer: { tipo: 'aviso', texto: '🟡 Por vencer (menos de 90 días)' },
  vencido: { tipo: 'error', texto: '🔴 Vencido' },
};

export function vistaValidar(): HTMLElement {
  const raiz = document.createElement('section');
  raiz.innerHTML = '<h2>Validar archivos</h2><p>Verifica un certificado .cer, una llave .key o que ambos sean pareja. Nada sale de tu navegador.</p>';

  let cer: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  const resultado = document.createElement('div');
  const contrasena = campoTexto('Contraseña de la llave', { tipo: 'password' });

  function pintar(): void {
    resultado.replaceChildren();
    const r = validar({ cer, key, contrasena: key ? contrasena.input.value : undefined });
    if (r.error) resultado.append(alerta('error', r.error));
    if (r.certificado) {
      const d = r.certificado;
      const datos = document.createElement('ul');
      datos.innerHTML = [
        `<li><strong>Tipo:</strong> ${d.tipo === 'FIEL' ? 'e.firma (FIEL)' : 'CSD (sello digital)'}</li>`,
        `<li><strong>RFC:</strong> ${d.rfc}</li>`,
        `<li><strong>Nombre/Razón social:</strong> ${d.razonSocial}</li>`,
        `<li><strong>No. de serie:</strong> ${d.numeroSerie}</li>`,
        `<li><strong>Vigencia:</strong> ${d.validoDesde.toLocaleDateString('es-MX')} – ${d.validoHasta.toLocaleDateString('es-MX')}</li>`,
      ].join('');
      resultado.append(datos);
      if (r.vigencia) {
        const v = ETIQUETA_VIGENCIA[r.vigencia];
        resultado.append(alerta(v.tipo, v.texto));
      }
    }
    if (r.contrasenaCorrecta !== undefined) {
      resultado.append(
        r.contrasenaCorrecta
          ? alerta('ok', 'La contraseña descifra la llave correctamente.')
          : alerta('error', 'La contraseña no descifra esta llave privada.'),
      );
    }
    if (r.pareja !== undefined) {
      resultado.append(
        r.pareja
          ? alerta('ok', 'El certificado y la llave son pareja.')
          : alerta('error', 'Esta llave privada no corresponde a este certificado.'),
      );
    }
  }

  raiz.append(
    selectorArchivo('Certificado (.cer)', (bytes) => { cer = bytes; pintar(); }),
    selectorArchivo('Llave privada (.key)', (bytes) => { key = bytes; pintar(); }),
    contrasena.raiz,
  );
  contrasena.input.addEventListener('input', () => { if (key) pintar(); });
  raiz.append(resultado);
  return raiz;
}
```

- [ ] **Step 5: Verificar que pasan**

Run: `npm test tests/validar-view.test.ts` → Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ui/components.ts src/ui/validar-view.ts tests/validar-view.test.ts
git commit -m "feat: componentes de UI y vista de validacion de archivos

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 11: UI — vista Generar CSD y main.ts

**Files:**
- Create: `src/ui/generar-view.ts`
- Modify: `src/main.ts`, `src/style.css`
- Test: `tests/generar-view.test.ts`

**Interfaces:**
- Consumes: `cargarEfirma`, `estadoVigencia` (T5); `generarParCSD` (T6); `cifrarLlaveCSD` (T7); `generarCSR` (T8); `generarSDG` (T9); `nombreBase`, `descargarArchivo` (T4); componentes (T10).
- Produces:
  - `generar-view.ts`: `validarFormulario(f: { rfc: string; razonSocial: string; sucursal: string; contrasena: string; confirmacion: string }): string | null` (mensaje de error o null); `ejecutarGeneracion(entrada: { cer: Uint8Array; key: Uint8Array; contrasenaEfirma: string; rfc: string; razonSocial: string; sucursal: string; contrasenaCsd: string }): Promise<{ nombre: string; keyDer: Uint8Array; sdgDer: Uint8Array }>`; `vistaGenerar(): HTMLElement`.
  - `main.ts`: navegación entre las dos vistas + botón "Limpiar todo" (recarga la página, descartando todo estado en memoria).

- [ ] **Step 1: Escribir tests que fallan**

`tests/generar-view.test.ts`:

```ts
// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ejecutarGeneracion, validarFormulario, vistaGenerar } from '../src/ui/generar-view';
import { descifrarLlave } from '../src/crypto/efirma';

const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md

describe('validarFormulario', () => {
  const base = {
    rfc: 'EKU9003173C9',
    razonSocial: 'ESCUELA KEMPER URGATE',
    sucursal: 'Matriz',
    contrasena: 'Secreta123',
    confirmacion: 'Secreta123',
  };

  it('acepta un formulario completo', () => {
    expect(validarFormulario(base)).toBeNull();
  });

  it('rechaza contraseña corta', () => {
    expect(validarFormulario({ ...base, contrasena: 'corta', confirmacion: 'corta' })).toContain('8');
  });

  it('rechaza confirmación distinta', () => {
    expect(validarFormulario({ ...base, confirmacion: 'Otra12345' })).toContain('coinciden');
  });

  it('rechaza campos vacíos', () => {
    expect(validarFormulario({ ...base, sucursal: '  ' })).not.toBeNull();
  });
});

describe('ejecutarGeneracion (flujo completo con fixtures)', () => {
  it('produce .key descifrable y .sdg no vacío con nombre correcto', async () => {
    const r = await ejecutarGeneracion({
      cer: fielCer,
      key: fielKey,
      contrasenaEfirma: CONTRASENA,
      rfc: 'EKU9003173C9',
      razonSocial: 'ESCUELA KEMPER URGATE',
      sucursal: 'Matriz',
      contrasenaCsd: 'Secreta123',
    });
    expect(r.nombre).toMatch(/^CSD_Matriz_EKU9003173C9_\d{8}$/);
    expect(r.sdgDer.length).toBeGreaterThan(500);
    const llave = descifrarLlave(r.keyDer, 'Secreta123');
    expect(llave.n.bitLength()).toBe(2048);
  }, 60_000);
});

describe('vistaGenerar (DOM)', () => {
  it('renderiza selectores de e.firma y campos del formulario', () => {
    const vista = vistaGenerar();
    expect(vista.querySelectorAll('input[type="file"]').length).toBe(2);
    expect(vista.querySelectorAll('input[type="password"]').length).toBe(3); // e.firma + CSD + confirmación
    expect(vista.querySelector('button')).not.toBeNull();
  });
});
```

- [ ] **Step 2: Verificar que fallan**

Run: `npm test tests/generar-view.test.ts` → Expected: FAIL (módulo inexistente).

- [ ] **Step 3: Implementar src/ui/generar-view.ts**

```ts
import { cargarEfirma, estadoVigencia, parsearCertificado } from '../crypto/efirma';
import { generarParCSD } from '../crypto/keygen';
import { cifrarLlaveCSD } from '../crypto/keyfile';
import { generarCSR } from '../crypto/csr';
import { generarSDG } from '../crypto/sdg';
import { descargarArchivo, nombreBase } from '../util/files';
import { SellosError } from '../util/errors';
import { alerta, campoTexto, selectorArchivo } from './components';

export interface FormularioCSD {
  rfc: string;
  razonSocial: string;
  sucursal: string;
  contrasena: string;
  confirmacion: string;
}

export function validarFormulario(f: FormularioCSD): string | null {
  if (!f.rfc.trim()) return 'Escribe el RFC.';
  if (!/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/i.test(f.rfc.trim())) return 'El RFC no tiene un formato válido.';
  if (!f.razonSocial.trim()) return 'Escribe el nombre o razón social.';
  if (!f.sucursal.trim()) return 'Escribe el nombre de la sucursal (ej. "Matriz").';
  if (f.contrasena.length < 8) return 'La contraseña del CSD debe tener al menos 8 caracteres.';
  if (f.contrasena !== f.confirmacion) return 'La contraseña y su confirmación no coinciden.';
  return null;
}

export interface EntradaGeneracion {
  cer: Uint8Array;
  key: Uint8Array;
  contrasenaEfirma: string;
  rfc: string;
  razonSocial: string;
  sucursal: string;
  contrasenaCsd: string;
}

export async function ejecutarGeneracion(entrada: EntradaGeneracion): Promise<{
  nombre: string;
  keyDer: Uint8Array;
  sdgDer: Uint8Array;
}> {
  const efirma = cargarEfirma(entrada.cer, entrada.key, entrada.contrasenaEfirma);
  const par = await generarParCSD();
  const csr = generarCSR({
    ...par,
    rfc: entrada.rfc,
    razonSocial: entrada.razonSocial,
    sucursal: entrada.sucursal,
  });
  const sdgDer = generarSDG(csr, efirma);
  const keyDer = cifrarLlaveCSD(par.privada, entrada.contrasenaCsd);
  return { nombre: nombreBase(entrada.sucursal, entrada.rfc, new Date()), keyDer, sdgDer };
}

export function vistaGenerar(): HTMLElement {
  const raiz = document.createElement('section');
  raiz.innerHTML =
    '<h2>Generar CSD</h2><p>Carga tu e.firma, captura los datos y descarga la llave (.key) y la solicitud (.sdg) para subirla a CertiSAT Web. Todo se procesa en tu navegador.</p>';

  let cer: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  const avisos = document.createElement('div');
  const contrasenaEfirma = campoTexto('Contraseña de tu e.firma', { tipo: 'password' });
  const rfc = campoTexto('RFC');
  const razonSocial = campoTexto('Nombre o razón social');
  const sucursal = campoTexto('Nombre de la sucursal', { valor: 'Matriz' });
  const contrasenaCsd = campoTexto('Contraseña nueva para el CSD (mínimo 8)', { tipo: 'password' });
  const confirmacion = campoTexto('Confirma la contraseña del CSD', { tipo: 'password' });

  function precargarDesdeCer(): void {
    if (!cer) return;
    avisos.replaceChildren();
    try {
      // Solo parsea el .cer para pre-llenar; la validación completa ocurre al generar.
      const datos = parsearCertificado(cer);
      rfc.input.value = rfc.input.value || datos.rfc;
      razonSocial.input.value = razonSocial.input.value || datos.razonSocial;
      const vigencia = estadoVigencia(datos, new Date());
      if (vigencia === 'vencido')
        avisos.append(alerta('aviso', 'Tu e.firma aparece vencida; el SAT rechazará la solicitud. Puedes continuar bajo tu propio riesgo.'));
    } catch (e) {
      avisos.append(alerta('error', e instanceof SellosError ? e.message : 'No se pudo leer el certificado.'));
    }
  }

  const boton = document.createElement('button');
  boton.textContent = 'Generar y descargar';
  const resultado = document.createElement('div');

  boton.addEventListener('click', async () => {
    resultado.replaceChildren();
    const f = {
      rfc: rfc.input.value,
      razonSocial: razonSocial.input.value,
      sucursal: sucursal.input.value,
      contrasena: contrasenaCsd.input.value,
      confirmacion: confirmacion.input.value,
    };
    const errorForm = validarFormulario(f);
    if (!cer || !key) {
      resultado.append(alerta('error', 'Carga el .cer y el .key de tu e.firma.'));
      return;
    }
    if (errorForm) {
      resultado.append(alerta('error', errorForm));
      return;
    }
    boton.disabled = true;
    boton.textContent = 'Generando…';
    try {
      const r = await ejecutarGeneracion({
        cer,
        key,
        contrasenaEfirma: contrasenaEfirma.input.value,
        rfc: f.rfc,
        razonSocial: f.razonSocial,
        sucursal: f.sucursal,
        contrasenaCsd: f.contrasena,
      });
      descargarArchivo(`${r.nombre}.key`, r.keyDer);
      descargarArchivo(`${r.nombre}.sdg`, r.sdgDer);
      resultado.append(
        alerta('ok', `Listos: ${r.nombre}.key y ${r.nombre}.sdg.`),
        alerta(
          'aviso',
          'Siguiente paso: entra a CertiSAT Web con tu e.firma, elige "Solicitud de certificado de sello digital" y sube el archivo .sdg. Guarda el .key y su contraseña: los necesitará tu sistema de facturación.',
        ),
      );
    } catch (e) {
      resultado.append(
        alerta('error', e instanceof SellosError ? e.message : 'Ocurrió un error inesperado al generar.'),
      );
    } finally {
      boton.disabled = false;
      boton.textContent = 'Generar y descargar';
    }
  });

  raiz.append(
    selectorArchivo('Certificado de tu e.firma (.cer)', (bytes) => { cer = bytes; precargarDesdeCer(); }),
    selectorArchivo('Llave privada de tu e.firma (.key)', (bytes) => { key = bytes; }),
    contrasenaEfirma.raiz,
    avisos,
    rfc.raiz,
    razonSocial.raiz,
    sucursal.raiz,
    contrasenaCsd.raiz,
    confirmacion.raiz,
    boton,
    resultado,
  );
  return raiz;
}
```

- [ ] **Step 4: Reescribir src/main.ts con navegación y "Limpiar todo"**

```ts
import './style.css';
import { vistaGenerar } from './ui/generar-view';
import { vistaValidar } from './ui/validar-view';

const app = document.querySelector<HTMLDivElement>('#app')!;

function render(vista: 'generar' | 'validar'): void {
  app.replaceChildren();

  const encabezado = document.createElement('header');
  encabezado.innerHTML = '<h1>Sellos — Generador de CSD</h1>';

  const nav = document.createElement('nav');
  const btnGenerar = document.createElement('button');
  btnGenerar.textContent = 'Generar CSD';
  btnGenerar.addEventListener('click', () => render('generar'));
  const btnValidar = document.createElement('button');
  btnValidar.textContent = 'Validar archivos';
  btnValidar.addEventListener('click', () => render('validar'));
  const btnLimpiar = document.createElement('button');
  btnLimpiar.textContent = 'Limpiar todo';
  btnLimpiar.title = 'Descarta todo lo cargado (recarga la página)';
  btnLimpiar.addEventListener('click', () => location.reload());
  nav.append(btnGenerar, btnValidar, btnLimpiar);

  app.append(encabezado, nav, vista === 'generar' ? vistaGenerar() : vistaValidar());
}

render('generar');
```

- [ ] **Step 5: Estilos mínimos en src/style.css** (agregar debajo de lo existente)

```css
nav { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
.selector-archivo, .campo-texto { display: block; margin: 0.75rem 0; }
.selector-archivo span, .campo-texto span { display: block; font-weight: 600; margin-bottom: 0.25rem; }
.campo-texto input { width: 100%; max-width: 24rem; padding: 0.4rem; }
button { padding: 0.5rem 1rem; cursor: pointer; }
.alerta { padding: 0.6rem 0.8rem; border-radius: 6px; margin: 0.5rem 0; }
.alerta-ok { background: #e6f6e6; color: #14532d; }
.alerta-aviso { background: #fef9e7; color: #713f12; }
.alerta-error { background: #fdecea; color: #7f1d1d; }
@media (prefers-color-scheme: dark) {
  .alerta-ok { background: #14532d; color: #e6f6e6; }
  .alerta-aviso { background: #713f12; color: #fef9e7; }
  .alerta-error { background: #7f1d1d; color: #fdecea; }
}
```

- [ ] **Step 6: Verificar que todos los tests pasan y el build sale**

Run: `npm test` → Expected: PASS todas las suites.
Run: `npm run build` → Expected: sin errores.

- [ ] **Step 7: Commit**

```bash
git add src/ui/generar-view.ts src/main.ts src/style.css tests/generar-view.test.ts
git commit -m "feat: vista de generacion de CSD, navegacion y limpiar todo

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 12: Verificación final, README y checklist manual

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces: app verificada de punta a punta en navegador real; README con instrucciones de uso, seguridad y estado del formato.

- [ ] **Step 1: Suite completa y build**

Run: `npm test && npm run build`
Expected: todo PASS; `dist/index.html` existe y es autocontenido: `grep -c "<script src" dist/index.html` → `0` (no hay scripts externos).

- [ ] **Step 2: Verificación manual en navegador**

Abrir `dist/index.html` directamente en el navegador (doble click / `open dist/index.html`) y verificar con las fixtures de `tests/fixtures/`:

1. Vista Validar: cargar `fiel.cer` → muestra RFC, tipo e.firma, serie y semáforo; contraseña mala → mensaje de error; `fiel.key` + contraseña buena → "pareja".
2. Vista Generar: cargar fixtures, llenar formulario, contraseña corta → error claro; flujo completo → descarga `.key` y `.sdg`.
3. DevTools → pestaña Network durante todo lo anterior: **cero requests** (solo el documento local).
4. DevTools → Console: sin contraseñas ni material sensible impreso.

Registrar el resultado de los 4 puntos en el mensaje de commit o en el reporte de la tarea. Si algo falla, es un bug: volver a la tarea correspondiente antes de continuar.

- [ ] **Step 3: Actualizar README.md**

Reescribirlo con: qué hace la app y qué la hace segura (procesamiento 100% local, CSP sin red, sin almacenamiento persistente); el modelo de memoria (los archivos y contraseñas cargados viven solo en memoria de la pestaña y se descartan con "Limpiar todo" o al cerrarla — limpieza best-effort, como promete el spec); requisitos (Node ≥ 20); uso (`npm install`, `npm run build`, abrir `dist/index.html`); desarrollo (`npm run dev`, `npm test`); estado del formato .sdg (enlazar `docs/reference/sdg-format.md` y aclarar si sigue en hipótesis hasta validarse contra CertiSAT); y advertencia de que las fixtures son material de prueba público, nunca llaves reales.

- [ ] **Step 4: Commit final**

```bash
git add README.md
git commit -m "docs: README con uso, garantias de seguridad y estado del formato

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Validación E2E pendiente (usuario)

Fuera del alcance de este plan (requiere la e.firma real de Juan Pablo): generar una solicitud real, subir el `.sdg` a CertiSAT Web y confirmar que el SAT emite el certificado. Hasta entonces, el formato .sdg conserva el nivel de confianza que haya documentado la Tarea 3. Si CertiSAT rechaza el archivo, la corrección se acota a `src/crypto/sdg.ts` / `src/crypto/csr.ts` + `docs/reference/sdg-format.md`.
