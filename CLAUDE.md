# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Qué es

Generador de solicitudes de CSD del SAT (reemplazo del Certifica deprecado): corre 100% en el navegador, sin red. Desde una e.firma (.cer/.key/contraseña) produce un `.key` (PKCS#8 PBES2) y un `.sdg` (CMS SignedData sobre un ZIP con el CSR) para CertiSAT Web, más una vista de validación de archivos.

## Comandos

```bash
npm test                              # suite completa (vitest run)
npx vitest run tests/sdg.test.ts      # un solo archivo de pruebas
npx vitest run -t "nombre del test"   # un solo test por nombre
npm run test:watch
npx tsc --noEmit                      # typecheck (también corre dentro de build)
npm run build                         # tsc + vite → dist/index.html ÚNICO autocontenido
npm run dev                           # dev server (respeta $PORT si está definida)
tests/fixtures/generate.sh            # regenera las fixtures sintéticas (OpenSSL)
```

Node ≥ 20 (los tests de keygen usan `crypto.subtle` global). El openssl del sistema es LibreSSL; para cross-checks usa `$(brew --prefix openssl@3)/bin/openssl`.

## Autoridad del formato

**`docs/reference/sdg-format.md` manda.** Se derivó descompilando el Certifica oficial y descartó las hipótesis originales del plan (no hay EnvelopedData; todo es SHA-1; el `.key` sale en PBES2). Los módulos de `src/crypto/` citan sus secciones (§1.x…§4.x) en comentarios: al cambiar formato, actualiza el doc y **cita solo texto que el doc realmente contenga** (una revisión encontró citas inventadas; es defecto reportable). El plan (`docs/superpowers/plans/…`) quedó superado en las tareas 7–9; el spec y el README lo explican.

Validación E2E contra CertiSAT **pendiente** (riesgos residuales en README: STORE vs DEFLATE, DER vs BER, Ñ). Si CertiSAT rechaza un `.sdg`, la corrección se acota a `src/crypto/sdg.ts`/`csr.ts` + el doc.

## Arquitectura

Regla de capas: `src/crypto/*` y `src/util/*` son puros (sin DOM, testeables aislados); `src/ui/*` solo orquesta; `src/main.ts` navega entre las dos vistas.

Pipeline de generación (`ejecutarGeneracion` en `generar-view.ts`, que normaliza con trim antes de todo):
`efirma.cargarEfirma` → `keygen.generarParCSD` (WebCrypto → import a forge) → `csr.generarCSR` → `sdg.generarSDG` → `keyfile.cifrarLlaveCSD`.

Detalles no obvios que cruzan módulos:

- **CSR (§1)**: subject de exactamente 4 RDNs en orden (`2.5.4.45`, `2.5.4.5`, CN-o-O según RFC de 13/12 chars, OU); los valores de `2.5.4.45`/`2.5.4.5` se copian **verbatim** del certificado de la e.firma (espacios incluidos); atributo `challengePassword` = doble SHA-1/Base64 del x500UniqueIdentifier (NO de la contraseña; `contrasenaCsd` en `EntradaCSR` existe pero no se usa, está documentado).
- **.sdg (§3)**: `SignedData` con contenido adjunto = ZIP STORE hecho a mano (`zip.ts`, sin dependencias); el orden del array `authenticatedAttributes` ES el orden en el wire (forge no ordena): contentType, signingTime, messageDigest. El SignerInfo construye issuer/serial a mano porque `addSigner({certificate})` de forge doble-codifica UTF-8 en issuers con acentos.
- **.key salida (§4)**: PBES2 construido a mano en ASN.1 — la opción `'3des'` de `forge.pki.encryptPrivateKeyInfo` produce PKCS#12 PBE, que es el formato EQUIVOCADO.
- **forge y encodings**: bytes ↔ binary strings vía `util/bytes.ts` (`aBinario`/`aBytes`); contraseñas SIEMPRE por `forge.util.encodeUtf8` (cifrado Y descifrado); atributos UTF8String de certificados llegan crudos — decodifica solo cuando `valueTagClass === forge.asn1.Type.UTF8` (un T61String decodificado se corrompe); el contenido de un `SignedData` debe entrar como buffer forge de binary string, nunca como string JS.
- **CSP**: se inyecta SOLO en build (`inyectarCspEnHtml` en `vite.config.ts`); `index.html` debe conservar el marcador `<!--CSP-->` o el build truena a propósito. El dev server no lleva CSP (HMR).

## Reglas del proyecto

- Texto de UI y mensajes de error en español; identificadores en español sin acentos.
- Strings derivados de certificados JAMÁS por `innerHTML` (solo `textContent`; el `.cer` es entrada no confiable y la CSP lleva `script-src 'unsafe-inline'`). Hay test de regresión XSS.
- Nunca loggear llaves/contraseñas; sin `localStorage`/IndexedDB/cookies.
- Única dependencia de runtime: `node-forge@^1.3.1`. No agregues otras sin decisión explícita.
- Tests: entorno node por default; los de UI declaran `// @vitest-environment happy-dom` por archivo. Errores tipados de `util/errors.ts` según el caso (`ContrasenaIncorrectaError` solo para contraseña realmente incorrecta — forge marca fallos estructurales con `'errors' in e`).
- Fixtures (`tests/fixtures/`): material de prueba PÚBLICO del SAT (RFC `AAA010101AAA`, contraseña `12345678a`, ver su README) o sintético. Jamás llaves reales.
