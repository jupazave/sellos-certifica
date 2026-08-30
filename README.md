# Sellos — Generador de CSD

Reemplazo de **Certifica**, la herramienta (ya deprecada) del SAT para generar la
Solicitud de Certificado de Sello Digital (CSD) a partir de tu e.firma (FIEL). Corre
enteramente en el navegador: sin backend, sin servidor propio y sin dependencias de red.

## Qué hace

- **Validar archivos**: verifica un `.cer`, una `.key` (con su contraseña) o que ambos
  formen pareja. Muestra RFC, tipo de certificado (e.firma o CSD), número de serie y un
  semáforo de vigencia.
- **Generar CSD**: a partir del `.cer` + `.key` de tu e.firma y los datos de la sucursal,
  genera un par de llaves RSA-2048 nuevo y descarga:
  - **`<nombre>.key`** — la llave privada del CSD, cifrada en el mismo formato que produce
    Certifica (PKCS#8 `EncryptedPrivateKeyInfo`, PBES2 + PBKDF2-HMAC-SHA1 + 3DES-EDE-CBC).
  - **`<nombre>.sdg`** — la solicitud lista para subir a **CertiSAT Web**: el CSR envuelto
    en un `SignedData` CMS/PKCS#7, firmado con tu e.firma.

## Por qué es segura

- **100% local**: no hay servidor ni backend propio. Toda la criptografía (parseo de
  certificados, generación de llaves, cifrado, firma, ensobretado) corre en tu navegador
  con WebCrypto y `node-forge`.
- **CSP sin red**: el build final trae una `Content-Security-Policy`
  (`default-src 'none'; connect-src 'none'; ...`) que bloquea cualquier request saliente —
  ni siquiera un `fetch`/XHR podría salir del documento, aunque el código lo intentara.
- **Sin almacenamiento persistente**: no se usa `localStorage`, `IndexedDB`, cookies ni
  ningún otro mecanismo de persistencia del navegador. Nada de lo que cargas o generas
  toca disco salvo los archivos que tú decides descargar.
- **Un solo archivo**: `dist/index.html` es autocontenido (JS y CSS inlineados con
  `vite-plugin-singlefile`, cero `<script src>` externos) — puedes inspeccionarlo,
  copiarlo o ejecutarlo desde cualquier lugar sin `node_modules` ni conexión a internet.

## Modelo de memoria

Los archivos (`.cer`/`.key`) y las contraseñas que cargas viven **solo en memoria de la
pestaña** (variables de JavaScript); nunca se escriben a disco ni a ningún almacenamiento
del navegador. Se descartan:

- al hacer clic en **"Limpiar todo"** (recarga la página, lo que destruye todo el estado
  en memoria), o
- al cerrar la pestaña.

Esta limpieza es **best-effort**, como establece el spec del proyecto: JavaScript no
controla cuándo el recolector de basura libera esa memoria ni puede forzar al sistema
operativo a sobrescribirla. Para el nivel de amenaza de esta herramienta (uso personal, en
tu propia máquina) es la misma garantía que ofrece cualquier app de escritorio normal — no
es un borrado criptográfico seguro tipo `shred`. Evita dejar la pestaña abierta con datos
cargados en una máquina compartida.

## Requisitos

- Node.js **≥ 20**.

## Uso

```bash
npm install
npm run build
open dist/index.html   # o doble clic desde el explorador de archivos
```

`dist/index.html` es el único artefacto que necesitas para usar la app: es autocontenido
y no requiere servidor. Si prefieres servirlo localmente en vez de abrirlo con `file://`,
`npm run preview` levanta un servidor estático sobre `dist/`.

## Desarrollo

```bash
npm run dev         # servidor de desarrollo (Vite, con recarga en caliente)
npm test            # corre la suite de pruebas (vitest)
npm run test:watch  # pruebas en modo watch
```

## Estado del formato `.sdg`

El formato `.sdg` (y el detalle exacto del CSR: subject, digest, ensobretado) **no está
documentado públicamente por el SAT**. Lo que implementa esta app se derivó de descompilar
`Certifica` —la propia aplicación oficial del SAT— y se corroboró contra certificados CSD
reales emitidos por el SAT. El detalle completo, con nivel de confianza por afirmación
(`confirmado` vs. `hipótesis`), está en
[`docs/reference/sdg-format.md`](docs/reference/sdg-format.md).

Quedan tres riesgos residuales, pendientes de validar contra CertiSAT Web (ver la
siguiente sección):

1. **DER vs. BER**: Certifica emite el `SignedData` en BER con longitudes indefinidas;
   esta app emite DER (un subconjunto válido de BER/CMS). Se espera que CertiSAT lo
   acepte, pero no está confirmado.
2. **STORE vs. DEFLATE en el ZIP interno**: el `.sdg` empaqueta el `.req` (CSR) dentro de
   un ZIP. Certifica siempre comprime con DEFLATE (el default de
   `java.util.zip.ZipOutputStream`); esta app usa STORE (sin comprimir) a propósito, para
   no sumar una dependencia de compresión solo para empaquetar archivos de unos KB. STORE
   es un método estándar de ZIP, pero no se confirmó que el parser de CertiSAT lo acepte
   igual que DEFLATE.
3. **La `Ñ`/`ñ` se preserva sin transliterar** en el nombre del `.req` dentro del ZIP.
   Certifica normaliza las vocales acentuadas en ese nombre (`á→a`, etc.); el mapa de
   transliteración documentado no incluye la `Ñ`, así que aquí se dejó tal cual — es una
   decisión razonada, pero no confirmada contra el bytecode de Certifica para ese caso
   específico.

Si CertiSAT rechaza el archivo, la corrección se acota a `src/crypto/sdg.ts` /
`src/crypto/csr.ts` + `docs/reference/sdg-format.md`.

## Prueba end-to-end pendiente (usuario)

Lo que no se puede verificar sin una e.firma real, ni sin subir el resultado al SAT, queda
fuera del alcance de este repositorio:

1. `npm run build`
2. Abre `dist/index.html` en tu navegador.
3. Usa tu e.firma real **localmente** (nunca la subas a ningún sitio) para generar un CSD:
   carga tu `.cer`/`.key`, captura RFC, razón social, sucursal y una contraseña nueva para
   el CSD.
4. Entra a **CertiSAT Web** con tu e.firma, elige "Solicitud de certificado de sello
   digital" y sube el `.sdg` generado.
5. Confirma que el SAT acepta el trámite y emite el certificado. Guarda el `.key` y su
   contraseña — los necesitará tu sistema de facturación junto con el `.cer` que emita el
   SAT.

Si el SAT **rechaza** el archivo, lo más útil que puedes reportar es el mensaje o código
de error exacto de CertiSAT: eso indica cuál de los tres riesgos residuales de la sección
anterior (u otro detalle no anticipado) hay que corregir.

### Qué ya está cubierto sin tu e.firma

La suite de pruebas (`npm test`, 94 pruebas) ejercita el flujo completo de generación
(`ejecutarGeneracion`) con las fixtures públicas del SAT — parseo de e.firma, generación
de llaves, CSR, cifrado del `.key` y ensobretado del `.sdg` — con los mismos handlers
reales que usa la UI (vitest + happy-dom, sin mocks de la criptografía). También se
verificó manualmente el build final (`dist/index.html`) en un navegador real: ambas
vistas renderizan y navegan correctamente, los errores de validación se muestran en
español, no hay ningún request de red (coherente con la CSP) y no se imprime ninguna
contraseña ni material sensible en la consola.

Lo que esas verificaciones **no** cubren, y por tanto queda para tu prueba manual, es:
(a) la interacción real con el selector de archivos del navegador (elegir un `.cer`/`.key`
desde el diálogo del sistema operativo o arrastrarlo) y (b) el veredicto real de
CertiSAT — los puntos 3 y 4 de la lista de arriba.

## Fixtures de prueba

`tests/fixtures/` contiene material de prueba **público** del SAT (vendoreado de
[`phpcfdi/credentials`](https://github.com/phpcfdi/credentials), RFC de pruebas
`AAA010101AAA`) más un par sintético generado localmente con OpenSSL. **Nunca hay llaves
reales de usuarios en este directorio.** Detalle completo, incluida la procedencia y las
contraseñas de cada fixture, en [`tests/fixtures/README.md`](tests/fixtures/README.md).
