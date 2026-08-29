# Diseño: Sellos — Generador de CSD (Sellos para Facturar)

- **Fecha:** 2026-08-29
- **Estado:** Aprobado por Juan Pablo
- **Camino:** Arquitectónico (proyecto nuevo desde cero)

## Propósito

Reemplazar la herramienta deprecada del SAT (Certifica) para generar Certificados
de Sello Digital (CSD) a partir de una e.firma (FIEL). La app corre 100% en el
navegador, sin dependencias de internet en runtime: las llaves privadas nunca
salen de la máquina del usuario.

## Alcance v1

1. **Generar solicitud de CSD**
   - Entrada: e.firma del usuario (.cer, .key, contraseña) + datos fiscales
     (RFC, razón social, nombre de sucursal) + contraseña nueva para el CSD.
   - Salida: archivo `.key` (llave privada del CSD, cifrada con la contraseña
     nueva) y archivo `.sdg` (requerimiento ensobretado) listos para subir a
     CertiSAT Web.
2. **Validador de archivos**
   - Cargar un `.cer`: mostrar RFC, razón social, tipo (FIEL o CSD), número de
     serie y vigencia con semáforo (vigente / por vencer / vencido).
   - Cargar `.key` + contraseña: verificar que la contraseña descifra la llave.
   - Con ambos: verificar que `.cer` y `.key` son pareja (mismo módulo público).

## No-alcance v1 (YAGNI)

- Renovación de e.firma (requerimiento `.ren`).
- PWA, hosting público o CI de publicación — la app es de **uso local**
  (clonar, `npm run build`, abrir).
- Envío automático al SAT: el usuario sube el `.sdg` a CertiSAT Web manualmente.
- Generación por lote de varias sucursales en una sesión (una solicitud a la vez).
- Soporte de e.firma de personas morales vs. físicas más allá de lo que el
  propio certificado indique (no hay ramas de flujo distintas).

## Restricciones

- **Cero red en runtime.** `index.html` declara una CSP estricta
  (`default-src 'self'; connect-src 'none'` y equivalentes) que bloquea toda
  conexión saliente. Sin analytics, sin CDNs, sin fuentes externas.
- **Todo en memoria.** Nada de llaves o contraseñas en localStorage, cookies o
  IndexedDB. Botón "limpiar todo" que resetea el estado.
- **UI en español.**

## Stack

- **Vite + TypeScript, sin framework.** App estática; la UI es un
  formulario/wizard y no necesita más.
- **node-forge** como motor criptográfico único: X.509, descifrado PKCS#8 con
  PBE legacy del SAT, PKCS#10, PKCS#7 (SignedData/EnvelopedData), cifrado de la
  llave de salida.
- **WebCrypto** únicamente para generar la llave RSA-2048 (nativo y rápido);
  se exporta PKCS#8 y se importa a forge para el resto del pipeline.
- **Vitest** para pruebas.

Justificación de forge sobre alternativas: WebCrypto no soporta los algoritmos
PBE legacy (SHA1/3DES) con los que el SAT cifra los `.key`, y PKI.js obligaría a
implementar ese descifrado y el ensobretado 3DES a mano. forge está en modo
mantenimiento, pero es la librería pura-JS más probada para estos formatos y la
app no tiene superficie de red que lo vuelva riesgoso.

## Arquitectura y módulos

```
sellos/
├── index.html                # CSP estricta, shell de la app
├── package.json / tsconfig.json / vite.config.ts
├── src/
│   ├── main.ts               # bootstrap, navegación entre las dos vistas
│   ├── ui/
│   │   ├── generar-view.ts   # wizard de generación de CSD
│   │   ├── validar-view.ts   # validador de .cer/.key
│   │   └── components.ts     # dropzone, alertas, botones de descarga
│   ├── crypto/
│   │   ├── efirma.ts         # parsear .cer/.key, descifrar, verificar pareja,
│   │   │                     #   clasificar FIEL vs CSD, extraer RFC/razón social
│   │   ├── keygen.ts         # RSA-2048 vía WebCrypto → import a forge
│   │   ├── csr.ts            # PKCS#10 con el subject que espera el SAT
│   │   ├── sdg.ts            # ensobretado PKCS#7 → bytes del .sdg
│   │   ├── keyfile.ts        # cifrar la llave nueva en formato .key SAT
│   │   └── sat-cert.ts       # certificado público del SAT embebido (para el
│   │                         #   EnvelopedData del .sdg)
│   └── util/
│       ├── files.ts          # File → ArrayBuffer, descarga de Blobs, nombres
│       └── errors.ts         # jerarquía de errores tipados, mensajes en español
├── tests/
│   ├── fixtures/             # e.firma de pruebas pública del SAT + sintéticas
│   │   └── generate.sh       # script OpenSSL para regenerar las sintéticas
│   └── *.test.ts             # unit tests por módulo cripto
└── docs/superpowers/specs/   # este documento
```

Regla de diseño: los módulos de `crypto/` y `util/` son puros (sin DOM, sin
estado global); reciben bytes/strings y devuelven bytes/objetos tipados. La UI
solo orquesta. Esto hace cada unidad testeable de forma aislada y permite
corregir el formato del `.sdg` sin tocar nada más.

## Flujo de datos — Generar CSD

1. Usuario carga `.cer` y `.key` de su e.firma y escribe su contraseña.
   `efirma.ts` descifra la llave, verifica que ambos son pareja, que el
   certificado es una FIEL (no un CSD) y su vigencia. Vencida → advertencia
   explícita pero se permite continuar (el SAT rechazará; el usuario decide).
2. Formulario de datos: RFC (pre-llenado desde el `.cer`, editable), razón
   social (pre-llenada), nombre de sucursal, contraseña nueva del CSD con
   confirmación y requisitos mínimos (8+ caracteres, como pedía Certifica).
3. `keygen.ts` genera el par RSA-2048.
4. `csr.ts` arma el CSR PKCS#10 firmado con la llave nueva (SHA-256).
5. `sdg.ts` firma el CSR con la e.firma y lo ensobreta hacia el certificado del
   SAT (`sat-cert.ts`) → bytes `.sdg`.
6. `keyfile.ts` cifra la llave nueva con la contraseña elegida en el mismo
   formato PKCS#8 cifrado que producía Certifica, para que la acepten los
   sistemas de facturación/PACs.
7. Descarga de `CSD_<sucursal>_<RFC>_<AAAAMMDD>.key` y `.sdg`, con instrucciones
   en pantalla del paso siguiente en CertiSAT Web.

## Flujo de datos — Validar

Cada verificación es independiente y muestra resultado en cuanto tiene los
insumos: `.cer` solo → datos y vigencia; `.key` + contraseña → contraseña
correcta o no; `.cer` + `.key` → pareja o no. Reusa `efirma.ts` completo.

## Manejo de errores

`errors.ts` define errores tipados, cada uno con mensaje en español accionable:

- `ArchivoInvalidoError` — "El archivo no parece ser un .cer/.key del SAT (DER)."
- `ContrasenaIncorrectaError` — "La contraseña no descifra esta llave privada."
- `ParejaInvalidaError` — "Esta llave no corresponde a este certificado."
- `TipoCertificadoError` — "Este certificado es un CSD; para generar sellos
  necesitas tu e.firma (FIEL)."
- `VigenciaError` (advertencia, no bloqueo) — certificado vencido/por vencer.

La UI mapea cada error a una alerta junto al campo correspondiente. Errores no
anticipados muestran mensaje genérico sin volcar detalles técnicos sensibles.
Nunca se loggean contraseñas, llaves ni buffers intermedios; las referencias a
material sensible se sobreescriben/liberan al terminar cada operación (best
effort en JS, documentado como tal).

## Testing

- **Unit (Vitest)** por módulo de `crypto/`:
  - `efirma`: parsea la e.firma de pruebas pública del SAT (RFC `EKU9003173C9`,
    vendoreada en `tests/fixtures/`), rechaza contraseña incorrecta, detecta
    pareja/no-pareja, clasifica FIEL vs CSD.
  - `keygen` + `keyfile`: round-trip — generar, cifrar con contraseña,
    descifrar con forge y con OpenSSL (fixture de referencia).
  - `csr`: el CSR generado se re-parsea con forge y valida firma y subject.
  - `sdg`: estructura ASN.1 verificable (SignedData/EnvelopedData bien
    formados, firmante correcto, destinatario = cert SAT).
- **Fixtures sintéticas** generadas con OpenSSL (`tests/fixtures/generate.sh`)
  imitando el cifrado legacy del SAT, committeadas junto con el script que las
  regenera.
- **Validación E2E manual (usuario):** Juan Pablo probará el flujo completo con
  su archivo real y hará la subida a CertiSAT Web.

### Criterio de éxito v1

CertiSAT Web acepta el `.sdg` generado y emite el certificado del CSD, y el
`.key` descargado (con su contraseña) funciona para sellar en el sistema de
facturación del usuario.

## Riesgos y decisiones abiertas

1. **Formato exacto del `.sdg` — riesgo principal.** No hay documentación
   oficial pública. **Tarea 1 del plan de implementación:** fijar el formato con
   referencias open-source de la comunidad CFDI (SOLCEDI/Certifica) y análisis
   de la propia herramienta si hace falta. `sdg.ts` queda aislado para absorber
   correcciones. Hasta no pasar la validación E2E manual, el formato se
   considera hipótesis.
2. **Subject exacto del CSR.** Candidato: `CN` = razón social, `OU` = sucursal,
   identificador del RFC en `x500UniqueIdentifier`/`serialNumber`. Se confirma
   en la misma tarea de investigación.
3. **Certificado público del SAT** para el ensobretado: identificar cuál usa
   CertiSAT hoy y vendorearlo en `sat-cert.ts` (misma tarea).
4. **forge en modo mantenimiento.** Aceptado: sin superficie de red, dependencia
   pineada, y el diseño por módulos permitiría sustituirla después.
