import forge from 'node-forge';
import { aBinario, aBytes } from '../util/bytes';
import { ArchivoInvalidoError } from '../util/errors';
import type { Efirma } from './efirma';
import { crearZip } from './zip';

// ---------------------------------------------------------------------------------------
// Estructura del .sdg — docs/reference/sdg-format.md §3 (ver también la corrección del
// controlador de esta tarea, que anula la hipótesis original del plan de un
// ContentInfo(EnvelopedData)):
//
//   ContentInfo(SignedData) con contenido ADJUNTO. El contenido firmado es un ZIP (STORE)
//   que contiene el .req (CSR DER); se firma con la e.firma (incluye su certificado),
//   SHA-1, con signedAttrs (contentType, signingTime, messageDigest) en ese orden exacto.
//   NO hay EnvelopedData, NO hay cifrado, NO hay certificado destinatario (§3, §5.1).
// ---------------------------------------------------------------------------------------

// OIDs literales (mismo criterio que csr.ts/keyfile.ts): `forge.pki.oids['...']` está
// tipado con un index signature genérico, así que cualquier acceso da `string | undefined`
// bajo `noUncheckedIndexedAccess`. Los literales además se comparan a simple vista contra
// el documento de referencia.
const OID_SHA1 = '1.3.14.3.2.26'; // §2.2/§3.2: digest del SignedData (id-sha1, OIW)
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'; // pkcs-9-at-contentType
const OID_DATA = '1.2.840.113549.1.7.1'; // pkcs7-data — valor del atributo contentType
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5'; // pkcs-9-at-signingTime
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'; // pkcs-9-at-messageDigest
const OID_OU = '2.5.4.11'; // organizationalUnitName — sucursal (mismo campo que csr.ts)

// `@types/node-forge` tipa `CertificateField.valueTagClass` como `asn1.Class` cuando en
// realidad es un tag de `asn1.Type` (mismo error de tipos ya documentado en
// src/crypto/csr.ts — verificado ahí en tiempo de ejecución contra `_dnToAsn1`/
// `_CRIAttributesToAsn1`, node_modules/node-forge/lib/x509.js). Se ensancha a `number`
// para poder comparar sin que TypeScript rechace la comparación entre dos enums distintos.
const TAG_UTF8: number = forge.asn1.Type.UTF8;

/**
 * Workaround de un bug verificado en node-forge (v1.4.0, la que trae el proyecto):
 * `PkcsSignedData.addSigner({ certificate })` reconstruye `issuerAndSerialNumber.issuer`
 * llamando a `forge.pki.distinguishedNameToAsn1({attributes: cert.issuer.attributes})`
 * (node_modules/node-forge/lib/pkcs7.js, `_signerToAsn1`). Esa función SIEMPRE aplica
 * `forge.util.encodeUtf8(valor)` a cualquier atributo con `valueTagClass === UTF8`
 * (x509.js, `_dnToAsn1`) — asumiendo que `.value` es un string Unicode "lógico" todavía sin
 * codificar. Eso es cierto cuando UNO arma el DN a mano (como hace csr.ts para el subject
 * del CSR), pero es FALSO para un `.issuer` obtenido de un certificado ya parseado: ahí
 * `.value` ya son los bytes UTF-8 crudos, sin decodificar (forge nunca decodifica
 * UTF8String al parsear — mismo comportamiento documentado en tests/csr.test.ts). El
 * resultado es una doble codificación UTF-8 que CORROMPE el campo `issuer` del SignerInfo
 * cada vez que la CA emisora del certificado tiene algún atributo UTF8String con bytes no
 * ASCII (nuestra propia fixture de e.firma real la tiene: "Administración", "Coyoacán").
 *
 * La certificateToAsn1 del propio forge NO sufre este bug porque reutiliza el
 * `tbsCertificate` cacheado del parseo original ("prefer cached TBSCertificate", x509.js) en
 * vez de reconstruirlo — por eso el certificado embebido sale bien pero el `issuer` del
 * SignerInfo (reconstruido aparte, sin ese cache) sale mal. Verificado empíricamente: sin
 * este workaround, `openssl cms -verify` falla con "signer certificate not found" porque
 * el `issuer` del SignerInfo ya no coincide byte a byte con el `issuer` real del
 * certificado embebido — un verificador CMS no puede emparejarlos. Con el workaround,
 * `openssl cms -verify` pasa (ver tests/sdg.test.ts).
 *
 * La corrección: pre-decodificar con `decodeUtf8` los atributos UTF8 antes de pasarlos, de
 * modo que la codificación que aplica `_dnToAsn1` los deje de vuelta en los bytes
 * originales (decode-then-encode es la identidad; encode-sobre-bytes-ya-crudos no lo es).
 * Para atributos ASCII puros (la mayoría) esto es un no-op, así que se aplica sin
 * distinción a todos los atributos UTF8.
 */
function atributosEmisorCorregidos(certificado: forge.pki.Certificate): forge.pki.CertificateField[] {
  return certificado.issuer.attributes.map((attr) => {
    if (attr.valueTagClass === TAG_UTF8 && typeof attr.value === 'string') {
      return { ...attr, value: forge.util.decodeUtf8(attr.value) };
    }
    return attr;
  });
}

// @types/node-forge solo tipa la variante `{ certificate }` de `addSigner` (y la marca
// requerida); no expone la variante `{ issuer, serialNumber }` que sí soporta el runtime
// (ver el JSDoc de `addSigner` en node_modules/node-forge/lib/pkcs7.js: "issuer the issuer
// attributes... serialNumber the signer's certificate's serial number"). Esa segunda
// variante es la que hace falta para el workaround de arriba — pasar `certificate` la
// ignoraría (addSigner sobreescribe `issuer`/`serialNumber` incondicionalmente cuando
// `certificate` está presente). Se declara aquí el shape real y se usa una única aserción
// de tipo localizada, documentada, en vez de silenciar todo con `any`.
interface OpcionesAddSignerConEmisor {
  key: forge.pki.rsa.PrivateKey;
  issuer: forge.pki.CertificateField[];
  serialNumber: string;
  digestAlgorithm: string;
  authenticatedAttributes: Array<{ type: string; value?: string }>;
}
type AddSignerConEmisor = (opciones: OpcionesAddSignerConEmisor) => void;

// §3.3: "la <sucursal> en el nombre va sin acentos (mx/sat/gob/f/m.java método e()
// reemplaza ÀÁÂÃÄÅ→A, àáâãäå→a, Ò…Ø→O, Ì…Ï→I, È…Ë→E, Ù…Ü→U, Çç→C, etc.) y con espacios
// convertidos a _. El valor OU del CSR conserva el nombre original" — es decir, este mapa
// SOLO aplica al nombre de la entrada dentro del ZIP, nunca al atributo OU del CSR (que ya
// construyó csr.ts con el valor tal cual). La "Ñ"/"ñ" no aparece en la lista documentada
// (no es una vocal acentuada, es una letra distinta en español) y aquí se preserva
// deliberadamente — es una decisión documentada, no confirmada contra el bytecode de
// Certifica; ver la sección de "concerns" en el reporte de esta tarea.
const MAPA_SIN_ACENTOS: Readonly<Record<string, string>> = {
  À: 'A', Á: 'A', Â: 'A', Ã: 'A', Ä: 'A', Å: 'A',
  à: 'a', á: 'a', â: 'a', ã: 'a', ä: 'a', å: 'a',
  È: 'E', É: 'E', Ê: 'E', Ë: 'E',
  è: 'e', é: 'e', ê: 'e', ë: 'e',
  Ì: 'I', Í: 'I', Î: 'I', Ï: 'I',
  ì: 'i', í: 'i', î: 'i', ï: 'i',
  Ò: 'O', Ó: 'O', Ô: 'O', Õ: 'O', Ö: 'O', Ø: 'O',
  ò: 'o', ó: 'o', ô: 'o', õ: 'o', ö: 'o', ø: 'o',
  Ù: 'U', Ú: 'U', Û: 'U', Ü: 'U',
  ù: 'u', ú: 'u', û: 'u', ü: 'u',
  Ç: 'C', ç: 'c',
};

function paraNombreDeZip(texto: string): string {
  const sinAcentos = Array.from(texto)
    .map((caracter) => MAPA_SIN_ACENTOS[caracter] ?? caracter)
    .join('');
  return sinAcentos.replaceAll(' ', '_');
}

function conCeros(n: number, ancho = 2): string {
  return String(n).padStart(ancho, '0');
}

/**
 * Extrae la sucursal (atributo OU) del subject del CSR ya construido — es la única fuente
 * disponible dentro de esta función, ya que `generarSDG` no recibe la sucursal por
 * separado (contrato fijo de la Tarea 11: `generarSDG(csrDer, efirma)`). `generarCSR`
 * (Tarea 8) siempre agrega esta RDN (§1.1: 4 RDN, ninguna opcional), así que en el flujo
 * normal de la app este atributo siempre está presente.
 */
function sucursalDelCSR(csr: forge.pki.CertificateSigningRequest): string {
  const attr = csr.subject.attributes.find((a) => a.type === OID_OU);
  if (typeof attr?.value !== 'string') {
    throw new ArchivoInvalidoError(
      'El CSR no trae el atributo OU (sucursal) esperado; no se puede armar el .sdg.',
    );
  }
  // csr.ts codifica OU como UTF8String; forge no decodifica UTF-8 al parsear de vuelta
  // (dejaría los bytes crudos en `.value`, no un string Unicode) — hay que decodificar
  // aquí, igual que hace tests/csr.test.ts al leer el mismo atributo.
  return forge.util.decodeUtf8(attr.value);
}

/**
 * Nombre de la entrada del CSR dentro del ZIP — §3.3/§3.4:
 * `CSD_<sucursal>_<RFC>_<yyyyMMdd>_<HHmmss>s.req` (nótese la "s" literal antes de ".req").
 * El RFC es el **bare** (`efirma.datos.rfc`, ya sin el compuesto " / RFC_RL" que sí lleva
 * el subject del CSR) — instrucción del controlador de esta tarea.
 */
function nombreEntradaReq(sucursal: string, rfc: string, fecha: Date): string {
  const yyyyMMdd = `${fecha.getFullYear()}${conCeros(fecha.getMonth() + 1)}${conCeros(fecha.getDate())}`;
  const HHmmss = `${conCeros(fecha.getHours())}${conCeros(fecha.getMinutes())}${conCeros(fecha.getSeconds())}`;
  return `CSD_${paraNombreDeZip(sucursal)}_${rfc}_${yyyyMMdd}_${HHmmss}s.req`;
}

/**
 * Ensobreta el CSR de CSD en el formato `.sdg` real del SAT — docs/reference/sdg-format.md
 * §3: `ContentInfo(SignedData)` con contenido adjunto = ZIP(STORE) del `.req`, firmado con
 * la e.firma (SHA-1, certificado incluido, signedAttrs en el orden canónico DER de §3.2).
 */
export function generarSDG(csrDer: Uint8Array, efirma: Efirma): Uint8Array {
  // La sucursal solo existe embebida en el propio CSR (ver sucursalDelCSR arriba) — se
  // reconstruye el objeto CSR de forge para leer esa RDN de vuelta.
  const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(csrDer)));
  const sucursal = sucursalDelCSR(csr);

  // §6 punto 2: el `signingTime` no se fija (Certifica usa la hora local de la máquina y
  // se asume que CertiSAT no la valida estrictamente) — aquí se usa la misma idea para el
  // nombre del .req (hora local, como ya hace `nombreBase` en util/files.ts) y, por
  // separado, para la marca de tiempo interna del ZIP (`crearZip` la codifica en UTC por
  // determinismo entre husos horarios — ver zip.ts). Ninguna de las dos fechas es validada
  // por el SAT (§6 punto 4: "metadatos del ZIP... se asume irrelevante"), así que un
  // pequeño desfase cosmético entre "la hora que dice el nombre del archivo" y "la hora que
  // guarda el ZIP por dentro" es inofensivo.
  const ahora = new Date();
  const nombreReq = nombreEntradaReq(sucursal, efirma.datos.rfc, ahora);

  // §3.1/§3.3: Certifica siempre arma un ZIP, incluso con una sola sucursal/CSR.
  const zip = crearZip([{ nombre: nombreReq, datos: csrDer, fecha: ahora }]);

  const firmado = forge.pkcs7.createSignedData();
  firmado.content = forge.util.createBuffer(aBinario(zip));
  firmado.addCertificate(efirma.datos.certificado);
  (firmado.addSigner as unknown as AddSignerConEmisor)({
    key: efirma.llave,
    // NO se pasa `certificate` (ver atributosEmisorCorregidos arriba) — se deriva
    // `issuer`/`serialNumber` a mano para evitar el bug de doble codificación UTF-8.
    issuer: atributosEmisorCorregidos(efirma.datos.certificado),
    serialNumber: efirma.datos.certificado.serialNumber,
    digestAlgorithm: OID_SHA1,
    // Importante: el orden de este arreglo ES el orden en el archivo (node-forge no ordena el SET
    // como sí hace BouncyCastle) — tiene que escribirse ya en el orden canónico DER que
    // documenta §3.2: contentType, signingTime, messageDigest.
    authenticatedAttributes: [
      { type: OID_CONTENT_TYPE, value: OID_DATA },
      { type: OID_SIGNING_TIME }, // forge lo autocompleta con la hora actual
      { type: OID_MESSAGE_DIGEST }, // forge lo autocompleta con SHA1(eContent)
    ],
  });
  firmado.sign(); // detached=false (default): contenido ADJUNTO, como exige §3.2.

  return aBytes(forge.asn1.toDer(firmado.toAsn1()).getBytes());
}
