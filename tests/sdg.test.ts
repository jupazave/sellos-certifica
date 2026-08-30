import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { cargarEfirma, type Efirma } from '../src/crypto/efirma';
import { generarParCSD } from '../src/crypto/keygen';
import { generarCSR } from '../src/crypto/csr';
import { generarSDG } from '../src/crypto/sdg';
import { aBinario, aBytes } from '../src/util/bytes';

// Fixtures reales del SAT — ver tests/fixtures/README.md.
const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const CONTRASENA = '12345678a';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SHA1 = '1.3.14.3.2.26';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';

// @types/node-forge no declara `.type` en `PkcsSignedData`, y `messageFromAsn1` devuelve
// la unión `Captured<PkcsEnvelopedData | PkcsSignedData>` (así que `.certificates`, propio
// solo de `PkcsSignedData`, tampoco es accesible sin angostar el tipo). Ambos existen en
// runtime (node_modules/node-forge/lib/pkcs7.js: `msg.type = forge.pki.oids.signedData`,
// `msg.certificates = []`). Se amplía el tipo aquí, documentado, en vez de usar `any` —
// mismo criterio que el resto del código (p.ej. src/crypto/csr.ts, `valueTagClass`).
type MensajeFirmado = forge.pkcs7.Captured<forge.pkcs7.PkcsSignedData> & { type: string };
function mensajeFirmadoDe(sdg: Uint8Array): MensajeFirmado {
  return forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(aBinario(sdg))) as MensajeFirmado;
}

// --- Helpers de navegación ASN.1, independientes de la implementación de sdg.ts: leen la
// estructura DER cruda con la misma lógica que cualquier parser CMS tendría que usar. Los
// índices están documentados en docs/reference/sdg-format.md §3.2 y fueron verificados
// navegando la salida real de forge antes de escribir esta prueba (no son un supuesto).
function hijos(nodo: forge.asn1.Asn1): forge.asn1.Asn1[] {
  if (!Array.isArray(nodo.value)) {
    throw new Error('Se esperaba un nodo ASN.1 compuesto (SEQUENCE/SET), llegó uno primitivo.');
  }
  return nodo.value;
}
function hijo(nodo: forge.asn1.Asn1, indice: number): forge.asn1.Asn1 {
  const encontrado = hijos(nodo)[indice];
  if (!encontrado) throw new Error(`ASN.1: no hay hijo en el índice ${indice}.`);
  return encontrado;
}
function comoBytes(nodo: forge.asn1.Asn1): string {
  if (typeof nodo.value !== 'string') {
    throw new Error('Se esperaba un nodo ASN.1 primitivo (bytes), llegó uno compuesto.');
  }
  return nodo.value;
}
function en<T>(arreglo: T[], indice: number): T {
  const encontrado = arreglo[indice];
  if (encontrado === undefined) throw new Error(`Índice ${indice} fuera de rango.`);
  return encontrado;
}

/** ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT content } */
function contentInfoDe(sdg: Uint8Array): forge.asn1.Asn1 {
  return forge.asn1.fromDer(aBinario(sdg));
}
/** [0] EXPLICIT content -> value[0] es el SignedData SEQUENCE — §3.2. */
function signedDataDe(ci: forge.asn1.Asn1): forge.asn1.Asn1 {
  return hijo(hijo(ci, 1), 0);
}
/**
 * SignedData.value = [version, digestAlgorithms SET, encapContentInfo, certificates [0],
 * signerInfos SET] — orden confirmado leyendo node_modules/node-forge/lib/pkcs7.js
 * `createSignedData().toAsn1()` y reproducido navegando la salida real de forge.
 */
function signerInfoDe(sd: forge.asn1.Asn1): forge.asn1.Asn1 {
  return hijo(hijo(sd, 4), 0); // signerInfos SET -> único SignerInfo (un solo firmante)
}

// Extrae la primera entrada de un ZIP navegando el Local File Header a mano — deliberadamente
// independiente de src/crypto/zip.ts (no lo importa), para que el cross-check no valide la
// implementación contra sí misma. Mismo formato que documenta tests/zip.test.ts.
function extraerPrimeraEntradaDeZip(zip: Uint8Array): { nombre: string; datos: Uint8Array } {
  const u16 = (o: number) => (zip[o] ?? 0) | ((zip[o + 1] ?? 0) << 8);
  const u32 = (o: number) =>
    ((zip[o] ?? 0) | ((zip[o + 1] ?? 0) << 8) | ((zip[o + 2] ?? 0) << 16) | ((zip[o + 3] ?? 0) << 24)) >>>
    0;
  expect(Array.from(zip.slice(0, 4))).toEqual([0x50, 0x4b, 0x03, 0x04]); // firma local "PK\x03\x04"
  const largoNombre = u16(26);
  const largoDatos = u32(18); // STORE: tamaño comprimido == tamaño real
  const inicioNombre = 30;
  const nombre = new TextDecoder().decode(zip.slice(inicioNombre, inicioNombre + largoNombre));
  const inicioDatos = inicioNombre + largoNombre;
  const datos = zip.slice(inicioDatos, inicioDatos + largoDatos);
  return { nombre, datos };
}

function candidatosOpenssl(): string[] {
  const candidatos: string[] = [];
  try {
    // docs/reference/sdg-format.md T3: "LibreSSL may lack cms — use $(brew --prefix openssl@3)".
    const prefijo = execFileSync('brew', ['--prefix', 'openssl@3']).toString().trim();
    if (prefijo) candidatos.push(join(prefijo, 'bin', 'openssl'));
  } catch {
    // Homebrew ausente o sin la fórmula — se sigue con el openssl del sistema.
  }
  candidatos.push('openssl');
  return candidatos;
}
function soportaCms(bin: string): boolean {
  try {
    const salida = execFileSync(bin, ['cms', '-help'], { stdio: ['ignore', 'pipe', 'pipe'] });
    return salida.toString().includes('-verify');
  } catch (e) {
    const err = e as { stdout?: Buffer; stderr?: Buffer };
    return ((err.stdout?.toString() ?? '') + (err.stderr?.toString() ?? '')).includes('-verify');
  }
}
function resolverOpensslConCms(): string | null {
  for (const candidato of candidatosOpenssl()) {
    if (soportaCms(candidato)) return candidato;
  }
  return null;
}
const OPENSSL_CMS = resolverOpensslConCms();

describe('generarSDG', () => {
  let efirma: Efirma;
  let csr: Uint8Array;
  let sdg: Uint8Array;

  beforeAll(async () => {
    efirma = cargarEfirma(fielCer, fielKey, CONTRASENA);
    const par = await generarParCSD();
    csr = generarCSR({
      ...par,
      rfc: efirma.datos.rfc,
      razonSocial: efirma.datos.razonSocial,
      sucursal: 'Matriz',
      contrasenaCsd: CONTRASENA,
      certificadoEfirma: efirma.datos.certificado,
    });
    sdg = generarSDG(csr, efirma);
  }, 30_000);

  it('el ContentInfo externo tiene OID signedData (1.2.840.113549.1.7.2)', () => {
    const oid = forge.asn1.derToOid(comoBytes(hijo(contentInfoDe(sdg), 0)));
    expect(oid).toBe(OID_SIGNED_DATA);
  });

  it('parsea sin lanzar con forge.pkcs7.messageFromAsn1 y expone type=signedData', () => {
    const msg = mensajeFirmadoDe(sdg);
    expect(msg.type).toBe(OID_SIGNED_DATA);
  });

  it('SignedData incluye exactamente el certificado de la e.firma (ninguno más)', () => {
    const certificatesWrap = hijo(signedDataDe(contentInfoDe(sdg)), 3); // [0] IMPLICIT SET
    const certs = hijos(certificatesWrap);
    expect(certs).toHaveLength(1);
    const esperado = forge.asn1.toDer(forge.pki.certificateToAsn1(efirma.datos.certificado)).getBytes();
    expect(forge.asn1.toDer(hijo(certificatesWrap, 0)).getBytes()).toBe(esperado);

    // Cross-check vía la API de alto nivel (`certificates` sí está tipado en @types).
    const msg = mensajeFirmadoDe(sdg);
    expect(msg.certificates).toHaveLength(1);
    expect(msg.certificates[0]?.serialNumber).toBe(efirma.datos.certificado.serialNumber);
  });

  it('el algoritmo de digest es SHA-1 (1.3.14.3.2.26), tanto en digestAlgorithms como en el SignerInfo', () => {
    const sd = signedDataDe(contentInfoDe(sdg));
    const digestAlgorithms = hijos(hijo(sd, 1));
    expect(digestAlgorithms).toHaveLength(1);
    // digestAlgorithms es un SET { AlgorithmIdentifier } — hijo(sd,1) es el SET, hijo(.,0)
    // el único AlgorithmIdentifier SEQUENCE, y su hijo(.,0) el OID en sí.
    expect(forge.asn1.derToOid(comoBytes(hijo(hijo(hijo(sd, 1), 0), 0)))).toBe(OID_SHA1);

    const signerInfos = hijos(hijo(sd, 4));
    expect(signerInfos).toHaveLength(1); // un solo firmante: la e.firma
    const algSignerInfo = hijo(signerInfoDe(sd), 2);
    expect(forge.asn1.derToOid(comoBytes(hijo(algSignerInfo, 0)))).toBe(OID_SHA1);
  });

  it('signedAttrs están presentes y en el orden exacto de §3.2: contentType, signingTime, messageDigest', () => {
    const signerInfo = signerInfoDe(signedDataDe(contentInfoDe(sdg)));
    const signedAttrs = hijo(signerInfo, 3); // [0] IMPLICIT SET

    // §3.2: "la firma se calcula sobre la codificación DER del SET de signedAttrs (con tag
    // SET, no [0])" — pero lo que forge SERIALIZA en el mensaje sí va como [0] IMPLICIT.
    expect(signedAttrs.tagClass).toBe(forge.asn1.Class.CONTEXT_SPECIFIC);
    expect(signedAttrs.type).toBe(0);

    const atributos = hijos(signedAttrs);
    expect(atributos).toHaveLength(3);
    const oids = atributos.map((a) => forge.asn1.derToOid(comoBytes(hijo(a, 0))));
    // No es el orden por OID (9.3 < 9.4 < 9.5): es el orden canónico DER que Certifica
    // también produce (BouncyCastle ordena por longitud de codificación) — §3.2, "Orden de
    // los signedAttrs". node-forge NO ordena solo: hay que escribir el arreglo ya en este
    // orden (ver el comentario en src/crypto/sdg.ts).
    expect(oids).toEqual([OID_CONTENT_TYPE, OID_SIGNING_TIME, OID_MESSAGE_DIGEST]);
  });

  it('el atributo messageDigest es SHA1(eContent), es decir SHA1 del ZIP adjunto', () => {
    const sd = signedDataDe(contentInfoDe(sdg));
    const eContent = comoBytes(hijo(hijo(hijo(sd, 2), 1), 0)); // encapContentInfo -> [0] -> OCTETSTRING
    const esperado = forge.md.sha1.create().update(eContent).digest().getBytes();

    const atributos = hijos(hijo(signerInfoDe(sd), 3));
    const messageDigestAttr = en(atributos, 2); // [2] = messageDigest (orden ya probado arriba)
    const valor = comoBytes(hijo(hijo(messageDigestAttr, 1), 0)); // SEQUENCE{OID, SET{OCTETSTRING}}
    expect(valor).toBe(esperado);
  });

  it('el contenido adjunto es un ZIP (STORE) cuya única entrada .req es idéntica byte a byte al CSR', () => {
    const sd = signedDataDe(contentInfoDe(sdg));
    const encapContentInfo = hijo(sd, 2);
    expect(forge.asn1.derToOid(comoBytes(hijo(encapContentInfo, 0)))).toBe(OID_DATA); // eContentType

    const eContentOctet = hijo(hijo(encapContentInfo, 1), 0); // [0] EXPLICIT -> OCTET STRING
    const zipBytes = aBytes(comoBytes(eContentOctet));

    const { nombre, datos } = extraerPrimeraEntradaDeZip(zipBytes);
    expect(Array.from(datos)).toEqual(Array.from(csr));
    // §3.3/§3.4: CSD_<sucursal>_<RFC>_<yyyyMMdd>_<HHmmss>s.req — RFC bare (sin el
    // compuesto " / RFC_RL" que sí lleva el subject del CSR, por instrucción del
    // controlador). No se fija la hora exacta (generarSDG usa la hora actual).
    expect(nombre).toMatch(/^CSD_Matriz_AAA010101AAA_\d{8}_\d{6}s\.req$/);
  });

  // No hay una prueba análoga usando `messageFromAsn1(...).content` para el contenido
  // adjunto: es un límite verificado de node-forge (v1.4.0), no algo sobre nuestro código.
  // `_fromAsn1` (node_modules/node-forge/lib/pkcs7.js, ~línea 1195) captura el campo
  // `content` de `encapContentInfo` con `captureAsn1` (el nodo `[0] EXPLICIT` completo, no
  // sus bytes) y luego hace `forge.util.createBuffer(capture.content)` pasándole ese nodo
  // ASN.1 tal cual — no un string/ArrayBuffer — así que el resultado es un ByteBuffer
  // vacío. Confirmado interactivamente con node-forge standalone (no es un efecto de
  // sdg.ts): `msg.content` sale `ByteStringBuffer { data: '' }` para cualquier
  // SignedData con contenido adjunto simple, incluso uno de juguete sin ZIP de por medio.
  // La extracción del ZIP adjunto (arriba) navega el ASN.1 crudo en su lugar, que sí
  // funciona y además es lo que pide la consigna de esta tarea ("parse the ASN.1").

  it('la firma RSA del SignerInfo verifica contra la llave pública de la e.firma (sin depender de CLIs externas)', () => {
    const signerInfo = signerInfoDe(signedDataDe(contentInfoDe(sdg)));
    const signedAttrsImplicit = hijo(signerInfo, 3);

    // §3.2: la firma cubre la codificación DER del SET **universal** (no el [0] IMPLICIT
    // serializado). Se reconstruye ese SET a partir de los mismos nodos ya parseados —
    // exactamente lo que hace node-forge internamente al firmar (pkcs7.js
    // `addSignerInfos`: `attrsAsn1` vs `authenticatedAttributesAsn1`).
    const attrsComoSet = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      hijos(signedAttrsImplicit),
    );
    const digest = forge.md.sha1.create().update(forge.asn1.toDer(attrsComoSet).getBytes()).digest();

    const firma = comoBytes(hijo(signerInfo, 5));
    const publica = efirma.datos.certificado.publicKey as forge.pki.rsa.PublicKey;
    expect(publica.verify(digest.getBytes(), firma)).toBe(true);
  });

  it('una sucursal distinta produce un nombre de entrada .req distinto (no está fijo)', async () => {
    const par = await generarParCSD();
    const csrSucursal2 = generarCSR({
      ...par,
      rfc: efirma.datos.rfc,
      razonSocial: efirma.datos.razonSocial,
      sucursal: 'Sucursal Norte',
      contrasenaCsd: CONTRASENA,
      certificadoEfirma: efirma.datos.certificado,
    });
    const sdg2 = generarSDG(csrSucursal2, efirma);
    const sd = signedDataDe(contentInfoDe(sdg2));
    const eContentOctet = hijo(hijo(hijo(sd, 2), 1), 0);
    const { nombre, datos } = extraerPrimeraEntradaDeZip(aBytes(comoBytes(eContentOctet)));
    expect(nombre).toMatch(/^CSD_Sucursal_Norte_AAA010101AAA_\d{8}_\d{6}s\.req$/);
    expect(Array.from(datos)).toEqual(Array.from(csrSucursal2));
  }, 30_000);

  it('el nombre de la entrada .req sanea acentos de la sucursal (§3.3) — decisión: Ñ se preserva (no documentada en §3.3)', async () => {
    const par = await generarParCSD();
    const csrAcentos = generarCSR({
      ...par,
      rfc: efirma.datos.rfc,
      razonSocial: efirma.datos.razonSocial,
      sucursal: 'Cañón Sur Óptico',
      contrasenaCsd: CONTRASENA,
      certificadoEfirma: efirma.datos.certificado,
    });
    const sdgAcentos = generarSDG(csrAcentos, efirma);
    const sd = signedDataDe(contentInfoDe(sdgAcentos));
    const eContentOctet = hijo(hijo(hijo(sd, 2), 1), 0);
    const { nombre } = extraerPrimeraEntradaDeZip(aBytes(comoBytes(eContentOctet)));
    // "Cañón Sur Óptico" -> vocales acentuadas caen (ó->o, Ó->O) pero la "ñ" se conserva
    // (no es una vocal con acento, no aparece en la lista de §3.3) -> "Cañon_Sur_Optico".
    expect(nombre).toMatch(/^CSD_Cañon_Sur_Optico_AAA010101AAA_\d{8}_\d{6}s\.req$/);
  }, 30_000);
});

describe.skipIf(!OPENSSL_CMS)('generarSDG — cross-check con `openssl cms -verify`', () => {
  it('openssl valida la firma CMS y el ZIP extraído contiene el CSR original', async () => {
    const efirma = cargarEfirma(fielCer, fielKey, CONTRASENA);
    const par = await generarParCSD();
    const csr = generarCSR({
      ...par,
      rfc: efirma.datos.rfc,
      razonSocial: efirma.datos.razonSocial,
      sucursal: 'Matriz',
      contrasenaCsd: CONTRASENA,
      certificadoEfirma: efirma.datos.certificado,
    });
    const sdg = generarSDG(csr, efirma);

    const dir = mkdtempSync(join(tmpdir(), 'sellos-sdg-test-'));
    try {
      const rutaSdg = join(dir, 'archivo.sdg');
      const rutaZip = join(dir, 'contenido.zip');
      writeFileSync(rutaSdg, sdg);
      try {
        // -noverify: no se valida la cadena de confianza (no traemos la CA del SAT como
        // trust anchor local) — sí se valida la firma RSA sobre signedAttrs y que
        // messageDigest coincida con el eContent adjunto. Ver docs/reference/sdg-format.md
        // §3.7 y la nota del controlador: T3's reviewer confirmó que esto funciona sobre
        // un SignedData construido según §3.7.
        execFileSync(OPENSSL_CMS as string, [
          'cms',
          '-verify',
          '-inform',
          'DER',
          '-noverify',
          '-in',
          rutaSdg,
          '-out',
          rutaZip,
        ]);
      } catch (e) {
        const err = e as { stderr?: Buffer; stdout?: Buffer };
        throw new Error(
          `openssl cms -verify falló: ${err.stderr?.toString() ?? ''} ${err.stdout?.toString() ?? ''}`,
        );
      }
      const zipVerificado = new Uint8Array(readFileSync(rutaZip));
      const { datos } = extraerPrimeraEntradaDeZip(zipVerificado);
      expect(Buffer.compare(Buffer.from(datos), Buffer.from(csr))).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
