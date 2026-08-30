import forge from 'node-forge';
import { aBytes } from '../util/bytes';
import { ArchivoInvalidoError } from '../util/errors';

export interface EntradaCSR {
  privada: forge.pki.rsa.PrivateKey;
  publica: forge.pki.rsa.PublicKey;
  rfc: string; // decide CN vs O por longitud (13 física / 12 moral) — §1.3
  razonSocial: string; // valor del atributo CN u O
  sucursal: string; // valor del atributo OU
  contrasenaCsd: string; // ver nota en generarCSR: no alimenta el challengePassword
  certificadoEfirma: forge.pki.Certificate; // fuente verbatim de 2.5.4.45 y 2.5.4.5 — §1.2
}

// OIDs del subject del CSR de CSD — docs/reference/sdg-format.md §1.1. Literales (en vez
// de `forge.pki.oids['...']`) por la misma razón que en keyfile.ts: ese objeto está
// tipado con un index signature genérico y cualquier acceso da `string | undefined` bajo
// `noUncheckedIndexedAccess`; los literales además se comparan a simple vista contra el
// documento de referencia.
const OID_X500_UNIQUE_IDENTIFIER = '2.5.4.45'; // x500UniqueIdentifier: RFC (+ RFC del RL)
const OID_SERIAL_NUMBER = '2.5.4.5'; // serialNumber: CURP (+ CURP del RL)
const OID_CN = '2.5.4.3'; // commonName — persona física (RFC de 13 caracteres)
const OID_O = '2.5.4.10'; // organizationName — persona moral (RFC de 12 caracteres)
const OID_OU = '2.5.4.11'; // organizationalUnitName — sucursal
const OID_CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7'; // pkcs-9-at-challengePassword — §1.4

const LONGITUD_RFC_PERSONA_FISICA = 13; // §1.3: 13 => CN; cualquier otra longitud => O.

// `@types/node-forge` tipa `CertificateField.valueTagClass` como `asn1.Class` cuando en
// realidad es un tag de `asn1.Type` (verificado en tiempo de ejecución: `_dnToAsn1` y
// `_CRIAttributesToAsn1`, node_modules/node-forge/lib/x509.js, pasan este valor tal cual
// como el parámetro `type` de `asn1.create(tagClass, type, ...)`, nunca como `tagClass`).
// Es un error de tipos de la librería de terceros, no del runtime: `Type.PRINTABLESTRING`
// y `Type.UTF8` siguen siendo 19 y 12 respectivamente. Para no silenciar el chequeo de
// tipos con un `as any`/`as Class` a ciegas, se ensanchan explícitamente a `number` (el
// único tipo que TypeScript acepta aquí sin ser el propio `Class`) preservando el valor
// numérico real.
const TAG_PRINTABLESTRING: number = forge.asn1.Type.PRINTABLESTRING;
const TAG_UTF8: number = forge.asn1.Type.UTF8;

/**
 * Copia verbatim el valor de un atributo del subject de la e.firma — §1.2: "copiar los
 * valores de 2.5.4.45 y 2.5.4.5 verbatim del subject del .cer de la e.firma que sube el
 * usuario, sin re-derivarlos ni normalizarlos". El subject de un .cer es contenido
 * externo (aunque venga de la propia e.firma), así que se valida su forma antes de
 * confiar en él en vez de asumir silenciosamente un string vacío.
 */
function valorVerbatim(cert: forge.pki.Certificate, oid: string, etiqueta: string): string {
  const attr = cert.subject.attributes.find((a) => a.type === oid);
  if (typeof attr?.value !== 'string') {
    throw new ArchivoInvalidoError(
      `El certificado de e.firma no trae el atributo ${etiqueta} (OID ${oid}) que exige ` +
        'el CSR de CSD del SAT; vuelve a descargar tu e.firma desde el portal del SAT.',
    );
  }
  return attr.value;
}

// B64(SHA1(s1 + s2)) — helper de digest de §1.4 (mx/a/a/a/f.java, método `a` de
// CRequerimientoSello). `s1`/`s2` son siempre ASCII en este flujo (x500UniqueIdentifier y
// salidas de Base64), así que 'utf8' y la interpretación binaria por defecto de forge
// coinciden byte a byte; se explicita 'utf8' de todas formas por consistencia con el
// resto del código (efirma.ts, keyfile.ts).
function digestChallenge(s1: string, s2: string): string {
  const md = forge.md.sha1.create();
  md.update(s1 + s2, 'utf8');
  return forge.util.encode64(md.digest().getBytes());
}

/**
 * Construye el CSR PKCS#10 de CSD con el subject exacto que espera el SAT —
 * docs/reference/sdg-format.md §1 (subject y challengePassword) y §2.1 (digest de
 * firma). DER de salida, listo para empaquetarse en el .sdg (Tarea 9).
 *
 * Nota sobre `entrada.contrasenaCsd`: no se usa dentro de esta función. La fórmula de
 * `challengePassword` en §1.4 depende únicamente de `x500UniqueIdentifier` (ver `x`
 * abajo) — está confirmada leyendo el bytecode descompilado de Certifica
 * (`holder.a() == holder.c() == el string del x500UniqueIdentifier` en el flujo de CSD),
 * no de ninguna contraseña. El campo se conserva en `EntradaCSR` porque así lo fija el
 * contrato que consume la Tarea 11.
 */
export function generarCSR(entrada: EntradaCSR): Uint8Array {
  const x500Uid = valorVerbatim(
    entrada.certificadoEfirma,
    OID_X500_UNIQUE_IDENTIFIER,
    'x500UniqueIdentifier',
  );
  const serialNumber = valorVerbatim(entrada.certificadoEfirma, OID_SERIAL_NUMBER, 'serialNumber');

  const esPersonaFisica = entrada.rfc.length === LONGITUD_RFC_PERSONA_FISICA;

  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = entrada.publica;

  // §1.1: RDNSequence de exactamente 4 RDN, un solo atributo cada uno, en este orden —
  // node-forge respeta el orden del arreglo e inserta un RDN por entrada (_dnToAsn1 en
  // x509.js). El tipo ASN.1 por defecto de forge es PrintableString, así que las RDN
  // #3/#4 requieren `valueTagClass: UTF8` explícito (§1.5); #1/#2 se explicitan también
  // por claridad aunque coincidan con el default.
  csr.setSubject([
    {
      type: OID_X500_UNIQUE_IDENTIFIER,
      value: x500Uid,
      valueTagClass: TAG_PRINTABLESTRING,
    },
    {
      type: OID_SERIAL_NUMBER,
      value: serialNumber,
      valueTagClass: TAG_PRINTABLESTRING,
    },
    {
      type: esPersonaFisica ? OID_CN : OID_O,
      value: entrada.razonSocial,
      valueTagClass: TAG_UTF8,
    },
    { type: OID_OU, value: entrada.sucursal, valueTagClass: TAG_UTF8 },
  ]);

  // §1.4: challengePassword obligatorio. X = x500UniqueIdentifier (mismo valor que la
  // RDN #1, copiado verbatim arriba) — NO es `entrada.contrasenaCsd` (ver nota en el
  // docstring de esta función).
  const interno = digestChallenge(x500Uid, x500Uid);
  const challengePassword = digestChallenge(x500Uid, interno);
  csr.setAttributes([
    {
      type: OID_CHALLENGE_PASSWORD,
      value: challengePassword,
      valueTagClass: TAG_PRINTABLESTRING,
    },
  ]);

  // §2.1: sha1WithRSAEncryption — la hipótesis original del plan (SHA-256) es incorrecta
  // para el CSR; SHA-1 es el default de node-forge si no se pasa `md`, pero se explicita.
  csr.sign(entrada.privada, forge.md.sha1.create());

  return aBytes(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes());
}
