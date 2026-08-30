import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { generarParCSD } from '../src/crypto/keygen';
import { generarCSR, type EntradaCSR } from '../src/crypto/csr';
import { parsearCertificado } from '../src/crypto/efirma';
import { ArchivoInvalidoError } from '../src/util/errors';
import { aBinario } from '../src/util/bytes';

// Fixtures reales del SAT — ver tests/fixtures/README.md. RFC de pruebas AAA010101AAA
// (12 caracteres) => rama persona moral (O), no CN, per docs/reference/sdg-format.md §1.3.
const fielCerBytes = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const sinteticaCerBytes = new Uint8Array(readFileSync('tests/fixtures/sintetica.cer'));

// certificadoEfirma tal como lo produciría la Tarea 2 (mismo objeto forge.pki.Certificate
// que usa el resto de la app), no un parseo ad-hoc en el test.
const certificadoEfirma = parsearCertificado(fielCerBytes).certificado;

// Valores verbatim del subject de fiel.cer — confirmados leyendo el DER directamente
// (ver tests/fixtures/README.md) y coinciden con docs/reference/sdg-format.md §1.2:
// "AAA010101AAA / HEGT7610034S2" (x500UniqueIdentifier) y " / HEGT761003MDFRNN09"
// (serialNumber, con espacio inicial literal — es la trampa que documenta el §1.2).
const X500_UID_ESPERADO = 'AAA010101AAA / HEGT7610034S2';
const SERIAL_NUMBER_ESPERADO = ' / HEGT761003MDFRNN09';

const OID_X500_UID = '2.5.4.45';
const OID_SERIAL_NUMBER = '2.5.4.5';
const OID_CN = '2.5.4.3';
const OID_O = '2.5.4.10';
const OID_OU = '2.5.4.11';
const OID_CHALLENGE_PASSWORD = '1.2.840.113549.1.9.7';
const OID_SHA1_WITH_RSA = '1.2.840.113549.1.1.5';

function entradaBase(par: {
  privada: forge.pki.rsa.PrivateKey;
  publica: forge.pki.rsa.PublicKey;
}): EntradaCSR {
  return {
    ...par,
    rfc: 'AAA010101AAA',
    razonSocial: 'ACCEM SERVICIOS EMPRESARIALES SC',
    sucursal: 'Matriz',
    contrasenaCsd: '12345678a',
    certificadoEfirma,
  };
}

// §1.4: interno = B64(SHA1(X+X)); challengePassword = B64(SHA1(X+interno)), X =
// x500UniqueIdentifier. Recalculado aquí de forma independiente (no se llama al helper
// interno de csr.ts) para no validar la implementación contra sí misma.
function b64Sha1(s: string): string {
  return forge.util.encode64(forge.md.sha1.create().update(s, 'utf8').digest().getBytes());
}

describe('generarCSR', () => {
  it('produce un PKCS#10 verificable firmado en SHA-1 (no SHA-256)', async () => {
    const par = await generarParCSD();
    const der = generarCSR(entradaBase(par));
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));

    expect(csr.verify()).toBe(true);
    // §2.1: sha1WithRSAEncryption (1.2.840.113549.1.1.5), no sha256WithRSAEncryption.
    expect(csr.signatureOid).toBe(OID_SHA1_WITH_RSA);
  }, 20_000);

  it('el subject son exactamente 4 RDN en el orden de §1.1, con el tipo ASN.1 correcto', async () => {
    const par = await generarParCSD();
    const der = generarCSR(entradaBase(par));
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));

    const attrs = csr.subject.attributes;
    expect(attrs).toHaveLength(4);

    // #1 x500UniqueIdentifier — PrintableString
    expect(attrs[0]?.type).toBe(OID_X500_UID);
    expect(attrs[0]?.valueTagClass).toBe(forge.asn1.Type.PRINTABLESTRING);
    // #2 serialNumber — PrintableString
    expect(attrs[1]?.type).toBe(OID_SERIAL_NUMBER);
    expect(attrs[1]?.valueTagClass).toBe(forge.asn1.Type.PRINTABLESTRING);
    // #3 O (persona moral, RFC de 12 caracteres) — UTF8String
    expect(attrs[2]?.type).toBe(OID_O);
    expect(attrs[2]?.valueTagClass).toBe(forge.asn1.Type.UTF8);
    // #4 OU — UTF8String
    expect(attrs[3]?.type).toBe(OID_OU);
    expect(attrs[3]?.valueTagClass).toBe(forge.asn1.Type.UTF8);

    // CN NO debe estar presente en la rama persona moral.
    expect(attrs.find((a) => a.type === OID_CN)).toBeUndefined();
  }, 20_000);

  it('copia 2.5.4.45 y 2.5.4.5 verbatim del subject de la e.firma (incluido el espacio inicial)', async () => {
    const par = await generarParCSD();
    const der = generarCSR(entradaBase(par));
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));

    const attrs = csr.subject.attributes;
    expect(String(attrs[0]?.value)).toBe(X500_UID_ESPERADO);
    expect(String(attrs[1]?.value)).toBe(SERIAL_NUMBER_ESPERADO);
    // El valor de la RDN #2 no debe quedar "trimeado": pierde el espacio inicial si se
    // hace mal (§1.2).
    expect(String(attrs[1]?.value).startsWith(' ')).toBe(true);
  }, 20_000);

  it('usa la razón social y la sucursal recibidas para O y OU respectivamente', async () => {
    const par = await generarParCSD();
    const der = generarCSR(entradaBase(par));
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));

    const attrs = csr.subject.attributes;
    expect(String(attrs[2]?.value)).toBe('ACCEM SERVICIOS EMPRESARIALES SC');
    expect(String(attrs[3]?.value)).toBe('Matriz');
  }, 20_000);

  it('usa CN (no O) cuando el RFC tiene 13 caracteres (persona física, §1.3)', async () => {
    const par = await generarParCSD();
    const entrada = entradaBase(par);
    // RFC sintético de 13 caracteres solo para activar la rama; certificadoEfirma se
    // reutiliza como fuente verbatim de 2.5.4.45/2.5.4.5, tal como indican las
    // instrucciones de la tarea (no hace falta un .cer real de persona física).
    entrada.rfc = 'AAAA010101AAA';
    expect(entrada.rfc).toHaveLength(13);
    entrada.razonSocial = 'PERSONA FISICA DE PRUEBA';

    const der = generarCSR(entrada);
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));
    expect(csr.verify()).toBe(true);

    const attrs = csr.subject.attributes;
    expect(attrs).toHaveLength(4);
    expect(attrs[2]?.type).toBe(OID_CN);
    expect(attrs[2]?.valueTagClass).toBe(forge.asn1.Type.UTF8);
    expect(String(attrs[2]?.value)).toBe('PERSONA FISICA DE PRUEBA');
    expect(attrs.find((a) => a.type === OID_O)).toBeUndefined();
  }, 20_000);

  it('incluye challengePassword obligatorio igual a la fórmula de §1.4 (recalculada aquí, no vía el helper de la implementación)', async () => {
    const par = await generarParCSD();
    const der = generarCSR(entradaBase(par));
    const csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(der)));

    const challenge = csr.attributes.find((a) => a.type === OID_CHALLENGE_PASSWORD);
    expect(challenge).toBeDefined();
    expect(challenge?.valueTagClass).toBe(forge.asn1.Type.PRINTABLESTRING);

    const x = X500_UID_ESPERADO;
    const interno = b64Sha1(x + x);
    const esperado = b64Sha1(x + interno);
    expect(String(challenge?.value)).toBe(esperado);
  }, 20_000);

  it('lanza ArchivoInvalidoError si la e.firma no trae serialNumber', async () => {
    const par = await generarParCSD();
    // sintetica.cer trae 2.5.4.45 pero NO 2.5.4.5 (ver tests/fixtures/README.md) — es
    // exactamente el caso borde de un .cer sin uno de los dos atributos.
    const certificadoSinSerialNumber = parsearCertificado(sinteticaCerBytes).certificado;
    const entrada = entradaBase(par);
    entrada.certificadoEfirma = certificadoSinSerialNumber;

    expect(() => generarCSR(entrada)).toThrow(ArchivoInvalidoError);
  }, 20_000);

  it('lanza ArchivoInvalidoError si la e.firma no trae x500UniqueIdentifier', async () => {
    const par = await generarParCSD();
    // Ninguna fixture real carece de 2.5.4.45 (siempre está: es el RFC). Se simula
    // quitándolo de una copia mutable del subject de un certificado real, para probar la
    // rama simétrica de `valorVerbatim` sin inventar un .cer sintético nuevo.
    const certificadoSinX500Uid = parsearCertificado(fielCerBytes).certificado;
    certificadoSinX500Uid.subject.attributes = certificadoSinX500Uid.subject.attributes.filter(
      (a) => a.type !== OID_X500_UID,
    );
    const entrada = entradaBase(par);
    entrada.certificadoEfirma = certificadoSinX500Uid;

    expect(() => generarCSR(entrada)).toThrow(ArchivoInvalidoError);
  }, 20_000);
});
