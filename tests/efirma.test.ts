import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { aBytes } from '../src/util/bytes';
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

// Valores documentados en tests/fixtures/README.md (RFC de pruebas real del SAT,
// AAA010101AAA / "ACCEM SERVICIOS EMPRESARIALES SC" — NO el EKU9003173C9 del brief
// original, que era el RFC que el proyecto anticipaba antes de descargar las fixtures
// reales; ver README.md para la nota de discovery completa).
const CONTRASENA = '12345678a'; // fiel.key y csd.key comparten esta contraseña
const ESPERADO_RFC = 'AAA010101AAA';
const ESPERADO_RAZON = 'ACCEM SERVICIOS EMPRESARIALES SC';

// Llave PKCS#8 con cifrado legado PBES1 (pbeWithMD5AndDES-CBC), generada localmente y
// honestamente con OpenSSL para probar el mensaje de error de la Tarea 5 (controller
// update 3): forge no soporta este OID y lanza un Error tipo "Unsupported OID" en vez de
// devolver null, así que descifrarLlave debe distinguirlo de una contraseña incorrecta.
// No se agrega como archivo a tests/fixtures/ (no hay fixture real de este tipo) — se
// embebe aquí en base64. Contraseña usada al cifrar: "test1234". Reproducible con:
//   openssl genrsa -out plain.pem 1024
//   openssl pkcs8 -topk8 -v1 PBE-MD5-DES -in plain.pem -out legacy.der -outform DER \
//     -passout pass:test1234
const LLAVE_PBES1_LEGADA_B64 =
  'MIICoTAbBgkqhkiG9w0BBQMwDgQIOoxuaXOHPKoCAggABIICgN0Gs0FKF2kbUerE7o+pdfSki0d04FgwZ+US4unbWp1RYDHUH6NRU5Ti8Hd8C6pwSCBEhQ0U8NIYRPRY9fBcKToo1PmOoCRQ47Gc9p9X4deI6A391J2lcjo+7QfEvZfme0buXO+pyZQgIQvfIB8dLi704Y1/80cplKYpN0dFBQgbTh0iYqULDwJyJ8lpR+kRoHd+jYs8H/3K8kDVvwQ34Uiiw6nsGHpHOq/KBeg+3atl/a+Y6nZAhTlPptd28hmoTD3jHd2uVIdKwFc73FVVxf5kjaCS/zcWiNL3rFf40YXQdvmx1swL9kEYXoWDIjdRAG08aqqlhGWsWS2LEv/p/2GDKLGnIcb//dK8F2lCqnZo3Mm9nn5Tj+RbP/9ObeVQU0AC1LbQ6qNvoUtiVW4Ad1Jsop1+FQybxWLKun2Ld6cO1fPHo8ZPmvAlvfrCgDIn36XKrfZ359HP+QhTXIItTpllPBek54CRfsA68dbGIKXgF50EVXkB+rDKyom4x2l4Zs35iGWsBNwXWzhzbEoogD7sU45JEbKMYmUXsmW0lSkahMGWhoF9r9ctkjOUvnvswgkMD/NYhPTJ6o8kK0AAExDhWau2VZoky4u4uYGfWAWJ3huepx8tFwD8rH1NnCAzTZ2fpxlbbxi9k6jVMBkXAGV2K2pujkDb4et/v3zuh+3dlOEpjIwW72bwEHeMdiAEeIVMIaHAeRoiU7RGDrPRrKZGoX03fvuzYu6yeWzfCFhumO5Vec3sg2DHuSWwKGcixD1w/8wkIYb+g895/vz99+rXDRJ47+Z9FqkOAEu0QIq7C8hrZmi4rp0Z07/PLbs8lkW9QRq2Us49j/zNlpwIUAU=';

// `@types/node-forge` tipa `CertificateField.valueTagClass` como `asn1.Class` cuando en
// realidad es un tag de `asn1.Type` (mismo error de tipos ya documentado en src/crypto/
// csr.ts y src/crypto/sdg.ts). Se ensancha a `number` para poder pasarlo sin que
// TypeScript rechace la asignación entre dos enums distintos.
const TAG_UTF8: number = forge.asn1.Type.UTF8;

// Certificado sintético para la prueba de regresión de mojibake de abajo: reutiliza la
// llave privada real de fielKey solo para autofirmar un certificado con un CN UTF8String
// con acentos/ñ. parsearCertificado no valida la firma ni la cadena de CA (solo parsea la
// estructura DER), así que cualquier DER bien formado sirve — mismo patrón que
// certificadoConCNHostil en tests/validar-view.test.ts, aquí con valueTagClass UTF8
// explícito (el default de forge es PrintableString) para reproducir el caso real: un
// certificado del SAT cuyo CN es un UTF8String con bytes no ASCII.
function certificadoConCNUtf8(razonSocial: string): Uint8Array {
  const privada = descifrarLlave(fielKey, CONTRASENA);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.setRsaPublicKey(privada.n, privada.e);
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(2020, 0, 1);
  cert.validity.notAfter = new Date(2030, 0, 1);
  const subject = [{ name: 'commonName', value: razonSocial, valueTagClass: TAG_UTF8 }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.sign(privada, forge.md.sha256.create());
  return aBytes(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
}

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

  it('decodifica razonSocial cuando el CN es un UTF8String con acentos/ñ (regresión mojibake)', () => {
    // forge nunca decodifica un UTF8String al parsear un certificado: deja los bytes UTF-8
    // crudos en `.value`, uno por code unit (Latin-1). Sin decodeUtf8 esto produce mojibake
    // ("PEÑA" -> "PEÃ‘A") que se muestra tal cual en la vista validar y, al reusarse como
    // prefill en generar, se re-codifica a UTF-8 y produce un CSR con la razón social
    // doblemente codificada.
    const razonOriginal = 'PEÑA Y ASOCIADOS, DISEÑO GRÁFICO SA DE CV';
    const der = certificadoConCNUtf8(razonOriginal);
    expect(parsearCertificado(der).razonSocial).toBe(razonOriginal);
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

  it('rechaza un .cer puesto en el campo de la llave como archivo inválido, no como contraseña incorrecta', () => {
    // csd.cer es DER válido (parsea sin problema como Asn1), pero no tiene la forma de
    // un EncryptedPrivateKeyInfo. Antes de este fix, forge lanzaba un Error cuyo mensaje
    // ("...is not a supported EncryptedPrivateKeyInfo.") caía en el catch-all y se
    // reportaba como ContrasenaIncorrectaError, lo cual es engañoso: el problema es el
    // archivo, no la contraseña.
    expect(() => descifrarLlave(csdCer, CONTRASENA)).toThrow(ArchivoInvalidoError);
    expect(() => descifrarLlave(csdCer, CONTRASENA)).not.toThrow(ContrasenaIncorrectaError);
  });

  it('rechaza una llave con cifrado PBES1 legado con un mensaje claro (no "contraseña incorrecta")', () => {
    const legado = new Uint8Array(Buffer.from(LLAVE_PBES1_LEGADA_B64, 'base64'));
    expect(() => descifrarLlave(legado, 'test1234')).toThrow(ArchivoInvalidoError);
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
  const base = (hasta: Date): DatosCertificado => ({
    ...parsearCertificado(fielCer),
    validoDesde: new Date(2020, 0, 1),
    validoHasta: hasta,
  });

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
