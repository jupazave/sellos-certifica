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
  numeroSerie: string; // decodificado a ASCII, ej. "30001000000300023685"
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

// `@types/node-forge` tipa `CertificateField.valueTagClass` como `asn1.Class` cuando en
// realidad es un tag de `asn1.Type` (mismo error de tipos ya documentado y verificado en
// tiempo de ejecución en src/crypto/csr.ts y src/crypto/sdg.ts). Se ensancha a `number`
// para poder comparar sin que TypeScript rechace la comparación entre dos enums distintos.
const TAG_UTF8: number = forge.asn1.Type.UTF8;

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
  // El CN del subject de un certificado real del SAT es un UTF8String (§1.1 de
  // docs/reference/sdg-format.md aplica al CSR, pero el certificado *emitido* también usa
  // UTF8String para el nombre — confirmado contra las fixtures reales). forge nunca
  // decodifica UTF8String al parsear (deja los bytes UTF-8 crudos en `.value`, uno por code
  // unit / Latin-1 — mismo comportamiento documentado en csr.ts y sdg.ts), así que sin este
  // paso una razón social con acentos/ñ llega como mojibake ("PEÑA" -> "PEÃ‘A") a esta vista
  // y, peor, al reusarse como prefill en generar-view se re-codifica a UTF-8 sobre bytes ya
  // corruptos, doblemente codificando el CN/O del CSR resultante.
  const attrCN = attrs.find((a) => a.shortName === 'CN');
  let razonSocial = typeof attrCN?.value === 'string' ? attrCN.value : '';
  if (attrCN?.valueTagClass === TAG_UTF8) {
    try {
      razonSocial = forge.util.decodeUtf8(razonSocial);
    } catch {
      // Bytes malformados (no UTF-8 válido): se deja crudo en vez de reventar el parseo
      // completo del certificado por un campo de solo-display.
    }
  }
  // Heurística SAT (confirmada contra las fixtures de la Tarea 2, ver
  // tests/fixtures/README.md "Heuristica de OU"): los CSD llevan el nombre de la
  // sucursal en el atributo OU del subject; la e.firma (FIEL) nunca trae OU.
  const tipo: TipoCertificado = attrs.some((a) => a.shortName === 'OU') ? 'CSD' : 'FIEL';

  const serieHex = cert.serialNumber.replace(/^0+/, '');
  const numeroSerie =
    serieHex.match(/.{2}/g)?.map((h) => String.fromCharCode(parseInt(h, 16))).join('') ?? serieHex;

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
    // La contraseña debe pasar por UTF-8 antes de llegar a forge: las funciones de bajo
    // nivel de forge tratan un string de JS como binario/Latin-1 (un byte por code unit),
    // así que una contraseña con acentos o "ñ" produciría bytes distintos a los que usó
    // OpenSSL/el SAT para cifrar. Para contraseñas ASCII (el caso común) esto es
    // identidad; ver docs/reference/sdg-format.md §4.5.
    pki = forge.pki.decryptPrivateKeyInfo(epki, forge.util.encodeUtf8(contrasena));
  } catch (e) {
    if (e instanceof Error) {
      // forge adjunta `.errors` (el arreglo de fallas de forge.asn1.validate) solo
      // cuando lo que se le pasó no tiene la FORMA de un EncryptedPrivateKeyInfo —p.ej.
      // si el usuario sube un .cer en el campo de la llave—. Esa validación de forma
      // ocurre antes de que la contraseña se use para nada, así que es un problema del
      // archivo, no de la contraseña. Verificado empíricamente (no solo leyendo el
      // código): 21 combinaciones de contraseña incorrecta × las 3 llaves reales de las
      // fixtures nunca adjuntan `.errors` ni incluyen "Unsupported" en el mensaje; en
      // cambio, tanto csd.cer como fiel.cer metidos en el campo de la llave sí adjuntan
      // `.errors` (ver node_modules/node-forge/lib/pbe.js líneas ~366, ~794, ~881, los
      // tres únicos lugares donde forge hace `error.errors = errors`).
      if ('errors' in e) {
        throw new ArchivoInvalidoError(
          'El archivo no tiene la forma de una llave privada cifrada del SAT (¿subiste un ' +
            '.cer en el campo de la llave?).',
        );
      }
      // forge solo reconoce tres OID de cifrado (PBES2, y dos variantes de PBE de
      // PKCS#12); para cualquier otro —notablemente el PBES1 pbeWithMD5AndDES/
      // pbeWithMD2AndDES de las e.firma más antiguas del SAT— no devuelve null, sino que
      // lanza un Error cuyo mensaje contiene "Unsupported OID" (ver
      // node_modules/node-forge/lib/pbe.js, pki.pbe.getCipher/getCipherForPBES2). Ese
      // caso también es un archivo con un formato que no podemos leer, no una
      // contraseña incorrecta, así que se distingue aquí para no decirle al usuario que
      // su contraseña está mal cuando el problema es el formato de la llave.
      if (e.message.includes('Unsupported')) {
        throw new ArchivoInvalidoError(
          'Esta llave usa un cifrado antiguo no soportado (PBES1). Vuelve a descargar tu ' +
            'e.firma o CSD desde el portal del SAT para obtener una llave en el formato actual.',
        );
      }
    }
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
