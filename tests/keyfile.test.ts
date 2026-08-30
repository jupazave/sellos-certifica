import forge from 'node-forge';
import { describe, expect, it } from 'vitest';
import { generarParCSD } from '../src/crypto/keygen';
import { cifrarLlaveCSD } from '../src/crypto/keyfile';
import { descifrarLlave } from '../src/crypto/efirma';
import { ContrasenaIncorrectaError } from '../src/util/errors';
import { aBinario } from '../src/util/bytes';

// OIDs de docs/reference/sdg-format.md §4.1 — el formato .key del SAT es PKCS#8
// EncryptedPrivateKeyInfo con PBES2 (no el PBE de PKCS#12 que produce
// forge.pki.encryptPrivateKeyInfo({algorithm: '3des'})).
const OID_PBES2 = '1.2.840.113549.1.5.13';
const OID_PBKDF2 = '1.2.840.113549.1.5.12';
const OID_DES_EDE3_CBC = '1.2.840.113549.3.7';
const ITERACIONES_ESPERADAS = 2048;

// Helpers de traversal tipado para nodos forge.asn1.Asn1 — `.value` es `Bytes | Asn1[]`
// (string para nodos primitivos, arreglo para SEQUENCE/SET), y con
// `noUncheckedIndexedAccess` cualquier acceso indexado da `T | undefined`. Estas
// funciones afirman la forma esperada y lanzan si no coincide, en vez de silenciar el
// tipo con `as`/`!`.
function hijo(nodo: forge.asn1.Asn1, indice: number): forge.asn1.Asn1 {
  if (!Array.isArray(nodo.value)) throw new Error('se esperaba un nodo ASN.1 constructed (SEQUENCE)');
  const item = nodo.value[indice];
  if (!item) throw new Error(`nodo ASN.1 sin hijo en el índice ${indice}`);
  return item;
}

function bytesDe(nodo: forge.asn1.Asn1): string {
  if (typeof nodo.value !== 'string') {
    throw new Error('se esperaba un nodo ASN.1 primitivo (OID/OCTET STRING/INTEGER)');
  }
  return nodo.value;
}

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

  it('hace round-trip con una contraseña no-ASCII (ñ) — §4.5', async () => {
    // §4.5: PBKDF2 deriva de bytes, no de caracteres. Si la contraseña no pasa por
    // UTF-8 antes de PBKDF2, una contraseña con "ñ" produce una llave que solo esta
    // misma ruta de código puede reabrir (y que ni OpenSSL ni el software del PAC
    // pueden abrir). Este test reproduce el caso empírico documentado en §4.5.
    const { privada } = await generarParCSD();
    const der = cifrarLlaveCSD(privada, 'contrañseña');
    const recuperada = descifrarLlave(der, 'contrañseña');
    expect(recuperada.n.compareTo(privada.n)).toBe(0);
  }, 20_000);

  it('produce EncryptedPrivateKeyInfo con PBES2 + PBKDF2-HMAC-SHA1 (2048 iter) + des-EDE3-CBC — §4.1', async () => {
    // Aserciones estructurales sobre el DER (independientes de que descifrarLlave lo
    // pueda abrir): esto es lo que distingue el formato real del SAT (PBES2) del PBE
    // legado de PKCS#12 (pbeWithSHAAnd3-KeyTripleDES-CBC) que produce por defecto
    // forge.pki.encryptPrivateKeyInfo({algorithm: '3des'}) — ver §4.4 "trampa verificada".
    const { privada } = await generarParCSD();
    const der = cifrarLlaveCSD(privada, 'MiContrasena123');

    const epki = forge.asn1.fromDer(aBinario(der));
    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData }
    const encryptionAlgorithm = hijo(epki, 0);
    const algOid = forge.asn1.derToOid(bytesDe(hijo(encryptionAlgorithm, 0)));
    expect(algOid).toBe(OID_PBES2);

    // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
    const pbes2Params = hijo(encryptionAlgorithm, 1);
    const keyDerivationFunc = hijo(pbes2Params, 0);
    const encryptionScheme = hijo(pbes2Params, 1);

    const kdfOid = forge.asn1.derToOid(bytesDe(hijo(keyDerivationFunc, 0)));
    expect(kdfOid).toBe(OID_PBKDF2);

    // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER, ... }
    const pbkdf2Params = hijo(keyDerivationFunc, 1);
    const salt = bytesDe(hijo(pbkdf2Params, 0));
    const iterationCount = forge.asn1.derToInteger(bytesDe(hijo(pbkdf2Params, 1)));
    expect(salt.length).toBe(8); // salt de 8 bytes, §4.1
    expect(iterationCount).toBe(ITERACIONES_ESPERADAS);
    // Sin keyLength ni prf explícitos: así es como BouncyCastle (y por lo tanto
    // Certifica) los omite — ver §4.4.
    expect(Array.isArray(pbkdf2Params.value) && pbkdf2Params.value.length).toBe(2);

    const encOid = forge.asn1.derToOid(bytesDe(hijo(encryptionScheme, 0)));
    expect(encOid).toBe(OID_DES_EDE3_CBC);
    const iv = bytesDe(hijo(encryptionScheme, 1));
    expect(iv.length).toBe(8); // IV de 8 bytes, §4.1
  }, 20_000);

  it('genera salt e IV distintos en cada llamada (CSPRNG, no derivados del texto plano) — §4.2', async () => {
    // §4.2: Certifica deriva salt/IV del propio PKCS#8 en texto plano, lo que hace el
    // IV casi constante (los primeros 8 bytes de un PKCS#8 DER son casi siempre los
    // mismos). La instrucción explícita de la Tarea 7 es usar CSPRNG en su lugar.
    const { privada } = await generarParCSD();
    const der1 = cifrarLlaveCSD(privada, 'MiContrasena123');
    const der2 = cifrarLlaveCSD(privada, 'MiContrasena123');
    expect(aBinario(der1)).not.toBe(aBinario(der2));
  }, 20_000);
});
