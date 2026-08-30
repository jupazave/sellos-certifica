import forge from 'node-forge';
import { aBytes } from '../util/bytes';

// docs/reference/sdg-format.md §4/§4.4: el `.key` de salida que produce Certifica (la
// app oficial del SAT) NO usa el PBE de PKCS#12 (`pbeWithSHAAnd3-KeyTripleDES-CBC`,
// que es lo que produce `forge.pki.encryptPrivateKeyInfo({algorithm: '3des'})`). Usa
// PKCS#8 `EncryptedPrivateKeyInfo` con **PBES2**: PBKDF2-HMAC-SHA1 + 3DES-EDE-CBC.
// forge no tiene un helper de alto nivel para esa combinación exacta — verificado
// leyendo node_modules/node-forge/lib/pbe.js: la rama PBES2 de `encryptPrivateKeyInfo`
// (`algorithm.indexOf('aes') === 0 || algorithm === 'des'`) solo cubre AES y DES simple,
// nunca 3DES — así que el `EncryptedPrivateKeyInfo` se arma a mano siguiendo la
// estructura de §4.1 ("Opción A" de §4.4).
const ITERACIONES = 2048; // §4.1: mismo valor que Certifica (tam_llave_sellos=2048)
const TAM_SALT = 8; // bytes, §4.1
const TAM_IV = 8; // bytes, §4.1 (blockSize de DES/3DES)
const TAM_LLAVE_DERIVADA = 24; // bytes = 192 bits: 3 subllaves DES de 8 bytes (3DES-EDE)

// OIDs literales de §4.1 (en vez de `forge.pki.oids['...']`: ese objeto está tipado con
// un index signature genérico, así que cualquier acceso da `string | undefined` bajo
// `noUncheckedIndexedAccess`; los literales además se comparan a simple vista contra el
// documento de referencia).
const OID_PBES2 = '1.2.840.113549.1.5.13'; // id-PBES2
const OID_PBKDF2 = '1.2.840.113549.1.5.12'; // id-PBKDF2
const OID_DES_EDE3_CBC = '1.2.840.113549.3.7'; // des-EDE3-CBC

/**
 * Cifra una llave privada RSA en el formato `.key` que produce el SAT: PKCS#8
 * `EncryptedPrivateKeyInfo` con PBES2, PBKDF2-HMAC-SHA1 (2048 iteraciones, salt de 8
 * bytes) y cifrado 3DES-EDE-CBC (IV de 8 bytes) — docs/reference/sdg-format.md §4.1.
 *
 * A diferencia de Certifica (§4.2, que deriva `salt` e `iv` de los primeros bytes del
 * propio PKCS#8 en texto plano —un IV prácticamente constante—), aquí ambos se generan
 * con CSPRNG (`forge.random.getBytesSync`). El formato no exige los valores derivados:
 * `salt` e `iv` viajan explícitos en el `EncryptedPrivateKeyInfo`, así que cualquier
 * valor aleatorio se descifra igual; es una mejora de seguridad sin costo de
 * interoperabilidad.
 */
export function cifrarLlaveCSD(privada: forge.pki.rsa.PrivateKey, contrasena: string): Uint8Array {
  const pkcs8Der = forge.asn1.toDer(forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(privada)));

  // §4.5: la contraseña debe convertirse a bytes vía UTF-8 antes de PBKDF2 — las
  // funciones de bajo nivel de forge tratan un `string` de JS como binario/Latin-1 (un
  // byte por code unit), así que una contraseña con "ñ" o acentos produciría bytes
  // distintos a los que usarían OpenSSL, Node o el software del PAC al descifrar. Sin
  // esto, la llave *parece* correcta pero nadie más (ni siquiera esta misma app en otra
  // sesión, si ahí se codificara distinto) puede volver a abrirla.
  const pwBytes = forge.util.encodeUtf8(contrasena);
  const salt = forge.random.getBytesSync(TAM_SALT);
  const iv = forge.random.getBytesSync(TAM_IV);
  const llaveDerivada = forge.pkcs5.pbkdf2(
    pwBytes,
    salt,
    ITERACIONES,
    TAM_LLAVE_DERIVADA,
    forge.md.sha1.create(),
  );

  // Una llave derivada de 24 bytes hace que el motor DES de forge encadene 3 pasadas
  // (3DES-EDE) automáticamente — node_modules/node-forge/lib/des.js valida
  // explícitamente `key.length() !== 24` para cualquier algoritmo cuyo nombre empiece
  // con "3DES". Se usa la API genérica `forge.cipher.createCipher` (en vez de la
  // deprecated `forge.des.createEncryptionCipher`, que además no tiene tipos en
  // @types/node-forge) — ambas rutas llegan al mismo motor.
  const cifrador = forge.cipher.createCipher('3DES-CBC', llaveDerivada);
  cifrador.start({ iv });
  cifrador.update(pkcs8Der);
  cifrador.finish(); // padding PKCS#5/7, §4.1
  const datosCifrados = cifrador.output.getBytes();

  // PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER }
  // Se omiten `keyLength` y `prf` (default RFC 8018 = hmacWithSHA1): así es como
  // BouncyCastle —y por lo tanto Certifica— los omite; ver §4.4, el asn1parse esperado
  // no los trae. Incluirlos sería igualmente válido, pero esto reproduce a Certifica.
  const pbkdf2Params = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, salt),
    forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.INTEGER,
      false,
      forge.asn1.integerToDer(ITERACIONES).getBytes(),
    ),
  ]);

  // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData } — §4.1
  const epki = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    // encryptionAlgorithm AlgorithmIdentifier (id-PBES2, PBES2-params)
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(
        forge.asn1.Class.UNIVERSAL,
        forge.asn1.Type.OID,
        false,
        forge.asn1.oidToDer(OID_PBES2).getBytes(),
      ),
      // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        // keyDerivationFunc AlgorithmIdentifier (id-PBKDF2, PBKDF2-params)
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(OID_PBKDF2).getBytes(),
          ),
          pbkdf2Params,
        ]),
        // encryptionScheme AlgorithmIdentifier (des-EDE3-CBC, iv)
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
          forge.asn1.create(
            forge.asn1.Class.UNIVERSAL,
            forge.asn1.Type.OID,
            false,
            forge.asn1.oidToDer(OID_DES_EDE3_CBC).getBytes(),
          ),
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, iv),
        ]),
      ]),
    ]),
    // encryptedData OCTET STRING
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, datosCifrados),
  ]);

  return aBytes(forge.asn1.toDer(epki).getBytes());
}
