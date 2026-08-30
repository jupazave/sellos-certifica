import forge from 'node-forge';
import { aBinario } from '../util/bytes';

export async function generarParCSD(): Promise<{
  privada: forge.pki.rsa.PrivateKey;
  publica: forge.pki.rsa.PublicKey;
}> {
  const par = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  );
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', par.privateKey));
  const privada = forge.pki.privateKeyFromAsn1(
    forge.asn1.fromDer(aBinario(pkcs8)),
  ) as forge.pki.rsa.PrivateKey;
  const publica = forge.pki.setRsaPublicKey(privada.n, privada.e);
  return { privada, publica };
}
