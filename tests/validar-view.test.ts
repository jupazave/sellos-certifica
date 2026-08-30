// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import forge from 'node-forge';
import { describe, expect, it } from 'vitest';
import { descifrarLlave } from '../src/crypto/efirma';
import { aBytes } from '../src/util/bytes';
import { validar, vistaValidar } from '../src/ui/validar-view';

const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const sinteticaKey = new Uint8Array(readFileSync('tests/fixtures/sintetica.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md

// Certificado sintético para la prueba de regresión XSS de vistaValidar (abajo): reutiliza
// la llave privada real de la fixture fiel.key solo para autofirmar un certificado con un
// CN hostil. parsearCertificado no valida la firma ni la cadena de CA (src/crypto/efirma.ts
// solo parsea la estructura DER), así que cualquier DER bien formado sirve para probar cómo
// se renderiza un subject atacante-controlado — no hace falta generar un par de llaves
// nuevo (más lento, forge.pki.rsa.generateKeyPair es JS puro) ni agregar una fixture nueva.
function certificadoConCNHostil(cn: string): Uint8Array {
  const privada = descifrarLlave(fielKey, CONTRASENA);
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.setRsaPublicKey(privada.n, privada.e);
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(2020, 0, 1);
  cert.validity.notAfter = new Date(2030, 0, 1);
  const subject = [{ name: 'commonName', value: cn }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.sign(privada, forge.md.sha256.create());
  return aBytes(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes());
}

describe('validar (lógica pura)', () => {
  it('con .cer reporta datos y vigencia', () => {
    const r = validar({ cer: fielCer });
    expect(r.certificado?.rfc).toMatch(/^[A-ZÑ&0-9]{12,13}$/);
    expect(r.vigencia).toMatch(/^(vigente|por_vencer|vencido)$/);
  });

  it('con .key y contraseña reporta si es correcta', () => {
    expect(validar({ key: fielKey, contrasena: CONTRASENA }).contrasenaCorrecta).toBe(true);
    expect(validar({ key: fielKey, contrasena: 'mala' }).contrasenaCorrecta).toBe(false);
  });

  it('con ambos reporta pareja', () => {
    expect(validar({ cer: fielCer, key: fielKey, contrasena: CONTRASENA }).pareja).toBe(true);
    expect(
      validar({ cer: fielCer, key: sinteticaKey, contrasena: 'sintetica123' }).pareja,
    ).toBe(false);
  });

  it('con bytes basura reporta error en español', () => {
    const r = validar({ cer: new Uint8Array([1, 2, 3]) });
    expect(r.error).toContain('certificado');
  });
});

describe('vistaValidar (DOM)', () => {
  it('renderiza los dos selectores de archivo y el campo de contraseña', () => {
    const vista = vistaValidar();
    const archivos = vista.querySelectorAll<HTMLInputElement>('input[type="file"]');
    expect(archivos.length).toBe(2);
    expect(archivos[0]?.accept).toBe('.cer');
    expect(archivos[1]?.accept).toBe('.key');
    expect(vista.querySelector('input[type="password"]')).not.toBeNull();
  });

  it('un CN con markup se pinta como texto, no como HTML (regresión XSS)', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const cerHostil = certificadoConCNHostil(payload);

    const vista = vistaValidar();
    const inputCer = vista.querySelector<HTMLInputElement>('input[type="file"]')!;
    // slice() copia a un ArrayBuffer propio: BlobPart exige ArrayBufferView<ArrayBuffer> y
    // Uint8Array admite SharedArrayBuffer (mismo patrón que src/util/files.ts).
    const archivo = new File([cerHostil.slice()], 'hostil.cer');
    const dt = new DataTransfer();
    dt.items.add(archivo);
    inputCer.files = dt.files;
    inputCer.dispatchEvent(new Event('change'));
    // el listener de selectorArchivo es async (espera a archivo.arrayBuffer())
    await new Promise((r) => setTimeout(r, 0));

    // el payload debe aparecer como texto literal…
    expect(vista.textContent).toContain(payload);
    // …pero jamás haberse interpretado como HTML: cero elementos <img> creados.
    expect(vista.querySelector('img')).toBeNull();
  });
});
