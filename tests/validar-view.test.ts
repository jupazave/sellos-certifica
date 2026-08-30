// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { validar, vistaValidar } from '../src/ui/validar-view';

const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const sinteticaKey = new Uint8Array(readFileSync('tests/fixtures/sintetica.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md

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
    expect(vista.querySelectorAll('input[type="file"]').length).toBe(2);
    expect(vista.querySelector('input[type="password"]')).not.toBeNull();
  });
});
