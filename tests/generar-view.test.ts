// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ejecutarGeneracion, validarFormulario, vistaGenerar } from '../src/ui/generar-view';
import { descifrarLlave } from '../src/crypto/efirma';

// Fixtures reales del SAT — ver tests/fixtures/README.md. RFC de pruebas AAA010101AAA
// (12 caracteres) => persona moral; es el que documentan las fixtures del repo, no el
// EKU9003173C9 que asumía el diseño original (ver nota de discovery en ese README).
const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md
const RFC = 'AAA010101AAA';
const RAZON_SOCIAL = 'ACCEM SERVICIOS EMPRESARIALES SC';

describe('validarFormulario', () => {
  const base = {
    rfc: RFC,
    razonSocial: RAZON_SOCIAL,
    sucursal: 'Matriz',
    contrasena: 'Secreta123',
    confirmacion: 'Secreta123',
  };

  it('acepta un formulario completo', () => {
    expect(validarFormulario(base)).toBeNull();
  });

  it('rechaza RFC vacío', () => {
    expect(validarFormulario({ ...base, rfc: '   ' })).not.toBeNull();
  });

  it('rechaza RFC con formato inválido', () => {
    expect(validarFormulario({ ...base, rfc: '123' })).not.toBeNull();
  });

  it('rechaza razón social vacía', () => {
    expect(validarFormulario({ ...base, razonSocial: '   ' })).not.toBeNull();
  });

  it('rechaza contraseña corta', () => {
    expect(validarFormulario({ ...base, contrasena: 'corta', confirmacion: 'corta' })).toContain('8');
  });

  it('rechaza confirmación distinta', () => {
    expect(validarFormulario({ ...base, confirmacion: 'Otra12345' })).toContain('coinciden');
  });

  it('rechaza campos vacíos', () => {
    expect(validarFormulario({ ...base, sucursal: '  ' })).not.toBeNull();
  });

  // docs/reference/sdg-format.md §1.7 — restricciones de captura de Certifica
  // (mx/sat/gob/recursos/solcedi_mensajes.properties). No aplican aquí las reglas de
  // "dos sucursales con el mismo nombre" ni "máximo 30 sucursales": esta app genera una
  // sola sucursal por corrida, así que esas reglas de lote no tienen equivalente en el
  // formulario.
  describe('§1.7 restricciones de sucursal', () => {
    it('acepta una sucursal de exactamente 64 caracteres', () => {
      expect(validarFormulario({ ...base, sucursal: 'A'.repeat(64) })).toBeNull();
    });

    it('rechaza una sucursal de más de 64 caracteres', () => {
      const error = validarFormulario({ ...base, sucursal: 'A'.repeat(65) });
      expect(error).not.toBeNull();
      expect(error).toContain('64');
    });

    it.each(['/', '\\', ':', '*', '?', '"', '<', '>', '$', '|'])(
      'rechaza una sucursal que contiene el carácter prohibido %s',
      (caracter) => {
        const error = validarFormulario({ ...base, sucursal: `Matriz${caracter}Norte` });
        expect(error).not.toBeNull();
      },
    );

    it('acepta una sucursal con espacios y acentos (no están prohibidos)', () => {
      expect(validarFormulario({ ...base, sucursal: 'Cañón Sur' })).toBeNull();
    });
  });

  // §1.7: "Contraseña de la clave privada: mín. 8, máx. 256 caracteres" (ERR_M10).
  describe('§1.7 restricciones de contraseña', () => {
    it('acepta una contraseña de exactamente 256 caracteres', () => {
      const limite = 'a'.repeat(256);
      expect(validarFormulario({ ...base, contrasena: limite, confirmacion: limite })).toBeNull();
    });

    it('rechaza una contraseña de más de 256 caracteres', () => {
      const larga = 'a'.repeat(257);
      const error = validarFormulario({ ...base, contrasena: larga, confirmacion: larga });
      expect(error).not.toBeNull();
      expect(error).toContain('256');
    });
  });
});

describe('ejecutarGeneracion (flujo completo con fixtures)', () => {
  it('produce .key descifrable y .sdg no vacío con nombre correcto', async () => {
    const r = await ejecutarGeneracion({
      cer: fielCer,
      key: fielKey,
      contrasenaEfirma: CONTRASENA,
      rfc: RFC,
      razonSocial: RAZON_SOCIAL,
      sucursal: 'Matriz',
      contrasenaCsd: 'Secreta123',
    });
    expect(r.nombre).toMatch(/^CSD_Matriz_AAA010101AAA_\d{8}$/);
    expect(r.sdgDer.length).toBeGreaterThan(500);
    const llave = descifrarLlave(r.keyDer, 'Secreta123');
    expect(llave.n.bitLength()).toBe(2048);
  }, 60_000);
});

describe('vistaGenerar (DOM)', () => {
  it('renderiza selectores de e.firma y campos del formulario', () => {
    const vista = vistaGenerar();
    expect(vista.querySelectorAll('input[type="file"]').length).toBe(2);
    expect(vista.querySelectorAll('input[type="password"]').length).toBe(3); // e.firma + CSD + confirmación
    expect(vista.querySelector('button')).not.toBeNull();
  });
});
