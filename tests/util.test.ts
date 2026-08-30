import { describe, expect, it } from 'vitest';
import {
  ArchivoInvalidoError,
  ContrasenaIncorrectaError,
  SellosError,
} from '../src/util/errors';
import { aBinario, aBytes } from '../src/util/bytes';
import { nombreBase } from '../src/util/files';

describe('errores tipados', () => {
  it('tienen mensaje en español por defecto y son SellosError', () => {
    const err = new ContrasenaIncorrectaError();
    expect(err).toBeInstanceOf(SellosError);
    expect(err.message).toBe('La contraseña no descifra esta llave privada.');
    expect(new ArchivoInvalidoError('otro mensaje').message).toBe('otro mensaje');
  });
});

describe('bytes', () => {
  it('aBinario/aBytes hacen round-trip', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    expect(aBytes(aBinario(original))).toEqual(original);
  });
});

describe('nombreBase', () => {
  it('arma CSD_<sucursal>_<RFC>_<AAAAMMDD> saneando la sucursal', () => {
    const fecha = new Date(2026, 7, 29); // 29-ago-2026
    expect(nombreBase('Matriz Centro', 'EKU9003173C9', fecha)).toBe(
      'CSD_Matriz_Centro_EKU9003173C9_20260829',
    );
  });
});
