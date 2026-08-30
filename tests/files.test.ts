// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { descargarArchivo } from '../src/util/files';

function capturarBlob(): () => Blob | undefined {
  let capturado: Blob | undefined;
  vi.spyOn(URL, 'createObjectURL').mockImplementation((objeto) => {
    if (objeto instanceof Blob) capturado = objeto;
    return 'blob:prueba';
  });
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
  return () => capturado;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('descargarArchivo', () => {
  it('descarga exactamente los bytes de la vista, no el búfer completo', async () => {
    const blob = capturarBlob();
    // subarray comparte búfer: byteOffset 2, byteLength 3.
    const vista = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]).subarray(2, 5);

    descargarArchivo('CSD_prueba.key', vista);

    const generado = blob();
    expect(generado).toBeInstanceOf(Blob);
    expect(generado?.type).toBe('application/octet-stream');
    const bytes = new Uint8Array((await generado?.arrayBuffer()) ?? new ArrayBuffer(0));
    expect(bytes).toEqual(new Uint8Array([2, 3, 4]));
  });

  it('no comparte memoria con el arreglo original', async () => {
    const blob = capturarBlob();
    const original = new Uint8Array([10, 20, 30]);

    descargarArchivo('CSD_prueba.key', original);
    original.fill(0); // mutar después de encolar la descarga

    const generado = blob();
    const bytes = new Uint8Array((await generado?.arrayBuffer()) ?? new ArrayBuffer(0));
    expect(bytes).toEqual(new Uint8Array([10, 20, 30]));
  });
});
