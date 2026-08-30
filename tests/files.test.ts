// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { descargarArchivo } from '../src/util/files';

function espiarObjectUrl(): { blob: () => Blob | undefined; creadas: string[]; revocadas: string[] } {
  let capturado: Blob | undefined;
  const creadas: string[] = [];
  const revocadas: string[] = [];
  vi.spyOn(URL, 'createObjectURL').mockImplementation((objeto) => {
    if (objeto instanceof Blob) capturado = objeto;
    const url = `blob:prueba-${creadas.length}`;
    creadas.push(url);
    return url;
  });
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation((url) => {
    revocadas.push(url);
  });
  return { blob: () => capturado, creadas, revocadas };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe('descargarArchivo', () => {
  it('descarga exactamente los bytes de la vista, no el búfer completo', async () => {
    const { blob } = espiarObjectUrl();
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
    const { blob } = espiarObjectUrl();
    const original = new Uint8Array([10, 20, 30]);

    descargarArchivo('CSD_prueba.key', original);
    original.fill(0); // mutar después de encolar la descarga

    const generado = blob();
    const bytes = new Uint8Array((await generado?.arrayBuffer()) ?? new ArrayBuffer(0));
    expect(bytes).toEqual(new Uint8Array([10, 20, 30]));
  });

  it('no revoca la URL en el mismo turno: revocarla antes aborta la descarga', () => {
    vi.useFakeTimers();
    const { creadas, revocadas } = espiarObjectUrl();

    descargarArchivo('CSD_prueba.key', new Uint8Array([1, 2, 3]));

    expect(creadas).toHaveLength(1);
    expect(revocadas).toEqual([]); // la descarga aún no arranca

    vi.runAllTimers();
    expect(revocadas).toEqual(creadas);
  });

  it('revoca la URL de cada descarga cuando se encadenan .key y .sdg', () => {
    vi.useFakeTimers();
    const { creadas, revocadas } = espiarObjectUrl();

    descargarArchivo('CSD_prueba.key', new Uint8Array([1]));
    descargarArchivo('CSD_prueba.sdg', new Uint8Array([2]));

    expect(creadas).toHaveLength(2);
    expect(revocadas).toEqual([]);

    vi.runAllTimers();
    expect(revocadas).toEqual(creadas);
  });
});
