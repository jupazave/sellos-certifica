// @vitest-environment happy-dom
import { describe, expect, it, vi } from 'vitest';
import { selectorArchivo } from '../src/ui/components';

async function seleccionar(raiz: HTMLElement, nombre: string): Promise<void> {
  const input = raiz.querySelector<HTMLInputElement>('input[type="file"]')!;
  const dt = new DataTransfer();
  dt.items.add(new File([new Uint8Array([1, 2, 3])], nombre));
  input.files = dt.files;
  input.dispatchEvent(new Event('change'));
  // el listener de selectorArchivo es async (espera a archivo.arrayBuffer())
  await new Promise((r) => setTimeout(r, 0));
}

describe('selectorArchivo con extensión obligatoria', () => {
  it('pone el atributo accept en el input para filtrar el diálogo nativo', () => {
    const raiz = selectorArchivo('Certificado (.cer)', () => {}, '.cer');
    expect(raiz.querySelector('input')!.accept).toBe('.cer');
  });

  it('rechaza un archivo con otra extensión: no procesa, avisa y limpia el input', async () => {
    const onBytes = vi.fn();
    const raiz = selectorArchivo('Certificado (.cer)', onBytes, '.cer');

    await seleccionar(raiz, 'llave.key');

    expect(onBytes).not.toHaveBeenCalled();
    expect(raiz.textContent).toContain('extensión .cer');
    expect(raiz.querySelector('input')!.value).toBe('');
  });

  it('acepta la extensión correcta sin importar mayúsculas y quita el aviso previo', async () => {
    const onBytes = vi.fn();
    const raiz = selectorArchivo('Certificado (.cer)', onBytes, '.cer');

    await seleccionar(raiz, 'malo.txt'); // provoca el aviso
    await seleccionar(raiz, 'FIEL.CER'); // válida, case-insensitive

    expect(onBytes).toHaveBeenCalledTimes(1);
    expect(onBytes.mock.calls[0]?.[1]).toBe('FIEL.CER');
    expect(raiz.textContent).not.toContain('extensión .cer');
  });

  it('sin accept, acepta cualquier extensión (compatibilidad)', async () => {
    const onBytes = vi.fn();
    const raiz = selectorArchivo('Cualquiera', onBytes);

    await seleccionar(raiz, 'archivo.lo-que-sea');

    expect(onBytes).toHaveBeenCalledTimes(1);
  });
});
