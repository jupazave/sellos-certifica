export function selectorArchivo(
  etiqueta: string,
  onBytes: (bytes: Uint8Array, nombre: string) => void,
): HTMLElement {
  const raiz = document.createElement('label');
  raiz.className = 'selector-archivo';
  const texto = document.createElement('span');
  texto.textContent = etiqueta;
  const input = document.createElement('input');
  input.type = 'file';
  input.addEventListener('change', async () => {
    const archivo = input.files?.[0];
    if (!archivo) return;
    onBytes(new Uint8Array(await archivo.arrayBuffer()), archivo.name);
  });
  raiz.append(texto, input);
  return raiz;
}

export function alerta(tipo: 'ok' | 'aviso' | 'error', mensaje: string): HTMLElement {
  const div = document.createElement('div');
  div.className = `alerta alerta-${tipo}`;
  div.setAttribute('role', tipo === 'error' ? 'alert' : 'status');
  div.textContent = mensaje;
  return div;
}

export function campoTexto(
  etiqueta: string,
  opciones: { tipo?: 'text' | 'password'; valor?: string } = {},
): { raiz: HTMLElement; input: HTMLInputElement } {
  const raiz = document.createElement('label');
  raiz.className = 'campo-texto';
  const texto = document.createElement('span');
  texto.textContent = etiqueta;
  const input = document.createElement('input');
  input.type = opciones.tipo ?? 'text';
  input.value = opciones.valor ?? '';
  raiz.append(texto, input);
  return { raiz, input };
}
