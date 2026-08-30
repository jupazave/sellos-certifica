export function selectorArchivo(
  etiqueta: string,
  onBytes: (bytes: Uint8Array, nombre: string) => void,
  accept?: string,
): HTMLElement {
  const raiz = document.createElement('label');
  raiz.className = 'selector-archivo';
  const texto = document.createElement('span');
  texto.textContent = etiqueta;
  const input = document.createElement('input');
  input.type = 'file';
  if (accept) input.accept = accept;
  const aviso = document.createElement('div');
  input.addEventListener('change', async () => {
    const archivo = input.files?.[0];
    if (!archivo) return;
    aviso.replaceChildren();
    // El atributo accept filtra el diálogo nativo, pero el sistema permite elegir
    // "Todos los archivos": la extensión se valida también aquí.
    if (accept && !archivo.name.toLowerCase().endsWith(accept.toLowerCase())) {
      aviso.append(alerta('error', `El archivo debe tener extensión ${accept}`));
      input.value = '';
      return;
    }
    onBytes(new Uint8Array(await archivo.arrayBuffer()), archivo.name);
  });
  raiz.append(texto, input, aviso);
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
