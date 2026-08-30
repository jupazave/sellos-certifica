export async function leerArchivo(archivo: File): Promise<Uint8Array> {
  return new Uint8Array(await archivo.arrayBuffer());
}

// El navegador encola la descarga como una tarea aparte: si la URL se revoca en
// el mismo turno del bucle de eventos, la descarga puede abortar antes de leer
// el blob (Firefox bug 1282407; WebKit devuelve "WebKitBlobResource error 1").
// Un segundo basta de sobra para que arranque y evita retener el blob —que aquí
// lleva material de llave— más de lo necesario.
const MS_ANTES_DE_REVOCAR = 1000;

export function descargarArchivo(nombre: string, bytes: Uint8Array): void {
  // slice() copia la vista a un ArrayBuffer propio: BlobPart exige
  // ArrayBufferView<ArrayBuffer> y Uint8Array admite SharedArrayBuffer.
  const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = nombre;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), MS_ANTES_DE_REVOCAR);
}

export function nombreBase(sucursal: string, rfc: string, fecha: Date): string {
  const saneada = sucursal.trim().replace(/[^A-Za-z0-9ÁÉÍÓÚÑáéíóúñ]+/g, '_');
  const aaaa = fecha.getFullYear();
  const mm = String(fecha.getMonth() + 1).padStart(2, '0');
  const dd = String(fecha.getDate()).padStart(2, '0');
  return `CSD_${saneada}_${rfc.toUpperCase()}_${aaaa}${mm}${dd}`;
}
