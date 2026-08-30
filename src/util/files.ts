export async function leerArchivo(archivo: File): Promise<Uint8Array> {
  return new Uint8Array(await archivo.arrayBuffer());
}

export function descargarArchivo(nombre: string, bytes: Uint8Array): void {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = nombre;
  a.click();
  URL.revokeObjectURL(url);
}

export function nombreBase(sucursal: string, rfc: string, fecha: Date): string {
  const saneada = sucursal.trim().replace(/[^A-Za-z0-9ÁÉÍÓÚÑáéíóúñ]+/g, '_');
  const aaaa = fecha.getFullYear();
  const mm = String(fecha.getMonth() + 1).padStart(2, '0');
  const dd = String(fecha.getDate()).padStart(2, '0');
  return `CSD_${saneada}_${rfc.toUpperCase()}_${aaaa}${mm}${dd}`;
}
