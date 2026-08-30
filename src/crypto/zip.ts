// Escritor mínimo de ZIP (método STORE, sin compresión) escrito a mano: la restricción
// del proyecto es que node-forge sea la única dependencia de runtime, así que no se puede
// traer una librería de ZIP (p.ej. fflate, JSZip). Solo se necesita STORE — el .sdg
// empaqueta un puñado de .req de unos pocos KB cada uno (docs/reference/sdg-format.md
// §3.3), así que la compresión no aporta nada y evitarla simplifica bastante el código
// (no hace falta implementar DEFLATE).
//
// Formato de referencia: APPNOTE.TXT de PKWARE (ZIP File Format Specification) — Local
// File Header (§4.3.7), Central Directory File Header (§4.3.12) y End Of Central Directory
// Record (§4.3.16). No se usa Zip64 (innecesario para archivos de este tamaño) ni data
// descriptors (el tamaño y el CRC-32 se conocen de antemano, así que van directo en el
// local header).

export interface EntradaZip {
  nombre: string;
  datos: Uint8Array;
  /** Fecha/hora del archivo dentro del ZIP. Si se omite, usa EPOCA_DOS (determinístico). */
  fecha?: Date;
}

// Tabla de CRC-32 (polinomio reflejado 0xEDB88320 — el mismo que usan zlib/PNG/ZIP; IEEE
// 802.3). Construida una sola vez al cargar el módulo.
const TABLA_CRC32 = (() => {
  const tabla = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? (0xedb88320 ^ (c >>> 1)) >>> 0 : c >>> 1;
    }
    tabla[n] = c >>> 0;
  }
  return tabla;
})();

/** CRC-32 (IEEE 802.3 / zlib) de `datos`. Verificado contra los vectores estándar en tests/zip.test.ts. */
export function crc32(datos: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < datos.length; i++) {
    const indice = (crc ^ (datos[i] ?? 0)) & 0xff;
    crc = (TABLA_CRC32[indice] ?? 0) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
}

function u32le(n: number): Uint8Array {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

function concatenar(partes: Uint8Array[]): Uint8Array {
  const total = partes.reduce((suma, parte) => suma + parte.length, 0);
  const salida = new Uint8Array(total);
  let cursor = 0;
  for (const parte of partes) {
    salida.set(parte, cursor);
    cursor += parte.length;
  }
  return salida;
}

// El formato de fecha MS-DOS que usa ZIP no puede representar años anteriores a 1980. Se
// usa como default: es determinístico (no depende de `new Date()`, así que dos llamadas a
// crearZip con las mismas entradas producen bytes idénticos — útil para pruebas y para
// reproducibilidad) y es el valor neutro que ya usan otras herramientas de build
// reproducibles cuando el timestamp real no importa (que es el caso aquí: T3 concluyó en
// docs/reference/sdg-format.md §6 punto 4 que los metadatos del ZIP son irrelevantes para
// el SAT).
const EPOCA_DOS = new Date(Date.UTC(1980, 0, 1, 0, 0, 0));

// Se usan los métodos UTC (no los de hora local) para que la salida no dependa de la zona
// horaria de la máquina que ejecuta el código — importante para que las pruebas den el
// mismo resultado en cualquier entorno de CI.
function fechaMsDos(fecha: Date): { fechaDos: number; horaDos: number } {
  const f = fecha.getTime() < EPOCA_DOS.getTime() ? EPOCA_DOS : fecha;
  const anio = Math.min(f.getUTCFullYear(), 2107); // año máximo representable (1980+127)
  const fechaDos = (((anio - 1980) & 0x7f) << 9) | ((f.getUTCMonth() + 1) << 5) | f.getUTCDate();
  const horaDos =
    (f.getUTCHours() << 11) | (f.getUTCMinutes() << 5) | Math.floor(f.getUTCSeconds() / 2);
  return { fechaDos, horaDos };
}

const FIRMA_LOCAL = 0x04034b50;
const FIRMA_CENTRAL = 0x02014b50;
const FIRMA_EOCD = 0x06054b50;
const VERSION_ZIP = 20; // 2.0 — la mínima que soporta nombres largos; STORE no exige más.
const METODO_STORE = 0; // sin compresión
// Bit 11 (0x0800) del "general purpose bit flag" = language encoding flag (EFS): declara
// que el nombre de archivo está en UTF-8. Es retrocompatible con nombres ASCII puros.
const FLAG_UTF8 = 0x0800;

/**
 * Arma un archivo ZIP con las `entradas` dadas, sin comprimir (STORE). Pensado para el
 * único uso que necesita este proyecto: empaquetar el/los `.req` (CSR DER) dentro del
 * `.sdg` — docs/reference/sdg-format.md §3.1 documenta que Certifica arma este ZIP con
 * `java.util.zip.ZipOutputStream` (que comprime con DEFLATE por defecto, según §3.3);
 * aquí no se replica DEFLATE porque no aporta nada para archivos de este tamaño y el
 * formato no lo exige, solo exige que sea un ZIP válido.
 */
export function crearZip(entradas: EntradaZip[]): Uint8Array {
  const cuerposLocales: Uint8Array[] = [];
  const encabezadosCentrales: Uint8Array[] = [];
  let desplazamiento = 0;

  for (const entrada of entradas) {
    const nombreBytes = new TextEncoder().encode(entrada.nombre);
    const { datos } = entrada;
    const crc = crc32(datos);
    const { fechaDos, horaDos } = fechaMsDos(entrada.fecha ?? EPOCA_DOS);

    const camposComunes = [
      u16le(VERSION_ZIP),
      u16le(FLAG_UTF8),
      u16le(METODO_STORE),
      u16le(horaDos),
      u16le(fechaDos),
      u32le(crc),
      u32le(datos.length), // tamaño comprimido == sin comprimir (STORE)
      u32le(datos.length),
      u16le(nombreBytes.length),
      u16le(0), // extra field length
    ];

    const localHeader = concatenar([u32le(FIRMA_LOCAL), ...camposComunes, nombreBytes]);
    cuerposLocales.push(localHeader, datos);

    const encabezadoCentral = concatenar([
      u32le(FIRMA_CENTRAL),
      u16le(VERSION_ZIP), // version made by
      ...camposComunes,
      u16le(0), // file comment length
      u16le(0), // disk number start
      u16le(0), // internal file attributes
      u32le(0), // external file attributes
      u32le(desplazamiento), // offset del local header de esta entrada
      nombreBytes,
    ]);
    encabezadosCentrales.push(encabezadoCentral);

    desplazamiento += localHeader.length + datos.length;
  }

  const inicioDirectorioCentral = desplazamiento;
  const tamanoDirectorioCentral = encabezadosCentrales.reduce((s, h) => s + h.length, 0);

  const eocd = concatenar([
    u32le(FIRMA_EOCD),
    u16le(0), // número de este disco
    u16le(0), // disco donde empieza el directorio central
    u16le(entradas.length), // entradas del directorio central en este disco
    u16le(entradas.length), // entradas del directorio central en total
    u32le(tamanoDirectorioCentral),
    u32le(inicioDirectorioCentral),
    u16le(0), // longitud del comentario
  ]);

  return concatenar([...cuerposLocales, ...encabezadosCentrales, eocd]);
}
