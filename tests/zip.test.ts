import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { crc32, crearZip } from '../src/crypto/zip';

// CRC-32 (IEEE 802.3 / zlib) — vectores estándar usados universalmente para validar
// implementaciones de CRC-32. "123456789" -> 0xCBF43926 es el "check value" oficial del
// polinomio 0xEDB88320 (ver el catálogo de CRC de Koopman / la página de CRC RevEng).
describe('crc32', () => {
  it('de la cadena vacía es 0', () => {
    expect(crc32(new Uint8Array())).toBe(0x00000000);
  });

  it('de "a" es 0xE8B7BE43', () => {
    expect(crc32(new TextEncoder().encode('a'))).toBe(0xe8b7be43);
  });

  it('del vector de verificación estándar "123456789" es 0xCBF43926', () => {
    expect(crc32(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
  });
});

// Firmas de ZIP (Local File Header / Central Directory / End Of Central Directory) en
// little-endian, como las define la especificación APPNOTE.TXT de PKWARE.
const FIRMA_LOCAL = [0x50, 0x4b, 0x03, 0x04]; // "PK\x03\x04"
const FIRMA_CENTRAL = [0x50, 0x4b, 0x01, 0x02]; // "PK\x01\x02"
const FIRMA_EOCD = [0x50, 0x4b, 0x05, 0x06]; // "PK\x05\x06"

function buscarFirma(bytes: Uint8Array, firma: number[]): number {
  outer: for (let i = 0; i <= bytes.length - firma.length; i++) {
    for (let j = 0; j < firma.length; j++) {
      if (bytes[i + j] !== firma[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function u16le(bytes: Uint8Array, offset: number): number {
  return (bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8);
}
function u32le(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] ?? 0) |
      ((bytes[offset + 1] ?? 0) << 8) |
      ((bytes[offset + 2] ?? 0) << 16) |
      ((bytes[offset + 3] ?? 0) << 24)) >>>
    0
  );
}

describe('crearZip — estructura de bytes (sin depender de ninguna CLI)', () => {
  it('produce las tres firmas PK en orden: local, central, EOCD', () => {
    const datos = new TextEncoder().encode('contenido de prueba');
    const zip = crearZip([{ nombre: 'archivo.req', datos }]);

    const posLocal = buscarFirma(zip, FIRMA_LOCAL);
    const posCentral = buscarFirma(zip, FIRMA_CENTRAL);
    const posEocd = buscarFirma(zip, FIRMA_EOCD);

    expect(posLocal).toBe(0); // el archivo ZIP debe *empezar* con el local file header
    expect(posCentral).toBeGreaterThan(posLocal);
    expect(posEocd).toBeGreaterThan(posCentral);
    // el EOCD son los últimos 22 bytes (sin comment): confirma que no sobra nada después.
    expect(posEocd).toBe(zip.length - 22);
  });

  it('el método de compresión es STORE (0) y los tamaños comprimido/sin-comprimir son iguales', () => {
    const datos = new TextEncoder().encode('otro contenido de prueba, un poco más largo');
    const zip = crearZip([{ nombre: 'x.req', datos }]);

    const metodo = u16le(zip, 8); // local file header: bytes [8,10) = compression method
    expect(metodo).toBe(0);

    const tamComprimido = u32le(zip, 18);
    const tamSinComprimir = u32le(zip, 22);
    expect(tamComprimido).toBe(datos.length);
    expect(tamSinComprimir).toBe(datos.length);
  });

  it('el CRC-32 en el local file header coincide con crc32(datos) calculado independientemente', () => {
    const datos = new TextEncoder().encode('CSR DER simulado \x00\x01\x02\xff');
    const zip = crearZip([{ nombre: 'archivo.req', datos }]);

    const crcEnHeader = u32le(zip, 14); // local file header: bytes [14,18) = CRC-32
    expect(crcEnHeader).toBe(crc32(datos));
  });

  it('el nombre de archivo declarado en el local header coincide con el pedido', () => {
    const nombre = 'CSD_Matriz_AAA010101AAA_20260829_101500s.req';
    const zip = crearZip([{ nombre, datos: new Uint8Array([1, 2, 3]) }]);

    const largoNombre = u16le(zip, 26); // local file header: bytes [26,28) = file name length
    expect(largoNombre).toBe(new TextEncoder().encode(nombre).length);
    const nombreBytes = zip.slice(30, 30 + largoNombre);
    expect(new TextDecoder().decode(nombreBytes)).toBe(nombre);
  });

  it('el contenido crudo sigue inmediatamente al nombre en el local file header (STORE, sin relleno)', () => {
    const datos = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    const nombre = 'a.req';
    const zip = crearZip([{ nombre, datos }]);

    const inicioDatos = 30 + nombre.length; // 30 = tamaño fijo del local file header
    expect(Array.from(zip.slice(inicioDatos, inicioDatos + datos.length))).toEqual(
      Array.from(datos),
    );
  });

  it('la central directory declara exactamente 1 entrada cuando se pasa 1 entrada', () => {
    const zip = crearZip([{ nombre: 'a.req', datos: new Uint8Array([1]) }]);
    const posEocd = buscarFirma(zip, FIRMA_EOCD);
    const totalEntradas = u16le(zip, posEocd + 10); // EOCD: total entries in central dir
    expect(totalEntradas).toBe(1);
  });

  it('soporta múltiples entradas y cada una aparece en la central directory', () => {
    const entradas = [
      { nombre: 'uno.req', datos: new TextEncoder().encode('contenido uno') },
      { nombre: 'dos.req', datos: new TextEncoder().encode('contenido dos, distinto') },
    ];
    const zip = crearZip(entradas);
    const posEocd = buscarFirma(zip, FIRMA_EOCD);
    const totalEntradas = u16le(zip, posEocd + 10);
    expect(totalEntradas).toBe(2);

    // ambos nombres deben aparecer como texto en algún punto del archivo (local + central).
    const texto = new TextDecoder('latin1').decode(zip);
    expect(texto.split('uno.req').length - 1).toBe(2); // local header + central directory
    expect(texto.split('dos.req').length - 1).toBe(2);
  });

  it('sin fecha explícita, la salida es determinística (para reproducibilidad en pruebas)', () => {
    const zip1 = crearZip([{ nombre: 'a.req', datos: new Uint8Array([1, 2, 3]) }]);
    const zip2 = crearZip([{ nombre: 'a.req', datos: new Uint8Array([1, 2, 3]) }]);
    expect(Array.from(zip1)).toEqual(Array.from(zip2));
  });

  it('acepta una fecha explícita por entrada y la codifica en el formato MS-DOS del local header', () => {
    // DOS date/time: ver APPNOTE.TXT §4.4.6. 2026-08-29 10:15:30 UTC:
    //   fecha = ((2026-1980)<<9) | (8<<5) | 29 = (46<<9)|(8<<5)|29 = 23552+256+29=23837=0x5D1D
    //   hora  = (10<<11) | (15<<5) | (30/2) = 20480+480+15 = 20975 = 0x51EF
    const fecha = new Date(Date.UTC(2026, 7, 29, 10, 15, 30));
    const zip = crearZip([{ nombre: 'a.req', datos: new Uint8Array([1]), fecha }]);
    const horaDos = u16le(zip, 10);
    const fechaDos = u16le(zip, 12);
    expect(fechaDos).toBe(0x5d1d);
    expect(horaDos).toBe(0x51ef);
  });
});

describe('crearZip — extracción byte-idéntica al input', () => {
  it('el contenido de la entrada, leído a mano navegando el ZIP, es idéntico al original', () => {
    const original = new Uint8Array(300);
    for (let i = 0; i < original.length; i++) original[i] = (i * 31 + 7) % 256;
    const zip = crearZip([{ nombre: 'grande.req', datos: original }]);

    const largoNombre = u16le(zip, 26);
    const inicioDatos = 30 + largoNombre;
    const extraido = zip.slice(inicioDatos, inicioDatos + original.length);
    expect(Array.from(extraido)).toEqual(Array.from(original));
  });
});

// Cross-check con herramientas reales del sistema (unzip/ditto/python3 zipfile). Si el
// binario no existe en el entorno de CI, la prueba se salta en vez de fallar — las pruebas
// de arriba (firmas PK, CRC independiente, tamaños, extracción manual) ya cubren la
// corrección estructural sin depender de ninguna CLI externa.
function tieneComando(cmd: string): boolean {
  try {
    execFileSync('sh', ['-c', `command -v ${cmd}`], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

describe.skipIf(!tieneComando('unzip'))('crearZip — cross-check con `unzip` del sistema', () => {
  it('unzip -l lista la entrada y unzip -p la extrae byte-idéntica al input', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sellos-zip-test-'));
    try {
      const original = new TextEncoder().encode(
        'CSR DER de prueba para el cross-check con unzip \x00\x01\xff\xfe',
      );
      const nombre = 'CSD_Matriz_AAA010101AAA_20260829_101500s.req';
      const zip = crearZip([{ nombre, datos: original }]);
      const rutaZip = join(dir, 'prueba.zip');
      writeFileSync(rutaZip, zip);

      const listado = execFileSync('unzip', ['-l', rutaZip]).toString('utf8');
      expect(listado).toContain(nombre);

      const extraido = execFileSync('unzip', ['-p', rutaZip, nombre]);
      expect(Buffer.compare(extraido, Buffer.from(original))).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe.skipIf(!tieneComando('python3'))('crearZip — cross-check con `python3 -m zipfile`', () => {
  it('python3 zipfile reconoce el archivo como ZIP válido y su testzip() no reporta errores', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sellos-zip-test-py-'));
    try {
      const original = new TextEncoder().encode('otro CSR DER de prueba para python3 zipfile');
      const nombre = 'x.req';
      const zip = crearZip([{ nombre, datos: original }]);
      const rutaZip = join(dir, 'prueba.zip');
      writeFileSync(rutaZip, zip);

      // testzip() vuelve a calcular el CRC-32 de cada entrada y devuelve el primer nombre
      // corrupto, o None si todas están bien — es la validación de integridad que trae la
      // librería estándar de Python.
      const script = `
import zipfile, sys
with zipfile.ZipFile(sys.argv[1]) as zf:
    bad = zf.testzip()
    assert bad is None, f"entrada corrupta: {bad}"
    with zf.open(sys.argv[2]) as f:
        sys.stdout.buffer.write(f.read())
`;
      const salida = execFileSync('python3', ['-c', script, rutaZip, nombre]);
      expect(Buffer.compare(salida, Buffer.from(original))).toBe(0);

      const contenido = readFileSync(rutaZip);
      expect(contenido.length).toBe(zip.length);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
