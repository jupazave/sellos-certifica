// @vitest-environment happy-dom
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import forge from 'node-forge';
import { ejecutarGeneracion, validarFormulario, vistaGenerar } from '../src/ui/generar-view';
import { descifrarLlave } from '../src/crypto/efirma';
import { aBinario, aBytes } from '../src/util/bytes';

// Fixtures reales del SAT — ver tests/fixtures/README.md. RFC de pruebas AAA010101AAA
// (12 caracteres) => persona moral; es el que documentan las fixtures del repo, no el
// EKU9003173C9 que asumía el diseño original (ver nota de discovery en ese README).
const fielCer = new Uint8Array(readFileSync('tests/fixtures/fiel.cer'));
const fielKey = new Uint8Array(readFileSync('tests/fixtures/fiel.key'));
const CONTRASENA = '12345678a'; // la de tests/fixtures/README.md
const RFC = 'AAA010101AAA';
const RAZON_SOCIAL = 'ACCEM SERVICIOS EMPRESARIALES SC';

const OID_OU = '2.5.4.11';
const OID_O = '2.5.4.10';
const OID_CN = '2.5.4.3';

// --- Helpers para desenvolver un .sdg real (SignedData -> ZIP -> CSR) y leer el subject
// del CSR embebido. Deliberadamente independientes de src/crypto/sdg.ts (no lo importan):
// mismo criterio y mismo patrón de bajo nivel que ya usa tests/sdg.test.ts, reducidos a lo
// mínimo que hace falta para las pruebas de regresión de normalización de abajo. Se
// duplican aquí en vez de importarse de ese archivo porque los tests no se importan entre
// sí en este proyecto (cada archivo de prueba es autocontenido).
function hijos(nodo: forge.asn1.Asn1): forge.asn1.Asn1[] {
  if (!Array.isArray(nodo.value)) {
    throw new Error('Se esperaba un nodo ASN.1 compuesto (SEQUENCE/SET), llegó uno primitivo.');
  }
  return nodo.value;
}
function hijo(nodo: forge.asn1.Asn1, indice: number): forge.asn1.Asn1 {
  const encontrado = hijos(nodo)[indice];
  if (!encontrado) throw new Error(`ASN.1: no hay hijo en el índice ${indice}.`);
  return encontrado;
}
function comoBytes(nodo: forge.asn1.Asn1): string {
  if (typeof nodo.value !== 'string') {
    throw new Error('Se esperaba un nodo ASN.1 primitivo (bytes), llegó uno compuesto.');
  }
  return nodo.value;
}

// Local File Header de ZIP (mismo formato que documenta tests/zip.test.ts): extrae solo la
// primera entrada, que es lo único que produce generarSDG (una sucursal por corrida).
function primeraEntradaDeZip(zip: Uint8Array): Uint8Array {
  const u16 = (o: number) => (zip[o] ?? 0) | ((zip[o + 1] ?? 0) << 8);
  const u32 = (o: number) =>
    ((zip[o] ?? 0) | ((zip[o + 1] ?? 0) << 8) | ((zip[o + 2] ?? 0) << 16) | ((zip[o + 3] ?? 0) << 24)) >>>
    0;
  const largoNombre = u16(26);
  const largoDatos = u32(18); // STORE: tamaño comprimido == tamaño real
  const inicioDatos = 30 + largoNombre;
  return zip.slice(inicioDatos, inicioDatos + largoDatos);
}

/**
 * Re-parsea el .sdg producido por ejecutarGeneracion hasta llegar al CSR embebido, para
 * poder inspeccionar directamente el subject (OU/CN/O) que de verdad quedó firmado —
 * no una copia derivada como el nombre del archivo (nombreBase sanea/recorta la sucursal
 * por su cuenta para el nombre, así que comparar contra el nombre NO habría detectado el
 * bug de normalización que corrigen las pruebas de abajo: hay que ir hasta el CSR real).
 */
function csrDelSdg(sdgDer: Uint8Array): forge.pki.CertificateSigningRequest {
  const contentInfo = forge.asn1.fromDer(aBinario(sdgDer));
  const signedData = hijo(hijo(contentInfo, 1), 0); // [0] EXPLICIT content -> SignedData
  const encapContentInfo = hijo(signedData, 2);
  const eContentOctet = hijo(hijo(encapContentInfo, 1), 0); // eContent [0] EXPLICIT -> OCTET STRING
  const zipBytes = aBytes(comoBytes(eContentOctet));
  const csrDer = primeraEntradaDeZip(zipBytes);
  return forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(aBinario(csrDer)));
}

describe('validarFormulario', () => {
  const base = {
    rfc: RFC,
    razonSocial: RAZON_SOCIAL,
    sucursal: 'Matriz',
    contrasena: 'Secreta123',
    confirmacion: 'Secreta123',
  };

  it('acepta un formulario completo', () => {
    expect(validarFormulario(base)).toBeNull();
  });

  it('rechaza RFC vacío', () => {
    expect(validarFormulario({ ...base, rfc: '   ' })).not.toBeNull();
  });

  it('rechaza RFC con formato inválido', () => {
    expect(validarFormulario({ ...base, rfc: '123' })).not.toBeNull();
  });

  it('rechaza razón social vacía', () => {
    expect(validarFormulario({ ...base, razonSocial: '   ' })).not.toBeNull();
  });

  it('rechaza contraseña corta', () => {
    expect(validarFormulario({ ...base, contrasena: 'corta', confirmacion: 'corta' })).toContain('8');
  });

  it('rechaza confirmación distinta', () => {
    expect(validarFormulario({ ...base, confirmacion: 'Otra12345' })).toContain('coinciden');
  });

  it('rechaza campos vacíos', () => {
    expect(validarFormulario({ ...base, sucursal: '  ' })).not.toBeNull();
  });

  // docs/reference/sdg-format.md §1.7 — restricciones de captura de Certifica
  // (mx/sat/gob/recursos/solcedi_mensajes.properties). No aplican aquí las reglas de
  // "dos sucursales con el mismo nombre" ni "máximo 30 sucursales": esta app genera una
  // sola sucursal por corrida, así que esas reglas de lote no tienen equivalente en el
  // formulario.
  describe('§1.7 restricciones de sucursal', () => {
    it('acepta una sucursal de exactamente 64 caracteres', () => {
      expect(validarFormulario({ ...base, sucursal: 'A'.repeat(64) })).toBeNull();
    });

    it('rechaza una sucursal de más de 64 caracteres', () => {
      const error = validarFormulario({ ...base, sucursal: 'A'.repeat(65) });
      expect(error).not.toBeNull();
      expect(error).toContain('64');
    });

    it.each(['/', '\\', ':', '*', '?', '"', '<', '>', '$', '|'])(
      'rechaza una sucursal que contiene el carácter prohibido %s',
      (caracter) => {
        const error = validarFormulario({ ...base, sucursal: `Matriz${caracter}Norte` });
        expect(error).not.toBeNull();
      },
    );

    it('acepta una sucursal con espacios y acentos (no están prohibidos)', () => {
      expect(validarFormulario({ ...base, sucursal: 'Cañón Sur' })).toBeNull();
    });
  });

  // §1.7: "Contraseña de la clave privada: mín. 8, máx. 256 caracteres" (ERR_M10).
  describe('§1.7 restricciones de contraseña', () => {
    it('acepta una contraseña de exactamente 256 caracteres', () => {
      const limite = 'a'.repeat(256);
      expect(validarFormulario({ ...base, contrasena: limite, confirmacion: limite })).toBeNull();
    });

    it('rechaza una contraseña de más de 256 caracteres', () => {
      const larga = 'a'.repeat(257);
      const error = validarFormulario({ ...base, contrasena: larga, confirmacion: larga });
      expect(error).not.toBeNull();
      expect(error).toContain('256');
    });
  });
});

describe('ejecutarGeneracion (flujo completo con fixtures)', () => {
  it('produce .key descifrable y .sdg no vacío con nombre correcto', async () => {
    const r = await ejecutarGeneracion({
      cer: fielCer,
      key: fielKey,
      contrasenaEfirma: CONTRASENA,
      rfc: RFC,
      razonSocial: RAZON_SOCIAL,
      sucursal: 'Matriz',
      contrasenaCsd: 'Secreta123',
    });
    expect(r.nombre).toMatch(/^CSD_Matriz_AAA010101AAA_\d{8}$/);
    expect(r.sdgDer.length).toBeGreaterThan(500);
    const llave = descifrarLlave(r.keyDer, 'Secreta123');
    expect(llave.n.bitLength()).toBe(2048);

    // Revisión final: hasta aquí las pruebas comprobaban por separado que el .key
    // descifra y que el .sdg no está vacío, pero nada comprobaba que ambos archivos
    // descargados sean en realidad la MISMA pareja de llaves — es decir, que la llave
    // pública que quedó firmada dentro del CSR embebido en el .sdg corresponda a la llave
    // privada que el usuario puede descifrar del .key con su contraseña nueva. Si
    // ejecutarGeneracion alguna vez generara o mezclara dos pares distintos (p. ej. un
    // futuro refactor que llamara a generarParCSD() dos veces), el .key y el .sdg
    // seguirían pasando las aserciones de arriba —cada uno por separado sigue siendo
    // válido— pero el CSD resultante sería inservible: el .key no correspondería al
    // certificado que el SAT emita a partir de ese CSR.
    const csr = csrDelSdg(r.sdgDer);
    expect((csr.publicKey as forge.pki.rsa.PublicKey).n.compareTo(llave.n)).toBe(0);
  }, 60_000);

  // Regresión: revisión de la Tarea 11 encontró que validarFormulario valida sobre
  // f.rfc.trim()/f.sucursal.trim(), pero el flujo de generación real (vistaGenerar ->
  // ejecutarGeneracion) pasaba los valores crudos sin recortar a generarCSR/nombreBase.
  // Un valor que "pasaba" la validación (por estar validada su versión recortada) podía
  // llegar sin recortar hasta el CSR real y violar las mismas reglas que se acababan de
  // validar. Las dos pruebas de abajo re-parsean el .sdg producido y leen el subject del
  // CSR embebido de verdad (ver csrDelSdg arriba) — no basta con mirar `r.nombre`, porque
  // nombreBase ya recorta/sanea la sucursal por su cuenta para el nombre del archivo, así
  // que un nombre "correcto" no habría demostrado que el CSR también recibió el valor
  // recortado.
  describe('normalización de espacios (regresión: validación vs. generación real)', () => {
    it('una sucursal con espacios que recorta a 64 caracteres pasa la validación Y llega recortada al OU del CSR', async () => {
      const sucursalSignificativa = 'A'.repeat(64);
      const sucursalConEspacios = `  ${sucursalSignificativa}  `; // 68 caracteres crudos
      expect(sucursalConEspacios.length).toBe(68);

      // Mitad 1 del bug: validarFormulario aprueba esto porque valida sobre el valor
      // recortado (comportamiento intencional — ver "§1.7 restricciones de sucursal").
      expect(
        validarFormulario({
          rfc: RFC,
          razonSocial: RAZON_SOCIAL,
          sucursal: sucursalConEspacios,
          contrasena: 'Secreta123',
          confirmacion: 'Secreta123',
        }),
      ).toBeNull();

      // Mitad 2 del bug (la que estaba rota): el CSR real debe recibir exactamente los 64
      // caracteres recortados, nunca los 68 crudos — si no se hubiera corregido
      // ejecutarGeneracion, aquí llegarían los 68 y se violaría el límite de §1.7.
      const r = await ejecutarGeneracion({
        cer: fielCer,
        key: fielKey,
        contrasenaEfirma: CONTRASENA,
        rfc: RFC,
        razonSocial: RAZON_SOCIAL,
        sucursal: sucursalConEspacios,
        contrasenaCsd: 'Secreta123',
      });

      const csr = csrDelSdg(r.sdgDer);
      const ou = csr.subject.attributes.find((a) => a.type === OID_OU);
      expect(typeof ou?.value).toBe('string');
      // OU se codifica UTF8String (csr.ts); forge no decodifica UTF-8 al parsear de
      // vuelta (deja los bytes crudos en .value) — mismo tratamiento que tests/sdg.test.ts.
      const valorOu = forge.util.decodeUtf8(ou!.value as string);
      expect(valorOu).toBe(sucursalSignificativa);
      expect(valorOu.length).toBe(64);
    }, 60_000);

    it('un RFC con un espacio inicial (13 crudos, 12 significativos) pasa la validación Y conserva la rama O — no CN — en el CSR (§1.3)', async () => {
      const rfcConEspacio = ` ${RFC}`; // 13 caracteres crudos; RFC (persona moral, 12) recortado
      expect(rfcConEspacio.length).toBe(13); // longitud "trampa": coincide con persona física

      // Mitad 1 del bug: validarFormulario aprueba esto porque el formato se valida sobre
      // f.rfc.trim().
      expect(
        validarFormulario({
          rfc: rfcConEspacio,
          razonSocial: RAZON_SOCIAL,
          sucursal: 'Matriz',
          contrasena: 'Secreta123',
          confirmacion: 'Secreta123',
        }),
      ).toBeNull();

      // Mitad 2 del bug (la que estaba rota): generarCSR (T8) decide CN vs. O con
      // `rfc.length === 13`. Si ejecutarGeneracion no recorta, el espacio inicial hace que
      // un RFC de persona moral (12 caracteres significativos) tome por error la rama CN
      // de persona física — violación de §1.3.
      const r = await ejecutarGeneracion({
        cer: fielCer,
        key: fielKey,
        contrasenaEfirma: CONTRASENA,
        rfc: rfcConEspacio,
        razonSocial: RAZON_SOCIAL,
        sucursal: 'Matriz',
        contrasenaCsd: 'Secreta123',
      });

      const csr = csrDelSdg(r.sdgDer);
      const tieneO = csr.subject.attributes.some((a) => a.type === OID_O);
      const tieneCN = csr.subject.attributes.some((a) => a.type === OID_CN);
      expect(tieneO).toBe(true); // persona moral (12 caracteres tras recortar) -> O
      expect(tieneCN).toBe(false); // nunca CN, aunque el valor crudo tenga 13 caracteres
    }, 60_000);
  });
});

describe('vistaGenerar (DOM)', () => {
  it('renderiza selectores de e.firma y campos del formulario', () => {
    const vista = vistaGenerar();
    const archivos = vista.querySelectorAll<HTMLInputElement>('input[type="file"]');
    expect(archivos.length).toBe(2);
    expect(archivos[0]?.accept).toBe('.cer');
    expect(archivos[1]?.accept).toBe('.key');
    expect(vista.querySelectorAll('input[type="password"]').length).toBe(3); // e.firma + CSD + confirmación
    expect(vista.querySelector('button')).not.toBeNull();
  });
});
