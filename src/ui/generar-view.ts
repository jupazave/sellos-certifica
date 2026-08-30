import { cargarEfirma, estadoVigencia, parsearCertificado } from '../crypto/efirma';
import { generarParCSD } from '../crypto/keygen';
import { cifrarLlaveCSD } from '../crypto/keyfile';
import { generarCSR } from '../crypto/csr';
import { generarSDG } from '../crypto/sdg';
import { descargarArchivo, nombreBase } from '../util/files';
import { SellosError } from '../util/errors';
import { alerta, campoTexto, selectorArchivo } from './components';

export interface FormularioCSD {
  rfc: string;
  razonSocial: string;
  sucursal: string;
  contrasena: string;
  confirmacion: string;
}

// docs/reference/sdg-format.md §1.7 — restricciones de captura de Certifica, leídas de
// mx/sat/gob/recursos/solcedi_mensajes.properties. Las reglas de lote de esa misma
// sección ("no se permiten dos sucursales con el mismo nombre", "máximo 30 sucursales
// por petición") no tienen equivalente aquí: este formulario genera una sola sucursal
// por corrida, nunca un lote.
const SUCURSAL_MAX = 64; // §1.7: máx. 64 caracteres (ERR_M12)
// §1.7: caracteres prohibidos en la sucursal, literal `/ \ : * ? " < > $ |` (ERR_M12).
// El primer carácter de la clase es `/` escapado porque coincide con el delimitador del
// literal regex; el segundo es `\` escapado.
const SUCURSAL_PROHIBIDOS = /[/\\:*?"<>$|]/;
const CONTRASENA_MIN = 8; // §1.7: mín. 8 caracteres (ERR_M10)
const CONTRASENA_MAX = 256; // §1.7: máx. 256 caracteres (ERR_M10)

export function validarFormulario(f: FormularioCSD): string | null {
  if (!f.rfc.trim()) return 'Escribe el RFC.';
  if (!/^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/i.test(f.rfc.trim())) return 'El RFC no tiene un formato válido.';
  if (!f.razonSocial.trim()) return 'Escribe el nombre o razón social.';
  const sucursal = f.sucursal.trim();
  if (!sucursal) return 'Escribe el nombre de la sucursal (ej. "Matriz").';
  if (sucursal.length > SUCURSAL_MAX) {
    return `El nombre de la sucursal no puede tener más de ${SUCURSAL_MAX} caracteres.`;
  }
  if (SUCURSAL_PROHIBIDOS.test(sucursal)) {
    return 'El nombre de la sucursal no puede contener los caracteres / \\ : * ? " < > $ |.';
  }
  if (f.contrasena.length < CONTRASENA_MIN) {
    return `La contraseña del CSD debe tener al menos ${CONTRASENA_MIN} caracteres.`;
  }
  if (f.contrasena.length > CONTRASENA_MAX) {
    return `La contraseña del CSD no puede tener más de ${CONTRASENA_MAX} caracteres.`;
  }
  if (f.contrasena !== f.confirmacion) return 'La contraseña y su confirmación no coinciden.';
  return null;
}

export interface EntradaGeneracion {
  cer: Uint8Array;
  key: Uint8Array;
  contrasenaEfirma: string;
  rfc: string;
  razonSocial: string;
  sucursal: string;
  contrasenaCsd: string;
}

export async function ejecutarGeneracion(entrada: EntradaGeneracion): Promise<{
  nombre: string;
  keyDer: Uint8Array;
  sdgDer: Uint8Array;
}> {
  // Normaliza aquí — único punto de verdad — para que lo que aprueba validarFormulario
  // coincida exactamente con lo que termina en el CSR y en el nombre del archivo.
  // validarFormulario valida sobre `f.rfc.trim()`/`f.sucursal.trim()` (para permitir que
  // el usuario tenga espacios accidentales al capturar), así que si aquí se usara el
  // valor crudo, un caso que "pasó" la validación podría violar las mismas reglas que
  // se acaban de validar: una sucursal de 68 caracteres crudos que recorta a 64 se
  // colaría al atributo OU del CSR sin respetar el límite de §1.7 (ERR_M12), y un RFC
  // con un espacio inicial (13 caracteres crudos aunque sean 12 significativos) haría
  // que generarCSR (T8) tomara la rama CN en vez de O, porque `esPersonaFisica` se
  // decide ahí con `entrada.rfc.length === 13` sobre el valor recibido tal cual (§1.3).
  // No se recortan `contrasenaEfirma`/`contrasenaCsd`: a diferencia de rfc/razonSocial/
  // sucursal (datos de captura que el SAT espera "limpios"), una contraseña con espacios
  // al inicio/fin podría ser intencional y alterarla en silencio sería sorprendente.
  const rfc = entrada.rfc.trim();
  const razonSocial = entrada.razonSocial.trim();
  const sucursal = entrada.sucursal.trim();

  const efirma = cargarEfirma(entrada.cer, entrada.key, entrada.contrasenaEfirma);
  const par = await generarParCSD();
  // generarCSR (Tarea 8) exige `certificadoEfirma`: el CSR copia verbatim el
  // x500UniqueIdentifier/serialNumber del subject de la e.firma (§1.2) y `contrasenaCsd`
  // viaja por el contrato aunque no alimenta el challengePassword (ver el docstring de
  // generarCSR en src/crypto/csr.ts).
  const csrDer = generarCSR({
    ...par,
    rfc,
    razonSocial,
    sucursal,
    contrasenaCsd: entrada.contrasenaCsd,
    certificadoEfirma: efirma.datos.certificado,
  });
  const sdgDer = generarSDG(csrDer, efirma);
  const keyDer = cifrarLlaveCSD(par.privada, entrada.contrasenaCsd);
  return { nombre: nombreBase(sucursal, rfc, new Date()), keyDer, sdgDer };
}

export function vistaGenerar(): HTMLElement {
  const raiz = document.createElement('section');
  raiz.innerHTML =
    '<h2>Generar CSD</h2><p>Carga tu e.firma, captura los datos y descarga la llave (.key) y la solicitud (.sdg) para subirla a CertiSAT Web. Todo se procesa en tu navegador.</p>';

  let cer: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  const avisos = document.createElement('div');
  const contrasenaEfirma = campoTexto('Contraseña de tu e.firma', { tipo: 'password' });
  const rfc = campoTexto('RFC');
  const razonSocial = campoTexto('Nombre o razón social');
  const sucursal = campoTexto('Nombre de la sucursal', { valor: 'Matriz' });
  const contrasenaCsd = campoTexto('Contraseña nueva para el CSD (mínimo 8)', { tipo: 'password' });
  const confirmacion = campoTexto('Confirma la contraseña del CSD', { tipo: 'password' });

  function precargarDesdeCer(): void {
    if (!cer) return;
    avisos.replaceChildren();
    try {
      // Solo parsea el .cer para pre-llenar; la validación completa ocurre al generar.
      const datos = parsearCertificado(cer);
      rfc.input.value = rfc.input.value || datos.rfc;
      razonSocial.input.value = razonSocial.input.value || datos.razonSocial;
      const vigencia = estadoVigencia(datos, new Date());
      if (vigencia === 'vencido')
        avisos.append(alerta('aviso', 'Tu e.firma aparece vencida; el SAT rechazará la solicitud. Puedes continuar bajo tu propio riesgo.'));
    } catch (e) {
      avisos.append(alerta('error', e instanceof SellosError ? e.message : 'No se pudo leer el certificado.'));
    }
  }

  const boton = document.createElement('button');
  boton.textContent = 'Generar y descargar';
  const resultado = document.createElement('div');

  boton.addEventListener('click', async () => {
    resultado.replaceChildren();
    const f = {
      rfc: rfc.input.value,
      razonSocial: razonSocial.input.value,
      sucursal: sucursal.input.value,
      contrasena: contrasenaCsd.input.value,
      confirmacion: confirmacion.input.value,
    };
    const errorForm = validarFormulario(f);
    if (!cer || !key) {
      resultado.append(alerta('error', 'Carga el .cer y el .key de tu e.firma.'));
      return;
    }
    if (errorForm) {
      resultado.append(alerta('error', errorForm));
      return;
    }
    boton.disabled = true;
    boton.textContent = 'Generando…';
    try {
      const r = await ejecutarGeneracion({
        cer,
        key,
        contrasenaEfirma: contrasenaEfirma.input.value,
        rfc: f.rfc,
        razonSocial: f.razonSocial,
        sucursal: f.sucursal,
        contrasenaCsd: f.contrasena,
      });
      descargarArchivo(`${r.nombre}.key`, r.keyDer);
      descargarArchivo(`${r.nombre}.sdg`, r.sdgDer);
      resultado.append(
        alerta('ok', `Listos: ${r.nombre}.key y ${r.nombre}.sdg.`),
        alerta(
          'aviso',
          'Siguiente paso: entra a CertiSAT Web con tu e.firma, elige "Solicitud de certificado de sello digital" y sube el archivo .sdg. Guarda el .key y su contraseña: los necesitará tu sistema de facturación.',
        ),
      );
    } catch (e) {
      resultado.append(
        alerta('error', e instanceof SellosError ? e.message : 'Ocurrió un error inesperado al generar.'),
      );
    } finally {
      boton.disabled = false;
      boton.textContent = 'Generar y descargar';
    }
  });

  raiz.append(
    selectorArchivo('Certificado de tu e.firma (.cer)', (bytes) => { cer = bytes; precargarDesdeCer(); }, '.cer'),
    selectorArchivo('Llave privada de tu e.firma (.key)', (bytes) => { key = bytes; }, '.key'),
    contrasenaEfirma.raiz,
    avisos,
    rfc.raiz,
    razonSocial.raiz,
    sucursal.raiz,
    contrasenaCsd.raiz,
    confirmacion.raiz,
    boton,
    resultado,
  );
  return raiz;
}
