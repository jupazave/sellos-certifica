import {
  descifrarLlave,
  estadoVigencia,
  parsearCertificado,
  sonPareja,
  type DatosCertificado,
  type EstadoVigencia,
} from '../crypto/efirma';
import { ContrasenaIncorrectaError, SellosError } from '../util/errors';
import { alerta, campoTexto, selectorArchivo } from './components';

export interface ResultadoValidacion {
  certificado?: DatosCertificado;
  vigencia?: EstadoVigencia;
  contrasenaCorrecta?: boolean;
  pareja?: boolean;
  error?: string;
}

export function validar(entrada: {
  cer?: Uint8Array;
  key?: Uint8Array;
  contrasena?: string;
}): ResultadoValidacion {
  const r: ResultadoValidacion = {};
  try {
    if (entrada.cer) {
      r.certificado = parsearCertificado(entrada.cer);
      r.vigencia = estadoVigencia(r.certificado, new Date());
    }
    if (entrada.key && entrada.contrasena !== undefined) {
      try {
        const llave = descifrarLlave(entrada.key, entrada.contrasena);
        r.contrasenaCorrecta = true;
        if (r.certificado) r.pareja = sonPareja(r.certificado.certificado, llave);
      } catch (e) {
        if (e instanceof ContrasenaIncorrectaError) r.contrasenaCorrecta = false;
        else throw e;
      }
    }
  } catch (e) {
    r.error = e instanceof SellosError ? e.message : 'Ocurrió un error inesperado al procesar los archivos.';
  }
  return r;
}

const ETIQUETA_VIGENCIA: Record<EstadoVigencia, { tipo: 'ok' | 'aviso' | 'error'; texto: string }> = {
  vigente: { tipo: 'ok', texto: '🟢 Vigente' },
  por_vencer: { tipo: 'aviso', texto: '🟡 Por vencer (menos de 90 días)' },
  vencido: { tipo: 'error', texto: '🔴 Vencido' },
};

export function vistaValidar(): HTMLElement {
  const raiz = document.createElement('section');
  raiz.innerHTML = '<h2>Validar archivos</h2><p>Verifica un certificado .cer, una llave .key o que ambos sean pareja. Nada sale de tu navegador.</p>';

  let cer: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  const resultado = document.createElement('div');
  const contrasena = campoTexto('Contraseña de la llave', { tipo: 'password' });

  function pintar(): void {
    resultado.replaceChildren();
    const r = validar({ cer, key, contrasena: key ? contrasena.input.value : undefined });
    if (r.error) resultado.append(alerta('error', r.error));
    if (r.certificado) {
      const d = r.certificado;
      const datos = document.createElement('ul');
      // Construido con DOM/textContent, no innerHTML: rfc, razonSocial y numeroSerie
      // vienen del subject de un certificado que parsearCertificado no valida contra
      // ninguna CA, así que un .cer manipulado a mano podría traer HTML/script en esos
      // campos. Con innerHTML eso se ejecutaría en la página; con textContent siempre
      // se trata como texto plano.
      const filas: [string, string][] = [
        ['Tipo', d.tipo === 'FIEL' ? 'e.firma (FIEL)' : 'CSD (sello digital)'],
        ['RFC', d.rfc],
        ['Nombre/Razón social', d.razonSocial],
        ['No. de serie', d.numeroSerie],
        [
          'Vigencia',
          `${d.validoDesde.toLocaleDateString('es-MX')} – ${d.validoHasta.toLocaleDateString('es-MX')}`,
        ],
      ];
      for (const [etiqueta, valor] of filas) {
        const li = document.createElement('li');
        const strong = document.createElement('strong');
        strong.textContent = `${etiqueta}:`;
        li.append(strong, ` ${valor}`);
        datos.append(li);
      }
      resultado.append(datos);
      if (r.vigencia) {
        const v = ETIQUETA_VIGENCIA[r.vigencia];
        resultado.append(alerta(v.tipo, v.texto));
      }
    }
    if (r.contrasenaCorrecta !== undefined) {
      resultado.append(
        r.contrasenaCorrecta
          ? alerta('ok', 'La contraseña descifra la llave correctamente.')
          : alerta('error', 'La contraseña no descifra esta llave privada.'),
      );
    }
    if (r.pareja !== undefined) {
      resultado.append(
        r.pareja
          ? alerta('ok', 'El certificado y la llave son pareja.')
          : alerta('error', 'Esta llave privada no corresponde a este certificado.'),
      );
    }
  }

  raiz.append(
    selectorArchivo('Certificado (.cer)', (bytes) => { cer = bytes; pintar(); }, '.cer'),
    selectorArchivo('Llave privada (.key)', (bytes) => { key = bytes; pintar(); }, '.key'),
    contrasena.raiz,
  );
  contrasena.input.addEventListener('input', () => { if (key) pintar(); });
  raiz.append(resultado);
  return raiz;
}
