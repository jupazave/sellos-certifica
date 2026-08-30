export class SellosError extends Error {}

export class ArchivoInvalidoError extends SellosError {
  constructor(mensaje = 'El archivo no parece ser un .cer/.key del SAT (formato DER).') {
    super(mensaje);
  }
}

export class ContrasenaIncorrectaError extends SellosError {
  constructor(mensaje = 'La contraseña no descifra esta llave privada.') {
    super(mensaje);
  }
}

export class ParejaInvalidaError extends SellosError {
  constructor(mensaje = 'Esta llave privada no corresponde a este certificado.') {
    super(mensaje);
  }
}

export class TipoCertificadoError extends SellosError {
  constructor(
    mensaje = 'Este certificado es un CSD; para generar sellos necesitas tu e.firma (FIEL).',
  ) {
    super(mensaje);
  }
}
