import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { inyectarCspEnHtml } from '../vite.config';

// Revisión final: transformIndexHtml (vite.config.ts) hacía `html.replace('<!--CSP-->', ...)`
// sin comprobar que el marcador existiera. Si index.html perdiera ese marcador (p. ej. una
// edición manual futura de la plantilla), `.replace()` simplemente no encuentra el string,
// no hace nada, y el build sale silenciosamente SIN ninguna Content-Security-Policy — la
// garantía de seguridad más importante del proyecto (ver README "Por qué es segura" / "CSP
// sin red"), sin que ningún test ni ningún error de build lo detecte. Estas pruebas cubren
// las dos mitades: que el marcador siga presente en el HTML real del repo, y que la función
// de inyección falle ruidosamente si algún día no lo está.
describe('CSP del build final', () => {
  it('index.html conserva el marcador <!--CSP--> que el build necesita para inyectar la CSP', () => {
    const html = readFileSync('index.html', 'utf-8');
    expect(html).toContain('<!--CSP-->');
  });

  it('inyectarCspEnHtml reemplaza el marcador por un <meta> con connect-src \'none\'', () => {
    const html = '<!doctype html><html><head><!--CSP--></head><body></body></html>';
    const salida = inyectarCspEnHtml(html);
    expect(salida).toContain("connect-src 'none'");
    expect(salida).toContain('Content-Security-Policy');
    expect(salida).not.toContain('<!--CSP-->');
  });

  it('lanza si el marcador <!--CSP--> falta, en vez de producir HTML sin CSP silenciosamente', () => {
    const html = '<!doctype html><html><head></head><body></body></html>';
    expect(() => inyectarCspEnHtml(html)).toThrow(/CSP/);
  });
});
