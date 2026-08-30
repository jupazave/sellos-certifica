// `defineConfig`/`Plugin` se importan de 'vitest/config' (que los re-exporta de 'vite') en
// vez de usar `/// <reference types="vitest" />` + `from 'vite'`: la referencia de tipos
// solo aumenta el ambiente de ESTE archivo, y deja de resolverse en cuanto vite.config.ts
// se importa transitivamente desde un archivo de pruebas (tests/csp.test.ts, para probar
// `inyectarCspEnHtml` sin depender del pipeline completo de Vite) — `tsc --noEmit` deja de
// ver la propiedad `test` de `defineConfig({ test: {...} })` y falla. Importar el
// `defineConfig` de 'vitest/config' trae consigo el `declare module 'vite'` que amplía
// `UserConfig` con `test`, así que el tipo queda resuelto sin importar desde dónde se
// importe este módulo.
import { defineConfig, type Plugin } from 'vitest/config';
import { viteSingleFile } from 'vite-plugin-singlefile';

const CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src data:; font-src data:; connect-src 'none'; base-uri 'none'; " +
  "form-action 'none'; object-src 'none'";

const MARCADOR_CSP = '<!--CSP-->';

/**
 * Inyecta el `<meta>` de Content-Security-Policy en `index.html`, reemplazando el marcador
 * `<!--CSP-->`. Exportada por separado del plugin (en vez de vivir solo como closure dentro
 * de `inyectarCsp`) para poder probarla directamente — ver tests/csp.test.ts — sin depender
 * del pipeline completo de Vite.
 *
 * Revisión final: antes, esto hacía `html.replace('<!--CSP-->', ...)` sin comprobar que el
 * marcador existiera. Si `index.html` lo perdiera (p. ej. una edición manual futura de la
 * plantilla), `.replace()` no encuentra el string, no hace nada, y el build sale
 * silenciosamente SIN ninguna Content-Security-Policy — la garantía de seguridad más
 * importante del proyecto (ver README "Por qué es segura" / "CSP sin red"), sin que ningún
 * test ni ningún error de build lo detectara. Ahora falla ruidosamente en vez de fallar mudo.
 */
export function inyectarCspEnHtml(html: string): string {
  if (!html.includes(MARCADOR_CSP)) {
    throw new Error(
      `index.html perdió el marcador ${MARCADOR_CSP}: el build saldría sin Content-Security-Policy.`,
    );
  }
  return html.replace(MARCADOR_CSP, `<meta http-equiv="Content-Security-Policy" content="${CSP}">`);
}

function inyectarCsp(): Plugin {
  return {
    name: 'inyectar-csp',
    apply: 'build',
    transformIndexHtml: inyectarCspEnHtml,
  };
}

export default defineConfig({
  plugins: [viteSingleFile(), inyectarCsp()],
  // El harness de desarrollo asigna un puerto libre vía la variable PORT (autoPort);
  // sin ella, Vite usa su default (5173).
  server: { port: Number(process.env.PORT) || undefined },
  build: { target: 'es2022' },
  test: {
    environment: 'node',
    exclude: ['**/node_modules/**', '**/dist/**', '.claude/**', '.superpowers/**'],
  },
});
