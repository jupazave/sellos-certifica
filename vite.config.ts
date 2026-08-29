/// <reference types="vitest" />
import { defineConfig, type Plugin } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

const CSP =
  "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "img-src data:; font-src data:; connect-src 'none'; base-uri 'none'; " +
  "form-action 'none'; object-src 'none'";

function inyectarCsp(): Plugin {
  return {
    name: 'inyectar-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<!--CSP-->',
        `<meta http-equiv="Content-Security-Policy" content="${CSP}">`,
      );
    },
  };
}

export default defineConfig({
  plugins: [viteSingleFile(), inyectarCsp()],
  build: { target: 'es2022' },
  test: { environment: 'node' },
});
