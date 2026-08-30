import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// El SEO vive en la plantilla estática: estos tests fijan su presencia para que una
// edición futura de index.html no lo pierda en silencio (mismo espíritu que csp.test.ts).
const html = readFileSync('index.html', 'utf8');

describe('SEO en index.html', () => {
  it('el título es descriptivo y buscable (CSD + SAT)', () => {
    const titulo = html.match(/<title>([^<]+)<\/title>/)?.[1] ?? '';
    expect(titulo).toContain('CSD');
    expect(titulo).toContain('SAT');
  });

  it('tiene meta description sustancial en español', () => {
    const desc = html.match(/<meta name="description" content="([^"]+)"/)?.[1] ?? '';
    expect(desc.length).toBeGreaterThan(80);
    expect(desc).toContain('Sello Digital');
    expect(desc).toContain('e.firma');
  });

  it('declara la URL canónica del dominio final', () => {
    expect(html).toContain('<link rel="canonical" href="https://generasellos.mx/"');
  });

  it('trae Open Graph y Twitter card', () => {
    expect(html).toContain('property="og:title"');
    expect(html).toContain('property="og:description"');
    expect(html).toContain('<meta property="og:url" content="https://generasellos.mx/"');
    expect(html).toContain('property="og:locale" content="es_MX"');
    expect(html).toContain('name="twitter:card"');
  });

  it('trae datos estructurados JSON-LD de SoftwareApplication', () => {
    const ld = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)?.[1];
    expect(ld).toBeTruthy();
    const datos = JSON.parse(ld!);
    expect(datos['@type']).toBe('SoftwareApplication');
    expect(datos.url).toBe('https://generasellos.mx/');
    expect(datos.isAccessibleForFree).toBe(true);
  });
});

describe('robots.txt y sitemap (public/, copiados a dist/ por Vite)', () => {
  it('robots.txt permite todo y apunta al sitemap', () => {
    const robots = readFileSync('public/robots.txt', 'utf8');
    expect(robots).toContain('User-agent: *');
    expect(robots).toContain('Sitemap: https://generasellos.mx/sitemap.xml');
  });

  it('sitemap.xml lista la URL del sitio', () => {
    const sitemap = readFileSync('public/sitemap.xml', 'utf8');
    expect(sitemap).toContain('<loc>https://generasellos.mx/</loc>');
  });
});
