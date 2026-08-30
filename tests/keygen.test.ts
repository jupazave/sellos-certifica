import { describe, expect, it } from 'vitest';
import { generarParCSD } from '../src/crypto/keygen';

describe('generarParCSD', () => {
  it('genera un par RSA-2048 cuyas mitades coinciden', async () => {
    const { privada, publica } = await generarParCSD();
    expect(privada.n.bitLength()).toBe(2048);
    expect(publica.n.compareTo(privada.n)).toBe(0);
    expect(publica.e.toString(16)).toBe('10001');
  }, 20_000);
});
