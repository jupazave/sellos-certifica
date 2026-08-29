import { describe, expect, it } from 'vitest';
import forge from 'node-forge';

describe('wiring del proyecto', () => {
  it('node-forge carga y calcula sha256', () => {
    const hex = forge.md.sha256.create().update('sellos').digest().toHex();
    expect(hex).toHaveLength(64);
  });
});
