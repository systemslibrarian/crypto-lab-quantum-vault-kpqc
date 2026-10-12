import { test, expect, type Page } from '@playwright/test';

const APP = '/crypto-lab-quantum-vault-kpqc/';

async function loaded(page: Page): Promise<string> {
  const chunks: string[] = [];
  page.on('response', response => {
    if (/\/assets\/haetae-[^/]+\.js$/.test(response.url())) chunks.push(response.url());
  });
  await page.goto(APP);
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible();
  expect(chunks).toHaveLength(1);
  return chunks[0];
}

test('real shipped HAETAE accepts a replacement self-signed key, without original signing key or passwords', async ({ page }, testInfo) => {
  const chunk = await loaded(page);
  // Import the actual production HAETAE loader chunk, not a mock or a test export.
  // The only signing input is public container data. Participant passwords are
  // supplied to the ordinary UI afterwards to prove ciphertext was unchanged.
  const controls = await page.evaluate(async ({ chunk, app }) => {
    const factory = (await import(chunk)).default;
    const module = await factory({ locateFile: (file: string) => new URL(app + file, location.origin).href });
    const state = JSON.parse(localStorage.getItem('quantum-vault-data')!);
    const original = state.boxes['06'];
    const decode = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
    const encode = (value: Uint8Array) => btoa(String.fromCharCode(...value));
    // Independently reproduce the documented canonical signed corpus.
    const corpus = (box: typeof original) => new TextEncoder().encode(JSON.stringify({
      ciphertext: box.ciphertext, createdAt: box.createdAt, nonce: box.nonce,
      sigPublicKey: box.sigPublicKey,
      wrappedShares: box.wrappedShares.map((share: Record<string, string | number>) => ({
        iterations: share.iterations ?? 100_000, kemCiphertext: share.kemCiphertext,
        publicKey: share.publicKey, salt: share.salt, shareNonce: share.shareNonce,
        skNonce: share.skNonce, wrappedSecretKey: share.wrappedSecretKey,
        wrappedShare: share.wrappedShare,
      })),
    }));
    const verify = (box: typeof original, key = decode(box.sigPublicKey)) => {
      const signature = decode(box.signature), message = corpus(box);
      const sigPtr = module._malloc(signature.length), msgPtr = module._malloc(message.length), pkPtr = module._malloc(key.length);
      try {
        module.HEAPU8.set(signature, sigPtr); module.HEAPU8.set(message, msgPtr); module.HEAPU8.set(key, pkPtr);
        return module._haetae_verify(sigPtr, signature.length, msgPtr, message.length, pkPtr) === 0;
      } finally { module._free(sigPtr); module._free(msgPtr); module._free(pkPtr); }
    };
    const originalAccepted = verify(original);
    const changed = { ...original, createdAt: '2000-01-01T00:00:00.000Z' };
    const unchangedKeyRejectsTimestamp = !verify(changed);
    const pkSize = module._haetae_publickeybytes(), skSize = module._haetae_secretkeybytes();
    const pkPtr = module._malloc(pkSize), skPtr = module._malloc(skSize);
    let replacementAccepted = false, fixedOriginalKeyRejects = false, keyOnlyRejected = false, keypairResult = -1, signResult = -1;
    try {
      keypairResult = module._haetae_keypair(pkPtr, skPtr);
      const newPublicKey = module.HEAPU8.slice(pkPtr, pkPtr + pkSize);
      changed.sigPublicKey = encode(newPublicKey);
      keyOnlyRejected = !verify(changed);
      const message = corpus(changed), msgPtr = module._malloc(message.length), sigPtr = module._malloc(module._haetae_sigbytes()), lenPtr = module._malloc(8);
      try {
        module.HEAPU8.set(message, msgPtr);
        signResult = module._haetae_sign(sigPtr, lenPtr, msgPtr, message.length, skPtr);
        const length = module.HEAPU32[lenPtr >> 2];
        changed.signature = encode(module.HEAPU8.slice(sigPtr, sigPtr + length));
      } finally { module._free(msgPtr); module._free(sigPtr); module._free(lenPtr); }
      replacementAccepted = verify(changed);
      fixedOriginalKeyRejects = !verify(changed, decode(original.sigPublicKey));
    } finally { module.HEAPU8.fill(0, skPtr, skPtr + skSize); module._free(pkPtr); module._free(skPtr); }
    const ciphertextUnchanged = changed.ciphertext === original.ciphertext && changed.nonce === original.nonce;
    const wrappedSharesUnchanged = JSON.stringify(changed.wrappedShares) === JSON.stringify(original.wrappedShares);
    state.boxes['06'] = changed;
    localStorage.setItem('quantum-vault-data', JSON.stringify(state));
    return { originalAccepted, unchangedKeyRejectsTimestamp, keyOnlyRejected, keypairResult, signResult,
      replacementAccepted, fixedOriginalKeyRejects, ciphertextUnchanged, wrappedSharesUnchanged };
  }, { chunk, app: APP });
  expect(controls).toEqual({ originalAccepted: true, unchangedKeyRejectsTimestamp: true, keyOnlyRejected: true,
    keypairResult: 0, signResult: 0, replacementAccepted: true, fixedOriginalKeyRejects: true,
    ciphertextUnchanged: true, wrappedSharesUnchanged: true });
  console.log('Real shipped-WASM trust controls:', JSON.stringify(controls));
  await testInfo.attach('real-WASM-public-key-controls', { body: JSON.stringify(controls, null, 2), contentType: 'application/json' });
  await page.reload();
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible();
  await page.locator('[data-box="06"]').click();
  await page.locator('#rpw-alice').fill('fortress');
  await page.locator('#rpw-bob').fill('bastion');
  await page.locator('#btn-open').click();
  await expect(page.locator('#retrieve-result')).toContainText('Launch code: ALPHA-7749-ZULU');
  await expect(page.locator('#signature-trust-note')).toContainText('not authenticated');
});

for (const width of [1280, 380, 320]) {
  test(`signature scope remains explicit in both languages at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await loaded(page);
    await expect(page.locator('#signature-trust-note')).toBeVisible();
    await expect(page.locator('#signature-trust-note')).toContainText('not authenticated');
    await expect(page.locator('#signature-trust-note')).toContainText('replace the key');
    await expect(page.locator('.pd-step-4')).not.toContainText('any tampering');
    // Locale changes re-render the app; the warning must survive as visible text.
    await page.locator('.lang-btn[data-lang="ko"]').click();
    await expect(page.locator('#signature-trust-note')).toContainText('인증되지');
    await expect(page.locator('#signature-trust-note')).toContainText('공개 키');
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    expect(errors).toEqual([]);
  });
}
