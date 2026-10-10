import { expect, test, type Page } from '@playwright/test';

const APP = '/crypto-lab-quantum-vault-kpqc/';

async function loaded(page: Page): Promise<string> {
  const chunks: string[] = [];
  page.on('response', r => {
    if (/\/assets\/haetae-[^/]+\.js$/.test(r.url())) chunks.push(r.url());
  });
  await page.goto(APP);
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible();
  expect(chunks).toHaveLength(1);
  return chunks[0];
}

async function openTwo(page: Page): Promise<void> {
  await page.locator('[data-box="06"]').click();
  await page.fill('#rpw-alice', 'fortress');
  await page.fill('#rpw-bob', 'bastion');
  await page.click('#btn-open');
}

for (const width of [1280, 380, 320]) {
  test(`reconstruction is confirmed by authenticated decryption, without a copied original, at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await loaded(page);
    await openTwo(page);
    await expect(page.locator('#retrieve-result')).toContainText('Launch code: ALPHA-7749-ZULU');
    await expect(page.locator('.ks-verdict.ks-ok')).toContainText('successful authenticated decryption');
    await expect(page.locator('.ks-evidence-note')).toContainText('no independent original-key comparison');
    await expect(page.locator('.ks-row.ks-original')).toHaveCount(0);
    await expect(page.locator('.ks-cell-match, .ks-cell-miss')).toHaveCount(0);
    await expect(page.locator('.ks-share.ks-merge')).toHaveCount(2);
    await expect(page.locator('#ps-aes.done')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    await page.locator('.lang-btn[data-lang="ko"]').click();
    // Locale switching regenerates the Korean demo set; wait for its real box.
    await expect(page.locator('[data-box="04"].occupied')).toBeVisible();
    await page.locator('[data-box="04"]').click();
    await page.fill('#rpw-alice', '거북선');
    await page.fill('#rpw-bob', '첨성대');
    await page.click('#btn-open');
    await expect(page.locator('.ks-verdict.ks-ok')).toContainText('인증된 복호화');
    await expect(page.locator('.ks-evidence-note')).toContainText('독립적인 원본 키 비교');
    await expect(page.locator('.ks-row.ks-original')).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
  });
}

test('two genuine shares cannot turn a correctly re-signed corrupt ciphertext into a green AES result', async ({ page }, testInfo) => {
  const chunk = await loaded(page);
  const controls = await page.evaluate(async ({ chunk, app }) => {
    // Actual shipped loader/WASM; no pipeline mocks or production test exports.
    const module = await (await import(chunk)).default({ locateFile: (f: string) => new URL(app + f, location.origin).href });
    const state = JSON.parse(localStorage.getItem('quantum-vault-data')!);
    const original = state.boxes['06'];
    const decode = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
    const encode = (b: Uint8Array) => btoa(String.fromCharCode(...b));
    const changed = { ...original };
    const ciphertext = decode(changed.ciphertext); ciphertext[0] ^= 1;
    changed.ciphertext = encode(ciphertext);
    const corpus = () => new TextEncoder().encode(JSON.stringify({
      ciphertext: changed.ciphertext, createdAt: changed.createdAt, nonce: changed.nonce,
      sigPublicKey: changed.sigPublicKey,
      wrappedShares: changed.wrappedShares.map((s: Record<string, string | number>) => ({
        iterations: s.iterations ?? 100_000, kemCiphertext: s.kemCiphertext,
        publicKey: s.publicKey, salt: s.salt, shareNonce: s.shareNonce, skNonce: s.skNonce,
        wrappedSecretKey: s.wrappedSecretKey, wrappedShare: s.wrappedShare,
      })),
    }));
    const pkPtr = module._malloc(module._haetae_publickeybytes()), skPtr = module._malloc(module._haetae_secretkeybytes());
    let keypairResult = -1, signResult = -1, verifyResult = -1;
    try {
      keypairResult = module._haetae_keypair(pkPtr, skPtr);
      changed.sigPublicKey = encode(module.HEAPU8.slice(pkPtr, pkPtr + module._haetae_publickeybytes()));
      const message = corpus(), msgPtr = module._malloc(message.length);
      const sigPtr = module._malloc(module._haetae_sigbytes()), lenPtr = module._malloc(8);
      try {
        module.HEAPU8.set(message, msgPtr);
        signResult = module._haetae_sign(sigPtr, lenPtr, msgPtr, message.length, skPtr);
        const len = module.HEAPU32[lenPtr >> 2];
        changed.signature = encode(module.HEAPU8.slice(sigPtr, sigPtr + len));
        verifyResult = module._haetae_verify(sigPtr, len, msgPtr, message.length, pkPtr);
      } finally { module._free(msgPtr); module._free(sigPtr); module._free(lenPtr); }
    } finally { module.HEAPU8.fill(0, skPtr, skPtr + module._haetae_secretkeybytes()); module._free(pkPtr); module._free(skPtr); }
    state.boxes['06'] = changed;
    localStorage.setItem('quantum-vault-data', JSON.stringify(state));
    return { keypairResult, signResult, verifyResult, ciphertextChanged: changed.ciphertext !== original.ciphertext,
      nonceUnchanged: changed.nonce === original.nonce,
      wrappedSharesUnchanged: JSON.stringify(changed.wrappedShares) === JSON.stringify(original.wrappedShares) };
  }, { chunk, app: APP });
  expect(controls).toEqual({ keypairResult: 0, signResult: 0, verifyResult: 0, ciphertextChanged: true, nonceUnchanged: true, wrappedSharesUnchanged: true });
  console.log('Shipped-WASM re-sign/AES-failure controls:', JSON.stringify(controls));
  await testInfo.attach('correctly-resigned-corrupt-ciphertext', { body: JSON.stringify(controls), contentType: 'application/json' });
  await page.reload();
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible();
  await openTwo(page);
  await expect(page.locator('#retrieve-result .result-failure')).toBeVisible();
  await expect(page.locator('#ps-haetae.done')).toBeVisible();
  await expect(page.locator('#ps-smaug')).toContainText('2 ✓');
  await expect(page.locator('#ps-aes.failed')).toBeVisible();
  await expect(page.locator('#ps-aes.done')).toHaveCount(0);
  await expect(page.locator('.ks-verdict.ks-ok')).toHaveCount(0);
  await expect(page.locator('.ks-verdict.ks-bad')).toContainText('authentication failed');
  await expect(page.locator('.ks-row.ks-original, .ks-cell-match')).toHaveCount(0);
  await expect(page.locator('#retrieve-result')).not.toContainText('Launch code: ALPHA-7749-ZULU');
});
