// End-to-end coverage of the real seal/open pipeline driven through the UI.
//
// Every demo box is sealed on load with genuine KpqC WASM crypto (AES-256-GCM →
// Shamir split → SMAUG-T wrap → HAETAE sign), so these tests exercise the full
// stack — not mocks. The English demo set occupies boxes 03 / 06 / 09; any two
// of each box's three passwords reconstruct the secret, one (or wrong) passwords
// must fail. See src/vault/demo.ts for the source of truth.

import { test, expect, type Page } from '@playwright/test';

const APP_PATH = '/crypto-lab-quantum-vault-kpqc/';

// English demo boxes — must stay in sync with src/vault/demo.ts (EN_BOXES).
const DEMO = {
  '03': {
    secret: 'The treasure map is under the old oak tree',
    passwords: ['ruby', 'emerald', 'diamond'] as const,
  },
  '06': {
    secret: 'Launch code: ALPHA-7749-ZULU',
    passwords: ['fortress', 'bastion', 'citadel'] as const,
  },
  '09': {
    secret: 'The meeting is moved to Friday at noon',
    passwords: ['monday', 'tuesday', 'wednesday'] as const,
  },
};

/** Navigate to the app and wait until demo boxes have been sealed and rendered. */
async function gotoLoadedVault(page: Page): Promise<string[]> {
  const pageErrors: string[] = [];
  page.on('pageerror', (err) => pageErrors.push(err.message));

  await page.goto(APP_PATH);

  // The demo boxes are sealed with real crypto on first load; box 06 gaining the
  // `.occupied` class is the signal that initialisation + WASM are fully ready.
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible({
    timeout: 30_000,
  });
  return pageErrors;
}

/** Open the retrieve panel for a box and submit the given passwords (a/b/c). */
async function attemptOpen(
  page: Page,
  box: string,
  passwords: [string?, string?, string?],
): Promise<void> {
  await page.locator(`[data-box="${box}"]`).click();
  await expect(page.locator('#retrieve-title')).toBeVisible();

  const [a, b, c] = passwords;
  if (a) await page.fill('#rpw-alice', a);
  if (b) await page.fill('#rpw-bob', b);
  if (c) await page.fill('#rpw-carol', c);

  await page.click('#btn-open');
}

test.describe('Quantum Vault — seal/open pipeline', () => {
  test('loads with 9 boxes, three pre-sealed, and no uncaught errors', async ({
    page,
  }) => {
    const pageErrors = await gotoLoadedVault(page);

    await expect(page.locator('[data-box]')).toHaveCount(9);
    for (const box of ['03', '06', '09']) {
      await expect(page.locator(`[data-box="${box}"]`)).toHaveClass(/occupied/);
    }
    // Empty boxes really are empty (no stale demo data leaking in).
    for (const box of ['01', '02', '04']) {
      await expect(page.locator(`[data-box="${box}"]`)).toHaveClass(/empty/);
    }

    expect(pageErrors).toEqual([]);
  });

  test('opens a box with two correct passwords and reveals the secret', async ({
    page,
  }) => {
    await gotoLoadedVault(page);
    await attemptOpen(page, '06', [DEMO['06'].passwords[0], DEMO['06'].passwords[1]]);

    await expect(page.locator('#retrieve-result')).toContainText(
      DEMO['06'].secret,
      { timeout: 30_000 },
    );
    await expect(page.locator('#retrieve-title')).toContainText('decrypted');
    await expect(page.locator('#retrieve-result .result-failure')).toHaveCount(0);
  });

  test('any two of the three passwords reconstruct (different pair)', async ({
    page,
  }) => {
    await gotoLoadedVault(page);
    // Use the 2nd + 3rd passwords — proves it is genuine threshold recovery,
    // not a hard-coded "first password wins" shortcut.
    await attemptOpen(page, '03', [
      undefined,
      DEMO['03'].passwords[1],
      DEMO['03'].passwords[2],
    ]);

    await expect(page.locator('#retrieve-result')).toContainText(
      DEMO['03'].secret,
      { timeout: 30_000 },
    );
  });

  test('a single correct password is below threshold — access denied', async ({
    page,
  }) => {
    await gotoLoadedVault(page);
    await attemptOpen(page, '09', [DEMO['09'].passwords[0]]);

    await expect(page.locator('#retrieve-result')).toContainText('ACCESS DENIED', {
      timeout: 30_000,
    });
    await expect(page.locator('#retrieve-title')).toContainText('access denied');
    // The real secret must never appear on a failed open.
    await expect(page.locator('#retrieve-result')).not.toContainText(
      DEMO['09'].secret,
    );
  });

  test('two wrong passwords are rejected — access denied', async ({ page }) => {
    await gotoLoadedVault(page);
    await attemptOpen(page, '03', ['not-the-password', 'also-wrong']);

    await expect(page.locator('#retrieve-result')).toContainText('ACCESS DENIED', {
      timeout: 30_000,
    });
    await expect(page.locator('#retrieve-result')).not.toContainText(
      DEMO['03'].secret,
    );
  });

  test('seals a new secret into an empty box and opens it again', async ({
    page,
  }) => {
    await gotoLoadedVault(page);

    const secret = 'e2e round-trip secret 42';
    const pws = ['alpha-key', 'bravo-key', 'charlie-key'];

    // Deposit into empty box 02.
    await page.locator('[data-box="02"]').click();
    await expect(page.locator('#deposit-message')).toBeVisible();
    await page.fill('#deposit-message', secret);
    await page.fill('#pw-alice', pws[0]);
    await page.fill('#pw-bob', pws[1]);
    await page.fill('#pw-carol', pws[2]);
    await page.click('#btn-seal');

    // Seal succeeds → panel switches to retrieve with a success notice.
    await expect(page.locator('#retrieve-result')).toContainText('box 02', {
      timeout: 30_000,
    });
    await expect(page.locator('[data-box="02"]')).toHaveClass(/occupied/);

    // Re-open with two of the freshly chosen passwords.
    await page.fill('#rpw-alice', pws[0]);
    await page.fill('#rpw-carol', pws[2]);
    await page.click('#btn-open');

    await expect(page.locator('#retrieve-result')).toContainText(secret, {
      timeout: 30_000,
    });
  });
});
