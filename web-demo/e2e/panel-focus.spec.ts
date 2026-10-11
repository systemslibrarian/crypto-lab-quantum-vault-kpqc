import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.goto('/crypto-lab-quantum-vault-kpqc/');
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible();
});

test('opening either form hands focus to its initial field', async ({ page }) => {
  await page.locator('[data-box="02"]').click();
  await expect(page.locator('#deposit-message')).toBeFocused();
  await page.locator('[data-box="03"]').click();
  await expect(page.locator('#rpw-alice')).toBeFocused();
});

test('delayed panel focus preserves a field already selected by the user', async ({ page }) => {
  // A single task guarantees that user focus precedes the application's
  // 50ms timer. No application timer or crypto implementation is mocked.
  await page.evaluate(() => {
    document.querySelector<HTMLButtonElement>('[data-box="02"]')!.click();
    document.querySelector<HTMLInputElement>('#pw-carol')!.focus();
  });
  await page.waitForTimeout(100);
  await expect(page.locator('#pw-carol')).toBeFocused();
  await page.keyboard.type('carol-password');
  await expect(page.locator('#pw-carol')).toHaveValue('carol-password');
  await expect(page.locator('#deposit-message')).toHaveValue('');

  await page.evaluate(() => {
    document.querySelector<HTMLButtonElement>('[data-box="03"]')!.click();
    document.querySelector<HTMLInputElement>('#rpw-carol')!.focus();
  });
  await page.waitForTimeout(100);
  await expect(page.locator('#rpw-carol')).toBeFocused();
  await page.keyboard.type('diamond');
  await expect(page.locator('#rpw-carol')).toHaveValue('diamond');
  await expect(page.locator('#rpw-alice')).toHaveValue('');
});
