import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the seal/open pipeline
 * (vault.spec.ts); this gates them on accessibility the same way. Scans the
 * full page with every <details> expanded, in both themes.
 *
 * This repo defaults to the LIGHT hanji palette; dark is reached via the toggle.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Load the app and wait until the demo boxes are sealed + rendered. */
async function gotoLoadedVault(page: Page): Promise<void> {
  await page.goto('.');
  // Box 06 gaining `.occupied` means init + WASM crypto are fully ready.
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible({
    timeout: 30_000,
  });
}

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true;
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in light theme (default)', async ({ page }) => {
  await gotoLoadedVault(page);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await openAllDetails(page);
  await scan(page);
});

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await gotoLoadedVault(page);
  await page.locator('#theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await openAllDetails(page);
  await scan(page);
});
