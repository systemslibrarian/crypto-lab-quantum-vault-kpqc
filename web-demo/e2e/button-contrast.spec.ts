import { expect, test } from '@playwright/test';

// Reproduce the real disabled-to-enabled styles without replacing CSS or the
// contrast oracle. The app toggles this state around ordinary open requests.
test('Open box stays readable as its actual disabled background transitions back to enabled', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/crypto-lab-quantum-vault-kpqc/');
  await expect(page.locator('[data-box="06"].occupied')).toBeVisible();
  await page.locator('[data-box="06"]').click();
  const measurement = await page.locator('#btn-open').evaluate(async element => {
    const button = element as HTMLButtonElement;
    button.disabled = true;
    // An actual open holds the disabled style while crypto/animation completes.
    // Finish the browser's own transition; do not inject styles or sleep.
    getComputedStyle(button).backgroundColor;
    await Promise.all(button.getAnimations().map(animation => animation.finished));
    const disabledBackground = getComputedStyle(button).backgroundColor;
    button.disabled = false;
    const style = getComputedStyle(button);
    const channel = (value: number) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    const luminance = (color: string) => {
      const rgb = color.match(/[\d.]+/g)!.slice(0, 3).map(value => channel(Number(value) / 255));
      return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
    };
    const foreground = style.color, background = style.backgroundColor;
    const light = luminance(foreground), dark = luminance(background);
    return { enabled: !button.disabled, disabledBackground, foreground, background,
      ratio: (Math.max(light, dark) + 0.05) / (Math.min(light, dark) + 0.05) };
  });
  console.log('Actual enabled-button transition control:', JSON.stringify(measurement));
  expect(measurement.enabled).toBe(true);
  expect(measurement.ratio).toBeGreaterThanOrEqual(4.5);
});
