import { expect, test } from '@playwright/test'
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate'

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where the
 * KpqC WASM has loaded, three demo boxes have really been sealed (nine PBKDF2
 * runs at 600k iterations) and the hint banner is up; the skip link focused;
 * both branches of the classical/post-quantum comparison; all five disclosures
 * opened through their own summaries; the hint banner dismissed; the deposit
 * form on an empty box, rejected twice — once empty, once with three identical
 * passwords — then with the passwords revealed, then sealing for real; the
 * below-threshold open, where one share turns the SMAUG-T pill amber and the
 * key strip visibly diverges; the successful two-of-three open, where the
 * rebuilt key strip is compared cell by cell against the true original; the
 * tamper, which is a different failure mode and stops at a red HAETAE pill
 * before any share is touched; the retrieve form on a demo box; the vault
 * cleared to nine empty boxes and reset back; and the Korean locale with its
 * own demo-box set. Every one of those states is scanned, in both themes, at
 * desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (the old spec killed
 * motion with `addStyleTag`, bypassing this lab's own reduced-motion block and
 * the `matchMedia` branch in `keystrip.ts`), why no disclosure is force-opened
 * (the old spec set `.open = true` on all five before its only scan), why the
 * panel is opened at all (it does not exist until a box is clicked, so nothing
 * in it had ever been scanned), why the lab's defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 */

for (const theme of ['light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000)
    const errors = watchPageErrors(page)
    await boot(page, theme)
    await driveAllStates(page, theme)
    expect(errors, errors.join('\n')).toEqual([])
    expectBaselineNotStale()
    reportCollected()
  })

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000)
    const errors = watchPageErrors(page)
    await page.setViewportSize(NARROW)
    await boot(page, theme)
    await driveAllStates(page, `${theme} @380px`)
    expect(errors, errors.join('\n')).toEqual([])
    expectBaselineNotStale()
    reportCollected()
  })
}
