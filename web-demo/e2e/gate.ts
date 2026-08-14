import AxeBuilder from '@axe-core/playwright'
import { expect, type Page } from '@playwright/test'
import { auditContrast, formatContrastFailures } from './contrast'
import { auditNonText } from './nontext'
import { NONTEXT_BASELINE } from './nontext-baseline'

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 }

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects a specific thing the
 * gate this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec's
 *     `neutralizeMotion()` pushed
 *     `transition-duration:0s!important; animation-duration:0s!important`
 *     through `addStyleTag`, and its own comment said why: a scan fired right
 *     after the theme toggle sampled the vault buttons' `color` part-way
 *     through a 150ms blend and reported a contrast violation the settled page
 *     does not have. The diagnosis was right and the fix was wrong twice over.
 *     It BYPASSES this lab's own `@media (prefers-reduced-motion: reduce)`
 *     block instead of exercising it — and that block is not a formality here:
 *     it cancels the `.panel-area` `max-height` slide, the `.deposit-box`
 *     transitions, and the `.keystrip` / `.ks-merge` fades, and `keystrip.ts`
 *     branches on `matchMedia('(prefers-reduced-motion: reduce)')` in
 *     JavaScript to skip the share-merge animation entirely. None of that was
 *     ever exercised. And it treats a timing bug as a colour bug: this gate
 *     waits for `document.getAnimations()` to drain instead (see `settle`), so
 *     the endpoint colours are sampled because the page has actually reached
 *     them.
 *
 *  2. IT FORCE-REVEALED DISCLOSURES FROM SCRIPT. The old `openAllDetails()` set
 *     `details.open = true` on all five `<details>` — the four glossary items
 *     and the "go deeper" note — before its only scan, so the shut state that
 *     every visitor arrives at was never measured, and neither was the act of
 *     opening one. This gate clicks each `<summary>`, which is the route a
 *     reader has, and scans both states.
 *
 *  3. IT NEVER OPENED THE PANEL, WHICH IS WHERE THE LAB LIVES. The old spec
 *     loaded the page, waited for box 06 to become occupied, and scanned. The
 *     deposit and retrieve forms are built by `panel.ts` into an empty
 *     `#panel` div on box click and do not exist until then — so every
 *     `<label>`, every password input, the textarea, the four inline
 *     `role="alert"` error slots, the seal/open/cancel/tamper buttons, the
 *     pipeline pills, the key-strip and both result boxes were outside every
 *     scan the repo had ever run. So were all three failure modes the lab
 *     exists to teach. This drive opens the panel on both an empty and an
 *     occupied box and scans after every step.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The shared top bar's
 *     ink and button edges are `color-mix(in srgb, …)`, which axe files under
 *     `incomplete` rather than judging, and so is an `aria-labelledby` on a
 *     role-less element — of which this page has two.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE, and it
 *     scanned one viewport. `nontext.ts` supplies the first two and runs at
 *     every driven state; `expectNoHorizontalOverflow` supplies 1.4.10, which
 *     axe has no rule for at all.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * This is the honest replacement for the old spec's `addStyleTag` motion kill.
 * The defect it was written for is real — `.btn-vault-action` and `.btn-reset`
 * carry `transition: background 150ms, color 150ms`, so a scan fired
 * immediately after the theme toggle samples a colour that exists in no state
 * of the page — and waiting for the animation set to empty fixes it without
 * touching the document.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number }
      const running = document.getAnimations().filter((a) => a.playState === 'running')
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0
      return w.__quietFrames >= 6
    },
    undefined,
    { timeout: 20_000, polling: 'raf' },
  )
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page has exactly that shape and gets it right, which is worth measuring
 * rather than reading: `.keystrip { opacity: 0 }` is the Shamir key-strip's
 * SHIPPED state, and `.keystrip.ks-in { opacity: 1 }` is its only route to
 * being visible. The reduced-motion block sets `transition: none` on
 * `.keystrip` — cancelling the fade, not the end state — and `keystrip.ts`
 * adds `ks-in` from a `requestAnimationFrame` callback, which still runs. Had
 * the block written `opacity: 0` or had the class been added from a
 * `transitionend` handler, every reader with the preference set would see an
 * empty box where the key and its three shares should be. The check runs in
 * every state because that is a property of the current stylesheet rather than
 * of the page.
 *
 * `aria-hidden` subtrees are excluded; see the note on `ariaHidden` in
 * `contrast.ts` for what this lab hides and why each one was checked by hand.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = []
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim()
      if (!own) continue
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue
      if (el.closest('[aria-hidden="true"]')) continue
      let effective = 1
      let node: Element | null = el
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity)
        node = node.parentElement
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`)
      }
    }
    return Array.from(new Set(out))
  })
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([])
}

/**
 * Uncaught page errors and console errors, collected from the moment the page is
 * created.
 *
 * This one is not decorative here. `main.ts` wraps its whole `init()` in a
 * `.catch()` that REPLACES the document body with a diagnostics dump, and wraps
 * demo-box generation in a `try/catch` that logs and recovers to an EMPTY
 * vault. Either path leaves a plausible-looking page that a scan reports green
 * — the second one silently, with all nine boxes empty and every occupied-box
 * state unreachable. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`)
  })
  return errors
}

/**
 * Exactly one banner landmark.
 *
 * This lab declares `<header class="cl-topbar" role="banner">` and also a
 * `<header class="cl-hero">` — but the hero is INSIDE `<main class="page-wrapper"
 * id="main-content">`, which scopes it out of the banner role on its own, and
 * `index.html` additionally ships the newer `dedupeBanner()` that demotes any
 * un-scoped second `<header>` to `role="group"`. Asserting the OUTCOME rather
 * than either mechanism is what catches a change to that nesting.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION'])
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true
      if (el.tagName !== 'HEADER') return false
      if (el.getAttribute('role')) return false // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false
      return true
    }
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length
  })
  expect(banners, 'exactly one banner landmark').toBe(1)
}

/**
 * An explicit role on a list REPLACES its implicit `list` role, orphaning every
 * `<li>` — a defect a source grep cannot see when the role is assigned as a JS
 * property rather than an HTML attribute.
 *
 * `role="list"` itself is the benign case (redundant, not destructive), and
 * this page uses it three times: `<ol class="pipeline-diagram" role="list">`,
 * `<ol class="layer-diagram" role="list">`, and `<div class="info-bar"
 * role="list">` with `role="listitem"` children. `pipeline-ui.ts` builds a
 * fourth at runtime the same way. Anything OTHER than `list` on a list element
 * is the destructive case and fails here.
 */
export async function assertListsKeepTheirSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list')
      .map((e) => `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`),
  )
  expect(broken, 'an explicit non-list role on a list deletes its list semantics').toEqual([])
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which pins down a real failure mode as a side effect: `index.html`'s
 * anti-flash script reads `localStorage.getItem('theme')` and `main.ts`'s
 * `setupThemeToggle` writes `localStorage.setItem('theme', …)`. If those keys
 * drift apart the theme silently stops persisting, and this boot fails on
 * `data-theme` rather than quietly scanning one theme twice. Note that THIS
 * LAB'S DEFAULT IS LIGHT, not dark — the warm hanji palette is the intended
 * look — so the seed is what makes "dark" a real configuration rather than a
 * post-hoc toggle, which is how the old spec reached it.
 *
 * The defaults are asserted at length because the entire vault is built by
 * JavaScript into empty hosts, after a real KpqC WASM load and NINE PBKDF2
 * runs at 600k iterations (three demo boxes × three keyholders). A navigation
 * that resolves proves nothing here: `main.ts` catches a demo-generation
 * failure and recovers to an EMPTY vault, and an empty vault is exactly what a
 * scan reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  // `btn-reset`, `btn-clear-vault` and the whole-vault import all gate on
  // `confirm()`, and Playwright's default is to DISMISS an unhandled dialog —
  // so a drive without this clicks Reset and silently gets nothing, then
  // asserts against a page that never changed.
  page.on('dialog', (d) => void d.accept())
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme)
  await page.goto('.')
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect',
  ).toBe(true)
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme)
  await assertSingleBanner(page)
  await assertListsKeepTheirSemantics(page)

  // The `hidden` attribute really removes an element. `[hidden]` has
  // specificity (0,1,0) — identical to a class — so any later `.foo { display:
  // … }` beats it and the attribute silently does nothing. This lab depends on
  // it in two places: the classical/post-quantum comparison shows one of
  // `#pq-body-classical` / `#pq-body-post` by toggling `hidden`, and both file
  // inputs (`#input-import-vault`, `#import-file`) are `hidden` with a styled
  // `<label>` as their visible control. Measured from a live element rather
  // than inferred from the CSS.
  expect(
    await page.evaluate(() => {
      const probe = document.createElement('div')
      probe.hidden = true
      document.body.appendChild(probe)
      const display = getComputedStyle(probe).display
      probe.remove()
      return display
    }),
    'the hidden attribute must actually hide (the pq comparison and both file inputs rely on it)',
  ).toBe('none')

  // `opacity: 0` plus `pointer-events: none` is NOT hiding — the element still
  // takes focus and is still read out. This page's one opacity-hidden element
  // is `.keystrip`, which is why the probe is aimed at the general rule: any
  // element that is invisible must also be out of the tab order.
  expect(
    await page.evaluate(() => {
      const probe = document.createElement('button')
      probe.textContent = 'probe'
      probe.style.cssText = 'opacity:0;pointer-events:none'
      document.body.appendChild(probe)
      probe.focus()
      const focused = document.activeElement === probe
      probe.remove()
      return focused
    }),
    'opacity:0 + pointer-events:none does NOT hide from the keyboard — if a real control ' +
      'is ever hidden that way it must use hidden/display:none instead',
  ).toBe(true)

  // The skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run says
  // nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#main-content')
  await expect(page.locator('main#main-content')).toHaveCount(1)

  // ── The vault really booted: WASM loaded, nine boxes rendered, and the
  //    three EN demo boxes really sealed (each one three PBKDF2 600k runs) ──
  await expect(page.locator('#wasm-loader')).toBeHidden({ timeout: 120_000 })
  await expect(page.locator('#vault-wall .deposit-box')).toHaveCount(9)
  for (const n of ['03', '06', '09']) {
    await expect(
      page.locator(`[data-box="${n}"]`),
      `demo box ${n} must be occupied — an empty wall means demo generation threw and main.ts recovered silently`,
    ).toHaveClass(/occupied/)
  }
  for (const n of ['01', '02', '04', '05', '07', '08']) {
    await expect(page.locator(`[data-box="${n}"]`)).toHaveClass(/empty/)
  }
  // No box is selected and no panel exists yet: `panel.ts` builds the deposit
  // and retrieve forms into `#panel` on click, so at first paint that host is
  // genuinely empty. This is the state the gate this replaces scanned, and it
  // is the ONLY state it scanned.
  await expect(page.locator('.deposit-box.selected')).toHaveCount(0)
  await expect(page.locator('#panel')).toBeEmpty()

  // ── Every shipped control default ───────────────────────────────────────
  await expect(page.locator('#hint-banner')).toBeVisible()
  await expect(page.locator('#pq-btn-post')).toHaveAttribute('aria-pressed', 'true')
  await expect(page.locator('#pq-btn-classical')).toHaveAttribute('aria-pressed', 'false')
  await expect(page.locator('#pq-body-post')).toBeVisible()
  await expect(page.locator('#pq-body-classical')).toBeHidden()
  await expect(page.locator('.lang-btn[data-lang="en"]')).toHaveAttribute('aria-pressed', 'true')

  // ── Five disclosures, all shut ──────────────────────────────────────────
  // The gate this replaces set `.open = true` on all of them from script before
  // its only scan.
  await expect(page.locator('main details')).toHaveCount(5)
  await expect(page.locator('main details[open]')).toHaveCount(0)

  await settle(page)
  await expectNotBlank(page, `${theme} first paint`)
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the gate this
 * replaces scanned one viewport only. The shapes at risk here are the 3×3
 * `.vault-wall` grid, the three-column `.password-row` inside the panel, the
 * `.pipeline` row of four pills plus three arrows, the `.ks-row` key strips
 * (sixteen `flex: 1 1 0` cells with a `min-width: 6px` floor each), and the
 * demo-credentials table.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement
    if (doc.scrollWidth <= doc.clientWidth) return null

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. The
    // demo-credentials table inside `.table-scroll` is exactly such a decoy.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true
        n = n.parentElement
      }
      return false
    }

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right)
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0]
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    }
  })
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull()
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * The candidate here is `.table-scroll` (`overflow-x: auto`) around the
 * demo-credentials table in the hint banner, which genuinely scrolls at 380px
 * and holds no focusable content at all.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])'
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el)
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`,
      )
  })
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`,
  ).toEqual([])
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT
const collected: string[] = []

function record(entry: string): void {
  collected.push(entry)
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`)
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected)
    return
  }
  try {
    expect(actual, message).toEqual(expected)
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`)
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([])
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label)
  try {
    await expectScrollersReachable(page, label)
  } catch (e) {
    record(String(e).slice(0, 6000))
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * The wrapper is written out longhand rather than folded into a neighbour
 * because of how this oracle died elsewhere in this fleet:
 * `expectNoNewNonTextFailures` had been called from inside
 * `expectScrollersReachableSoft`, AFTER that function's `if (!COLLECTING) return`
 * guard, so in a strict run — which is every run in CI and every run anyone reads
 * as a pass — the guard returned first and `nontext.ts` never executed at all.
 * It is called from `scan()` here, at every driven state, and this repo's
 * baseline was captured by that live path.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label)
  try {
    await expectNoNewNonTextFailures(page, label)
  } catch (e) {
    record(String(e).slice(0, 6000))
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label)
  try {
    await expectNoHorizontalOverflow(page, label)
  } catch (e) {
    record(String(e).slice(0, 6000))
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast, and
 * the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node.
 *
 * The baseline in this repo is EMPTY, and that is the finished state rather than
 * an unrun check: the first full drive found six control boundaries under 3:1 —
 * three shared-top-bar buttons at 1.14:1, `.btn-primary` at 2.74:1 and
 * `.btn-tamper` at 2.84:1 in the dark theme — and every one was fixed in the
 * page's own CSS. The top bar in particular used to be treated as fleet
 * furniture nobody lab could touch; the fix there is accent-independent (see
 * `.cl-btn` in `index.html`) precisely so it is not per-lab drift.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything in
 * the baseline that has been FIXED fails until its entry is deleted. That last
 * rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>()

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page)
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`)
    }
    return
  }
  const problems: string[] = []
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`
    nonTextSeen.add(key)
    const base = NONTEXT_BASELINE[key]
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`)
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`)
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([])
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k))
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)',
  ).toEqual([])
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the shared top bar's
 *    ink and every `.cl-btn` edge are `color-mix(in srgb, …)` and axe resolves
 *    none of them. Everything else in that bucket is a real result axe simply
 *    could not finish — including `aria-prohibited-attr`, which is where an
 *    `aria-label`/`aria-labelledby` on a role-less element hides, a defect that
 *    never reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page)
  await expectNotBlank(page, label)
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads exactly
  // like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of axe-core
  // 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Confirmed here by experiment rather than by reading: `<html lang="en">` was
  // changed to `<html>` and the full drive re-run against the identical page. The
  // merged form below failed on `html-has-lang` (SC 3.1.1, tagged `wcag2a`) at
  // the very first state. See the commit message for the measured before/after.
  //
  // The landmark four are still wanted because they are best-practice rather than
  // WCAG-tagged, so `withTags` alone does not reach them — and this page has the
  // shape they catch: a sticky `<header role="banner">` above a
  // `<main id="main-content">` that itself contains a `<header class="cl-hero">`
  // with an `<aside class="cl-hero-why">` inside it.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze()
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  }

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }))
  softExpect(violations, `axe violations in state: ${label}`, [])

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }))
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, [])

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))))
  softExpect(contrast, `measured contrast failures in state: ${label}`, [])

  await expectNoNewNonTextFailuresSoft(page, label)
  await expectScrollersReachableSoft(page, label)
  await expectNoHorizontalOverflowSoft(page, label)
}

// ── The drive ───────────────────────────────────────────────────────────────

/** The demo secret and passwords sealed into a fresh box by the drive. */
const NEW_SECRET = 'A secret the gate sealed itself'
const NEW_PW: [string, string, string] = ['gatealpha', 'gatebravo', 'gatecharlie']

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE PANEL IS WHERE THE LAB LIVES, AND IT DID NOT EXIST IN ANY PREVIOUS
 *    SCAN. `panel.ts` builds the deposit form (a textarea, three password
 *    inputs, four inline `role="alert"` error slots, a show-passwords checkbox,
 *    an import control) or the retrieve form (three password inputs, export,
 *    tamper, open, cancel) into `#panel` on box click. Both are driven, on an
 *    EMPTY box and an OCCUPIED one respectively.
 *
 *  - THE PREREQUISITE STATE IS SCANNED BEFORE THE UNLOCK. An empty box shows
 *    the deposit form; the same box after sealing shows the retrieve form with
 *    a success banner. Both, in that order.
 *
 *  - ALL THREE FAILURE MODES ARE DRIVEN, and they are three genuinely different
 *    renderings: form validation (four inline errors and `aria-invalid`), the
 *    below-threshold open (an AMBER SMAUG-T pill, a diverging key strip and a
 *    `role="alert"` ACCESS DENIED box), and the tamper (a RED HAETAE pill that
 *    stops the pipeline before any share is touched). None had ever been
 *    scanned.
 *
 *  - THE EMPTY VAULT IS A STATE. "Clear vault" empties all nine boxes, and that
 *    is both the state a returning visitor can be in and the state `main.ts`
 *    silently recovers to when demo generation throws. It is scanned, and then
 *    "Reset to demo" restores the boxes and is scanned too.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `.btn-vault-action:hover`,
 *    `.btn-outline:hover` and `.cl-btn:hover` all repaint, and a reader is in
 *    one of those states for as long as the pointer sits where it clicked.
 *
 *  - NO FIXED TIMEOUTS. Every operation here has a real DOM completion signal —
 *    a box gaining `occupied`, a pipeline pill reaching `done`/`warn`/`failed`,
 *    the key strip appearing, an error slot filling — and the drive waits on
 *    those. Sealing and opening run genuine PBKDF2 at 600k iterations per
 *    keyholder, so the waits are generous but they are still waits on signals.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`)
  const panel = page.locator('#panel')

  await scanAt('first paint, demo vault sealed and the hint banner showing')

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.())
  await page.keyboard.press('Tab')
  await expect(page.locator('a.cl-skip-link')).toBeFocused()
  await scanAt('skip link focused, slid into view')

  // ── The two static mode forks on the page ───────────────────────────────
  await page.click('#pq-btn-classical')
  await expect(page.locator('#pq-body-classical')).toBeVisible()
  await expect(page.locator('#pq-body-post')).toBeHidden()
  await scanAt('classical-crypto branch of the comparison, and its button still hovered')

  await page.click('#pq-btn-post')
  await expect(page.locator('#pq-body-post')).toBeVisible()
  await scanAt('post-quantum branch restored')

  // ── The five disclosures, opened through their own summaries ────────────
  const shut = page.locator('main details:not([open]) > summary')
  await expect(shut).toHaveCount(5)
  for (let i = 0; i < 5; i++) await shut.first().click()
  await expect(page.locator('main details:not([open])')).toHaveCount(0)
  await scanAt('all five glossary and go-deeper disclosures open')

  // ── The hint banner dismissed — the state every returning reader is in ──
  await page.click('#btn-dismiss-hint')
  await expect(page.locator('#hint-banner')).toBeHidden()
  await scanAt('hint banner dismissed')

  // ── An EMPTY box: the deposit form, its validation errors, and a real seal ─
  await page.click('[data-box="01"]')
  await expect(panel.locator('#btn-seal')).toBeVisible()
  await expect(page.locator('[data-box="01"]')).toHaveClass(/selected/)
  await expect(panel.locator('#deposit-message')).toHaveValue('')
  await scanAt('deposit form open on empty box 01, nothing typed')

  // Submitting an untouched form: four inline `role="alert"` errors at once,
  // and `aria-invalid="true"` on all four fields.
  await page.click('#btn-seal')
  await expect(panel.locator('#err-message')).toHaveText('Message cannot be empty.')
  await expect(panel.locator('#err-alice')).toHaveText('Required.')
  await expect(panel.locator('#deposit-message')).toHaveAttribute('aria-invalid', 'true')
  await scanAt('deposit form rejected empty input — four inline alerts')

  // The other validation branch: three identical passwords defeat the whole
  // point of a 2-of-3 threshold, and the form says so in one error rather than
  // four.
  await page.fill('#deposit-message', NEW_SECRET)
  for (const id of ['pw-alice', 'pw-bob', 'pw-carol']) await page.fill(`#${id}`, 'samesame')
  await page.click('#btn-seal')
  await expect(panel.locator('#err-alice')).toHaveText('All 3 passwords must be different.')
  await expect(panel.locator('#err-message')).toBeEmpty()
  await scanAt('deposit form rejected three identical passwords')

  // Show-passwords: the three inputs flip from `password` to `text`, so their
  // content becomes real rendered text for the first time.
  await panel.locator('#show-pw-toggle').check()
  await expect(panel.locator('#pw-alice')).toHaveAttribute('type', 'text')
  await scanAt('passwords revealed as plain text')

  // A genuine seal: three PBKDF2 runs at 600k iterations, then the four-pill
  // pipeline and the real Shamir key strip.
  const pws: [string, string, string] = NEW_PW
  await page.fill('#pw-alice', pws[0])
  await page.fill('#pw-bob', pws[1])
  await page.fill('#pw-carol', pws[2])
  await page.click('#btn-seal')
  await expect(page.locator('[data-box="01"]'), 'the seal must really have happened').toHaveClass(
    /occupied/,
    { timeout: 180_000 },
  )
  await expect(panel.locator('.result-success')).toBeVisible()
  await expect(panel.locator('#btn-open')).toBeVisible()
  await scanAt('box 01 sealed for real — success banner and the retrieve form')

  // ── The below-threshold open: one password is not enough ────────────────
  await page.fill('#rpw-alice', pws[0])
  await page.click('#btn-open')
  await expect(panel.locator('.result-failure'), 'one share must fail closed').toBeVisible({
    timeout: 180_000,
  })
  await expect(panel.locator('#ps-smaug.warn')).toBeVisible()
  await expect(panel.locator('.ks-verdict.ks-bad')).toBeVisible()
  // ONE share, not none. The amber pill and the diverged strip render the same
  // way for zero correct passwords as for one, so without this the state could
  // silently degrade into "typed nothing" and still satisfy every assertion
  // above — which is exactly how the wipe below was masked.
  await expect(panel.locator('.result-failure')).toContainText('only 1 correct')
  await scanAt('open with ONE share — amber SMAUG-T pill, diverged key strip, ACCESS DENIED')

  // A denied open is not finished when ACCESS DENIED appears. `handleRetrieve`
  // holds that message for 1500ms so it can be read and THEN wipes every
  // password field, and both halves happen after the assertions above resolve.
  // Typing the next attempt straight away therefore races the wipe: the fields
  // are filled, cleared underneath, and the retry submits three empty strings —
  // which the lab correctly reports as "only 0 correct", so the drive fails on
  // the SUCCESS assertion below having proved nothing about two-of-three. Wait
  // for the app's own reset, which is the real completion signal for this state.
  await expect(
    panel.locator('#rpw-alice'),
    'the denial resets the password fields; the retry must start after that',
  ).toHaveValue('')

  // ── The successful open: any two of the three ───────────────────────────
  await page.fill('#rpw-alice', pws[0])
  await page.fill('#rpw-carol', pws[2])
  await page.click('#btn-open')
  await expect(panel.locator('.result-success'), 'two shares must reconstruct the key').toBeVisible({
    timeout: 180_000,
  })
  await expect(panel.locator('.ks-verdict.ks-ok')).toBeVisible()
  await expect(panel.locator('#retrieve-title')).toContainText('decrypted')
  await scanAt('open with TWO shares — key strip matches the original, secret revealed')

  // ── The tamper: a DIFFERENT failure mode, red rather than amber, and it
  //    stops before any share is touched ─────────────────────────────────────
  await page.click('#btn-tamper')
  await expect(panel.locator('#ps-haetae.failed')).toBeVisible({ timeout: 180_000 })
  await expect(panel.locator('.narr-fail')).toBeVisible()
  await expect(panel.locator('.result-failure')).toBeVisible()
  await scanAt('tampered container — HAETAE verify fails RED, pipeline stops there')

  // Hover persists after a click: this is the state a reader occupies for as
  // long as the pointer sits where it just clicked.
  await panel.locator('#btn-cancel-retrieve').hover()
  await scanAt('a secondary panel button hovered')

  await page.click('#btn-cancel-retrieve')
  await expect(page.locator('#panel')).toBeEmpty()
  await expect(page.locator('.deposit-box.selected')).toHaveCount(0)
  await scanAt('panel cancelled and cleared')

  // ── An OCCUPIED demo box, straight from first paint state ───────────────
  await page.click('[data-box="03"]')
  await expect(panel.locator('#btn-open')).toBeVisible()
  await expect(panel.locator('#btn-tamper')).toBeVisible()
  await scanAt('retrieve form on demo box 03, nothing typed')

  await panel.locator('#show-rpw-toggle').check()
  await expect(panel.locator('#rpw-alice')).toHaveAttribute('type', 'text')
  await scanAt('retrieve form with passwords revealed')

  // Clicking a selected box a second time deselects and closes it.
  await page.click('[data-box="03"]')
  await expect(page.locator('#panel')).toBeEmpty()
  await scanAt('box 03 deselected by a second click')

  // ── The EMPTY vault: what "Clear vault" leaves, and what main.ts silently
  //    recovers to when demo generation throws ──────────────────────────────
  await page.click('#btn-clear-vault')
  await expect(page.locator('.deposit-box.occupied')).toHaveCount(0)
  await scanAt('vault cleared — all nine boxes empty')

  await page.click('[data-box="05"]')
  await expect(panel.locator('#btn-seal')).toBeVisible()
  await scanAt('deposit form on an empty box in an empty vault')

  await page.click('#btn-cancel-deposit')
  await expect(page.locator('#panel')).toBeEmpty()

  // ── Reset restores the demo boxes, running the three real seals again ───
  await page.click('#btn-reset')
  await expect(page.locator('.deposit-box.occupied'), 'reset must re-seal the demo boxes').toHaveCount(
    3,
    { timeout: 180_000 },
  )
  await scanAt('reset to demo — the three demo boxes re-sealed')

  // ── The Korean locale: a different script, longer button labels, and a
  //    different demo-box set (01/04/07 rather than 03/06/09) ───────────────
  await page.click('.lang-btn[data-lang="ko"]')
  await expect(page.locator('html')).toHaveAttribute('lang', 'ko')
  await expect(page.locator('[data-box="01"]'), 'the Korean demo boxes must re-seal').toHaveClass(
    /occupied/,
    { timeout: 180_000 },
  )
  await scanAt('Korean locale, Korean demo boxes')

  await page.click('[data-box="01"]')
  await expect(panel.locator('#btn-open')).toBeVisible()
  await scanAt('Korean retrieve form')

  await page.click('#btn-cancel-retrieve')
  await page.click('.lang-btn[data-lang="en"]')
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  await expect(page.locator('[data-box="03"]')).toHaveClass(/occupied/, { timeout: 180_000 })

  // Hover on the always-dark shared bar, whose ink is a `color-mix` axe cannot
  // resolve in either state.
  await page.locator('#cl-theme-toggle').hover()
  await scanAt('the shared top bar theme toggle hovered')
}
