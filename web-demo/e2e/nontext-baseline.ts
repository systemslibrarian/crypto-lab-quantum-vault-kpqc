/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * IT IS EMPTY, AND THAT IS THE POINT — this is the terminal state of the
 * ratchet, not an unrun check. The gate's first full drive found six control
 * boundaries under 3:1 and every one was fixed rather than listed here:
 *   - the three shared-top-bar buttons (`.cl-btn`), whose 1px border is their
 *     whole boundary and was mixed from this lab's `--accent:#003478` navy at
 *     38% — 1.14:1 on the always-dark bar, and unreachable at ANY mix
 *     percentage for a hue that dark. Now mixed from `--cl-ink`, 3.80:1;
 *   - the dark theme's `.btn-primary`, which draws `border: none`, so its own
 *     fill is the boundary: 2.74:1 on `.panel-inner`, now 3.22:1;
 *   - the dark `.btn-tamper` / `.btn-delete` danger edge at 2.84:1 on the same
 *     panel — it cleared 3:1 only against the darker page, which is not where
 *     those buttons live. Now 3.32:1.
 * The generated content this page paints — the `⚠` before each disclaimer and
 * the `.keyhole` pseudo-elements on all nine boxes — cleared its floor unaided.
 *
 * A run with `NT_BASELINE_CAPTURE=1` prints every finding through this same
 * path and asserts nothing, which is how this file is regenerated; the capture
 * run after those fixes printed zero findings across all four
 * {dark, light} × {1280px, 380px} drives.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {}
