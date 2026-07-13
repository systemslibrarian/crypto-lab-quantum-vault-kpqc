// Shamir key-strip visualization — makes "any 2 rebuild the exact key, 1 gives
// unrelated garbage" a thing you SEE, driven entirely by REAL bytes.
//
// A "strip" is a row of colored cells, one per byte, hue derived from the byte
// value. The AES key and its 3 Shamir shares are real Uint8Arrays produced by
// the genuine seal/open pipeline (see pipeline.ts SealVisual / OpenVisual) — no
// value here is fabricated. On a below-threshold open the reconstructed strip
// genuinely differs from the true key because Lagrange interpolation with one
// share lands on unrelated bytes.
//
// Open side (renderReconstructStrip): when >= 2 shares are recovered we have the
// TRUE original key (Lagrange is exact), so we render it directly ABOVE the
// rebuilt key and mark every cell that is byte-identical with a green check —
// the "same colors" claim becomes a seen fact. We also animate the two recovered
// share strips (tied to Alice/Bob/Carol) sliding down and merging into the key.
// Below threshold the original is mathematically unknowable from one share, so
// there is nothing honest to compare against — we show that single share failing
// to converge onto an unrelated strip, which IS the security guarantee.

import { t } from '../i18n';
import { sleep } from '../crypto/utils';

// Show the first N bytes so the strip stays readable on small screens. The full
// key is 32 bytes; 16 cells is plenty to make "same vs different" obvious.
const STRIP_CELLS = 16;

/** Map a byte to a stable, high-contrast hue so equal bytes render identically. */
function byteToColor(b: number): string {
  const hue = (b * 360) / 256;
  return `hsl(${hue.toFixed(0)}, 62%, 52%)`;
}

function stripCellsHTML(bytes: Uint8Array): string {
  const n = Math.min(STRIP_CELLS, bytes.length);
  let cells = '';
  for (let i = 0; i < n; i++) {
    cells += `<span class="ks-cell" style="background:${byteToColor(bytes[i])}"></span>`;
  }
  return cells;
}

/**
 * Cells for a row that is compared against a reference, cell by cell. Matching
 * cells (byte-identical to `ref`) get a green ring + check glyph; mismatches get
 * a red ring + ✗. The markers are driven purely by the real byte comparison.
 */
function comparedCellsHTML(bytes: Uint8Array, ref: Uint8Array): string {
  const n = Math.min(STRIP_CELLS, bytes.length, ref.length);
  let cells = '';
  for (let i = 0; i < n; i++) {
    const match = bytes[i] === ref[i];
    const cls = match ? 'ks-cell ks-cell-match' : 'ks-cell ks-cell-miss';
    const mark = match ? '✓' : '✗';
    cells +=
      `<span class="${cls}" style="background:${byteToColor(bytes[i])}">` +
      `<span class="ks-mark" aria-hidden="true">${mark}</span></span>`;
  }
  return cells;
}

/** Build a labeled strip row. `variant` tints the label chip. */
function stripRowHTML(
  label: string,
  bytes: Uint8Array,
  variant = '',
  ref?: Uint8Array,
): string {
  const cells = ref ? comparedCellsHTML(bytes, ref) : stripCellsHTML(bytes);
  return `
    <div class="ks-row ${variant}">
      <span class="ks-label">${label}</span>
      <span class="ks-strip" aria-hidden="true">${cells}</span>
    </div>`;
}

/**
 * Render the seal-side split: one AES key strip breaking into 3 share strips.
 * All bytes are real (from SealVisual). Keyholder names line up with the panel.
 */
export function renderSplitStrips(
  container: HTMLElement,
  key: Uint8Array,
  shares: [Uint8Array, Uint8Array, Uint8Array],
): void {
  const names = [t('aliceKey'), t('bobKey'), t('carolKey')];
  container.innerHTML = `
    <div class="keystrip" role="group" aria-label="${t('ksSealAria')}">
      <p class="ks-caption">${t('ksSealCaption')}</p>
      ${stripRowHTML(t('ksKeyLabel'), key, 'ks-key')}
      <div class="ks-split-arrow" aria-hidden="true">↓ ${t('ksSplitInto')}</div>
      ${stripRowHTML(names[0], shares[0], 'ks-share ks-share-a')}
      ${stripRowHTML(names[1], shares[1], 'ks-share ks-share-b')}
      ${stripRowHTML(names[2], shares[2], 'ks-share ks-share-c')}
    </div>`;
  requestAnimationFrame(() => {
    container.querySelector('.keystrip')?.classList.add('ks-in');
  });
}

// Keyholder colour band + name, indexed by slot (Alice/Bob/Carol) — the same
// order used everywhere in the panel and by the SMAUG-T unlock pills.
function keyholderName(slot: number): string {
  return [t('aliceKey'), t('bobKey'), t('carolKey')][slot] ?? '';
}
function keyholderVariant(slot: number): string {
  return ['ks-share-a', 'ks-share-b', 'ks-share-c'][slot] ?? '';
}

/**
 * Render the open-side reconstruction as a WITNESSED mechanism:
 *
 *   success (>= 2 recovered shares)
 *     · the recovered share strips (tied to the keyholders who unlocked) animate
 *       sliding down and merging into the rebuilt key;
 *     · the TRUE original key is drawn above the rebuilt key with a per-cell green
 *       ✓ on every byte that matches — the "same colors as the original" claim is
 *       now shown, not asserted.
 *
 *   below threshold (1 recovered share)
 *     · the lone share is shown failing to converge onto an unrelated strip;
 *     · no original is drawn because ONE share cannot reveal the key — that
 *       unknowability is precisely the Shamir security guarantee.
 *
 * All bytes are REAL: `reconstructed` and `originalKey` come straight from the
 * open pipeline (originalKey is the exact Lagrange result, non-null only when the
 * open genuinely succeeds); `recoveredShares` are the actual GF(2^8) share rows.
 */
export async function renderReconstructStrip(
  container: HTMLElement,
  reconstructed: Uint8Array,
  enough: boolean,
  recoveredShares: [Uint8Array | null, Uint8Array | null, Uint8Array | null],
  originalKey: Uint8Array | null,
): Promise<void> {
  // Which keyholder slots actually contributed a recovered share.
  const contributors: number[] = [];
  recoveredShares.forEach((s, i) => { if (s) contributors.push(i); });

  const shareRows = contributors
    .map(
      i =>
        stripRowHTML(
          keyholderName(i),
          recoveredShares[i] as Uint8Array,
          `ks-share ${keyholderVariant(i)} ks-merge`,
        ),
    )
    .join('');

  const caption = enough ? t('ksOpenCaptionOk') : t('ksOpenCaptionBad');

  // The rebuilt-key row: on success compare it cell-by-cell against the true
  // original above it (green ✓ / red ✗ per byte); below threshold there is no
  // honest original to compare against, so render the wrong bytes plainly.
  const rebuiltRow =
    enough && originalKey
      ? stripRowHTML(t('ksReconKeyLabel'), reconstructed, 'ks-key ks-recon-ok', originalKey)
      : stripRowHTML(
          enough ? t('ksReconKeyLabel') : t('ksReconWrongLabel'),
          reconstructed,
          enough ? 'ks-key ks-recon-ok' : 'ks-key ks-recon-bad',
        );

  const originalRow =
    enough && originalKey
      ? `${stripRowHTML(t('ksOriginalLabel'), originalKey, 'ks-key ks-original')}
         <div class="ks-vs" aria-hidden="true">${t('ksCompareTo')}</div>`
      : '';

  const verdict = enough
    ? `<p class="ks-verdict ks-ok">${t('ksReconOk')}</p>`
    : `<p class="ks-verdict ks-bad">${t('ksReconBad')}</p>`;

  const belowNote = !enough
    ? `<p class="ks-caption ks-unknowable">${t('ksNoOriginal')}</p>`
    : '';

  container.innerHTML = `
    <div class="keystrip" role="group" aria-label="${t('ksOpenAria')}">
      <p class="ks-caption">${caption}</p>
      ${shareRows}
      <div class="ks-split-arrow" aria-hidden="true">↓ ${t('ksLagrange')}</div>
      ${originalRow}
      ${rebuiltRow}
      ${belowNote}
      ${verdict}
    </div>`;

  const strip = container.querySelector('.keystrip');
  requestAnimationFrame(() => strip?.classList.add('ks-in'));

  // Play the merge: the contributing share strips fade/slide toward the rebuilt
  // key. On success they converge (class ks-converge); below threshold the lone
  // share visibly fails to (class ks-diverge). Motion is skipped for users who
  // prefer reduced motion — the static side-by-side still tells the whole story.
  const reduce = typeof window !== 'undefined'
    && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  if (reduce) return;

  await sleep(120);
  const mergeRows = container.querySelectorAll<HTMLElement>('.ks-merge');
  mergeRows.forEach(r => r.classList.add(enough ? 'ks-converge' : 'ks-diverge'));
  await sleep(enough ? 620 : 520);
}
