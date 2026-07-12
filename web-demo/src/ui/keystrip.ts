// Shamir key-strip visualization — makes "any 2 rebuild the exact key, 1 gives
// unrelated garbage" a thing you SEE, driven entirely by REAL bytes.
//
// A "strip" is a row of colored cells, one per byte, hue derived from the byte
// value. The AES key and its 3 Shamir shares are real Uint8Arrays produced by
// the genuine seal/open pipeline (see pipeline.ts SealVisual / OpenVisual) — no
// value here is fabricated. On a below-threshold open the reconstructed strip
// genuinely differs from the key strip because Lagrange interpolation with one
// share lands on unrelated bytes.

import { t } from '../i18n';

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

/** Build a labeled strip row. `variant` tints the label chip. */
function stripRowHTML(label: string, bytes: Uint8Array, variant = ''): string {
  return `
    <div class="ks-row ${variant}">
      <span class="ks-label">${label}</span>
      <span class="ks-strip" aria-hidden="true">${stripCellsHTML(bytes)}</span>
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
      ${stripRowHTML(names[0], shares[0], 'ks-share')}
      ${stripRowHTML(names[1], shares[1], 'ks-share')}
      ${stripRowHTML(names[2], shares[2], 'ks-share')}
    </div>`;
  requestAnimationFrame(() => {
    container.querySelector('.keystrip')?.classList.add('ks-in');
  });
}

/**
 * Render the open-side reconstruction: the Lagrange-recovered key strip, plus a
 * reference to whether it matched. `reconstructed` are the REAL recovered bytes.
 * `enough` is whether >= 2 shares were combined (true → strip is the real key).
 */
export function renderReconstructStrip(
  container: HTMLElement,
  reconstructed: Uint8Array,
  enough: boolean,
): void {
  const verdict = enough
    ? `<p class="ks-verdict ks-ok">${t('ksReconOk')}</p>`
    : `<p class="ks-verdict ks-bad">${t('ksReconBad')}</p>`;

  container.innerHTML = `
    <div class="keystrip" role="group" aria-label="${t('ksOpenAria')}">
      <p class="ks-caption">${enough ? t('ksOpenCaptionOk') : t('ksOpenCaptionBad')}</p>
      <div class="ks-split-arrow" aria-hidden="true">↓ ${t('ksLagrange')}</div>
      ${stripRowHTML(
        enough ? t('ksReconKeyLabel') : t('ksReconWrongLabel'),
        reconstructed,
        enough ? 'ks-key ks-recon-ok' : 'ks-key ks-recon-bad',
      )}
      ${verdict}
    </div>`;
  requestAnimationFrame(() => {
    container.querySelector('.keystrip')?.classList.add('ks-in');
  });
}
