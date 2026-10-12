// Shamir strips show real seal-side shares and open-side reconstruction bytes.
// The open has no independent original reference. Only successful AES-GCM
// authentication confirms the candidate; two recovered shares alone do not.

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

/** Build a labeled strip row. `variant` tints the label chip. */
function stripRowHTML(
  label: string,
  bytes: Uint8Array,
  variant = '',
): string {
  const cells = stripCellsHTML(bytes);
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

/** Show actual recovered shares and the candidate, without a copied reference.
 * `aesAuthenticated` is the observed decryption outcome, not the share count.
 */
export async function renderReconstructStrip(
  container: HTMLElement,
  reconstructed: Uint8Array,
  enough: boolean,
  recoveredShares: [Uint8Array | null, Uint8Array | null, Uint8Array | null],
  aesAuthenticated: boolean,
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

  const confirmed = enough && aesAuthenticated;
  const rebuiltRow = stripRowHTML(
    enough ? t('ksReconKeyLabel') : t('ksReconWrongLabel'),
    reconstructed,
    confirmed ? 'ks-key ks-recon-ok' : 'ks-key ks-recon-bad',
  );
  const verdict = confirmed
    ? `<p class="ks-verdict ks-ok">${t('ksReconOk')}</p>`
    : `<p class="ks-verdict ks-bad">${t(enough ? 'ksAuthFailed' : 'ksReconBad')}</p>`;

  const belowNote = !enough
    ? `<p class="ks-caption ks-unknowable">${t('ksNoOriginal')}</p>`
    : '';

  container.innerHTML = `
    <div class="keystrip" role="group" aria-label="${t('ksOpenAria')}">
      <p class="ks-caption">${caption}</p>
      ${shareRows}
      <div class="ks-split-arrow" aria-hidden="true">↓ ${t('ksLagrange')}</div>
      ${rebuiltRow}
      ${belowNote}
      ${verdict}
      <p class="ks-caption ks-evidence-note">${t('ksEvidenceNote')}</p>
    </div>`;

  const strip = container.querySelector('.keystrip');
  requestAnimationFrame(() => strip?.classList.add('ks-in'));

  // Play the merge: the contributing share strips fade/slide toward the rebuilt
  // key. On success they converge (class ks-converge); below threshold the lone
  // share visibly fails to (class ks-diverge). Motion is skipped for users who
  // prefer reduced motion — the static candidate and outcome remain visible.
  const reduce = typeof window !== 'undefined'
    && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  if (reduce) return;

  await sleep(120);
  const mergeRows = container.querySelectorAll<HTMLElement>('.ks-merge');
  mergeRows.forEach(r => r.classList.add(enough ? 'ks-converge' : 'ks-diverge'));
  await sleep(enough ? 620 : 520);
}
