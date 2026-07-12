// Pipeline step indicator animation + per-step plain-language narration.
//
// Seal  : AES-256-GCM → Shamir split → SMAUG-T wrap → HAETAE sign
// Open  : HAETAE verify → SMAUG-T unlock → Shamir reconstruct → AES-256-GCM
//
// As each pill goes "active" the matching walkthrough sentence is revealed below
// it, so the four labels stop being opaque buzzwords. Two open-failure modes are
// drawn distinctly: a wrong password turns just that keyholder's SMAUG-T pill
// AMBER ("share unavailable", with an "N of 2 needed" count) while a tampered
// container turns the HAETAE-verify pill RED and stops the pipeline there.
//
// The Shamir step also renders a REAL key-strip (see keystrip.ts): on seal the
// 32-byte AES key splits into 3 colored share strips; on open the recovered key
// strip re-forms from >= 2 shares, or lands on unrelated bytes from just 1.

import { sleep } from '../crypto/utils';
import { t } from '../i18n';
import type { OpenVisual, SealVisual } from '../crypto/pipeline';
import { renderSplitStrips, renderReconstructStrip } from './keystrip';

export type PipelineStepId = 'aes' | 'shamir' | 'smaug' | 'haetae';
export type StepStatus = 'pending' | 'active' | 'done' | 'failed' | 'warn';

interface StepConfig {
  id: PipelineStepId;
  labelKey: string;
  narrKey: string;
}

const SEAL_STEPS: StepConfig[] = [
  { id: 'aes',    labelKey: 'pipeAes',         narrKey: 'narrAes' },
  { id: 'shamir', labelKey: 'pipeShamirSplit', narrKey: 'narrShamirSplit' },
  { id: 'smaug',  labelKey: 'pipeSmaugWrap',   narrKey: 'narrSmaugWrap' },
  { id: 'haetae', labelKey: 'pipeHaetaeSign',  narrKey: 'narrHaetaeSign' },
];

const OPEN_STEPS: StepConfig[] = [
  { id: 'haetae', labelKey: 'pipeHaetaeVerify', narrKey: 'narrHaetaeVerify' },
  { id: 'smaug',  labelKey: 'pipeSmaugUnlock',  narrKey: 'narrSmaugUnlock' },
  { id: 'shamir', labelKey: 'pipeShamirRecon',  narrKey: 'narrShamirRecon' },
  { id: 'aes',    labelKey: 'pipeAes',          narrKey: 'narrAesDecrypt' },
];

function createPipelineHTML(steps: StepConfig[]): string {
  const parts: string[] = [];
  steps.forEach((s, idx) => {
    const label = t(s.labelKey);
    parts.push(
      `<div class="pipeline-step pending" id="ps-${s.id}" role="listitem" aria-label="${label}">
         <span class="step-label">${label}</span>
         <span class="step-sub" id="pss-${s.id}"></span>
       </div>`,
    );
    if (idx < steps.length - 1) {
      parts.push('<div class="pipeline-arrow" aria-hidden="true">→</div>');
    }
  });
  return `
    <div class="pipeline" role="list">${parts.join('')}</div>
    <p class="pipeline-narration" id="pipeline-narration" role="status" aria-live="polite"></p>
    <div class="pipeline-viz" id="pipeline-viz"></div>`;
}

function setStep(container: HTMLElement, stepId: PipelineStepId, status: StepStatus): void {
  const el = container.querySelector<HTMLElement>(`#ps-${stepId}`);
  if (el) el.className = `pipeline-step ${status}`;
}

function setStepSub(container: HTMLElement, stepId: PipelineStepId, text: string): void {
  const el = container.querySelector<HTMLElement>(`#pss-${stepId}`);
  if (el) el.textContent = text;
}

function narrate(container: HTMLElement, narrKey: string): void {
  const el = container.querySelector<HTMLElement>('#pipeline-narration');
  if (el) el.textContent = t(narrKey);
}

function viz(container: HTMLElement): HTMLElement | null {
  return container.querySelector<HTMLElement>('#pipeline-viz');
}

export async function animateSealPipeline(
  container: HTMLElement,
  sealVisual?: SealVisual,
): Promise<void> {
  container.innerHTML = createPipelineHTML(SEAL_STEPS);
  for (const step of SEAL_STEPS) {
    setStep(container, step.id, 'active');
    narrate(container, step.narrKey);
    await sleep(650);
    // After the Shamir split step, show the real key splitting into 3 shares.
    if (step.id === 'shamir' && sealVisual) {
      const vizEl = viz(container);
      if (vizEl) renderSplitStrips(vizEl, sealVisual.key, sealVisual.shares);
    }
    setStep(container, step.id, 'done');
  }
}

/**
 * Animate the open pipeline, driven by the REAL open result so the two distinct
 * failure modes are visible:
 *   - signatureValid === false → HAETAE pill goes RED, pipeline stops there.
 *   - a wrong/absent password   → that SMAUG-T slot's pill goes AMBER, with a
 *                                 running "N of 2 needed" count.
 *   - < 2 valid shares          → Shamir reconstruct lands on the wrong strip.
 */
export async function animateOpenPipeline(
  container: HTMLElement,
  visual: OpenVisual,
): Promise<void> {
  container.innerHTML = createPipelineHTML(OPEN_STEPS);
  const validCount = visual.shareStatus.filter(Boolean).length;
  const enough = validCount >= 2;

  // Step 1 — HAETAE verify (integrity gate)
  setStep(container, 'haetae', 'active');
  narrate(container, 'narrHaetaeVerify');
  await sleep(650);
  if (!visual.signatureValid) {
    setStep(container, 'haetae', 'failed');
    setStepSub(container, 'haetae', '✗');
    const n = container.querySelector<HTMLElement>('#pipeline-narration');
    if (n) {
      n.textContent = t('pillSigInvalid');
      n.classList.add('narr-fail');
    }
    return; // integrity failure — stop here, before any share is touched
  }
  setStep(container, 'haetae', 'done');

  // Step 2 — SMAUG-T unlock (per-keyholder). Show amber for slots that failed.
  setStep(container, 'smaug', 'active');
  narrate(container, 'narrSmaugUnlock');
  await sleep(650);
  if (enough) {
    setStep(container, 'smaug', 'done');
    setStepSub(container, 'smaug', `${validCount} ✓`);
  } else {
    // Confidentiality-side shortfall: not enough shares. Amber, not red — the
    // container is intact, we simply lack keyholders.
    setStep(container, 'smaug', 'warn');
    setStepSub(
      container,
      'smaug',
      `${t('pillShareUnavailable')} · ${validCount} ${t('pillNeedCount')}`,
    );
  }

  // Step 3 — Shamir reconstruct (real key-strip re-forms, or lands wrong)
  setStep(container, 'shamir', 'active');
  narrate(container, 'narrShamirRecon');
  await sleep(500);
  if (visual.reconstructedKey) {
    const vizEl = viz(container);
    if (vizEl) renderReconstructStrip(vizEl, visual.reconstructedKey, enough);
  }
  if (!enough) {
    // Amber, not red: this is a confidentiality shortfall (too few shares), a
    // DIFFERENT failure mode from the red HAETAE integrity failure above. The
    // key reconstructs to the WRONG bytes, so AES-GCM will reject it downstream.
    setStep(container, 'shamir', 'warn');
    return; // below threshold — key is wrong, AES will reject it
  }
  setStep(container, 'shamir', 'done');

  // Step 4 — AES-256-GCM decrypt
  setStep(container, 'aes', 'active');
  narrate(container, 'narrAesDecrypt');
  await sleep(500);
  setStep(container, 'aes', 'done');
}
