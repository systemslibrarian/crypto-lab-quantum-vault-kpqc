// Initialize both KpqC WASM modules before any vault operations run.
// Called once at application startup in main.ts.

import { initSmaug } from './smaug';
import { initHaetae } from './haetae';

export async function initCrypto(): Promise<void> {
  await Promise.all([initSmaug(), initHaetae()]);
}
