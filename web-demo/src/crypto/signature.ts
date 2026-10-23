// HAETAE Mode 2 (a final KpqC competition algorithm still under Korean
// standardization review, not itself a published standard) container signing.
// Thin re-export shim so pipeline.ts and tests can use a stable import.

export { haetaeKeypair, haetaeSign, haetaeVerify } from './haetae';
