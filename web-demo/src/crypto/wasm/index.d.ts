// Type declarations for Emscripten-generated JS module loaders.
// The actual runtime objects are `any` — type-safety is enforced in smaug.ts / haetae.ts.

declare module './smaug.js' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const createSmaugModule: (opts?: Record<string, unknown>) => Promise<any>;
  export default createSmaugModule;
}

declare module './haetae.js' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const createHaetaeModule: (opts?: Record<string, unknown>) => Promise<any>;
  export default createHaetaeModule;
}
