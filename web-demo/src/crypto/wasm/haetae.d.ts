import type { EmscriptenModuleFactory, HaetaeModule } from '../wasm-types';

declare const createHaetaeModule: EmscriptenModuleFactory<HaetaeModule>;
export default createHaetaeModule;
