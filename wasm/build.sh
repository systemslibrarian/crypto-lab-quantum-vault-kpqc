#!/usr/bin/env bash
# Build SMAUG-T Level 1 and HAETAE Mode 2 to WebAssembly via Emscripten.
#
# Prerequisites:
#   - Emscripten SDK (emsdk) installed and activated, e.g.:
#       source ~/emsdk/emsdk_env.sh
#   - Vendor sources present under wasm/vendor/ (see README.md for how to
#     clone / extract them)
#
# Outputs:
#   wasm/dist/smaug.js   + smaug.wasm
#   wasm/dist/haetae.js  + haetae.wasm
#
# After a successful build, copy the artefacts to the web demo:
#   wasm/dist/smaug.js  → web-demo/src/crypto/wasm/smaug.js
#   wasm/dist/haetae.js → web-demo/src/crypto/wasm/haetae.js
#   wasm/dist/*.wasm    → web-demo/public/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$SCRIPT_DIR/dist"
mkdir -p "$DIST"

# ── SMAUG-T Level 1 ────────────────────────────────────────────────────────────
SMAUG_SRC="$SCRIPT_DIR/vendor/smaug-t/reference_implementation"

SMAUG_C_FILES=(
  "$SMAUG_SRC/src/cbd.c"
  "$SMAUG_SRC/src/ciphertext.c"
  "$SMAUG_SRC/src/dg.c"
  "$SMAUG_SRC/src/fips202.c"
  "$SMAUG_SRC/src/hash.c"
  "$SMAUG_SRC/src/hwt.c"
  "$SMAUG_SRC/src/indcpa.c"
  "$SMAUG_SRC/src/io.c"
  "$SMAUG_SRC/src/kem.c"
  "$SMAUG_SRC/src/key.c"
  "$SMAUG_SRC/src/pack.c"
  "$SMAUG_SRC/src/poly.c"
  "$SMAUG_SRC/src/toomcook.c"
  "$SMAUG_SRC/src/verify.c"
  "$SCRIPT_DIR/src/randombytes_wasm.c"
  "$SCRIPT_DIR/src/smaug_exports.c"
)

echo "▶ Building SMAUG-T Level 1..."
emcc \
  -O2 \
  -DSMAUG_MODE=1 \
  -I"$SMAUG_SRC/include" \
  "${SMAUG_C_FILES[@]}" \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='createSmaugModule' \
  -s ENVIRONMENT='web,node' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","getValue"]' \
  -o "$DIST/smaug.js"
echo "   → $DIST/smaug.js + smaug.wasm"

# ── HAETAE Mode 2 ──────────────────────────────────────────────────────────────
HAETAE_SRC="$SCRIPT_DIR/vendor/haetae/HAETAE-1.1.2/reference_implementation"

HAETAE_C_FILES=(
  "$HAETAE_SRC/decompose.c"
  "$HAETAE_SRC/encoding.c"
  "$HAETAE_SRC/fft.c"
  "$HAETAE_SRC/fips202.c"
  "$HAETAE_SRC/fixpoint.c"
  "$HAETAE_SRC/ntt.c"
  "$HAETAE_SRC/packing.c"
  "$HAETAE_SRC/poly.c"
  "$HAETAE_SRC/polyfix.c"
  "$HAETAE_SRC/polymat.c"
  "$HAETAE_SRC/polyvec.c"
  "$HAETAE_SRC/reduce.c"
  "$HAETAE_SRC/sampler.c"
  "$HAETAE_SRC/sign.c"
  "$HAETAE_SRC/symmetric-shake.c"
  "$SCRIPT_DIR/src/randombytes_wasm.c"
  "$SCRIPT_DIR/src/haetae_exports.c"
)

echo "▶ Building HAETAE Mode 2..."
emcc \
  -O2 \
  -I"$HAETAE_SRC" \
  "${HAETAE_C_FILES[@]}" \
  -s WASM=1 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='createHaetaeModule' \
  -s ENVIRONMENT='web,node' \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s EXPORTED_RUNTIME_METHODS='["cwrap","getValue"]' \
  -o "$DIST/haetae.js"
echo "   → $DIST/haetae.js + haetae.wasm"

echo ""
echo "✓ Build complete.  Copy to web demo with:"
echo "  cp $DIST/smaug.js  web-demo/src/crypto/wasm/smaug.js"
echo "  cp $DIST/haetae.js web-demo/src/crypto/wasm/haetae.js"
echo "  cp $DIST/smaug.wasm  web-demo/public/smaug.wasm"
echo "  cp $DIST/haetae.wasm web-demo/public/haetae.wasm"
