// SPDX-License-Identifier: MIT
// Lightweight i18n — English (default) and Korean UI strings.
// Call setLang('ko') to switch language globally.
// Use t(key) anywhere in TypeScript for the current language.
// Static HTML elements use data-en / data-ko attributes, toggled by main.ts.

const LOCALE_KEY = 'qv-locale';

const strings: Record<string, { en: string; ko: string }> = {
  storeSecret:       { en: 'store a secret',           ko: '비밀 저장' },
  enterPasswords:    { en: 'enter passwords to open',  ko: '비밀번호로 열기' },
  secretMessage:     { en: 'Secret message',           ko: '비밀 메시지' },
  secretPlaceholder: { en: 'Type your secret…',        ko: '비밀을 입력하세요…' },
  showPasswords:     { en: 'Show passwords',           ko: '비밀번호 표시' },
  aliceKey:          { en: "Alice's key",              ko: '영희 키' },
  bobKey:            { en: "Bob's key",                ko: '철수 키' },
  carolKey:          { en: "Carol's key",              ko: '민수 키' },
  alicePh:           { en: "alice's password",         ko: '영희 비밀번호' },
  bobPh:             { en: "bob's password",           ko: '철수 비밀번호' },
  carolPh:           { en: "carol's password",         ko: '민수 비밀번호' },
  thresholdNote:     { en: 'Any 2 of these 3 passwords will unlock this box.',
                       ko: '이 3개 비밀번호 중 2개로 보관함을 열 수 있습니다.' },
  thresholdOpen:     { en: 'Enter at least 2 of the 3 passwords to unlock this box.',
                       ko: '3개 비밀번호 중 최소 2개를 입력하세요.' },
  sealBtn:           { en: 'Seal deposit box',         ko: '봉인하기' },
  openBtn:           { en: 'Open box',                 ko: '열기' },
  clearBtn:          { en: 'Clear / Delete box',       ko: '보관함 비우기 / 삭제' },
  cancelBtn:         { en: 'Cancel',                   ko: '취소' },
  confirmClear:      { en: 'Are you sure you want to empty and delete this box?',
                       ko: '이 보관함을 정말로 비우고 삭제하시겠습니까?' },
  sealing:           { en: 'Sealing…',                 ko: '봉인 중…' },
  opening:           { en: 'Opening…',                 ko: '열기 중…' },
  msgEmpty:          { en: 'Message cannot be empty.', ko: '메시지를 입력하세요.' },
  minChars:          { en: 'Min 4 characters.',        ko: '최소 4자 이상.' },
  required:          { en: 'Required.',                ko: '필수 항목.' },
  allDiff:           { en: 'All 3 passwords must be different.',
                       ko: '3개의 비밀번호는 모두 달라야 합니다.' },
  sealedIn:          { en: 'Secret sealed in box',     ko: '봉인 완료 — 보관함' },
  sealedCheck:       { en: '✓',                        ko: '✓' },
  decrypted:         { en: 'decrypted',                ko: '복호화 완료' },
  accessDenied:      { en: 'access denied',            ko: '접근 거부' },
  thresholdMet:      { en: 'of 3 passwords correct — threshold met — secret recovered',
                       ko: '/ 3개 중 임계값 충족 — 비밀 복원 완료' },
  accessDeniedMsg:   { en: 'ACCESS DENIED',            ko: '접근 거부' },
  needPasswords:     { en: 'need 2 of 3 passwords, only',
                       ko: '필요: 2개, 현재 유효:' },
  correct:           { en: 'correct',                  ko: '개' },
  occupied:          { en: 'occupied',                 ko: '사용 중' },
  empty:             { en: 'empty',                    ko: '비어 있음' },
  boxLabel:          { en: 'Box',                      ko: '보관함' },
  selectedLabel:     { en: 'selected',                 ko: '선택됨' },
  // Pipeline step labels
  pipeAes:           { en: 'AES-256-GCM',              ko: 'AES-256-GCM' },
  pipeShamirSplit:   { en: 'Shamir split',             ko: '샤미르 분할' },
  pipeSmaugWrap:     { en: 'SMAUG-T wrap',             ko: '스마우그-T 래핑' },
  pipeHaetaeSign:    { en: 'HAETAE sign',              ko: '해태 서명' },
  pipeHaetaeVerify:  { en: 'HAETAE verify',            ko: '해태 검증' },
  pipeSmaugUnlock:   { en: 'SMAUG-T unlock',           ko: '스마우그-T 해제' },
  pipeShamirRecon:   { en: 'Shamir reconstruct',       ko: '샤미르 복원' },
  // Per-step plain-language narration, revealed as each pipeline pill animates.
  narrAes:           { en: 'Your secret is locked with one random AES-256 key.',
                       ko: '비밀이 하나의 무작위 AES-256 키로 잠깁니다.' },
  narrShamirSplit:   { en: 'That key is split into 3 pieces — any 2 rebuild it exactly, 1 alone reveals nothing.',
                       ko: '그 키가 3조각으로 나뉩니다 — 아무 2개면 정확히 복원, 1개만으론 아무것도 못 얻습니다.' },
  narrSmaugWrap:     { en: 'Each piece is sealed to one keyholder with a quantum-safe lock (SMAUG-T).',
                       ko: '각 조각이 양자내성 잠금(SMAUG-T)으로 한 명의 키홀더에게 봉인됩니다.' },
  narrHaetaeSign:    { en: 'The whole box is signed (HAETAE) so any tampering is detected.',
                       ko: '상자 전체가 서명(HAETAE)되어 변조가 감지됩니다.' },
  narrHaetaeVerify:  { en: 'First we check the signature — if the box was altered, we stop here.',
                       ko: '먼저 서명을 확인합니다 — 상자가 변조되었으면 여기서 멈춥니다.' },
  narrSmaugUnlock:   { en: 'Each password unlocks its keyholder’s quantum-safe seal to recover a piece.',
                       ko: '각 비밀번호가 키홀더의 양자내성 봉인을 열어 조각을 되찾습니다.' },
  narrShamirRecon:   { en: 'The recovered pieces are combined by Lagrange interpolation back into the key.',
                       ko: '되찾은 조각들이 라그랑주 보간으로 다시 키로 결합됩니다.' },
  narrAesDecrypt:    { en: 'The rebuilt key decrypts your secret — and AES-GCM’s tag proves it is the RIGHT key.',
                       ko: '복원된 키가 비밀을 복호화하고, AES-GCM 태그가 올바른 키임을 증명합니다.' },
  // Failure-mode pill sublabels
  pillShareUnavailable: { en: 'share unavailable', ko: '조각 없음' },
  pillNeedCount:     { en: 'of 2 needed',            ko: '/ 2개 필요' },
  pillSigInvalid:    { en: 'signature invalid — container was altered',
                       ko: '서명 무효 — 컨테이너가 변조됨' },
  // Key-strip visualization
  ksSealCaption:     { en: 'The real 32-byte AES key (first 16 bytes shown) splits into 3 shares:',
                       ko: '실제 32바이트 AES 키(앞 16바이트 표시)가 3개 조각으로 나뉩니다:' },
  ksSealAria:        { en: 'AES key splitting into three Shamir shares',
                       ko: 'AES 키가 3개의 샤미르 조각으로 분할됨' },
  ksKeyLabel:        { en: 'AES key',                 ko: 'AES 키' },
  ksSplitInto:       { en: 'Shamir split (2-of-3)',   ko: '샤미르 분할 (3개 중 2개)' },
  ksReconKeyLabel:   { en: 'rebuilt key',             ko: '복원된 키' },
  ksReconWrongLabel: { en: 'wrong key',               ko: '잘못된 키' },
  ksLagrange:        { en: 'Lagrange combine',        ko: '라그랑주 결합' },
  ksOpenAria:        { en: 'Shares combined back into the AES key',
                       ko: '조각들이 다시 AES 키로 결합됨' },
  ksOpenCaptionOk:   { en: '2 shares combine back into the identical AES key:',
                       ko: '2개 조각이 동일한 AES 키로 다시 결합됩니다:' },
  ksOpenCaptionBad:  { en: '1 share lands on an unrelated key — the colors don’t match the original:',
                       ko: '1개 조각은 무관한 키가 됩니다 — 색이 원본과 다릅니다:' },
  ksReconOk:         { en: '✓ Same bytes as the original — the secret decrypts.',
                       ko: '✓ 원본과 같은 바이트 — 비밀이 복호화됩니다.' },
  ksReconBad:        { en: '✗ Different bytes — mathematically unrelated, so decryption fails.',
                       ko: '✗ 다른 바이트 — 수학적으로 무관하므로 복호화 실패.' },
  // How-this-box-works walkthrough
  howTitle:          { en: 'How this box works',      ko: '이 상자의 작동 방식' },
  howIntro:          { en: 'Four primitives compose into one seal. Watch each sentence light up as its step runs when you seal or open a box.',
                       ko: '네 가지 기본 요소가 하나의 봉인으로 조합됩니다. 상자를 봉인하거나 열 때 각 단계가 실행되면 해당 문장이 켜집니다.' },
  // Classical-vs-PQ side note
  pqToggleLabel:     { en: 'What if we’d used classical RSA here?',
                       ko: '여기서 기존 RSA를 썼다면?' },
  pqClassical:       { en: 'RSA / ECDH (classical)',  ko: 'RSA / ECDH (기존)' },
  pqPost:            { en: 'SMAUG-T (post-quantum)',  ko: 'SMAUG-T (양자내성)' },
  pqClassicalBody:   { en: 'A quantum computer running Shor’s algorithm factors RSA and breaks ECDH. An attacker who copied this sealed box today — "harvest now, decrypt later" — retroactively unwraps every share once such a machine exists. The box you sealed years ago pops open.',
                       ko: '쇼어 알고리즘을 실행하는 양자 컴퓨터는 RSA를 인수분해하고 ECDH를 깨뜨립니다. 오늘 이 봉인 상자를 복사한 공격자는 "지금 수집, 나중에 복호화" 방식으로, 그런 기계가 등장하면 모든 조각을 소급해 풀어냅니다.' },
  pqPostBody:        { en: 'SMAUG-T’s security rests on the Module-LWE lattice problem, for which no efficient quantum algorithm is known. The same harvested box stays sealed even against a future quantum attacker — that is exactly what the post-quantum KEM buys you here.',
                       ko: 'SMAUG-T의 안전성은 효율적인 양자 알고리즘이 알려지지 않은 Module-LWE 격자 문제에 기반합니다. 수집된 상자는 미래의 양자 공격자에게도 봉인된 채로 남습니다.' },
  // Tamper demo
  tamperBtn:         { en: 'Tamper with this container',
                       ko: '이 컨테이너 변조하기' },
  tamperNote:        { en: 'Flips one byte of the ciphertext, then tries to open — HAETAE catches it.',
                       ko: '암호문 1바이트를 뒤집은 뒤 열기를 시도합니다 — HAETAE가 잡아냅니다.' },
  // Footer
  footerCopyright:   { en: '© 2026 Paul Clark',        ko: '© 2026 Paul Clark' },
  footerLicense:     { en: 'MIT License',              ko: 'MIT 라이선스' },
  // Algorithm names (order swaps per locale)
  algoSmaug:         { en: 'SMAUG-T (스마우그-T)',     ko: '스마우그-T (SMAUG-T)' },
  algoHaetae:        { en: 'HAETAE (해태)',            ko: '해태 (HAETAE)' },
  // Tooltips
  haetaeTooltip:     { en: '해태 — mythical Korean guardian', ko: '해태 — 한국의 수호 신수' },
  // Toggle aria
  switchToKorean:    { en: 'Switch to Korean',         ko: '영어로 전환' },
  switchToEnglish:   { en: 'Switch to English',        ko: '영어로 전환' },
  // Export / Import
  exportBtn:         { en: 'Export .qvault',           ko: '.qvault 내보내기' },
  exportSuccess:     { en: 'File downloaded',          ko: '파일 다운로드 완료' },
  importBtn:         { en: 'Import .qvault',           ko: '.qvault 가져오기' },
  importOrCreate:    { en: 'or import an existing file',
                       ko: '또는 기존 파일 가져오기' },
  importing:         { en: 'Verifying…',               ko: '검증 중…' },
  importSuccess:     { en: 'Container loaded and verified',
                       ko: '컨테이너 로드 및 검증 완료' },
  importErrorJson:   { en: 'Invalid file format',      ko: '잘못된 파일 형식' },
  importErrorVer:    { en: 'Unsupported vault format', ko: '지원하지 않는 볼트 형식' },
  importErrorField:  { en: 'Incomplete container',     ko: '불완전한 컨테이너' },
  importErrorPart:   { en: 'Invalid participant count', ko: '잘못된 참여자 수' },
  importErrorData:   { en: 'Corrupted data',           ko: '손상된 데이터' },
  importErrorAlgo:   { en: 'Unsupported algorithm',    ko: '지원하지 않는 알고리즘' },
  importErrorSig:    { en: 'Container signature invalid — file may be tampered',
                       ko: '컨테이너 서명이 유효하지 않습니다 — 파일이 변조되었을 수 있습니다' },
  chooseFile:        { en: 'Choose .qvault file',      ko: '.qvault 파일 선택' },
};

let _lang: 'en' | 'ko' = 'en';

// Detect initial locale from localStorage or navigator.language
function detectInitialLocale(): 'en' | 'ko' {
  try {
    const stored = localStorage.getItem(LOCALE_KEY);
    if (stored === 'ko' || stored === 'en') return stored;
  } catch {
    // localStorage may be unavailable (private browsing, etc.)
  }
  // Auto-detect from browser language
  if (typeof navigator !== 'undefined' && navigator.language?.startsWith('ko')) {
    return 'ko';
  }
  return 'en';
}

// Initialize on module load
_lang = detectInitialLocale();

/**
 * Set the active UI language and persist to localStorage.
 * @param lang - The language code ('en' or 'ko')
 */
export function setLang(lang: 'en' | 'ko'): void {
  _lang = lang;
  try {
    localStorage.setItem(LOCALE_KEY, lang);
  } catch {
    // Ignore storage errors
  }
}

/**
 * Get the current UI language.
 * @returns The active language code
 */
export function getLang(): 'en' | 'ko' {
  return _lang;
}

/**
 * Translate a key to the current language.
 * Falls back to English, then to the key itself if not found.
 * @param key - The translation key (e.g., 'sealBtn', 'openBtn')
 * @returns The translated string
 */
export function t(key: string): string {
  return strings[key]?.[_lang] ?? strings[key]?.en ?? key;
}
