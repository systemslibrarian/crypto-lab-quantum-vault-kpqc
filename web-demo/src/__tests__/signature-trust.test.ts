import { afterEach, describe, expect, it } from 'vitest';
import html from '../../index.html?raw';
import { setLang, t } from '../i18n';

afterEach(() => setLang('en'));

describe('signature trust explanation', () => {
  it('keeps the persistent English and Korean warning consistent with runtime narration', () => {
    const paragraph = html.match(/<p id="signature-trust-note"[\s\S]*?<\/p>/)?.[0];
    expect(paragraph).toBeTruthy();
    for (const lang of ['en', 'ko'] as const) {
      setLang(lang);
      const attribute = paragraph!.match(new RegExp(`data-${lang}="([^"]+)"`))?.[1];
      expect(attribute).toBe(t('signatureTrust'));
    }
    setLang('en');
    expect(paragraph!.replace(/<[^>]+>/g, '').trim()).toBe(t('signatureTrust'));
  });

  it('states the included-key replacement limit in English without weakening the invalid-signature gate', () => {
    setLang('en');
    expect(t('narrHaetaeSign')).toContain('not authenticated');
    expect(t('narrHaetaeVerify')).toContain('replacement key and new signature can still pass');
    expect(t('signatureTrust')).toContain('does not unlock encrypted shares');
    expect(t('signatureTrust')).toContain('outside the container');
    expect(t('pillSigInvalid')).toContain('signature invalid under the included key');
  });

  it('states the same authenticity and confidentiality distinction in Korean', () => {
    setLang('ko');
    expect(t('narrHaetaeSign')).toContain('인증되지');
    expect(t('narrHaetaeVerify')).toContain('통과할 수');
    expect(t('signatureTrust')).toContain('공개 키');
    expect(t('signatureTrust')).toContain('암호화된 조각은 풀리지');
    expect(t('signatureTrust')).toContain('컨테이너 외부');
    expect(t('pillSigInvalid')).toContain('서명 무효');
  });
});
