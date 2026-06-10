'use client';

import { useState, useEffect } from 'react';
import { ExternalLink, Copy, CopyCheck } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────

const ATTACK_TYPE_LABEL = {
  RANSOMWARE:          '랜섬웨어',
  CREDENTIAL_STUFFING: '크리덴셜 스터핑',
  PHISHING:            '피싱 공격',
  WEB_ATTACK:          '웹페이지 취약점',
  DDOS:                'DDoS',
  IOC_ONLY:            '침해 지표',
};

const TRUST_STYLE = {
  HIGH:   { color: '#0F6E56' },
  MEDIUM: { color: '#BA7517' },
  LOW:    { color: '#A32D2D' },
};

// Snort/YARA는 react-syntax-highlighter 미지원 → 유사 언어로 대체
const LANGUAGE_MAP = {
  SNORT: 'nginx', // 키워드 구조 유사
  YARA:  'cpp',   // 문법 구조 유사
};

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  const ymd = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const hm  = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
  return `${ymd} ${hm}`;
}

// ─── 서브 컴포넌트 ────────────────────────────────────────────────────────────

function TrustBadge({ level }) {
  const s = TRUST_STYLE[level] ?? {};
  // DB ENUM은 대문자(HIGH)로 오므로 첫 글자만 대문자, 나머지 소문자로 변환하여 표시 (High)
  const display = level ? level.charAt(0).toUpperCase() + level.slice(1).toLowerCase() : '-';
  return (
    <span style={{ fontWeight: 700, color: s.color, fontSize: '13px' }}>
      {display}
    </span>
  );
}

// pass: true(통과) / false(실패) / null(검증 전)
// grammar_detail 등이 null인 검증 전 상태는 반드시 null로 전달해야 함
function VerifyChip({ label, pass }) {
  if (pass === null || pass === undefined) {
    return (
      <span style={{
        display:         'inline-flex',
        alignItems:      'center',
        gap:             '4px',
        padding:         '3px 10px',
        borderRadius:    '999px',
        fontSize:        '12px',
        fontWeight:      600,
        backgroundColor: 'rgba(17,45,78,0.06)',
        color:           'var(--ctink-text-light)',
      }}>
        {label} -
      </span>
    );
  }
  return (
    <span style={{
      display:         'inline-flex',
      alignItems:      'center',
      gap:             '4px',
      padding:         '3px 10px',
      borderRadius:    '999px',
      fontSize:        '12px',
      fontWeight:      600,
      backgroundColor: pass ? 'rgba(15,110,86,0.10)' : 'rgba(163,45,45,0.10)',
      color:           pass ? '#0F6E56' : '#A32D2D',
    }}>
      {label} {pass ? '✓' : '✗'}
    </span>
  );
}

function CodeBlock({ content, ruleType }) {
  const [hovered, setHovered] = useState(false);
  const [copied,  setCopied]  = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(content)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => {
        // HTTPS 미지원 환경 등 복사 실패 시 조용히 무시
      });
  };

  const language = LANGUAGE_MAP[ruleType] ?? 'plaintext';

  return (
    <div
      style={{ position: 'relative' }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <SyntaxHighlighter
        language={language}
        style={vscDarkPlus}
        customStyle={{
          borderRadius: '8px',
          fontSize:     '12px',
          lineHeight:   1.7,
          margin:       0,
          fontFamily:   '"JetBrains Mono", "Fira Code", monospace',
          backgroundColor: 'var(--ctink-text)',
        }}
      >
        {content}
      </SyntaxHighlighter>
      {hovered && (
        <button
          onClick={handleCopy}
          style={{
            position:        'absolute',
            top:             '8px',
            right:           '8px',
            padding:         '4px 6px',
            borderRadius:    '6px',
            border:          'none',
            backgroundColor: copied ? 'rgba(15,110,86,0.85)' : 'rgba(255,255,255,0.15)',
            color:           '#fff',
            display:         'flex',
            alignItems:      'center',
            cursor:          'pointer',
            transition:      'background-color 0.15s',
          }}
          title={copied ? '복사됨' : '복사'}
        >
          {copied ? <CopyCheck size={14} /> : <Copy size={14} />}
        </button>
      )}
    </div>
  );
}

function MetaItem({ label, children }) {
  return (
    <div>
      <p style={{ fontSize: '11px', color: 'var(--ctink-text-muted)', fontWeight: 600, marginBottom: '3px' }}>{label}</p>
      <div style={{ fontSize: '13px', color: 'var(--ctink-text)', fontWeight: 600 }}>{children}</div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ backgroundColor: 'var(--ctink-background)', borderRadius: '10px', padding: '14px 16px', boxShadow: '0 1px 4px rgba(17,45,78,0.08)' }}>
      <p style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ctink-text-muted)', marginBottom: '10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{title}</p>
      {children}
    </div>
  );
}

// pass: success(통과) / failure(실패) / null·undefined(검증 전 → '-' 표시)
function VerifyRow({ label, pass }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--ctink-border)' }}>
      <span style={{ fontSize: '13px', color: 'var(--ctink-text)' }}>{label}</span>
      <span style={{ fontSize: '13px', fontWeight: 700, color: pass ? '#0F6E56' : (pass === false ? '#A32D2D' : 'var(--ctink-text-light)') }}>
        {pass === null || pass === undefined ? '-' : pass ? '통과' : '실패'}
      </span>
    </div>
  );
}

// ─── 모달 ─────────────────────────────────────────────────────────────────────

export default function RuleDetailModal({ ruleId, ruleName, onClose }) {
  const [detail,  setDetail]  = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null); // API 에러 메시지 (null이면 미표시)

  useEffect(() => {
    setLoading(true);
    setDetail(null);
    setError(null);
    api.get(`/ctink/rules/${ruleId}`)
      .then(r => setDetail(r.data))
      .catch(e => {
        if (e.response?.status === 404) setError('존재하지 않는 정책입니다.');
        else setError('데이터를 불러오지 못했습니다.');
      })
      .finally(() => setLoading(false));
  }, [ruleId]);

  // ESC 키로 모달 닫기
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const tr = detail?.target_rule;

  // grammar_result 등이 null이면 검증 전 상태 → VerifyChip/VerifyRow에 null 전달
  const grammarPass = tr?.grammar_result != null ? tr.grammar_result === 'success' : null;
  const fnPass      = tr?.fn_result      != null ? tr.fn_result      === 'success' : null;
  const fpPass      = tr?.fp_result      != null ? tr.fp_result      === 'success' : null;

  return (
    <div
      onClick={onClose}
      style={{
        position:        'fixed',
        inset:           0,
        zIndex:          50,
        display:         'flex',
        alignItems:      'center',
        justifyContent:  'center',
        backdropFilter:  'blur(6px)',
        backgroundColor: 'rgba(17, 45, 78, 0.35)',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          backgroundColor: 'var(--ctink-bg)',
          borderRadius:    '14px',
          width:           '90%',
          maxWidth:        '860px',
          maxHeight:       '88vh',
          overflowY:       'auto',
          padding:         '28px 32px',
          boxShadow:       '0 24px 64px rgba(17, 45, 78, 0.22)',
          position:        'relative',
        }}
      >
        {/* 헤더 */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--ctink-text-light)', fontWeight: 600, marginBottom: '4px' }}>탐지 정책 상세</p>
            <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--ctink-text)', margin: 0 }}>{ruleName}</h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border:     'none',
              cursor:     'pointer',
              fontSize:   '20px',
              color:      'var(--ctink-text-light)',
              lineHeight: 1,
              padding:    '4px',
            }}
            aria-label="닫기"
          >✕</button>
        </div>

        {/* 로딩 상태 */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--ctink-text-light)' }}>불러오는 중...</div>
        ) : error ? (
          // API 호출 실패 시 에러 메시지 표시
          <div style={{ textAlign: 'center', padding: '40px 0', color: '#A32D2D' }}>{error}</div>
        ) : !detail ? (
          // detail이 null인 예외 케이스 (정상적으로는 error로 먼저 처리됨)
          <div style={{ textAlign: 'center', padding: '40px 0', color: '#A32D2D' }}>데이터를 불러오지 못했습니다.</div>
        ) : (
          <>
            {/* 메타 정보 */}
            <div style={{
              display:             'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap:                 '12px',
              backgroundColor:     'var(--ctink-card)',
              borderRadius:        '10px',
              padding:             '14px 18px',
              marginBottom:        '22px',
            }}>
              <MetaItem label="출처">
                {detail.source_url
                  ? <a href={detail.source_url} target="_blank" rel="noreferrer"
                      style={{ color: 'var(--ctink-accent)', fontSize: '12px', wordBreak: 'break-all', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      {(() => {
                        const cleaned = detail.source_url.replace(/^https?:\/\//, '');
                        return cleaned.length > 40 ? cleaned.slice(0, 40) + '…' : cleaned;
                      })()}
                      <ExternalLink size={14} />
                    </a>
                  : '-'}
              </MetaItem>
              <MetaItem label="공격 유형">
                {ATTACK_TYPE_LABEL[detail.attack_type] ?? detail.attack_type ?? '-'}
              </MetaItem>
              <MetaItem label="신뢰도">
                <TrustBadge level={detail.trust_level} />
              </MetaItem>
              <MetaItem label="정책 유형">
                <span style={{
                  fontSize:        '12px',
                  fontWeight:      700,
                  padding:         '2px 8px',
                  borderRadius:    '999px',
                  backgroundColor: tr?.rule_type === 'SNORT' ? 'rgba(63,114,175,0.12)' : 'rgba(107,94,168,0.10)',
                  color:           tr?.rule_type === 'SNORT' ? 'var(--ctink-accent)' : '#6B5EA8',
                  textTransform:   'uppercase',
                }}>
                  {tr?.rule_type ?? '-'}
                </span>
              </MetaItem>
              {/* YARA 룰인 경우에만 운영체제 표시 */}
              {tr?.rule_type === 'YARA' && (
                <MetaItem label="운영체제">
                  {/* os_type도 DB ENUM 대문자(WINDOWS/LINUX)로 수신 */}
                  {tr?.os_type ?? '-'}
                </MetaItem>
              )}
              <MetaItem label="생성일">
                {formatDate(tr?.created_at)}
              </MetaItem>
              {/* 검증 전(null)이면 '-', 통과면 ✓, 실패면 ✗ */}
              <MetaItem label="3단계 검증">
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                  <VerifyChip label="문법" pass={grammarPass} />
                  <VerifyChip label="미탐" pass={fnPass} />
                  <VerifyChip label="오탐" pass={fpPass} />
                </div>
              </MetaItem>
            </div>

            {/* 2단 그리드: IoC + 검증 결과 (모달 너비가 좁아지면 자동으로 1단으로 전환) */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '22px' }}>
              <Section title="추출된 IoC">
                {(detail.ioc_list ?? []).length === 0 ? (
                  <p style={{ fontSize: '13px', color: 'var(--ctink-text-light)', padding: '6px 0' }}>
                    추출된 IoC가 없습니다.
                  </p>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
                    <tbody>
                      {/* ioc_list에 고유 id 없어 index를 key로 사용 */}
                      {(detail.ioc_list ?? []).map((ioc, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--ctink-border)' }}>
                          <td style={{ padding: '7px 8px', color: 'var(--ctink-text-muted)', fontWeight: 600, width: '70px', textTransform: 'uppercase', fontSize: '11px' }}>
                            {/* ioc_type은 DB ENUM 대문자(IP/DOMAIN/HASH/URL)로 수신, CSS textTransform은 유지 */}
                            {ioc.ioc_type}
                          </td>
                          <td style={{ padding: '7px 8px', color: 'var(--ctink-text)', wordBreak: 'break-all' }}>
                            {ioc.ioc_value}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Section>

              <Section title="검증 결과 상세">
                {/* 검증 전(null)이면 '-', 통과면 '통과', 실패면 '실패' */}
                <VerifyRow label="1차 · 문법 검증" pass={grammarPass} />
                <VerifyRow label="2차 · 미탐 검증" pass={fnPass} />
                <VerifyRow label="3차 · 오탐 검증" pass={fpPass} />
                <div style={{ marginTop: '12px', padding: '8px 10px', backgroundColor: 'rgba(63,114,175,0.07)', borderRadius: '8px' }}>
                  <p style={{ fontSize: '11px', color: 'var(--ctink-text-muted)', fontWeight: 600, marginBottom: '3px' }}>에이전트 판단 근거</p>
                  <p style={{ fontSize: '12px', color: 'var(--ctink-text)', lineHeight: 1.6 }}>{tr?.agent_judgement ?? '-'}</p>
                </div>
                <p style={{ marginTop: '10px', fontSize: '12px', color: 'var(--ctink-text-muted)' }}>
                  재생성 횟수 <strong style={{ color: 'var(--ctink-accent)' }}>{tr?.regen_count ?? 0}</strong>
                </p>
              </Section>
            </div>

            {/* target_rule 코드 */}
            <div style={{ backgroundColor: 'var(--ctink-background)', borderRadius: '10px', padding: '16px 18px', boxShadow: '0 1px 4px rgba(17,45,78,0.08)', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                <span style={{
                  fontSize:        '11px',
                  fontWeight:      700,
                  padding:         '2px 8px',
                  borderRadius:    '999px',
                  backgroundColor: tr?.rule_type === 'SNORT' ? 'rgba(63,114,175,0.12)' : 'rgba(107,94,168,0.10)',
                  color:           tr?.rule_type === 'SNORT' ? 'var(--ctink-accent)' : '#6B5EA8',
                  textTransform:   'uppercase',
                }}>
                  {tr?.rule_type ?? '-'}
                </span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ctink-text)' }}>
                  {tr?.rule_name}
                  {tr?.os_type
                    ? <span style={{ fontSize: '11px', color: 'var(--ctink-text-light)', marginLeft: '6px' }}>({tr.os_type})</span>
                    : null}
                </span>
              </div>
              <CodeBlock content={tr?.rule_content ?? ''} ruleType={tr?.rule_type} />
            </div>

            {/* 동일 CTI에서 생성된 관련 룰 목록 (target_rule 제외, 없으면 미표시) */}
            {(() => {
              // snort_rules/yara_rules는 API 응답에 rule_type 필드가 없으므로 직접 주입
              const related = [
                ...(detail.snort_rules ?? []).map(r => ({ ...r, rule_type: 'SNORT' })),
                ...((detail.yara_rules ?? []).map(r  => ({ ...r, rule_type: 'YARA'  }))),
              ];
              if (related.length === 0) return null;
              return (
                <>
                  <p style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ctink-text-muted)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    동일 CTI 관련 룰 ({related.length})
                  </p>
                  {/* 관련 룰도 2단 그리드, 좁아지면 1단으로 전환 */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '12px' }}>
                    {related.map(r => (
                      <div key={r.rule_id} style={{ backgroundColor: 'var(--ctink-background)', borderRadius: '10px', padding: '12px 14px', boxShadow: '0 1px 4px rgba(17,45,78,0.08)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                          <span style={{
                            fontSize:        '10px',
                            fontWeight:      700,
                            padding:         '2px 7px',
                            borderRadius:    '999px',
                            backgroundColor: r.rule_type === 'SNORT' ? 'rgba(63,114,175,0.12)' : 'rgba(107,94,168,0.10)',
                            color:           r.rule_type === 'SNORT' ? 'var(--ctink-accent)' : '#6B5EA8',
                            textTransform:   'uppercase',
                          }}>
                            {r.rule_type}
                          </span>
                          <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ctink-text)' }}>
                            {r.rule_name}
                            {/* YARA 룰인 경우에만 os_type 표시 */}
                            {r.rule_type === 'YARA' && r.os_type && (
                              <span style={{ fontSize: '11px', color: 'var(--ctink-text-light)', marginLeft: '6px' }}>
                                ({r.os_type})
                              </span>
                            )}
                          </span>
                        </div>
                        <CodeBlock content={r.rule_content} ruleType={r.rule_type} />
                      </div>
                    ))}
                  </div>
                </>
              );
            })()}
          </>
        )}
      </div>
    </div>
  );
}