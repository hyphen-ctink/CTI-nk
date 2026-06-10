'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import RuleDetailModal from '@/components/common/RuleDetailModal';
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

const IDS_RESULT_LABEL = {
  ALERT:  '알림',
  DETECT: '탐지',
  BLOCK:  '차단',
};

// globals.css에 정의되지 않은 시맨틱 색상으로 인라인 지정
const IDS_RESULT_STYLE = {
  ALERT:  { color: '#BA7517',             background: 'rgba(186,117,23,0.08)'  },
  DETECT: { color: 'var(--ctink-accent)', background: 'rgba(63,114,175,0.10)' },
  BLOCK:  { color: '#A32D2D',             background: 'rgba(163,45,45,0.08)'  },
};

const PAGE_SIZE = 15; // API 명세서 기준 페이지당 항목 수 고정값

// ── 폴링 주기 ─────────────────────────────────────────────────────────────────
const POLLING_INTERVAL = 30_000; // 30초

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  const ymd = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const hm  = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
  return `${ymd} ${hm}`;
}

// ─── 서브 컴포넌트 ────────────────────────────────────────────────────────────

function IdsResultBadge({ result }) {
  const s = IDS_RESULT_STYLE[result] ?? {};
  return (
    <span style={{
      display:         'inline-block',
      padding:         '2px 10px',
      borderRadius:    '999px',
      fontSize:        '12px',
      fontWeight:      600,
      color:           s.color,
      backgroundColor: s.background,
      whiteSpace:      'nowrap',
    }}>
      {IDS_RESULT_LABEL[result] ?? result ?? '-'}
    </span>
  );
}

function FilterSelect({ label, value, onChange, options }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      style={{
        padding:         '7px 12px',
        borderRadius:    '8px',
        border:          '1px solid var(--ctink-border)',
        backgroundColor: 'var(--ctink-background)',
        color:           value ? 'var(--ctink-text)' : 'var(--ctink-text-light)',
        fontSize:        '13px',
        fontWeight:      600,
        cursor:          'pointer',
        outline:         'none',
        fontFamily:      'inherit',
      }}
    >
      <option value="">{label} ▾</option>
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

function DateInput({ value, onChange, min, max }) {
  return (
    <input
      type="date"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      min={min}
      max={max}
      style={{
        padding:         '7px 10px',
        borderRadius:    '8px',
        border:          '1px solid var(--ctink-border)',
        backgroundColor: 'var(--ctink-background)',
        fontSize:        '13px',
        fontWeight:      600,
        color:           value ? 'var(--ctink-text)' : 'var(--ctink-text-light)',
        outline:         'none',
        cursor:          'pointer',
        fontFamily:      'inherit',
      }}
    />
  );
}

function StatChip({ label, count, color }) {
  return (
    <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--ctink-text-muted)' }}>
      {label}{' '}
      <span style={{ color: color ?? 'var(--ctink-text)' }}>{count}</span>
    </span>
  );
}

function PageBtn({ label, disabled, onClick }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding:         '5px 12px',
        borderRadius:    '6px',
        border:          '1px solid var(--ctink-border)',
        backgroundColor: disabled ? 'var(--ctink-card)' : 'var(--ctink-background)',
        fontSize:        '12px',
        fontWeight:      600,
        color:           disabled ? 'var(--ctink-text-light)' : 'var(--ctink-text)',
        cursor:          disabled ? 'default' : 'pointer',
        fontFamily:      'inherit',
      }}
    >
      {label}
    </button>
  );
}

// ─── 공통 테이블 헤더 스타일 ──────────────────────────────────────────────────

const TH_STYLE = {
  backgroundColor: 'var(--ctink-card)',
  opacity:         0.7,
  padding:         '10px 20px',
  textAlign:       'left',
  fontSize:        '13px',
  fontWeight:      800,
  color:           'var(--ctink-text)',
  whiteSpace:      'nowrap',
};

// ─── 메인 컴포넌트 ────────────────────────────────────────────────────────────

export default function IdsLogPage() {
  const [idsLogs,       setIdsLogs]       = useState([]);
  const [isLoading,     setIsLoading]     = useState(true);
  const [error,         setError]         = useState(null);
  const [idsAttackType, setIdsAttackType] = useState('');
  const [idsResult,     setIdsResult]     = useState('');
  const [idsDateFrom,   setIdsDateFrom]   = useState('');
  const [idsDateTo,     setIdsDateTo]     = useState('');
  const [currentPage,   setCurrentPage]   = useState(1);
  const [pageInput,     setPageInput]     = useState('1');
  const [totalCount,    setTotalCount]    = useState(0);
  const [alertCount,    setAlertCount]    = useState(0);
  const [blockedCount,  setBlockedCount]  = useState(0);
  const [detectedCount, setDetectedCount] = useState(0);
  const [totalPages,    setTotalPages]    = useState(1);
  const [selectedRule,  setSelectedRule]  = useState(null);
  const [hoveredLogId,  setHoveredLogId]  = useState(null);

  // ── PDF 생성 상태 ─────────────────────────────────────────────────────────
  const [isPdfGenerating, setIsPdfGenerating] = useState(false);

  // 최초 로드 여부
  const isInitialLoad = useRef(true);

  // ── IDS 로그 폴링 ────────────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    const fetchLogs = async () => {
      try {
        if (isInitialLoad.current) {
          setIsLoading(true);
          isInitialLoad.current = false;
        }
        setError(null);

        const r = await api.get('/ctink/logs/ids', {
          params: {
            page:        currentPage,
            attackType: idsAttackType || undefined,
            result:      idsResult     || undefined,
            dateFrom: idsDateFrom ? `${idsDateFrom}T00:00:00` : undefined,
            dateTo:   idsDateTo   ? `${idsDateTo}T23:59:59`   : undefined,
          },
        });
        if (cancelled) return;
        setIdsLogs(r.data.logs);
        setTotalCount(r.data.total_count);
        setAlertCount(r.data.alert_count);
        setBlockedCount(r.data.blocked_count);
        setDetectedCount(r.data.detected_count);
        setTotalPages(r.data.total_pages);
        setCurrentPage(r.data.current_page);
        setPageInput(String(r.data.current_page));
      } catch (err) {
        if (cancelled) return;
        if (err.response?.status !== 401) {
          setError('로그를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.');
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    fetchLogs();
    const intervalId = setInterval(fetchLogs, POLLING_INTERVAL);
    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, [currentPage, idsAttackType, idsResult, idsDateFrom, idsDateTo]);

  // ── 필터 변경 시 1페이지로 초기화 ─────────────────────────────────────────
  const withReset = (setter) => (val) => {
    setter(val);
    setCurrentPage(1);
    setPageInput('1');
    setIsLoading(true);
    isInitialLoad.current = true;
  };

  const handlePageChange = (n) => {
    if (n === currentPage) return;
    setCurrentPage(n);
    setPageInput(String(n));
    setIsLoading(true);
    isInitialLoad.current = true;
  };

  const handleCloseModal = useCallback(() => setSelectedRule(null), []);

  // ── 리포트 다운로드 핸들러 ────────────────────────────────────────────────────
  // API 호출 → generateIdsReport(data) → PDF 즉시 다운로드.
  const handleDownloadReport = async () => {
    if (isPdfGenerating) return;
    setIsPdfGenerating(true);
    try {
      const r = await api.get('/ctink/logs/ids/report');
      const { generateIdsReport } = await import('@/lib/generateIdsReport');
      await generateIdsReport(r.data);
    } catch (err) {
      console.error('[CTI-nk] PDF 생성 오류:', err);
    } finally {
      setIsPdfGenerating(false);
    }
  };

  // 초기 로드 실패
  if (error && idsLogs.length === 0) {
    return (
      <div style={{ padding: '32px' }}>
        <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>
          IDS Detection Log
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '300px' }}>
          <span style={{ fontSize: '13px', color: '#A32D2D' }}>{error}</span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '32px' }}>

      {/* 페이지 제목 + 리포트 다운로드 버튼 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)' }}>
          IDS Detection Log
        </h1>
        <button
          onClick={handleDownloadReport}
          disabled={isPdfGenerating}
          style={{
            display:         'flex',
            alignItems:      'center',
            gap:             '6px',
            padding:         '8px 16px',
            borderRadius:    '8px',
            border:          '1px solid var(--ctink-accent)',
            backgroundColor: isPdfGenerating ? 'var(--ctink-card)' : 'var(--ctink-accent)',
            color:           isPdfGenerating ? 'var(--ctink-text-muted)' : '#FFFFFF',
            fontSize:        '13px',
            fontWeight:      700,
            cursor:          isPdfGenerating ? 'default' : 'pointer',
            transition:      'opacity 0.15s',
            opacity:         isPdfGenerating ? 0.7 : 1,
            fontFamily:      'inherit',
            whiteSpace:      'nowrap',
          }}
        >
          {isPdfGenerating ? (
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none"
              style={{ animation: 'spin 1s linear infinite' }}>
              <circle cx="7" cy="7" r="5.5" stroke="currentColor" strokeWidth="1.5" strokeDasharray="8 4" />
            </svg>
          ) : (
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M7 1v8M4 6l3 3 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M2 11h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
          )}
          {isPdfGenerating ? '리포트 생성 중...' : '리포트 다운로드'}
        </button>
      </div>

      {/* 통계 + 필터 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', gap: '12px' }}>
          <StatChip label="전체"  count={totalCount}    />
          <StatChip label="알림"  count={alertCount}    color="#BA7517"             />
          <StatChip label="차단"  count={blockedCount}  color="#A32D2D"             />
          <StatChip label="탐지"  count={detectedCount} color="var(--ctink-accent)" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <FilterSelect
            label="공격 유형"
            value={idsAttackType}
            onChange={withReset(setIdsAttackType)}
            options={Object.entries(ATTACK_TYPE_LABEL).map(([v, l]) => ({ value: v, label: l }))}
          />
          <FilterSelect
            label="처리 결과"
            value={idsResult}
            onChange={withReset(setIdsResult)}
            options={Object.entries(IDS_RESULT_LABEL).map(([v, l]) => ({ value: v, label: l }))}
          />
          <DateInput value={idsDateFrom} onChange={withReset(setIdsDateFrom)} max={idsDateTo || undefined} />
          <span style={{ fontSize: '13px', color: 'var(--ctink-text-light)' }}>~</span>
          <DateInput value={idsDateTo}   onChange={withReset(setIdsDateTo)}   min={idsDateFrom || undefined} />
        </div>
      </div>

      {/* 에러 메시지 */}
      {error && (
        <div style={{
          marginBottom:    '16px',
          padding:         '12px 16px',
          borderRadius:    '8px',
          backgroundColor: 'rgba(163,45,45,0.08)',
          color:           '#A32D2D',
          fontSize:        '13px',
          fontWeight:      600,
        }}>
          {error}
        </div>
      )}

      {/* 카드 */}
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius:    '12px',
        boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
        overflow:        'hidden',
      }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['탐지 시간', '위협 유형', '정책명', '처리 결과'].map(h => (
                  <th key={h} style={TH_STYLE}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody style={{ borderBottom: '1px solid var(--ctink-border)' }}>
              {isLoading ? (
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--ctink-border)' }}>
                    {Array.from({ length: 4 }).map((_, j) => (
                      <td key={j} style={{ padding: '12px 20px' }}>
                        <div style={{
                          height:         '14px',
                          borderRadius:   '6px',
                          background:     'linear-gradient(90deg, var(--ctink-card) 25%, var(--ctink-bg) 50%, var(--ctink-card) 75%)',
                          backgroundSize: '200% 100%',
                          animation:      'shimmer 1.4s infinite',
                          width:          j === 2 ? '70%' : '50%',
                        }} />
                      </td>
                    ))}
                  </tr>
                ))
              ) : idsLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
                    조회된 로그가 없습니다.
                  </td>
                </tr>
              ) : idsLogs.map((log) => (
                <tr
                  key={log.log_id}
                  onClick={() => setSelectedRule({ rule_id: log.rule_id, rule_name: log.rule_name })}
                  onMouseEnter={() => setHoveredLogId(log.log_id)}
                  onMouseLeave={() => setHoveredLogId(null)}
                  style={{
                    borderBottom:    '1px solid var(--ctink-border)',
                    cursor:          'pointer',
                    backgroundColor: hoveredLogId === log.log_id ? 'var(--ctink-hover)' : 'transparent',
                    transition:      'background-color 0.1s',
                  }}
                >
                  <td style={{ padding: '12px 20px', color: 'var(--ctink-text-light)', fontSize: '13px', whiteSpace: 'nowrap' }}>
                    {formatDate(log.detected_at)}
                  </td>
                  <td style={{ padding: '12px 20px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
                    {ATTACK_TYPE_LABEL[log.attack_type] ?? log.attack_type ?? '-'}
                  </td>
                  <td style={{
                    padding:                 '12px 20px',
                    color:                   'var(--ctink-accent)',
                    fontWeight:              700,
                    fontSize:                '13px',
                    textDecorationLine:      hoveredLogId === log.log_id ? 'underline' : 'none',
                    textDecorationThickness: '2px',
                  }}>
                    {log.rule_name ?? '-'}
                  </td>
                  <td style={{ padding: '12px 20px' }}>
                    <IdsResultBadge result={log.result} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 하단: 결과 수 + 페이지네이션 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px' }}>
        <p style={{ fontSize: '12px', color: 'var(--ctink-text-light)' }}>
          총 {totalCount}건
        </p>
        {totalPages > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <PageBtn
              label="← 이전"
              disabled={currentPage === 1}
              onClick={() => handlePageChange(currentPage - 1)}
            />
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <input
                type="text"
                inputMode="numeric"
                value={pageInput}
                onChange={(e) => setPageInput(e.target.value)}
                onBlur={() => {
                  const val = Number(pageInput);
                  if (/^\d+$/.test(pageInput) && val >= 1 && val <= totalPages) {
                    handlePageChange(val);
                  } else {
                    setPageInput(String(currentPage));
                  }
                }}
                onKeyDown={(e) => { if (e.key === 'Enter') e.target.blur(); }}
                style={{
                  width:           '44px',
                  padding:         '5px 6px',
                  borderRadius:    '6px',
                  border:          '1px solid var(--ctink-border)',
                  backgroundColor: 'var(--ctink-background)',
                  fontSize:        '13px',
                  fontWeight:      700,
                  color:           'var(--ctink-text)',
                  textAlign:       'center',
                  outline:         'none',
                  fontFamily:      'inherit',
                }}
              />
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--ctink-text-muted)', whiteSpace: 'nowrap' }}>
                / {totalPages} 페이지
              </span>
            </div>
            <PageBtn
              label="다음 →"
              disabled={currentPage === totalPages}
              onClick={() => handlePageChange(currentPage + 1)}
            />
          </div>
        )}
      </div>

      {/* 룰 상세 모달 */}
      {selectedRule && (
        <RuleDetailModal
          ruleId={selectedRule.rule_id}
          ruleName={selectedRule.rule_name}
          onClose={handleCloseModal}
        />
      )}

      {/* 스피너 keyframe */}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>

    </div>
  );
}