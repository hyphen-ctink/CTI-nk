'use client';

import { useState, useEffect } from 'react';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────

// stage 값 → 한국어 레이블 매핑 (API 명세: COLLECT / PROCESS / APPLY / REMOVED)
const STAGE_LABEL = {
  COLLECT: '수집',
  PROCESS: 'AI Agent',
  APPLY:   'IDS 적용',
  REMOVED: '삭제',
};

// 시맨틱 색상 — globals.css CTI-nk 변수에 없어 직접 정의
const SYS_STATUS_STYLE = {
  SUCCESS: { color: '#0F6E56', background: 'rgba(15,110,86,0.08)'  },
  FAILURE: { color: '#A32D2D', background: 'rgba(163,45,45,0.08)'  },
};

const PAGE_SIZE = 15; // API 명세 고정값

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (isNaN(d)) return '-';
  const ymd = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const hm  = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
  return `${ymd} ${hm}`;
}

// ─── 서브 컴포넌트 ────────────────────────────────────────────────────────────

function SysStatusBadge({ status }) {
  const s = SYS_STATUS_STYLE[status] ?? {};
  const label =
    status === 'SUCCESS' ? '성공' :
    status === 'FAILURE' ? '실패' :
    status ?? '-';
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
      {label}
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

function DateInput({ value, onChange }) {
  return (
    <input
      type="date"
      value={value}
      onChange={(e) => onChange(e.target.value)}
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

export default function SystemLogPage() {
  const [sysLogs,      setSysLogs]      = useState([]);
  const [isLoading,    setIsLoading]    = useState(true);
  const [error,        setError]        = useState(null);
  const [sysStage,     setSysStage]     = useState('');
  const [sysStatus,    setSysStatus]    = useState('');
  const [sysDateFrom,  setSysDateFrom]  = useState('');
  const [sysDateTo,    setSysDateTo]    = useState('');
  const [currentPage,  setCurrentPage]  = useState(1);
  const [pageInput,    setPageInput]    = useState('1');
  const [totalCount,   setTotalCount]   = useState(0);
  const [successCount, setSuccessCount] = useState(0);
  const [failureCount, setFailureCount] = useState(0);
  const [totalPages,   setTotalPages]   = useState(1);

  useEffect(() => {
    const controller = new AbortController();

    setIsLoading(true);
    setError(null);

    api.get('/ctink/logs/system', {
      params: {
        page:      currentPage,
        stage:     sysStage    || undefined,
        status:    sysStatus   || undefined,
        date_from: sysDateFrom || undefined,
        date_to:   sysDateTo   || undefined,
      },
      signal: controller.signal, // 필터 변경 시 이전 요청 취소
    })
      .then(r => {
        setSysLogs(r.data.logs);
        setTotalCount(r.data.total_count);
        setSuccessCount(r.data.success_count);
        setFailureCount(r.data.failure_count);
        setTotalPages(r.data.total_pages);
        setCurrentPage(r.data.current_page);
        setPageInput(String(r.data.current_page));
        setError(null);
      })
      .catch((err) => {
        if (err.name === 'CanceledError') return; // abort된 요청은 에러 처리 생략
        if (err.response?.status === 400) {
          setError('날짜 범위가 올바르지 않습니다. 시작일이 종료일보다 클 수 없습니다.');
        } else {
          setError('로그를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.');
        }
        setSysLogs([]);
        setTotalCount(0);
        setSuccessCount(0);
        setFailureCount(0);
        setTotalPages(1);
      })
      .finally(() => setIsLoading(false));

    return () => controller.abort();

  }, [currentPage, sysStage, sysStatus, sysDateFrom, sysDateTo]);

  // 필터 변경 시 페이지를 1로 초기화
  const withReset = (setter) => (val) => {
    setter(val);
    setCurrentPage(1);
    setPageInput('1');
  };

  const handlePageChange = (n) => {
    setCurrentPage(n);
    setPageInput(String(n));
  };

  return (
    <div style={{ padding: '32px' }}>

      {/* 페이지 제목 */}
      <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>
        System Log
      </h1>

      {/* 통계 + 필터 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', gap: '12px' }}>
          <StatChip label="전체" count={totalCount}   />
          <StatChip label="성공" count={successCount} color="#0F6E56" />
          <StatChip label="실패" count={failureCount} color="#A32D2D" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          <FilterSelect
            label="단계"
            value={sysStage}
            onChange={withReset(setSysStage)}
            options={[
              { value: 'COLLECT', label: '수집' },
              { value: 'PROCESS', label: 'AI Agent' },
              { value: 'APPLY',   label: 'IDS 적용' },
              { value: 'REMOVED', label: '삭제' },
            ]}
          />
          <FilterSelect
            label="결과"
            value={sysStatus}
            onChange={withReset(setSysStatus)}
            options={[
              { value: 'SUCCESS', label: '성공' },
              { value: 'FAILURE', label: '실패' },
            ]}
          />
          <DateInput value={sysDateFrom} onChange={withReset(setSysDateFrom)} />
          <span style={{ fontSize: '13px', color: 'var(--ctink-text-light)' }}>~</span>
          <DateInput value={sysDateTo}   onChange={withReset(setSysDateTo)}   />
        </div>
      </div>

      {/* 테이블 카드 */}
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius:    '12px',
        boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
        overflow:        'hidden',
      }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '150px' }} />
              <col style={{ width: '110px' }} />
              <col />
              <col style={{ width: '100px' }} />
            </colgroup>
            <thead>
              <tr>
                {['시간', '단계', '처리 내용', '결과'].map(h => (
                  <th key={h} style={TH_STYLE}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                // 로딩 중: shimmer 스켈레톤 (@keyframes shimmer는 globals.css에 정의)
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
              ) : error ? (
                // API 호출 실패 시 에러 메시지
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: '#A32D2D', fontSize: '13px' }}>
                    {error}
                  </td>
                </tr>
              ) : sysLogs.length === 0 ? (
                // 조회 결과 없음
                <tr>
                  <td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
                    조회된 로그가 없습니다.
                  </td>
                </tr>
              ) : sysLogs.map((log, i) => (
                <tr
                  key={log.log_id}
                  style={{ borderBottom: i < sysLogs.length - 1 ? '1px solid var(--ctink-border)' : 'none' }}
                >
                  <td style={{ padding: '12px 20px', color: 'var(--ctink-text-light)', fontSize: '13px', whiteSpace: 'nowrap' }}>
                    {formatDate(log.created_at)}
                  </td>
                  <td style={{ padding: '12px 20px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
                    {STAGE_LABEL[log.stage] ?? log.stage ?? '-'}
                  </td>
                  <td
                    title={log.message ?? '-'}
                    style={{
                      padding:      '12px 20px',
                      color:        'var(--ctink-text)',
                      fontSize:     '13px',
                      whiteSpace:   'nowrap',
                      overflow:     'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {log.message ?? '-'}
                  </td>
                  <td style={{ padding: '12px 20px' }}>
                    <SysStatusBadge status={log.status} />
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

    </div>
  );
}