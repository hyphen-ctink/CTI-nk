'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import RuleDetailModal from '@/components/common/RuleDetailModal';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────
// 키값은 API 응답 기준 대문자 스네이크케이스 (DB ENUM은 소문자이나 백엔드에서 대문자로 변환하여 전달)

const ATTACK_TYPE_LABEL = {
  RANSOMWARE:          '랜섬웨어',
  CREDENTIAL_STUFFING: '크리덴셜 스터핑',
  PHISHING:            '피싱 공격',
  WEB_ATTACK:          '웹페이지 취약점',
  DDOS:                'DDoS',
  OTHER:              '기타',
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
const POLLING_INTERVAL = 30_000; // 30초 (Overview 페이지와 동일)

// ─── [백엔드 연동 시 이 블록 전체 삭제] 목업 데이터 ──────────────────────────
// attack_type, result 값은 API 응답과 동일하게 대문자로 작성

const MOCK_IDS_LOGS = [
  { log_id:  1, rule_id: 1, rule_name: 'RULE_LOCKBIT3_002',    attack_type: 'RANSOMWARE',          result: 'ALERT',  detected_at: '2026-03-23T14:51:00' },
  { log_id:  2, rule_id: 2, rule_name: 'RULE_CRED_GS25_011',   attack_type: 'CREDENTIAL_STUFFING', result: 'BLOCK',  detected_at: '2026-03-23T14:23:00' },
  { log_id:  3, rule_id: 3, rule_name: 'RULE_PHISH_SKT_007',   attack_type: 'PHISHING',            result: 'DETECT', detected_at: '2026-03-23T13:58:00' },
  { log_id:  4, rule_id: 5, rule_name: 'RULE_DDOS_DNS_005',    attack_type: 'DDOS',                result: 'BLOCK',  detected_at: '2026-03-23T13:41:00' },
  { log_id:  5, rule_id: 4, rule_name: 'RULE_WEB_STRUTS_003',  attack_type: 'WEB_ATTACK',          result: 'DETECT', detected_at: '2026-03-23T13:12:00' },
  { log_id:  6, rule_id: 1, rule_name: 'RULE_LOCKBIT3_002',    attack_type: 'RANSOMWARE',          result: 'BLOCK',  detected_at: '2026-03-23T12:44:00' },
  { log_id:  7, rule_id: 3, rule_name: 'RULE_PHISH_SKT_007',   attack_type: 'PHISHING',            result: 'DETECT', detected_at: '2026-03-23T12:09:00' },
  { log_id:  8, rule_id: 2, rule_name: 'RULE_CRED_GS25_011',   attack_type: 'CREDENTIAL_STUFFING', result: 'BLOCK',  detected_at: '2026-03-23T11:38:00' },
  { log_id:  9, rule_id: 4, rule_name: 'RULE_WEB_STRUTS_003',  attack_type: 'WEB_ATTACK',          result: 'DETECT', detected_at: '2026-03-23T10:55:00' },
  { log_id: 10, rule_id: 5, rule_name: 'RULE_DDOS_DNS_005',    attack_type: 'DDOS',                result: 'ALERT',  detected_at: '2026-03-23T10:20:00' },
  { log_id: 11, rule_id: 1, rule_name: 'RULE_LOCKBIT3_002',    attack_type: 'RANSOMWARE',          result: 'BLOCK',  detected_at: '2026-03-23T09:44:00' },
  { log_id: 12, rule_id: 2, rule_name: 'RULE_CRED_GS25_011',   attack_type: 'CREDENTIAL_STUFFING', result: 'BLOCK',  detected_at: '2026-03-23T09:10:00' },
  { log_id: 13, rule_id: 3, rule_name: 'RULE_PHISH_SKT_007',   attack_type: 'PHISHING',            result: 'ALERT',  detected_at: '2026-03-23T08:45:00' },
  { log_id: 14, rule_id: 4, rule_name: 'RULE_WEB_STRUTS_003',  attack_type: 'WEB_ATTACK',          result: 'BLOCK',  detected_at: '2026-03-23T08:20:00' },
  { log_id: 15, rule_id: 5, rule_name: 'RULE_DDOS_DNS_005',    attack_type: 'DDOS',                result: 'DETECT', detected_at: '2026-03-23T07:55:00' },
  { log_id: 16, rule_id: 1, rule_name: 'RULE_LOCKBIT3_002',    attack_type: 'RANSOMWARE',          result: 'BLOCK',  detected_at: '2026-03-22T18:30:00' },
  { log_id: 17, rule_id: 6, rule_name: 'RULE_RANSOM_CLOP_001', attack_type: 'RANSOMWARE',          result: 'DETECT', detected_at: '2026-03-22T17:10:00' },
  { log_id: 18, rule_id: 7, rule_name: 'RULE_DDOS_UDP_014',    attack_type: 'DDOS',                result: 'BLOCK',  detected_at: '2026-03-22T16:50:00' },
  { log_id: 19, rule_id: 8, rule_name: 'RULE_WEB_LOG4J_009',   attack_type: 'WEB_ATTACK',          result: 'ALERT',  detected_at: '2026-03-22T15:30:00' },
  { log_id: 20, rule_id: 2, rule_name: 'RULE_CRED_GS25_011',   attack_type: 'CREDENTIAL_STUFFING', result: 'DETECT', detected_at: '2026-03-22T14:15:00' },
  { log_id: 21, rule_id: 9, rule_name: 'RULE_PHISH_KAKAO_002', attack_type: 'PHISHING',            result: 'BLOCK',  detected_at: '2026-03-22T13:40:00' },
  { log_id: 22, rule_id: 5, rule_name: 'RULE_DDOS_DNS_005',    attack_type: 'DDOS',                result: 'BLOCK',  detected_at: '2026-03-22T12:55:00' },
  { log_id: 23, rule_id: 4, rule_name: 'RULE_WEB_STRUTS_003',  attack_type: 'WEB_ATTACK',          result: 'DETECT', detected_at: '2026-03-22T11:20:00' },
  { log_id: 24, rule_id: 1, rule_name: 'RULE_LOCKBIT3_002',    attack_type: 'RANSOMWARE',          result: 'ALERT',  detected_at: '2026-03-22T10:05:00' },
  { log_id: 25, rule_id: 3, rule_name: 'RULE_PHISH_SKT_007',   attack_type: 'PHISHING',            result: 'DETECT', detected_at: '2026-03-22T09:30:00' },
];

// ─── [백엔드 연동 시 삭제 끝] ─────────────────────────────────────────────────

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
  const [error,         setError]         = useState(null); // 에러 메시지 (null이면 미표시)
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
  const [selectedRule,  setSelectedRule]  = useState(null); // { rule_id, rule_name }
  const [hoveredLogId,  setHoveredLogId]  = useState(null); // 마우스 오버된 행의 log_id

  // 최초 로드 여부: true일 때만 shimmer 표시, 폴링 갱신 시에는 백그라운드 교체
  const isInitialLoad = useRef(true);

  useEffect(() => {
    let cancelled = false; // Race Condition 방지: cleanup 시 true로 전환
    const fetchLogs = async () => {
      try {
        if (isInitialLoad.current) {
          setIsLoading(true);
          isInitialLoad.current = false;
        }
        setError(null);

        // ─── [백엔드 연동 시 이 블록 전체 삭제] 목업 처리 ─────────────────────────
        await new Promise((r) => setTimeout(r, 300));
        let filtered = [...MOCK_IDS_LOGS];
        if (idsAttackType) filtered = filtered.filter(l => l.attack_type === idsAttackType);
        if (idsResult)     filtered = filtered.filter(l => l.result === idsResult);
        // date_from: 해당 날짜 00:00:00 이후, date_to: 해당 날짜 23:59:59 이전
        if (idsDateFrom)   filtered = filtered.filter(l => l.detected_at >= idsDateFrom);
        if (idsDateTo)     filtered = filtered.filter(l => l.detected_at <= idsDateTo + 'T23:59:59');

        // 통계값은 API 명세서 기준 필터 무관 전체 집계
        setTotalCount(MOCK_IDS_LOGS.length);
        setAlertCount(MOCK_IDS_LOGS.filter(l => l.result === 'ALERT').length);
        setBlockedCount(MOCK_IDS_LOGS.filter(l => l.result === 'BLOCK').length);
        setDetectedCount(MOCK_IDS_LOGS.filter(l => l.result === 'DETECT').length);
        setTotalPages(Math.max(1, Math.ceil(filtered.length / PAGE_SIZE)));

        const start = (currentPage - 1) * PAGE_SIZE;
        setIdsLogs(filtered.slice(start, start + PAGE_SIZE));
        // ─── [백엔드 연동 시 삭제 끝] ──────────────────────────────────────────────

        // ─── [백엔드 연동 시 주석 해제, 위 목업 블록 삭제] 실제 API 호출 ───────────
        // const r = await api.get('/ctink/logs/ids', {
        //   params: {
        //     page:        currentPage,
        //     attack_type: idsAttackType || undefined, // 빈 문자열이면 파라미터 제외
        //     result:      idsResult     || undefined,
        //     date_from:   idsDateFrom   || undefined,
        //     date_to:     idsDateTo     || undefined,
        //   },
        // });
        // if (cancelled) return; // Race Condition 방지: cleanup 이후 완료된 요청은 상태 업데이트 안 함
        // setIdsLogs(r.data.logs);
        // setTotalCount(r.data.total_count);
        // setAlertCount(r.data.alert_count);
        // setBlockedCount(r.data.blocked_count);
        // setDetectedCount(r.data.detected_count);
        // setTotalPages(r.data.total_pages);
        // setCurrentPage(r.data.current_page);
        // setPageInput(String(r.data.current_page));
        // ─────────────────────────────────────────────────────────────────────────

      } catch (err) {
        if (cancelled) return; // Race Condition 방지
        // 401(세션 만료)은 api.js 인터셉터에서 전역 처리 (window.location.href = '/login')
        if (err.response?.status !== 401) {
            setError('로그를 불러오는 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.');
        }
      } finally {
        if (!cancelled) setIsLoading(false); // Race Condition 방지
      }
    };

    fetchLogs();
    const intervalId = setInterval(fetchLogs, POLLING_INTERVAL);
    return () => {
      cancelled = true;          // Race Condition 방지: 진행 중인 요청 무효화
      clearInterval(intervalId); // 언마운트 또는 필터 변경 시 인터벌 정리
    };
  }, [currentPage, idsAttackType, idsResult, idsDateFrom, idsDateTo]);

  // 필터 변경 시 1페이지로 초기화 + shimmer 표시
  const withReset = (setter) => (val) => {
    setter(val);
    setCurrentPage(1);
    setPageInput('1');
    setIsLoading(true);      // 필터 변경 시 즉시 shimmer 표시
    isInitialLoad.current = true; // 다음 fetchLogs 호출에서 shimmer 유지
  };

  const handlePageChange = (n) => {
    if (n === currentPage) return;
    setCurrentPage(n);
    setPageInput(String(n));
    setIsLoading(true);           // 페이지 변경 시 shimmer 표시 (필터 변경과 동일하게 처리)
    isInitialLoad.current = true;
  };

  const handleCloseModal = useCallback(() => setSelectedRule(null), []);

  // 초기 로드 실패: 데이터가 없는 상태에서 에러 → Overview 스타일로 전체 페이지 에러 표시
  // 폴링 갱신 실패: 기존 데이터 유지 + 에러 배너만 표시 (필터 조작 가능하도록)
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

      {/* 페이지 제목 */}
      <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>
        IDS Detection Log
      </h1>

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
          {/* min/max로 역방향 날짜 입력 방지 → 서버 400 예방 */}
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
                // 로딩 중: shimmer 스켈레톤 (globals.css @keyframes shimmer 사용)
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
                // 행 클릭 시 RuleDetailModal에 rule_id/rule_name 전달 → 모달 내부에서 API 호출
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
                  {/* textDecorationLine + textDecorationThickness: longhand끼리 사용하여 React 충돌 경고 방지 */}
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

      {/* 룰 상세 모달: RuleDetailModal 내부에서 rule_id로 API 호출 */}
      {selectedRule && (
        <RuleDetailModal
          ruleId={selectedRule.rule_id}
          ruleName={selectedRule.rule_name}
          onClose={handleCloseModal}
        />
      )}

    </div>
  );
}