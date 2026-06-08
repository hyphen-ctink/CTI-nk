'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import RuleDetailModal from '@/components/common/RuleDetailModal';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────

const RULE_TYPE_LABEL = {
  SNORT: 'Snort',
  YARA:  'YARA',
};

const ATTACK_TYPE_LABEL = {
  RANSOMWARE:          '랜섬웨어',
  CREDENTIAL_STUFFING: '크리덴셜 스터핑',
  PHISHING:            '피싱 공격',
  WEB_ATTACK:          '웹페이지 취약점',
  DDOS:                'DDoS',
  IOC_ONLY:            '침해 지표', 
};

const STATUS_LABEL = {
  PENDING:  '관리자 검토 필요',
  ACTIVE:   'IDS 적용 완료',
  INACTIVE: '비활성',
  REMOVED:  '제거됨',
};

// 신뢰도/상태 배지 색상은 globals.css에 없는 시맨틱 색상이므로 하드코딩 유지
const STATUS_STYLE = {
  PENDING:  { color: '#BA7517', background: 'rgba(186,117,23,0.08)'  },
  ACTIVE:   { color: '#0F6E56', background: 'rgba(15,110,86,0.08)'   },
  INACTIVE: { color: 'var(--ctink-text-light)', background: 'var(--ctink-border)' },
  REMOVED:  { color: '#A32D2D', background: 'rgba(163,45,45,0.08)'   },
};

const TRUST_STYLE = {
  HIGH:   { color: '#0F6E56' },
  MEDIUM: { color: '#BA7517' },
  LOW:    { color: '#A32D2D' },
};

const PAGE_SIZE = 15; // API 명세서: 페이지당 항목 수 15개 고정

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  const ymd = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const hm  = `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
  return `${ymd} ${hm}`;
}

// ─── 서브 컴포넌트: 배지 ──────────────────────────────────────────────────────

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

function StatusBadge({ status }) {
  const s = STATUS_STYLE[status] ?? {};
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
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

// ─── 페이지 버튼 ──────────────────────────────────────────────────────────────

function PageBtn({ label, active, disabled, onClick }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        minWidth:        '32px',
        height:          '32px',
        padding:         '0 8px',
        borderRadius:    '6px',
        border:          active ? '1.5px solid var(--ctink-accent)' : '1px solid var(--ctink-border)',
        backgroundColor: active ? 'var(--ctink-accent)' : 'transparent',
        color:           active ? 'var(--ctink-background)' : disabled ? 'var(--ctink-text-light)' : 'var(--ctink-text)',
        fontSize:        '13px',
        fontWeight:      700,
        cursor:          disabled ? 'not-allowed' : 'pointer',
        fontFamily:      'inherit',
        transition:      'all 0.1s',
      }}
    >
      {label}
    </button>
  );
}

// ─── 필터 드롭다운 ─────────────────────────────────────────────────────────────

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
      {options.map(o => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

// ─── 메인 페이지 ──────────────────────────────────────────────────────────────

const dateInputStyle = {
  padding:         '7px 10px',
  borderRadius:    '8px',
  border:          '1px solid var(--ctink-border)',
  backgroundColor: 'var(--ctink-background)',
  fontSize:        '13px',
  fontWeight:      600,
  outline:         'none',
  fontFamily:      'inherit',
  cursor:          'pointer',
};

export default function RulePage() {
  const [rules, setRules]             = useState([]);    // 초기값 빈 배열 (로딩 전)
  const [isLoading, setIsLoading]     = useState(true);  // 초기값 true: 첫 로드 시 skeleton 표시
  const [error, setError]             = useState(null);  // API 에러 메시지 (null이면 미표시)
  const [totalCount, setTotalCount]   = useState(0);
  const [totalPages, setTotalPages]   = useState(1);
  const [currentPage, setCurrentPage] = useState(1);
  const [search, setSearch]                 = useState('');
  const [filterAttack, setFilterAttack]     = useState('');
  const [filterRuleType, setFilterRuleType] = useState('');
  const [filterTrust, setFilterTrust]       = useState('');
  const [filterStatus, setFilterStatus]     = useState('');
  const [dateFrom, setDateFrom]             = useState('');
  const [dateTo, setDateTo]                 = useState('');
  const [selectedRule, setSelectedRule]     = useState(null);
  const [pageInput, setPageInput]           = useState('1');
  const [hoveredId, setHoveredId]           = useState(null); // 테이블 행 hover 상태

  // AbortController를 통해 이전 요청을 취소하여 race condition 방지:
  //   필터 변경 → 필터 useEffect에서 새 controller 생성, cleanup에서 abort()
  //   페이지 변경 → handlePageChange에서 새 controller 생성, abort()
  //
  const fetchRules = useCallback(async (page = 1, signal) => {
    try {
      setIsLoading(true);
      setError(null);
      const params = { page };
      if (search)         params.search      = search;
      if (filterAttack)   params.attackType = filterAttack;   // 예: 'RANSOMWARE'
      if (filterRuleType) params.ruleType   = filterRuleType; // 예: 'SNORT'
      if (filterTrust)    params.trustLevel = filterTrust;    // 예: 'HIGH'
      if (filterStatus)   params.status      = filterStatus;   // 예: 'ACTIVE'
      if (dateFrom)       params.dateFrom   = dateFrom;
      if (dateTo)         params.dateTo     = dateTo;
      const { data } = await api.get('/ctink/rules', { params, signal });
      setRules(data.rules);
      setTotalCount(data.total_count);
      setTotalPages(data.total_pages);
      setCurrentPage(data.current_page);
      setPageInput(String(data.current_page));
    } catch (e) {
      if (e.code === 'ERR_CANCELED') return; // AbortController 취소 요청은 에러 처리 생략
      if (e.response?.status === 400) setError('날짜 범위가 올바르지 않습니다.');
      else setError('데이터를 불러오지 못했습니다.');
    } finally {
      // abort된 요청의 finally는 후속 요청의 로딩 상태를 덮어쓰지 않도록 체크
      if (!signal?.aborted) setIsLoading(false);
    }
  }, [search, filterAttack, filterRuleType, filterTrust, filterStatus, dateFrom, dateTo]);
  // currentPage를 의존성에서 제외 → page 파라미터로 직접 전달하여 이중 호출 방지
  
  // 초기 로드
  useEffect(() => {
    const controller = new AbortController();
    fetchRules(1, controller.signal);
    return () => controller.abort();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  
  // 필터 변경 → page=1로 직접 호출 (currentPage 리셋 + API 1회 호출 + 이전 요청 취소)
  useEffect(() => {
    setCurrentPage(1);
    setPageInput('1');
    const controller = new AbortController();
    fetchRules(1, controller.signal);
    return () => controller.abort();
  }, [search, filterAttack, filterRuleType, filterTrust, filterStatus, dateFrom, dateTo]);
  // ↑ fetchRules를 dep에서 의도적으로 제외 (필터값을 useCallback deps로 직접 관리)

  // 페이지 변경 핸들러
  // pageControllerRef: 페이지 변경 요청의 AbortController를 추적
  // 연속 클릭 시 이전 요청을 abort()하여 race condition 방지
  const pageControllerRef = useRef(null);
  const handlePageChange = (newPage) => {
    if (pageControllerRef.current) pageControllerRef.current.abort();
    const controller = new AbortController();
    pageControllerRef.current = controller;
    fetchRules(newPage, controller.signal);
  };

  const handleCloseModal = useCallback(() => setSelectedRule(null), []);

  return (
    <div style={{ padding: '32px', minHeight: '100vh', backgroundColor: 'var(--ctink-bg)' }}>

      {/* 페이지 제목 */}
      <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>Rule</h1>

      {/* 검색 + 필터 */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="정책명 검색..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            flex:            1,
            minWidth:        '200px',
            maxWidth:        '320px',
            padding:         '7px 14px',
            borderRadius:    '8px',
            border:          '1px solid var(--ctink-border)',
            backgroundColor: 'var(--ctink-background)',
            fontSize:        '13px',
            fontWeight:      600,
            color:           'var(--ctink-text)',
            outline:         'none',
            fontFamily:      'inherit',
          }}
        />
        <FilterSelect
          label="정책 유형"
          value={filterRuleType}
          onChange={setFilterRuleType}
          options={Object.entries(RULE_TYPE_LABEL).map(([v, l]) => ({ value: v, label: l }))}
        />
        <FilterSelect
          label="위협 유형"
          value={filterAttack}
          onChange={setFilterAttack}
          options={Object.entries(ATTACK_TYPE_LABEL).map(([v, l]) => ({ value: v, label: l }))}
        />
        <FilterSelect
          label="신뢰도"
          value={filterTrust}
          onChange={setFilterTrust}
          options={[
            { value: 'HIGH',   label: 'High'   },
            { value: 'MEDIUM', label: 'Medium' },
            { value: 'LOW',    label: 'Low'    },
          ]}
        />
        <FilterSelect
          label="상태"
          value={filterStatus}
          onChange={setFilterStatus}
          options={Object.entries(STATUS_LABEL)
            .filter(([v]) => v !== 'REMOVED') // REMOVED는 필터 선택지에서 제외 (API 명세 반영)
            .map(([v, l]) => ({ value: v, label: l }))}
        />
        {/* 날짜 범위 */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <input
            type="date"
            value={dateFrom}
            max={dateTo || undefined}
            onChange={(e) => setDateFrom(e.target.value)}
            style={{ ...dateInputStyle, color: dateFrom ? 'var(--ctink-text)' : 'var(--ctink-text-light)' }}
          />
          <span style={{ fontSize: '13px', color: 'var(--ctink-text-light)', fontWeight: 600 }}>~</span>
          <input
            type="date"
            value={dateTo}
            min={dateFrom || undefined}
            onChange={(e) => setDateTo(e.target.value)}
            style={{ ...dateInputStyle, color: dateTo ? 'var(--ctink-text)' : 'var(--ctink-text-light)' }}
          />
        </div>

        {/* 필터가 하나라도 적용된 경우 초기화 버튼 표시 */}
        {(filterAttack || filterRuleType || filterTrust || filterStatus || search || dateFrom || dateTo) && (
          <button
            onClick={() => {
              setSearch('');
              setFilterAttack('');
              setFilterRuleType('');
              setFilterTrust('');
              setFilterStatus('');
              setDateFrom('');
              setDateTo('');
            }}
            style={{
              padding:         '7px 14px',
              borderRadius:    '8px',
              border:          '1px solid var(--ctink-border)',
              backgroundColor: 'transparent',
              fontSize:        '13px',
              color:           'var(--ctink-text-muted)',
              cursor:          'pointer',
              fontFamily:      'inherit',
              fontWeight:      600,
            }}
          >
            초기화
          </button>
        )}
      </div>

      {/* 에러 메시지 (API 호출 실패 시 표시) */}
      {error && (
        <div style={{
          marginBottom:    '16px',
          padding:         '10px 16px',
          borderRadius:    '8px',
          backgroundColor: 'rgba(163,45,45,0.08)',
          color:           '#A32D2D',
          fontSize:        '13px',
          fontWeight:      600,
        }}>
          {error}
        </div>
      )}

      {/* 테이블 */}
      <div style={{ backgroundColor: 'var(--ctink-background)', borderRadius: '12px', boxShadow: '0 1px 4px rgba(17,45,78,0.08)', overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr>
              {['정책명', '정책 유형', '위협 유형', '신뢰도', '상태', '생성일'].map(h => (
                <th key={h} style={{
                  padding:         '10px 20px',
                  textAlign:       'left',
                  fontWeight:      800,
                  backgroundColor: 'var(--ctink-card)',
                  opacity:         0.7,
                  color:           'var(--ctink-text)',
                  fontSize:        '13px',
                  whiteSpace:      'nowrap',
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              // 로딩 중: skeleton 애니메이션 표시 (globals.css에 @keyframes shimmer 정의됨)
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--ctink-border)' }}>
                  {Array.from({ length: 6 }).map((_, j) => (
                    <td key={j} style={{ padding: '12px 20px' }}>
                      <div style={{
                        height:          '14px',
                        borderRadius:    '6px',
                        background:      'linear-gradient(90deg, var(--ctink-card) 25%, var(--ctink-bg) 50%, var(--ctink-card) 75%)',
                        backgroundSize:  '200% 100%',
                        animation:       'shimmer 1.4s infinite',
                        width:           j === 0 ? '70%' : j === 5 ? '60%' : '50%',
                      }} />
                    </td>
                  ))}
                </tr>
              ))
            ) : rules.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '40px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
                  조회된 정책이 없습니다.
                </td>
              </tr>
            ) : (
              rules.map((rule, i) => {
                const isHovered = hoveredId === rule.rule_id;
                return (
                  <tr
                    key={rule.rule_id}
                    onClick={() => setSelectedRule({ rule_id: rule.rule_id, rule_name: rule.rule_name })}
                    onMouseEnter={() => setHoveredId(rule.rule_id)}
                    onMouseLeave={() => setHoveredId(null)}
                    style={{
                      borderBottom:    i < rules.length - 1 ? '1px solid var(--ctink-border)' : 'none',
                      cursor:          'pointer',
                      transition:      'background-color 0.1s',
                      backgroundColor: isHovered ? 'var(--ctink-hover)' : 'transparent',
                    }}
                  >
                    <td style={{
                      padding:                 '12px 20px',
                      color:                   'var(--ctink-accent)',
                      fontWeight:              700,
                      textDecoration:          isHovered ? 'underline' : 'none',
                      textDecorationThickness: isHovered ? '2px' : undefined,
                    }}>
                      {rule.rule_name}
                    </td>
                    <td style={{ padding: '12px 20px', color: 'var(--ctink-text-muted)' }}>
                      {RULE_TYPE_LABEL[rule.rule_type] ?? rule.rule_type ?? '-'}
                    </td>
                    <td style={{ padding: '12px 20px', color: 'var(--ctink-text-muted)' }}>
                      {ATTACK_TYPE_LABEL[rule.attack_type] ?? rule.attack_type ?? '-'}
                    </td>
                    <td style={{ padding: '12px 20px' }}>
                      <TrustBadge level={rule.trust_level} />
                    </td>
                    <td style={{ padding: '12px 20px' }}>
                      <StatusBadge status={rule.status} />
                    </td>
                    <td style={{ padding: '12px 20px', color: 'var(--ctink-text-light)', whiteSpace: 'nowrap' }}>
                      {formatDate(rule.created_at)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* 하단: 결과 수 + 페이지네이션 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px' }}>
        <p style={{ fontSize: '12px', color: 'var(--ctink-text-light)' }}>
          총 {totalCount}개 정책
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

      {/* 상세 모달 */}
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