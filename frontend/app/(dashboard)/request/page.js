'use client';

import { useState, useEffect, useCallback } from 'react';
import RuleDetailModal from '@/components/common/RuleDetailModal';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────

const ATTACK_TYPE_LABEL = {
  WEB_ATTACK:          '웹페이지 취약점',
  RANSOMWARE:          '랜섬웨어',
  PHISHING:            '피싱 공격',
  DDOS:                'DDoS',
  CREDENTIAL_STUFFING: '크리덴셜 스터핑',
  IOC_ONLY:            '침해 지표', 
};

const RULE_PAGE_SIZE         = 5;
const OTHER_THREAT_PAGE_SIZE = 10;

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '-';
  const d   = new Date(iso);
  const ymd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const hm  = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  return `${ymd} ${hm}`;
}

// ─── 공통 서브 컴포넌트 ───────────────────────────────────────────────────────

function CountBadge({ label, count, color, bg }) {
  return (
    <span style={{
      display:         'inline-flex',
      alignItems:      'center',
      gap:             '5px',
      padding:         '3px 10px',
      borderRadius:    '999px',
      fontSize:        '12px',
      fontWeight:      700,
      color,
      backgroundColor: bg,
    }}>
      {label} <span>{count}</span>
    </span>
  );
}

function LowTrustBadge() {
  return (
    <span style={{
      display:         'inline-block',
      padding:         '2px 10px',
      borderRadius:    '999px',
      fontSize:        '12px',
      fontWeight:      600,
      color:           '#A32D2D',
      backgroundColor: 'rgba(163,45,45,0.08)',
      whiteSpace:      'nowrap',
    }}>
      Low
    </span>
  );
}

function DecisionResult({ decision }) {
  if (decision === 'APPROVED') return (
    <span style={{ fontSize: '13px', fontWeight: 700, color: '#0F6E56' }}>승인됨</span>
  );
  if (decision === 'REJECTED') return (
    <span style={{ fontSize: '13px', fontWeight: 700, color: '#A32D2D' }}>거부됨</span>
  );
  return null;
}

function ActionButton({ label, disabled, loading, color, bg, onClick }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding:         '4px 12px',
        borderRadius:    '6px',
        border:          `1px solid ${color}`,
        backgroundColor: bg,
        fontSize:        '12px',
        fontWeight:      700,
        color:           disabled && !loading ? 'var(--ctink-text-light)' : color,
        cursor:          disabled ? 'default' : 'pointer',
        opacity:         disabled && !loading ? 0.5 : 1,
        fontFamily:      'inherit',
        transition:      'opacity 0.15s',
        whiteSpace:      'nowrap',
      }}
    >
      {loading ? '...' : label}
    </button>
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

// ─── 공통 스켈레톤 행 ─────────────────────────────────────────────────────────

function SkeletonRows({ colCount, rowCount }) {
  return Array.from({ length: rowCount }).map((_, i) => (
    <tr key={i} style={{ borderBottom: '1px solid var(--ctink-border)' }}>
      {Array.from({ length: colCount }).map((_, j) => (
        <td key={j} style={{ padding: '12px 20px' }}>
          <div style={{
            height:         '14px',
            borderRadius:   '6px',
            background:     'linear-gradient(90deg, var(--ctink-card) 25%, var(--ctink-bg) 50%, var(--ctink-card) 75%)',
            backgroundSize: '200% 100%',
            animation:      'shimmer 1.4s infinite',
            width:          j === colCount - 1 ? '70%' : '50%',
          }} />
        </td>
      ))}
    </tr>
  ));
}

// ─── 공통 에러 행 ─────────────────────────────────────────────────────────────

function ErrorRow({ colSpan, onRetry }) {
  return (
    <tr>
      <td colSpan={colSpan} style={{ textAlign: 'center', padding: '40px', fontSize: '13px' }}>
        <span style={{ color: '#A32D2D' }}>목록을 불러오지 못했습니다.</span>
        <button
          onClick={onRetry}
          style={{
            marginLeft:      '10px',
            padding:         '3px 10px',
            borderRadius:    '6px',
            border:          '1px solid var(--ctink-border)',
            backgroundColor: 'var(--ctink-background)',
            fontSize:        '12px',
            fontWeight:      700,
            color:           'var(--ctink-text)',
            cursor:          'pointer',
            fontFamily:      'inherit',
          }}
        >
          재시도
        </button>
      </td>
    </tr>
  );
}

// ─── 공통 빈 데이터 행 ────────────────────────────────────────────────────────

function EmptyRow({ colSpan, message }) {
  return (
    <tr>
      <td colSpan={colSpan} style={{ textAlign: 'center', padding: '40px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
        {message}
      </td>
    </tr>
  );
}

// ─── Pagination ───────────────────────────────────────────────────────────────

function Pagination({ currentPage, totalPages, totalCount, onPageChange }) {
  const [pageInput, setPageInput] = useState(String(currentPage));

  useEffect(() => {
    setPageInput(String(currentPage));
  }, [currentPage]);

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px' }}>
      <p style={{ fontSize: '12px', color: 'var(--ctink-text-light)' }}>
        총 {totalCount}건
      </p>
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <PageBtn
            label="← 이전"
            disabled={currentPage === 1}
            onClick={() => onPageChange(currentPage - 1)}
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
                  onPageChange(val);
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
            onClick={() => onPageChange(currentPage + 1)}
          />
        </div>
      )}
    </div>
  );
}

// ─── RuleTable ────────────────────────────────────────────────────────────────

function RuleTable({ rules, decisions, isAdmin, onDecision, processingId, isLoading, hasError, onRetry, onRowClick }) {
  const COL_COUNT = 5;

  const bodyContent = () => {
    if (isLoading) return <SkeletonRows colCount={COL_COUNT} rowCount={RULE_PAGE_SIZE} />;
    if (hasError)  return <ErrorRow colSpan={COL_COUNT} onRetry={onRetry} />;
    if (rules.length === 0) return <EmptyRow colSpan={COL_COUNT} message="승인 대기 중인 룰이 없습니다." />;

    return rules.map((rule, i) => {
      const decided = decisions[rule.rule_id];
      return (
        <tr
          key={rule.rule_id}
          onClick={() => onRowClick({ rule_id: rule.rule_id, rule_name: rule.rule_name })}
          style={{
            borderBottom:    i < rules.length - 1 ? '1px solid var(--ctink-border)' : 'none',
            backgroundColor: decided ? 'rgba(17,45,78,0.02)' : 'transparent',
            opacity:         decided ? 0.6 : 1,
            cursor:          'pointer',
            transition:      'background-color 0.1s, opacity 0.2s',
          }}
          onMouseEnter={(e) => { if (!decided) e.currentTarget.style.backgroundColor = 'var(--ctink-hover)'; }}
          onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = decided ? 'rgba(17,45,78,0.02)' : 'transparent'; }}
        >
          <td style={{ padding: '12px 20px', color: 'var(--ctink-text-light)', fontSize: '13px', whiteSpace: 'nowrap' }}>
            {formatDate(rule.created_at)}
          </td>
          <td style={{ padding: '12px 20px', color: 'var(--ctink-text-muted)', fontSize: '13px' }}>
            {ATTACK_TYPE_LABEL[rule.attack_type] ?? (rule.attack_type ?? '-')}
          </td>
          <td style={{ padding: '12px 20px', color: 'var(--ctink-accent)', fontSize: '13px', fontWeight: 700 }}>
            {rule.rule_name ?? '-'}
          </td>
          <td style={{ padding: '12px 20px' }}>
            <LowTrustBadge />
          </td>
          <td style={{ padding: '12px 20px' }} onClick={(e) => e.stopPropagation()}>
            {decided ? (
              <DecisionResult decision={decided} />
            ) : isAdmin ? (
              <div style={{ display: 'flex', gap: '6px' }}>
                <ActionButton
                  label="승인"
                  disabled={!!processingId}
                  loading={processingId === `${rule.rule_id}_APPROVED`}
                  color="#0F6E56"
                  bg="rgba(15,110,86,0.08)"
                  onClick={() => onDecision(rule.rule_id, 'APPROVED')}
                />
                <ActionButton
                  label="거부"
                  disabled={!!processingId}
                  loading={processingId === `${rule.rule_id}_REJECTED`}
                  color="#A32D2D"
                  bg="rgba(163,45,45,0.08)"
                  onClick={() => onDecision(rule.rule_id, 'REJECTED')}
                />
              </div>
            ) : (
              <span style={{ color: 'var(--ctink-text-light)', fontSize: '13px' }}>-</span>
            )}
          </td>
        </tr>
      );
    });
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
        <colgroup>
          <col style={{ width: '160px' }} />
          <col style={{ width: '130px' }} />
          <col />
          <col style={{ width: '80px'  }} />
          <col style={{ width: isAdmin ? '140px' : '60px' }} />
        </colgroup>
        <thead>
          <tr>
            {['시간', '유형', '정책명', '신뢰도', '처리'].map(h => (
              <th key={h} style={TH_STYLE}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>{bodyContent()}</tbody>
      </table>
    </div>
  );
}

// ─── SectionCard (Snort / YARA 룰 승인 요청) ─────────────────────────────────
// GET /ctink/notifications/rules/pending?rule_type=<SNORT|YARA>&page=N
// 섹션별로 독립 호출 — 한 섹션의 페이지 변경이 다른 섹션에 영향을 주지 않음

function SectionCard({ title, ruleType, decisions, isAdmin, onDecision, processingId, onRowClick }) {
  const [currentPage,        setCurrentPage]        = useState(1);
  const [rules,              setRules]              = useState([]);
  const [totalCount,         setTotalCount]         = useState(0);
  const [totalPages,         setTotalPages]         = useState(1);
  const [isLoading,          setIsLoading]          = useState(true);
  const [hasError,           setHasError]           = useState(false);

  // 페이지 이동과 무관하게 이 섹션에서 처리된 누적 카운트를 별도 관리
  const [localDecidedCount,  setLocalDecidedCount]  = useState(0);
  const [localApprovedCount, setLocalApprovedCount] = useState(0);

  const pendingCount  = Math.max(0, totalCount - localDecidedCount);
  const approvedCount = localApprovedCount;

  const fetchRules = useCallback(async (page) => {
    setIsLoading(true);
    setHasError(false);
    try {
      const res = await api.get('/ctink/notifications/rules/pending', {
        params: { ruleType, page },
      });
      const { rules, total_count, total_pages, current_page } = res.data;
      setRules(rules);
      setTotalCount(total_count);
      setTotalPages(total_pages);
      setCurrentPage(current_page);
      setLocalDecidedCount(0);
    } catch {
      setHasError(true);
    } finally {
      setIsLoading(false);
    }
  }, [ruleType]);

  const handleDecision = useCallback(async (ruleId, decision) => {
    const success = await onDecision(ruleId, decision);
    if (success) {
      setLocalDecidedCount(prev => prev + 1);
      if (decision === 'APPROVED') setLocalApprovedCount(prev => prev + 1);
    }
  }, [onDecision]);

  useEffect(() => {
    fetchRules(1);
  }, [fetchRules]);

  const handlePageChange = useCallback((page) => {
    setCurrentPage(page);
    fetchRules(page);
  }, [fetchRules]);

  return (
    <div style={{ marginBottom: '24px' }}>
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius:    '12px',
        boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
        overflow:        'hidden',
      }}>
        <div style={{
          display:      'flex',
          alignItems:   'center',
          gap:          '10px',
          padding:      '16px 20px',
          borderBottom: '1px solid var(--ctink-border)',
        }}>
          <span style={{ fontSize: '15px', fontWeight: 800, color: 'var(--ctink-text)' }}>
            {title}
          </span>
          <CountBadge
            label="대기"
            count={isLoading ? '-' : pendingCount}
            color="#BA7517"
            bg="rgba(186,117,23,0.10)"
          />
          {approvedCount > 0 && (
            <CountBadge
              label="승인"
              count={approvedCount}
              color="#0F6E56"
              bg="rgba(15,110,86,0.10)"
            />
          )}
        </div>

        <RuleTable
          rules={isLoading ? [] : rules}
          decisions={decisions}
          isAdmin={isAdmin}
          onDecision={handleDecision}
          processingId={processingId}
          isLoading={isLoading}
          hasError={hasError}
          onRetry={() => fetchRules(currentPage)}
          onRowClick={onRowClick}
        />
      </div>

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalCount={totalCount}
        onPageChange={handlePageChange}
      />
    </div>
  );
}

// ─── OtherThreatTable ─────────────────────────────────────────────────────────

function OtherThreatTable({ notifications, isLoading, hasError, onRetry }) {
  const COL_COUNT = 2;

  const bodyContent = () => {
    if (isLoading) return <SkeletonRows colCount={COL_COUNT} rowCount={OTHER_THREAT_PAGE_SIZE} />;
    if (hasError)  return <ErrorRow colSpan={COL_COUNT} onRetry={onRetry} />;
    if (notifications.length === 0) return <EmptyRow colSpan={COL_COUNT} message="기타 위협 유형 알림이 없습니다." />;

    return notifications.map((n, i) => (
      <tr
        key={n.notification_id}
        style={{ borderBottom: i < notifications.length - 1 ? '1px solid var(--ctink-border)' : 'none' }}
      >
        <td style={{ padding: '12px 20px', color: 'var(--ctink-text-light)', fontSize: '13px', whiteSpace: 'nowrap' }}>
          {formatDate(n.created_at)}
        </td>
        <td style={{ padding: '12px 20px', color: 'var(--ctink-text)', fontSize: '13px', fontWeight: 700 }}>
          {n.suspected_type ?? '-'}
        </td>
      </tr>
    ));
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
        <colgroup>
          <col style={{ width: '160px' }} />
          <col />
        </colgroup>
        <thead>
          <tr>
            {['시간', '추정 위협 유형'].map(h => (
              <th key={h} style={TH_STYLE}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>{bodyContent()}</tbody>
      </table>
    </div>
  );
}

// ─── OtherThreatSection (관리자 전용) ─────────────────────────────────────────
// GET /ctink/notifications/other-threat?page=N

function OtherThreatSection() {
  const [currentPage,    setCurrentPage]    = useState(1);
  const [notifications,  setNotifications]  = useState([]);
  const [totalCount,     setTotalCount]     = useState(0);
  const [totalPages,     setTotalPages]     = useState(1);
  const [isLoading,      setIsLoading]      = useState(true);
  const [hasError,       setHasError]       = useState(false);

  const fetchNotifications = useCallback(async (page) => {
    setIsLoading(true);
    setHasError(false);
    try {
      const res = await api.get('/ctink/notifications/other-threat', {
        params: { page },
      });
      const { notifications, total_count, total_pages, current_page } = res.data;
      setNotifications(notifications);
      setTotalCount(total_count);
      setTotalPages(total_pages);
      setCurrentPage(current_page);
    } catch {
      setHasError(true);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchNotifications(1);
  }, [fetchNotifications]);

  const handlePageChange = useCallback((page) => {
    setCurrentPage(page);
    fetchNotifications(page);
  }, [fetchNotifications]);

  return (
    <div style={{ marginBottom: '24px' }}>
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius:    '12px',
        boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
        overflow:        'hidden',
      }}>
        <div style={{
          display:      'flex',
          alignItems:   'center',
          gap:          '10px',
          padding:      '16px 20px',
          borderBottom: '1px solid var(--ctink-border)',
        }}>
          <span style={{ fontSize: '15px', fontWeight: 800, color: 'var(--ctink-text)' }}>
            기타 위협 유형 알림
          </span>
          <CountBadge
            label="총"
            count={isLoading ? '-' : totalCount}
            color="#3F72AF"
            bg="rgba(63,114,175,0.10)"
          />
        </div>

        <OtherThreatTable
          notifications={isLoading ? [] : notifications}
          isLoading={isLoading}
          hasError={hasError}
          onRetry={() => fetchNotifications(currentPage)}
        />
      </div>

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalCount={totalCount}
        onPageChange={handlePageChange}
      />
    </div>
  );
}

// ─── 메인 컴포넌트 ────────────────────────────────────────────────────────────

export default function RequestPage() {
  const [decisions,    setDecisions]    = useState({});
  const [processingId, setProcessingId] = useState(null);
  const [isAdmin,      setIsAdmin]      = useState(false);
  const [selectedRule, setSelectedRule] = useState(null);

  // Next.js SSR 환경에서 lazy initializer는 서버 측 렌더링 시 window가 없어 false를 반환하고
  // 이후 재실행되지 않으므로, useEffect로 클라이언트 마운트 후 sessionStorage를 읽어야 함
  useEffect(() => {
    setIsAdmin(sessionStorage.getItem('role') === 'ADMIN');
  }, []);

  const handleDecision = useCallback(async (ruleId, decision) => {
    const key = `${ruleId}_${decision}`;
    setProcessingId(key);

    try {
      await api.patch(`/ctink/admin/rules/${ruleId}/decision`, { decision });

      setDecisions(prev => ({ ...prev, [ruleId]: decision }));
      return true;
    } catch (err) {
      const status = err.response?.status;
      if      (status === 409) alert('이미 처리된 룰입니다.');
      else if (status === 403) alert('관리자 권한이 없습니다.');
      else if (status === 404) alert('해당 룰을 찾을 수 없습니다.');
      else if (status === 400) alert('잘못된 요청입니다. 다시 시도해주세요.');
      else if (status !== 401) alert('처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.');
      return false;
    } finally {
      setProcessingId(null);
    }
  }, []);

  return (
    <div style={{ padding: '32px' }}>

      <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>
        Request
      </h1>

      {/* GET /ctink/notifications/rules/pending?rule_type=SNORT&page=N */}
      <SectionCard
        title="Snort 룰 적용 승인 요청"
        ruleType="SNORT"
        decisions={decisions}
        isAdmin={isAdmin}
        onDecision={handleDecision}
        processingId={processingId}
        onRowClick={setSelectedRule}
      />

      {/* GET /ctink/notifications/rules/pending?rule_type=YARA&page=N */}
      <SectionCard
        title="YARA 룰 적용 승인 요청"
        ruleType="YARA"
        decisions={decisions}
        isAdmin={isAdmin}
        onDecision={handleDecision}
        processingId={processingId}
        onRowClick={setSelectedRule}
      />

      {/* GET /ctink/notifications/other-threat?page=N — 관리자 전용 */}
      {isAdmin && <OtherThreatSection />}

      {selectedRule && (
        <RuleDetailModal
          ruleId={selectedRule.rule_id}
          ruleName={selectedRule.rule_name}
          onClose={() => setSelectedRule(null)}
        />
      )}

    </div>
  );
}