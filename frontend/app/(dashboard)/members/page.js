'use client';

import { useState, useEffect, useCallback } from 'react';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────

const PAGE_SIZE_PENDING = 3; // 신규 가입 요청: 페이지당 3개 고정
const PAGE_SIZE_USERS   = 5; // 사용자 목록: 페이지당 5개 고정

// ─── 목업 데이터 ──────────────────────────────────────────────────────────────
// ※ API 연동 시:
//   1. MOCK_PENDING, MOCK_USERS 상수 전체 삭제
//   2. 각 fetch 함수 안의 [API 연동 시] 블록 주석 해제
//   3. 각 fetch 함수 안의 [목업] 블록 전체 삭제
// ※ phone 필드는 사용자 목록 API 응답에 Nullable로 포함됨
//   UserDetailPanel 전화번호 항목은 null인 경우 '-' 표시됨

const MOCK_PENDING = [
  { user_id: 46, name: '강유현',  organization: '개발팀',     position: '주임', email: 'yoohyun.kang@company.com', phone: '010-2345-6789', created_at: '2026-04-28T12:27:00' },
  { user_id: 47, name: '이효정',  organization: '보안팀',     position: '선임', email: 'hyojeong.lee@company.com',  phone: '010-5678-1234', created_at: '2026-04-28T10:48:00' },
  { user_id: 48, name: '서민경',  organization: 'IT인프라팀', position: '사원', email: 'mingyung.seo@company.com',  phone: '010-9876-5432', created_at: '2026-04-28T09:22:00' },
  { user_id: 49, name: '류동현',  organization: '개발팀',     position: '대리', email: 'donghyun.ryu@company.com',  phone: '010-1122-3344', created_at: '2026-04-27T17:05:00' },
  { user_id: 50, name: '임지수',  organization: '보안팀',     position: '사원', email: 'jisu.lim@company.com',       phone: '010-5566-7788', created_at: '2026-04-27T14:30:00' },
  { user_id: 51, name: '황민서',  organization: 'IT인프라팀', position: '주임', email: 'minseo.hwang@company.com',  phone: '010-9900-1122', created_at: '2026-04-27T11:10:00' },
];

const MOCK_USERS = [
  { user_id: 1,  name: '김민준', organization: '보안팀',     position: '팀장', email: 'minjun.kim@company.com',    role: 'ADMIN', status: 'ACTIVE',   last_login_at: '2026-03-23T14:22:00', phone: '010-1234-5678' },
  { user_id: 2,  name: '이서연', organization: 'IT인프라팀', position: '선임', email: 'seoyeong.lee@company.com',  role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-23T13:47:00', phone: '010-2345-6789' },
  { user_id: 3,  name: '박지훈', organization: '보안팀',     position: '주임', email: 'jihun.park@company.com',    role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-23T11:30:00', phone: '010-3456-7890' },
  { user_id: 4,  name: '최수아', organization: '개발팀',     position: '과장', email: 'sua.choi@company.com',      role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-22T17:55:00', phone: '010-4567-8901' },
  { user_id: 5,  name: '정태양', organization: 'IT인프라팀', position: '사원', email: 'taeyang.jung@company.com',  role: 'USER',  status: 'INACTIVE', last_login_at: '2026-03-20T09:10:00', phone: '010-5678-9012' },
  { user_id: 6,  name: '한수진', organization: '보안팀',     position: '사원', email: 'sujin.han@company.com',     role: 'USER',  status: 'LOCKED',   last_login_at: '2026-03-19T16:40:00', phone: '010-6789-0123' },
  { user_id: 7,  name: '오준혁', organization: '개발팀',     position: '대리', email: 'junhyuk.oh@company.com',    role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-19T14:20:00', phone: '010-7890-1234' },
  { user_id: 8,  name: '윤채원', organization: '보안팀',     position: '사원', email: 'chaewon.yoon@company.com',  role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-18T10:05:00', phone: '010-8901-2345' },
  { user_id: 9,  name: '송다은', organization: 'IT인프라팀', position: '선임', email: 'daeun.song@company.com',    role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-17T09:30:00', phone: '010-9012-3456' },
  { user_id: 10, name: '권혁준', organization: '개발팀',     position: '주임', email: 'hyukjun.kwon@company.com',  role: 'USER',  status: 'INACTIVE', last_login_at: '2026-03-15T16:00:00', phone: '010-0123-4567' },
  { user_id: 11, name: '노지현', organization: '보안팀',     position: '사원', email: 'jihyun.noh@company.com',    role: 'USER',  status: 'ACTIVE',   last_login_at: '2026-03-14T11:20:00', phone: '010-1234-0000' },
];

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

// ISO 날짜 문자열 → 'YYYY-MM-DD HH:mm' 포맷
function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  const ymd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const hm  = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  return `${ymd} ${hm}`;
}

// user_id → 'USR_XXX' 포맷 (화면 표시용)
function formatUserId(id) {
  return `USR_${String(id).padStart(3, '0')}`;
}

// ─── 공통 스타일 상수 ─────────────────────────────────────────────────────────

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

const TD_STYLE = {
  padding:      '12px 20px',
  fontSize:     '13px',
  fontWeight:   600,
  color:        'var(--ctink-text)',
  borderBottom: '1px solid var(--ctink-border)',
  whiteSpace:   'nowrap',
};

// ─── 서브 컴포넌트 ────────────────────────────────────────────────────────────

// 헤더 영역의 카운트 뱃지 (대기/승인/거부 수 표시)
function Badge({ label, count, color, bg }) {
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

// 역할 표시 뱃지 (admin: 파란색, user: 회색)
function RoleBadge({ role }) {
  const isAdmin = role === 'ADMIN';
  return (
    <span style={{
      display:         'inline-block',
      padding:         '2px 8px',
      borderRadius:    '4px',
      fontSize:        '12px',
      fontWeight:      700,
      color:           isAdmin ? '#3F72AF' : 'var(--ctink-text-muted)',
      backgroundColor: isAdmin ? 'rgba(63,114,175,0.10)' : 'rgba(17,45,78,0.06)',
    }}>
      {isAdmin ? '관리자' : '일반'}
    </span>
  );
}

// 계정 상태 표시 (활성/비활성/잠김)
function StatusDot({ status }) {
  const map = {
    ACTIVE:   { label: '활성',   color: '#0F6E56' },
    INACTIVE: { label: '비활성', color: '#A32D2D' },
    LOCKED:   { label: '잠김',   color: '#BA7517' },
  };
  const { label, color } = map[status] || { label: status, color: 'var(--ctink-text-muted)' };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
      <span style={{
        display:         'inline-block',
        width:           '8px',
        height:          '8px',
        borderRadius:    '50%',
        backgroundColor: color,
        flexShrink:      0,
      }} />
      <span style={{ color, fontSize: '13px', fontWeight: 600 }}>{label}</span>
    </span>
  );
}

// 공통 액션 버튼 (테이블 내 버튼 및 상세 패널 버튼에 사용)
function ActionButton({ label, color, bg, onClick, disabled, loading }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{
        padding:         '4px 12px',
        borderRadius:    '6px',
        border:          `1px solid ${color}`,
        backgroundColor: bg || 'transparent',
        fontSize:        '12px',
        fontWeight:      700,
        color:           disabled ? 'var(--ctink-text-light)' : color,
        cursor:          disabled ? 'default' : 'pointer',
        opacity:         disabled ? 0.5 : 1,
        fontFamily:      'inherit',
        whiteSpace:      'nowrap',
        transition:      'opacity 0.15s',
      }}
    >
      {loading ? '...' : label}
    </button>
  );
}

// 데이터 로딩 중 표시할 스켈레톤 행 (cols: 열 수)
function SkeletonRow({ cols }) {
  return Array.from({ length: 3 }).map((_, i) => (
    <tr key={i} style={{ borderBottom: '1px solid var(--ctink-border)' }}>
      {Array.from({ length: cols }).map((_, j) => (
        <td key={j} style={{ padding: '12px 20px' }}>
          <div style={{
            height:         '14px',
            borderRadius:   '6px',
            background:     'linear-gradient(90deg, var(--ctink-card) 25%, var(--ctink-bg) 50%, var(--ctink-card) 75%)',
            backgroundSize: '200% 100%',
            animation:      'shimmer 1.4s infinite',
          }} />
        </td>
      ))}
    </tr>
  ));
}

// 페이지네이션 이전/다음 버튼
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

// 페이지네이션 컴포넌트 (이전/다음 버튼 + 직접 입력)
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

// ─── 사용자 상세 정보 패널 ────────────────────────────────────────────────────
// 사용자 행의 '상세' 버튼 클릭 시 테이블 하단에 펼쳐지는 패널
// onRoleToggle: 역할 변경 핸들러 (UsersSection에서 주입)
// processingRoleId: 역할 변경 중인 user_id (버튼 로딩 상태에 사용)

function UserDetailPanel({ user, onRoleToggle, processingRoleId }) {
  const isRoleProcessing = processingRoleId === user.user_id;

  const items = [
    { label: 'ID',         value: formatUserId(user.user_id) },
    { label: '이름',        value: user.name },
    { label: '소속',        value: user.organization },
    { label: '직책',        value: user.position },
    { label: '메일',        value: user.email },
    { label: '전화번호',    value: user.phone || '-' },
    { label: '상태',        value: <StatusDot status={user.status} /> },
    { label: '역할',        value: <RoleBadge role={user.role} /> },
    { label: '마지막 접속', value: formatDate(user.last_login_at) },
  ];

  const half = Math.ceil(items.length / 2);
  const left  = items.slice(0, half);
  const right = items.slice(half);

  return (
    <div style={{
      borderTop:       '1px solid var(--ctink-border)',
      padding:         '20px 24px',
      backgroundColor: 'var(--ctink-bg)',
    }}>
      {/* 헤더 + 역할 변경 버튼 */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <span style={{ fontSize: '14px', fontWeight: 800, color: 'var(--ctink-text)' }}>
          사용자 상세 정보
        </span>
        {/* 역할 변경: ADMIN ↔ USER 토글. 본인 계정 변경 시도는 서버에서 403 반환 */}
        <ActionButton
          label={user.role === 'ADMIN' ? '일반으로 변경' : '관리자로 변경'}
          color="var(--ctink-accent)"
          bg="rgba(63,114,175,0.08)"
          loading={isRoleProcessing}
          disabled={isRoleProcessing}
          onClick={() => onRoleToggle(user)}
        />
      </div>

      <div style={{ display: 'flex', gap: '40px', flexWrap: 'wrap' }}>
        {/* 왼쪽 정보 */}
        <div style={{ flex: 1, minWidth: '240px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {left.map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ctink-text-muted)', width: '80px', flexShrink: 0, paddingTop: '1px' }}>
                {label}
              </span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ctink-text)', wordBreak: 'break-all' }}>
                {value}
              </span>
            </div>
          ))}
        </div>
        {/* 오른쪽 정보 */}
        <div style={{ flex: 1, minWidth: '240px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {right.map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start' }}>
              <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--ctink-text-muted)', width: '80px', flexShrink: 0, paddingTop: '1px' }}>
                {label}
              </span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ctink-text)', wordBreak: 'break-all' }}>
                {value}
              </span>
            </div>
          ))}
        </div>
        {/* 프로필 이미지 자리 */}
        <div style={{
          width:           '80px',
          height:          '80px',
          borderRadius:    '50%',
          backgroundColor: 'var(--ctink-card)',
          display:         'flex',
          alignItems:      'center',
          justifyContent:  'center',
          flexShrink:      0,
          alignSelf:       'flex-start',
        }}>
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="8" r="4" fill="var(--ctink-text-muted)" />
            <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="var(--ctink-text-muted)" strokeWidth="1.5" strokeLinecap="round" fill="none" />
          </svg>
        </div>
      </div>
    </div>
  );
}

// ─── 신규 가입자 승인 요청 섹션 ───────────────────────────────────────────────

function PendingSection() {
  const [pending,      setPending]      = useState([]);
  const [decisions,    setDecisions]    = useState({}); // { [user_id]: 'approved' | 'rejected' }
  const [processingId, setProcessingId] = useState(null);
  const [currentPage,  setCurrentPage]  = useState(1);
  const [totalPages,   setTotalPages]   = useState(1);
  const [totalCount,   setTotalCount]   = useState(0);
  const [isLoading,    setIsLoading]    = useState(true);
  const [fetchError,   setFetchError]   = useState(false);

  const fetchPending = useCallback(async (page) => {
    setIsLoading(true);
    setFetchError(false);
    try {
      // ─ [API 연동 시] 아래 주석 해제 후 [목업] 블록 전체 삭제 ─────────────
      // const res = await api.get('/ctink/admin/users/pending', { params: { page } });
      // const { users, total_count, total_pages, current_page } = res.data;
      // setPending(users);
      // setTotalCount(total_count);
      // setTotalPages(total_pages);
      // setCurrentPage(current_page);
      // ────────────────────────────────────────────────────────────────────

      // ─ [목업] API 연동 시 아래 블록 전체 삭제 ────────────────────────────
      await new Promise(r => setTimeout(r, 300));
      const total = MOCK_PENDING.length;
      const pages = Math.max(1, Math.ceil(total / PAGE_SIZE_PENDING));
      const cur   = Math.min(page, pages);
      setPending(MOCK_PENDING.slice((cur - 1) * PAGE_SIZE_PENDING, cur * PAGE_SIZE_PENDING));
      setTotalCount(total);
      setTotalPages(pages);
      setCurrentPage(cur);
      // ─────────────────────────────────────────────────────────────────────

      setDecisions({}); // 페이지 이동 시 이전 결정 상태 초기화
    } catch (err) {
      console.error('가입 요청 목록 조회 실패:', err);
      setFetchError(true);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { fetchPending(1); }, [fetchPending]);

  const handleDecision = async (targetUserId, decision) => {
    setProcessingId(`${targetUserId}_${decision}`);
    try {
      // ─ [API 연동 시] 아래 3줄 주석 해제 후 [목업] 블록 전체 삭제 ──────────
      // await api.patch(`/ctink/admin/users/${targetUserId}/decision`, { decision: decision.toUpperCase() });
      // await fetchPending(currentPage); // 승인/거부 후 목록 재조회 (서버에서 해당 레코드 삭제됨)
      // return;
      // ────────────────────────────────────────────────────────────────────

      // ─ [목업] API 연동 시 아래 블록 전체 삭제 ────────────────────────────
      await new Promise(r => setTimeout(r, 300));
      setDecisions(prev => ({ ...prev, [targetUserId]: decision }));
      // ─────────────────────────────────────────────────────────────────────

    } catch (err) {
      const s = err.response?.status;
      if      (s === 400) alert('잘못된 요청입니다.');
      else if (s === 403) alert('관리자 권한이 없습니다.');
      else if (s === 404) alert('해당 사용자를 찾을 수 없습니다.');
      else if (s === 409) alert('이미 처리된 요청입니다.');
      else                console.error('가입 요청 처리 실패:', err);
    } finally {
      setProcessingId(null);
    }
  };

  const decidedCount  = Object.keys(decisions).length;
  const approvedCount = Object.values(decisions).filter(d => d === 'approved').length;
  const rejectedCount = Object.values(decisions).filter(d => d === 'rejected').length;
  const pendingCount  = Math.max(0, totalCount - decidedCount);

  return (
    <div style={{ marginBottom: '24px' }}>
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius:    '12px',
        boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
        overflow:        'hidden',
      }}>
        {/* 섹션 헤더 */}
        <div style={{
          display:      'flex',
          alignItems:   'center',
          gap:          '10px',
          padding:      '16px 20px',
          borderBottom: '1px solid var(--ctink-border)',
        }}>
          <span style={{ fontSize: '15px', fontWeight: 800, color: 'var(--ctink-text)' }}>신규 가입자 승인 요청</span>
          <Badge label="대기" count={isLoading ? '-' : pendingCount} color="#BA7517" bg="rgba(186,117,23,0.10)" />
          {approvedCount > 0 && <Badge label="승인" count={approvedCount} color="#0F6E56" bg="rgba(15,110,86,0.10)" />}
          {rejectedCount > 0 && <Badge label="거부" count={rejectedCount} color="#A32D2D" bg="rgba(163,45,45,0.10)" />}
        </div>

        {/* 테이블 */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '130px' }} />
              <col style={{ width: '90px'  }} />
              <col style={{ width: '80px'  }} />
              <col style={{ width: '110px' }} />
              <col style={{ width: '70px'  }} />
              <col style={{ width: '180px' }} />
              <col style={{ width: '130px' }} />
              <col style={{ width: '130px' }} />
            </colgroup>
            <thead>
              <tr>
                {['신청 시간', 'ID', '이름', '소속', '직책', '메일', '전화번호', '처리'].map(h => (
                  <th key={h} style={TH_STYLE}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <SkeletonRow cols={8} />
              ) : fetchError ? (
                <tr>
                  <td colSpan={8} style={{ ...TD_STYLE, textAlign: 'center', color: '#A32D2D', padding: '32px 20px', borderBottom: 'none' }}>
                    데이터를 불러오는 데 실패했습니다.
                  </td>
                </tr>
              ) : pending.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ ...TD_STYLE, textAlign: 'center', color: 'var(--ctink-text-muted)', padding: '32px 20px', borderBottom: 'none' }}>
                    대기 중인 가입 요청이 없습니다.
                  </td>
                </tr>
              ) : (
                pending.map(user => {
                  const decided    = decisions[user.user_id];
                  const processing = processingId?.startsWith(`${user.user_id}_`);
                  return (
                    <tr key={user.user_id}>
                      <td style={TD_STYLE}>{formatDate(user.created_at)}</td>
                      <td style={{ ...TD_STYLE, color: 'var(--ctink-text-muted)' }}>{formatUserId(user.user_id)}</td>
                      <td style={TD_STYLE}>{user.name}</td>
                      <td style={TD_STYLE}>{user.organization}</td>
                      <td style={TD_STYLE}>{user.position}</td>
                      <td style={{ ...TD_STYLE, overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.email}</td>
                      <td style={TD_STYLE}>{user.phone}</td>
                      <td style={TD_STYLE}>
                        {decided ? (
                          <span style={{
                            fontSize:   '13px',
                            fontWeight: 700,
                            color:      decided === 'approved' ? '#0F6E56' : '#A32D2D',
                          }}>
                            {decided === 'approved' ? '승인됨' : '거부됨'}
                          </span>
                        ) : (
                          <div style={{ display: 'flex', gap: '6px' }}>
                            <ActionButton
                              label="승인"
                              color="#0F6E56"
                              bg="rgba(15,110,86,0.08)"
                              loading={processingId === `${user.user_id}_approved`}
                              disabled={!!processing}
                              onClick={() => handleDecision(user.user_id, 'approved')}
                            />
                            <ActionButton
                              label="거부"
                              color="#A32D2D"
                              bg="rgba(163,45,45,0.08)"
                              loading={processingId === `${user.user_id}_rejected`}
                              disabled={!!processing}
                              onClick={() => handleDecision(user.user_id, 'rejected')}
                            />
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalCount={totalCount}
        onPageChange={(p) => { setCurrentPage(p); fetchPending(p); }}
      />
    </div>
  );
}

// ─── 사용자 목록 섹션 ─────────────────────────────────────────────────────────

function UsersSection() {
  const [users,            setUsers]            = useState([]);
  const [statusMap,        setStatusMap]        = useState({}); // { [user_id]: status } 낙관적 업데이트용
  const [roleMap,          setRoleMap]          = useState({}); // { [user_id]: role }   낙관적 업데이트용
  const [processingId,     setProcessingId]     = useState(null); // 상태 변경 중인 'status_{user_id}'
  const [processingRoleId, setProcessingRoleId] = useState(null); // 역할 변경 중인 user_id
  const [currentPage,      setCurrentPage]      = useState(1);
  const [totalPages,       setTotalPages]       = useState(1);
  const [totalCount,       setTotalCount]       = useState(0);
  const [isLoading,        setIsLoading]        = useState(true);
  const [fetchError,       setFetchError]       = useState(false);
  const [selectedUser,     setSelectedUser]     = useState(null); // 상세 패널 표시 대상

  const fetchUsers = useCallback(async (page) => {
    setIsLoading(true);
    setFetchError(false);
    try {
      // ─ [API 연동 시] 아래 주석 해제 후 [목업] 블록 전체 삭제 ─────────────
      // const res = await api.get('/ctink/admin/users', { params: { page } });
      // const { users, total_count, total_pages, current_page } = res.data;
      // setUsers(users);
      // setTotalCount(total_count);
      // setTotalPages(total_pages);
      // setCurrentPage(current_page);
      // ────────────────────────────────────────────────────────────────────

      // ─ [목업] API 연동 시 아래 블록 전체 삭제 ────────────────────────────
      await new Promise(r => setTimeout(r, 300));
      const total = MOCK_USERS.length;
      const pages = Math.max(1, Math.ceil(total / PAGE_SIZE_USERS));
      const cur   = Math.min(page, pages);
      setUsers(MOCK_USERS.slice((cur - 1) * PAGE_SIZE_USERS, cur * PAGE_SIZE_USERS));
      setTotalCount(total);
      setTotalPages(pages);
      setCurrentPage(cur);
      // ─────────────────────────────────────────────────────────────────────

      setStatusMap({});
      setRoleMap({});
      setSelectedUser(null);
    } catch (err) {
      console.error('사용자 목록 조회 실패:', err);
      setFetchError(true);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(1); }, [fetchUsers]);

  // 계정 상태 변경: active ↔ inactive 토글, locked → active (잠금 해제)
  const handleToggleStatus = async (user) => {
    const curStatus  = statusMap[user.user_id] ?? user.status;
    const nextStatus = curStatus === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';

    setProcessingId(`status_${user.user_id}`);
    try {
      // ─ [API 연동 시] 아래 주석 해제 후 [목업] 블록 전체 삭제 ─────────────
      // await api.patch(`/ctink/admin/users/${user.user_id}`, { status: nextStatus });
      // ────────────────────────────────────────────────────────────────────

      // ─ [목업] API 연동 시 아래 블록 전체 삭제 ────────────────────────────
      await new Promise(r => setTimeout(r, 300));
      // ─────────────────────────────────────────────────────────────────────

      setStatusMap(prev => ({ ...prev, [user.user_id]: nextStatus }));
      if (selectedUser?.user_id === user.user_id) {
        setSelectedUser(prev => ({ ...prev, status: nextStatus }));
      }
    } catch (err) {
      const s = err.response?.status;
      if      (s === 400) alert('잘못된 요청입니다.');
      else if (s === 403) alert('권한이 없습니다.');
      else if (s === 404) alert('해당 사용자를 찾을 수 없습니다.');
      else                console.error('사용자 상태 변경 실패:', err);
    } finally {
      setProcessingId(null);
    }
  };

  // 역할 변경: admin ↔ user 토글
  // 본인 계정 역할 변경 시도는 서버에서 403 반환
  const handleToggleRole = async (user) => {
    const curRole  = roleMap[user.user_id] ?? user.role;
    const nextRole = curRole === 'ADMIN' ? 'USER' : 'ADMIN';

    setProcessingRoleId(user.user_id);
    try {
      // ─ [API 연동 시] 아래 주석 해제 후 [목업] 블록 전체 삭제 ─────────────
      // await api.patch(`/ctink/admin/users/${user.user_id}`, { role: nextRole });
      // ────────────────────────────────────────────────────────────────────

      // ─ [목업] API 연동 시 아래 블록 전체 삭제 ────────────────────────────
      await new Promise(r => setTimeout(r, 300));
      // ─────────────────────────────────────────────────────────────────────

      setRoleMap(prev => ({ ...prev, [user.user_id]: nextRole }));
      if (selectedUser?.user_id === user.user_id) {
        setSelectedUser(prev => ({ ...prev, role: nextRole }));
      }
    } catch (err) {
      const s = err.response?.status;
      if      (s === 400) alert('잘못된 요청입니다.');
      else if (s === 403) alert('본인의 역할은 변경할 수 없습니다.');
      else if (s === 404) alert('해당 사용자를 찾을 수 없습니다.');
      else                console.error('사용자 역할 변경 실패:', err);
    } finally {
      setProcessingRoleId(null);
    }
  };

  // 상세 패널 열기/닫기 — statusMap, roleMap의 최신 값을 병합하여 전달
  const handleDetailClick = (user) => {
    const curStatus = statusMap[user.user_id] ?? user.status;
    const curRole   = roleMap[user.user_id]   ?? user.role;
    const merged    = { ...user, status: curStatus, role: curRole };
    setSelectedUser(prev => prev?.user_id === user.user_id ? null : merged);
  };

  return (
    <div style={{ marginBottom: '24px' }}>
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius:    '12px',
        boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
        overflow:        'hidden',
      }}>
        {/* 섹션 헤더 */}
        <div style={{
          display:        'flex',
          alignItems:     'center',
          justifyContent: 'space-between',
          padding:        '16px 20px',
          borderBottom:   '1px solid var(--ctink-border)',
        }}>
          <span style={{ fontSize: '15px', fontWeight: 800, color: 'var(--ctink-text)' }}>사용자 목록</span>
          {!isLoading && !fetchError && (
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--ctink-text-muted)' }}>
              전체 {totalCount}명
            </span>
          )}
        </div>

        {/* 테이블 */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: '90px'  }} />
              <col style={{ width: '80px'  }} />
              <col style={{ width: '110px' }} />
              <col style={{ width: '70px'  }} />
              <col style={{ width: '170px' }} />
              <col style={{ width: '80px'  }} />
              <col style={{ width: '80px'  }} />
              <col style={{ width: '150px' }} />
              <col style={{ width: '140px' }} />
            </colgroup>
            <thead>
              <tr>
                {['ID', '이름', '소속', '직책', '메일', '상태', '역할', '마지막 접속', '관리'].map(h => (
                  <th key={h} style={TH_STYLE}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <SkeletonRow cols={9} />
              ) : fetchError ? (
                <tr>
                  <td colSpan={9} style={{ ...TD_STYLE, textAlign: 'center', color: '#A32D2D', padding: '32px 20px', borderBottom: 'none' }}>
                    데이터를 불러오는 데 실패했습니다.
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ ...TD_STYLE, textAlign: 'center', color: 'var(--ctink-text-muted)', padding: '32px 20px', borderBottom: 'none' }}>
                    등록된 사용자가 없습니다.
                  </td>
                </tr>
              ) : (
                users.map(user => {
                  const curStatus    = statusMap[user.user_id] ?? user.status;
                  const curRole      = roleMap[user.user_id]   ?? user.role;
                  const isSelected   = selectedUser?.user_id === user.user_id;
                  const isProcessing = processingId === `status_${user.user_id}`;

                  // 상태에 따른 버튼 레이블 및 색상
                  // LOCKED → ACTIVE (잠금 해제), ACTIVE → INACTIVE (비활성화), INACTIVE → ACTIVE (활성화)
                  const toggleLabel = curStatus === 'ACTIVE' ? '비활성화' : curStatus === 'LOCKED' ? '잠금 해제' : '활성화';
                  const toggleColor = curStatus === 'ACTIVE' ? '#A32D2D' : curStatus === 'LOCKED' ? '#BA7517' : '#0F6E56';
                  const toggleBg    = curStatus === 'ACTIVE' ? 'rgba(163,45,45,0.08)' : curStatus === 'LOCKED' ? 'rgba(186,117,23,0.08)' : 'rgba(15,110,86,0.08)';

                  const bdrBottom = isSelected ? 'none' : '1px solid var(--ctink-border)';

                  return (
                    <tr
                      key={user.user_id}
                      style={{
                        backgroundColor: isSelected ? 'rgba(63,114,175,0.04)' : 'transparent',
                        transition:      'background-color 0.15s',
                      }}
                    >
                      <td style={{ ...TD_STYLE, color: 'var(--ctink-text-muted)', borderBottom: bdrBottom }}>
                        {formatUserId(user.user_id)}
                      </td>
                      <td style={{ ...TD_STYLE, borderBottom: bdrBottom }}>{user.name}</td>
                      <td style={{ ...TD_STYLE, borderBottom: bdrBottom }}>{user.organization}</td>
                      <td style={{ ...TD_STYLE, borderBottom: bdrBottom }}>{user.position}</td>
                      <td style={{ ...TD_STYLE, overflow: 'hidden', textOverflow: 'ellipsis', borderBottom: bdrBottom }}>
                        {user.email}
                      </td>
                      <td style={{ ...TD_STYLE, borderBottom: bdrBottom }}>
                        <StatusDot status={curStatus} />
                      </td>
                      <td style={{ ...TD_STYLE, borderBottom: bdrBottom }}>
                        <RoleBadge role={curRole} />
                      </td>
                      <td style={{ ...TD_STYLE, color: 'var(--ctink-text-muted)', borderBottom: bdrBottom }}>
                        {formatDate(user.last_login_at)}
                      </td>
                      <td style={{ ...TD_STYLE, borderBottom: bdrBottom }}>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <ActionButton
                            label="상세"
                            color={isSelected ? 'var(--ctink-accent)' : '#0F6E56'}
                            bg={isSelected ? 'rgba(63,114,175,0.12)' : 'rgba(15,110,86,0.08)'}
                            onClick={() => handleDetailClick(user)}
                          />
                          <ActionButton
                            label={toggleLabel}
                            color={toggleColor}
                            bg={toggleBg}
                            loading={isProcessing}
                            disabled={isProcessing}
                            onClick={() => handleToggleStatus(user)}
                          />
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* 상세 정보 패널 — 선택된 행 아래에 펼쳐짐 */}
        {selectedUser && !isLoading && (
          <UserDetailPanel
            user={selectedUser}
            onRoleToggle={handleToggleRole}
            processingRoleId={processingRoleId}
          />
        )}
      </div>

      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        totalCount={totalCount}
        onPageChange={(p) => { setCurrentPage(p); fetchUsers(p); }}
      />
    </div>
  );
}

// ─── 메인 컴포넌트 ────────────────────────────────────────────────────────────

export default function MembersPage() {
  return (
    <div style={{ padding: '32px' }}>
      <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>
        Admin
      </h1>

      {/* 신규 가입자 승인 요청 */}
      <PendingSection />

      {/* 사용자 목록 */}
      <UsersSection />
    </div>
  );
}