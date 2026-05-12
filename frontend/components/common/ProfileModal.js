'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { User } from 'lucide-react';
import api from '@/lib/api';

// ─── 상수 ────────────────────────────────────────────────────────────────────

// status 값은 active만 실제 노출됨
// (pending / inactive / locked 계정은 로그인 불가 → 이 모달 진입 불가)
const STATUS_STYLE = {
  active:   { label: '활성',   color: '#0F6E56', backgroundColor: 'rgba(15,110,86,0.10)'  },
  inactive: { label: '비활성', color: 'var(--ctink-text-muted)', backgroundColor: 'rgba(0,0,0,0.06)' },
  locked:   { label: '잠금',   color: '#A32D2D', backgroundColor: 'rgba(163,45,45,0.10)' },
};

// ─── [TODO] 백엔드 연동 시 아래 목업 데이터 블록 전체 제거 ──────────────────
const MOCK_PROFILE = {
  login_id:      'hong01',
  name:          '홍길동',
  organization:  '하이픈 보안',
  position:      '보안 담당자',
  email:         'hong@ctink.com',
  phone:         '010-1234-5678',
  status:        'active',
  last_login_at: '2025-04-01T09:00:00',
};
// ─── [TODO] 백엔드 연동 시 위 목업 데이터 블록 전체 제거 ────────────────────

// ─── 유틸 ─────────────────────────────────────────────────────────────────────

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  const ymd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const hm  = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  return `${ymd} ${hm}`;
}

// ─── 서브 컴포넌트 ────────────────────────────────────────────────────────────

function InfoItem({ label, value }) {
  return (
    <div>
      <p style={{ fontSize: '11px', color: 'var(--ctink-text-muted)', fontWeight: 600, marginBottom: '3px' }}>
        {label}
      </p>
      <p style={{ fontSize: '13px', color: 'var(--ctink-text)', fontWeight: 700, wordBreak: 'break-all' }}>
        {value || '-'}
      </p>
    </div>
  );
}

// ─── 모달 ─────────────────────────────────────────────────────────────────────

export default function ProfileModal({ onClose }) {
  const router = useRouter();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null); // 에러 메시지 (null이면 에러 없음)

  useEffect(() => {
    // ── [TODO] 백엔드 연동 시 아래 목업 블록 제거 후 실제 API 블록 주석 해제 ──
    setTimeout(() => {
      setProfile(MOCK_PROFILE);
      setLoading(false);
    }, 300);
    // ── [TODO] 백엔드 연동 시 위 목업 블록 제거 후 아래 실제 API 블록 주석 해제 ─

    // ── 실제 API 호출 (백엔드 연동 시 주석 해제) ─────────────────────────────
    // api.get('/ctink/profile')
    //   .then((r) => setProfile(r.data))
    //   .catch((err) => {
    //     if (err.response?.status === 401) {
    //       // 세션 만료 또는 미인증 → 로그인 페이지로 리다이렉트
    //       router.replace('/login')
    //     } else {
    //       setError('프로필 정보를 불러오는 데 실패했습니다.');
    //     }
    //   })
    //   .finally(() => setLoading(false));
    // ── 실제 API 호출 끝 ──────────────────────────────────────────────────────
  }, [router]);

  // ESC 키 닫기
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const statusStyle = STATUS_STYLE[profile?.status] ?? STATUS_STYLE.inactive;

  // ── 콘텐츠 영역 렌더링 분기 ───────────────────────────────────────────────
  const renderContent = () => {
    if (loading) {
      return (
        <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--ctink-text-light)' }}>
          불러오는 중...
        </div>
      );
    }
    if (error) {
      // 401 외 네트워크 오류 등 예외 상황
      return (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#A32D2D' }}>
          {error}
        </div>
      );
    }
    if (!profile) {
      // 에러 없이 데이터가 null로 반환된 경우
      return (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#A32D2D' }}>
          데이터를 불러오지 못했습니다.
        </div>
      );
    }
    return (
      <>
        {/* 사진 + 기본 정보 */}
        <div style={{ display: 'flex', gap: '24px', marginBottom: '20px' }}>
          {/* 프로필 사진 영역 */}
          <div style={{
            width:           '100px',
            height:          '100px',
            flexShrink:      0,
            backgroundColor: 'var(--ctink-card)',
            borderRadius:    '10px',
            display:         'flex',
            flexDirection:   'column',
            alignItems:      'center',
            justifyContent:  'center',
            gap:             '4px',
            boxShadow:       '0 1px 4px rgba(17,45,78,0.08)',
          }}>
            <User size={32} color="var(--ctink-text-light)" />
            <span style={{ fontSize: '11px', color: 'var(--ctink-text-light)' }}>사진</span>
          </div>

          {/* ID, 이름, 소속, 직책, 메일, 전화번호 */}
          <div style={{
            flex:                1,
            display:             'grid',
            gridTemplateColumns: '1fr 1fr',
            gap:                 '14px 24px',
            alignContent:        'start',
          }}>
            <InfoItem label="ID"       value={profile.login_id}     />
            <InfoItem label="이름"     value={profile.name}         />
            <InfoItem label="소속"     value={profile.organization} />
            <InfoItem label="직책"     value={profile.position}     />
            <InfoItem label="메일"     value={profile.email}        />
            <InfoItem label="전화번호" value={profile.phone}        />
          </div>
        </div>

        {/* 구분선 */}
        <div style={{ height: '1px', backgroundColor: 'var(--ctink-border)', marginBottom: '20px' }} />

        {/* 상태 + 마지막 접속 */}
        <div style={{
          display:             'grid',
          gridTemplateColumns: '1fr 1fr',
          gap:                 '14px 24px',
          marginBottom:        '20px',
        }}>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--ctink-text-muted)', fontWeight: 600, marginBottom: '6px' }}>상태</p>
            <span style={{
              display:         'inline-block',
              padding:         '3px 12px',
              borderRadius:    '999px',
              fontSize:        '13px',
              fontWeight:      700,
              color:           statusStyle.color,
              backgroundColor: statusStyle.backgroundColor,
            }}>
              {statusStyle.label}
            </span>
          </div>
          <div>
            <p style={{ fontSize: '11px', color: 'var(--ctink-text-muted)', fontWeight: 600, marginBottom: '6px' }}>마지막 접속</p>
            <p style={{ fontSize: '13px', color: 'var(--ctink-text)', fontWeight: 700 }}>
              {formatDate(profile.last_login_at)}
            </p>
          </div>
        </div>

        {/* 닫기 버튼 */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '4px' }}>
          <button
            onClick={onClose}
            style={{
              padding:         '9px 28px',
              borderRadius:    '8px',
              border:          'none',
              backgroundColor: 'var(--ctink-accent)',
              color:           '#fff',
              fontSize:        '14px',
              fontWeight:      700,
              cursor:          'pointer',
            }}
          >
            닫기
          </button>
        </div>
      </>
    );
  };

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
          maxWidth:        '560px',
          padding:         '28px 32px',
          boxShadow:       '0 24px 64px rgba(17, 45, 78, 0.22)',
          position:        'relative',
        }}
      >
        {/* 헤더 */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--ctink-text)', margin: 0 }}>
            Profile
          </h2>
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

        {renderContent()}
      </div>
    </div>
  );
}