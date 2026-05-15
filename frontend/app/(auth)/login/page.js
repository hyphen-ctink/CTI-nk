'use client';

import { useState, useEffect } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
import api from '@/lib/api';

/* ── 컴포넌트 외부 상수 ───────────────────────────────────────────────
 * 렌더마다 재생성되지 않도록 컴포넌트 함수 밖에 선언
 * ────────────────────────────────────────────────────────────────── */

// 서버 메시지 박스 색상 정의
// error   : 일반 인증 실패 (빨간 계열)
// locked  : 5회 실패 계정 잠금 (빨간 계열)
// pending : 관리자 승인 대기 (파란 계열)
// inactive: 계정 비활성화 (빨간 계열)
const MESSAGE_COLORS = {
  error:    { bg: 'rgba(163, 45, 45, 0.08)',  border: 'rgba(163, 45, 45, 0.25)',  text: '#A32D2D' },
  locked:   { bg: 'rgba(163, 45, 45, 0.08)',  border: 'rgba(163, 45, 45, 0.25)',  text: '#A32D2D' },
  pending:  { bg: 'rgba(63, 114, 175, 0.08)', border: 'rgba(63, 114, 175, 0.25)', text: 'var(--ctink-accent)' },
  inactive: { bg: 'rgba(163, 45, 45, 0.08)',  border: 'rgba(163, 45, 45, 0.25)',  text: '#A32D2D' },
};

// 비밀번호 표시 토글 아이콘
const EyeOpen = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const EyeOff = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

// 인라인 스타일 상수
const inputStyle = {
  width: '100%',
  padding: '10px 14px',
  fontSize: '13px',
  color: 'var(--ctink-text)',
  backgroundColor: 'var(--ctink-bg)',
  border: '1px solid var(--ctink-border)',
  borderRadius: '8px',
  outline: 'none',
};

const labelStyle = {
  display: 'block',
  fontSize: '12px',
  fontWeight: 700,
  color: 'var(--ctink-text-muted)',
  marginBottom: '6px',
};

const eyeButtonStyle = {
  position: 'absolute',
  right: '12px',
  top: '50%',
  transform: 'translateY(-50%)',
  background: 'none',
  border: 'none',
  cursor: 'pointer',
  color: 'var(--ctink-text-muted)',
  padding: 0,
  display: 'flex',
  alignItems: 'center',
};

/* ── 컴포넌트 ─────────────────────────────────────────────────────── */
export default function LoginPage() {
  const router = useRouter();

  const [isLoading, setIsLoading] = useState(false);
  const [serverMessage, setServerMessage] = useState('');
  // messageType: 'error' | 'warning' | 'locked' | 'pending' | 'inactive'
  const [messageType, setMessageType] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({ mode: 'onBlur' });

  // 이미 로그인된 사용자 리다이렉트
  // sessionStorage에 role이 존재하면 로그인 상태로 판단하여 overview로 이동
  // 주의: useEffect는 클라이언트 마운트 후 실행되므로 로그인 페이지가 잠깐 노출될 수 있음 (sessionStorage 특성상 불가피)
  useEffect(() => {
    const role = sessionStorage.getItem('role');
    if (role) {
      router.replace('/overview');
    }
  }, [router]);

  const onSubmit = async (data) => {
    setIsLoading(true);
    setServerMessage('');
    setMessageType('');

    const payload = {
      login_id: data.login_id,
      password: data.password,
    };

    try {
      const res = await api.post('/ctink/auth/login', payload);
    
      // 200: 로그인 성공
      // API 명세상 role, name은 Nullable이므로 null 방어 처리 후 저장
      // null이 그대로 저장되면 'null' 문자열로 저장되어 로그인 상태 오판 발생
      if (!res.data.role) {
        // role이 null인 경우 비정상 응답으로 판단하여 에러 처리
        // 백엔드에서 role이 null로 내려오는 경우가 없어야 정상 → 발생 시 팀 확인 필요
        setMessageType('error');
        setServerMessage(res.data.message || '로그인 처리 중 오류가 발생했습니다. 관리자에게 문의해주세요.');
        return;
      }
      sessionStorage.setItem('role', res.data.role);
      if (res.data.name) sessionStorage.setItem('name', res.data.name);
      router.replace('/overview');
    } catch (error) {
      const body = error.response?.data;
      setMessageType('error');
      setServerMessage(body?.message || '오류가 발생했습니다. 다시 시도해주세요.');
    } finally {
      setIsLoading(false);
    }
  };

  const onInvalid = () => {
    setMessageType('error');
    setServerMessage('아이디 또는 비밀번호가 일치하지 않습니다.');
  };

  const mc = MESSAGE_COLORS[messageType] ?? MESSAGE_COLORS.error;

  return (
    <div style={{ minHeight: '100vh', display: 'flex', backgroundColor: 'var(--ctink-bg)' }}>

      {/* ── 왼쪽 브랜딩 패널 ── */}
      <div
        className="hidden md:flex"
        style={{
          width: '360px',
          flexShrink: 0,
          backgroundColor: 'var(--ctink-card)',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '20px',
          padding: '40px',
        }}
      >
        <Image
          src="/logo.png"
          alt="CTI-nk 로고"
          width={160}
          height={180}
          style={{ objectFit: 'contain' }}
        />
        <div style={{ textAlign: 'center' }}>
          <p style={{ fontSize: '28px', fontWeight: 800, color: 'var(--ctink-text)', letterSpacing: '-0.5px' }}>
            CTI-<span style={{ color: 'var(--ctink-accent)' }}>nk</span>
          </p>
          <p style={{ fontSize: '12px', color: 'var(--ctink-text-muted)', letterSpacing: '2px', marginTop: '4px' }}>
            THINK · LINK · INK
          </p>
        </div>
      </div>

      {/* ── 오른쪽 폼 영역 ── */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '40px 24px',
        }}
      >
        <div
          style={{
            width: '100%',
            maxWidth: '480px',
            backgroundColor: 'var(--ctink-background)',
            borderRadius: '12px',
            boxShadow: '0 1px 4px rgba(17,45,78,0.08)',
            padding: '40px 44px',
          }}
        >
          {/* 헤더 */}
          <div style={{ borderBottom: '1px solid var(--ctink-border)', paddingBottom: '16px', marginBottom: '28px' }}>
            <p style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', letterSpacing: '-0.5px' }}>
              CTI-<span style={{ color: 'var(--ctink-accent)' }}>nk</span>
            </p>
            <p style={{ fontSize: '11px', color: 'var(--ctink-text-muted)', letterSpacing: '1.5px', marginTop: '2px' }}>
              THINK · LINK · INK
            </p>
          </div>

          <p style={{ fontSize: '18px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '24px' }}>
            로그인
          </p>

          <form onSubmit={handleSubmit(onSubmit, onInvalid)} noValidate>

            {/* 아이디 */}
            <div style={{ marginBottom: '16px' }}>
              <label htmlFor="login_id" style={labelStyle}>아이디</label>
              <input
                id="login_id"
                type="text"
                placeholder="아이디를 입력하세요"
                autoComplete="username"
                className="ctink-input"
                style={{ ...inputStyle, borderColor: errors.login_id ? '#A32D2D' : 'var(--ctink-border)' }}
                {...register('login_id', {
                  required: '아이디를 입력해주세요.',
                })}
              />
            </div>

            {/* 비밀번호 */}
            <div style={{ marginBottom: '8px' }}>
              <label htmlFor="password" style={labelStyle}>비밀번호</label>
              <div style={{ position: 'relative' }}>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="비밀번호를 입력하세요"
                  autoComplete="current-password"
                  className="ctink-input"
                  style={{
                    ...inputStyle,
                    paddingRight: '40px',
                    borderColor: errors.password ? '#A32D2D' : 'var(--ctink-border)',
                  }}
                  {...register('password', {
                    required: '비밀번호를 입력해주세요.',
                  })}
                />
                <button type="button" onClick={() => setShowPassword((v) => !v)} style={eyeButtonStyle} aria-label={showPassword ? '비밀번호 숨기기' : '비밀번호 표시'}>
                  {showPassword ? EyeOff : EyeOpen}
                </button>
              </div>
            </div>

            {/* 서버 메시지 박스 (경고 팝업이 표시 중일 때는 렌더링하지 않음) */}
            {serverMessage && (
              <div
                style={{
                  padding: '10px 14px',
                  backgroundColor: mc.bg,
                  border: `1px solid ${mc.border}`,
                  borderRadius: '8px',
                  fontSize: '12px',
                  color: mc.text,
                  marginTop: '12px',
                }}
              >
                {serverMessage}
              </div>
            )}

            {/* 로그인 버튼 */}
            <button
              type="submit"
              disabled={isLoading}
              style={{
                width: '100%',
                padding: '13px',
                marginTop: '20px',
                backgroundColor: isLoading ? 'var(--ctink-text-light)' : 'var(--ctink-accent)',
                color: 'var(--ctink-bg)',
                border: 'none',
                borderRadius: '8px',
                fontSize: '14px',
                fontWeight: 800,
                cursor: isLoading ? 'not-allowed' : 'pointer',
                letterSpacing: '0.5px',
              }}
            >
              {isLoading ? '처리 중...' : '로그인'}
            </button>

            {/* 회원가입 링크 */}
            <div style={{ textAlign: 'center', marginTop: '20px' }}>
              <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>계정이 없으신가요? </span>
              <Link
                href="/signup"
                style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ctink-accent)', textDecoration: 'underline' }}
              >
                회원가입
              </Link>
            </div>
            <div style={{ textAlign: 'center', marginTop: '12px' }}>
              <span style={{ fontSize: '11px', color: 'var(--ctink-text-light)' }}>v1.0.0</span>
            </div>

          </form>
        </div>
      </div>
    </div>
  );
}