'use client';

import { useState, useEffect, useRef } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useForm } from 'react-hook-form';
// ↓ [연동 시 주석 해제]
// import api from '@/lib/api';

/* ── 컴포넌트 외부 상수 ─────────────────────────────────────────────── */

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

const errorStyle = {
  fontSize: '11px',
  color: '#A32D2D',
  marginTop: '4px',
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

export default function SignupPage() {
  const router = useRouter();
  const timerRef = useRef(null);

  const [isLoading, setIsLoading] = useState(false);
  const [serverMessage, setServerMessage] = useState('');
  const [isSuccess, setIsSuccess] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false);

  const {
    register,
    handleSubmit,
    watch,
    trigger,
    formState: { errors, touchedFields },
  } = useForm({ mode: 'onBlur' });

  const passwordValue = watch('password');

  // 이미 로그인된 사용자 리다이렉트
  // sessionStorage에 role이 존재하면 로그인 상태로 판단하여 overview로 이동
  // 주의: useEffect는 클라이언트 마운트 후 실행되므로 페이지가 잠깐 노출될 수 있음 (sessionStorage 특성상 불가피)
  useEffect(() => {
    const role = sessionStorage.getItem('role');
    if (role) {
      router.replace('/overview');
    }
  }, [router]);

  // 비밀번호가 변경될 때 비밀번호 확인 필드를 재검증
  // (한 번이라도 터치된 경우에만 실행하여 초기 렌더링 시 에러 표시 방지)
  const touchedFieldsRef = useRef(touchedFields);
  touchedFieldsRef.current = touchedFields;

  useEffect(() => {
    if (touchedFieldsRef.current.password_confirm) {
      trigger('password_confirm');
    }
  }, [passwordValue, trigger]);

  // 성공 후 리다이렉트 타이머 — 컴포넌트 언마운트 시 정리
  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const onSubmit = async (data) => {
    setIsLoading(true);
    setServerMessage('');

    const payload = {
      login_id:     data.login_id,
      password:     data.password,
      name:         data.name,
      organization: data.organization,
      position:     data.position,
      email:        data.email,
      phone:        data.phone,
    };

    // ↓↓↓ [연동 시 아래 블록 전체 삭제] ↓↓↓
    await new Promise((r) => setTimeout(r, 800));
    setIsSuccess(true);
    setServerMessage('회원가입이 완료되었습니다. 관리자 승인 후 이용 가능합니다.');
    setIsLoading(false);
    timerRef.current = setTimeout(() => router.replace('/login'), 2500);
    return;
    // ↑↑↑ [연동 시 위 블록 전체 삭제] ↑↑↑

    // ↓ [연동 시 주석 해제]
    // try {
    //   const res = await api.post('/ctink/auth/join', payload);
    //   setIsSuccess(true);
    //   setServerMessage(res.data.message);
    //   timerRef.current = setTimeout(() => router.replace('/login'), 2500);
    // } catch (error) {
    //   const msg = error.response?.data?.message || '오류가 발생했습니다.';
    //   setServerMessage(msg);
    // } finally {
    //   setIsLoading(false);
    // }
  };

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
        {/* public/logo.png 에 로고 파일을 저장하면 표시됩니다 */}
        <Image
          src="/logo.png"
          alt="CTI-nk 로고"
          width={160}
          height={180}
          priority
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
            maxWidth: '560px',
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
            회원가입
          </p>

          {/* 성공 메시지 */}
          {isSuccess && (
            <div
              style={{
                padding: '12px 14px',
                backgroundColor: 'rgba(15, 110, 86, 0.08)',
                border: '1px solid rgba(15, 110, 86, 0.25)',
                borderRadius: '8px',
                fontSize: '13px',
                color: '#0F6E56',
                marginBottom: '20px',
              }}
            >
              {serverMessage}
              <p style={{ fontSize: '12px', marginTop: '4px', opacity: 0.8 }}>
                잠시 후 로그인 페이지로 이동합니다.
              </p>
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} noValidate>

            {/*
              성공 후 모든 입력 필드를 한 번에 비활성화
              fieldset의 disabled 속성은 하위 모든 input/button에 적용됨
              (가입하기 버튼은 fieldset 바깥에 있어 별도로 disabled 처리)
            */}
            <fieldset disabled={isSuccess || isLoading} style={{ border: 'none', padding: 0, margin: 0 }}>

              {/* ID / 이름 */}
              <div className="grid grid-cols-1 md:grid-cols-2" style={{ gap: '16px', marginBottom: '16px' }}>
                <div>
                  <label htmlFor="login_id" style={labelStyle}>ID</label>
                  <input
                    id="login_id"
                    type="text"
                    autoComplete="username" 
                    placeholder="ID를 입력하세요"
                    className="ctink-input"
                    style={{ ...inputStyle, borderColor: errors.login_id ? '#A32D2D' : 'var(--ctink-border)' }}
                    {...register('login_id', {
                      required: '아이디를 입력해주세요.',
                      minLength: { value: 4, message: '4자 이상 입력해주세요.' },
                      maxLength: { value: 20, message: '20자 이하로 입력해주세요.' },
                      pattern: { value: /^[a-zA-Z0-9]+$/, message: '영문·숫자만 사용 가능합니다.' },
                    })}
                  />
                  {errors.login_id && <p style={errorStyle}>{errors.login_id.message}</p>}
                </div>
                <div>
                  <label htmlFor="name" style={labelStyle}>이름</label>
                  <input
                    id="name"
                    type="text"
                    autoComplete="name"
                    placeholder="이름을 입력하세요"
                    className="ctink-input"
                    style={{ ...inputStyle, borderColor: errors.name ? '#A32D2D' : 'var(--ctink-border)' }}
                    {...register('name', { required: '이름을 입력해주세요.' })}
                  />
                  {errors.name && <p style={errorStyle}>{errors.name.message}</p>}
                </div>
              </div>

              {/* 비밀번호 / 비밀번호 확인 */}
              <div className="grid grid-cols-1 md:grid-cols-2" style={{ gap: '16px', marginBottom: '16px' }}>
                <div>
                  <label htmlFor="password" style={labelStyle}>비밀번호</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      placeholder="비밀번호를 입력하세요"
                      className="ctink-input"
                      style={{
                        ...inputStyle,
                        paddingRight: '40px',
                        borderColor: errors.password ? '#A32D2D' : 'var(--ctink-border)',
                      }}
                      {...register('password', {
                        required: '비밀번호를 입력해주세요.',
                        pattern: {
                          value: /^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/,
                          message: '영문·숫자·특수문자를 포함하여 8자 이상 입력해주세요.',
                        },
                      })}
                    />
                    <button
                      type="button"
                      aria-label={showPassword ? '비밀번호 숨기기' : '비밀번호 보기'}
                      onClick={() => setShowPassword((v) => !v)}
                      style={eyeButtonStyle}
                    >
                      {showPassword ? EyeOff : EyeOpen}
                    </button>
                  </div>
                  {errors.password && <p style={errorStyle}>{errors.password.message}</p>}
                </div>
                <div>
                  <label htmlFor="password_confirm" style={labelStyle}>비밀번호 확인</label>
                  <div style={{ position: 'relative' }}>
                    <input
                      id="password_confirm"
                      type={showPasswordConfirm ? 'text' : 'password'}
                      autoComplete="new-password"
                      placeholder="비밀번호를 재입력하세요"
                      className="ctink-input"
                      style={{
                        ...inputStyle,
                        paddingRight: '40px',
                        borderColor: errors.password_confirm ? '#A32D2D' : 'var(--ctink-border)',
                      }}
                      {...register('password_confirm', {
                        required: '비밀번호를 다시 입력해주세요.',
                        validate: (v) => v === (passwordValue || '') || '비밀번호가 일치하지 않습니다.',
                      })}
                    />
                    <button
                      type="button"
                      aria-label={showPasswordConfirm ? '비밀번호 숨기기' : '비밀번호 보기'}
                      onClick={() => setShowPasswordConfirm((v) => !v)}
                      style={eyeButtonStyle}
                    >
                      {showPasswordConfirm ? EyeOff : EyeOpen}
                    </button>
                  </div>
                  {errors.password_confirm && <p style={errorStyle}>{errors.password_confirm.message}</p>}
                </div>
              </div>

              {/* 소속 / 직책 */}
              <div className="grid grid-cols-1 md:grid-cols-2" style={{ gap: '16px', marginBottom: '16px' }}>
                <div>
                  <label htmlFor="organization" style={labelStyle}>소속</label>
                  <input
                    id="organization"
                    type="text"
                    autoComplete="organization"
                    placeholder="소속을 입력하세요"
                    className="ctink-input"
                    style={{ ...inputStyle, borderColor: errors.organization ? '#A32D2D' : 'var(--ctink-border)' }}
                    {...register('organization', { required: '소속을 입력해주세요.' })}
                  />
                  {errors.organization && <p style={errorStyle}>{errors.organization.message}</p>}
                </div>
                <div>
                  <label htmlFor="position" style={labelStyle}>직책</label>
                  <input
                    id="position"
                    type="text"
                    autoComplete="organization-title"
                    placeholder="직책을 입력하세요"
                    className="ctink-input"
                    style={{ ...inputStyle, borderColor: errors.position ? '#A32D2D' : 'var(--ctink-border)' }}
                    {...register('position', { required: '직책을 입력해주세요.' })}
                  />
                  {errors.position && <p style={errorStyle}>{errors.position.message}</p>}
                </div>
              </div>

              {/* 메일 */}
              <div style={{ marginBottom: '16px' }}>
                <label htmlFor="email" style={labelStyle}>메일</label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="이메일 주소를 입력하세요"
                  className="ctink-input"
                  style={{ ...inputStyle, borderColor: errors.email ? '#A32D2D' : 'var(--ctink-border)' }}
                  {...register('email', {
                    required: '이메일을 입력해주세요.',
                    pattern: { value: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, message: '이메일 형식이 올바르지 않습니다.' },
                  })}
                />
                {errors.email && <p style={errorStyle}>{errors.email.message}</p>}
              </div>

              {/* 전화번호 */}
              <div style={{ marginBottom: '16px' }}>
                <label htmlFor="phone" style={labelStyle}>전화번호</label>
                <input
                  id="phone"
                  type="tel"
                  autoComplete="tel"
                  placeholder="전화번호를 입력하세요 (예: 010-1234-5678)"
                  className="ctink-input"
                  style={{ ...inputStyle, borderColor: errors.phone ? '#A32D2D' : 'var(--ctink-border)' }}
                  {...register('phone', {
                    required: '전화번호를 입력해주세요.',
                    pattern: {
                      value: /^[0-9]{2,3}-[0-9]{3,4}-[0-9]{4}$/,
                      message: '올바른 형식으로 입력해주세요. (예: 010-1234-5678)',
                    },
                  })}
                />
                {errors.phone && <p style={errorStyle}>{errors.phone.message}</p>}
              </div>

            </fieldset>

            {/* 서버 오류 메시지 (성공 상태일 때는 위의 성공 배너로 대체) */}
            {!isSuccess && serverMessage && (
              <p style={{ ...errorStyle, marginTop: '12px' }}>{serverMessage}</p>
            )}

            {/* 가입하기 버튼 */}
            <button
              type="submit"
              disabled={isLoading || isSuccess}
              style={{
                width: '100%',
                padding: '13px',
                marginTop: '20px',
                backgroundColor: isLoading || isSuccess ? 'var(--ctink-text-light)' : 'var(--ctink-accent)',
                color: 'var(--ctink-bg)',
                border: 'none',
                borderRadius: '8px',
                fontSize: '14px',
                fontWeight: 800,
                cursor: isLoading || isSuccess ? 'not-allowed' : 'pointer',
                letterSpacing: '0.5px',
              }}
            >
              {isLoading ? '처리 중...' : '가입하기'}
            </button>

            {/* 로그인 페이지 이동 링크 */}
            <div style={{ textAlign: 'center', marginTop: '20px' }}>
              <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>이미 계정이 있으신가요? </span>
              <Link
                href="/login"
                style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ctink-accent)', textDecoration: 'underline' }}
              >
                로그인
              </Link>
            </div>

          </form>
        </div>
      </div>
    </div>
  );
}