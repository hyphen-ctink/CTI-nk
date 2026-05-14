'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

import api from '@/lib/api';

/**
 * 인증 가드 컴포넌트
 * - 세션 유효성: /ctink/profile 호출로 확인 (401 시 api.js 인터셉터가 /login 리다이렉트 처리)
 * - role: 로그인 성공 시 /ctink/auth/login 응답에서 받아 sessionStorage에 저장한 값 사용
 *            (/ctink/profile 응답에 role 필드 없음)
 * - requiredRole이 지정된 경우 해당 role과 일치하지 않으면 /overview로 리다이렉트
 * - 확인 전까지 children을 렌더링하지 않아 보호된 페이지 노출 방지
 */
export default function AuthGuard({ children, requiredRole = null }) {
  const router = useRouter();
  const [isVerified, setIsVerified] = useState(false);

  useEffect(() => {
    // role은 /ctink/profile 응답에 없으므로 sessionStorage에서 가져옴
    // (로그인 성공 시 /ctink/auth/login 응답의 role을 sessionStorage에 저장해야 함)
    let cancelled = false;
    const verifySession = async () => {
      try {
        await api.get('/ctink/profile'); // 세션 유효성 확인용 (응답 데이터 불필요)
        if (cancelled) return; // 언마운트 후 상태 업데이트 방지
        const role = sessionStorage.getItem('role');
        if (!role) {
          router.replace('/login');
          return;
        }
        if (requiredRole && role.toUpperCase() !== requiredRole.toUpperCase()) {
          router.replace('/overview');
          return;
        }
        setIsVerified(true);
      } catch {
        // 401: api.js 인터셉터에서 sessionStorage.clear() 및 /login 리다이렉트 처리됨
      }
    };
    verifySession();
    return () => { cancelled = true; }; // cleanup: 언마운트 시 비동기 콜백 무효화
  }, [router, requiredRole]);

  if (!isVerified) {
    return (
      <div className="flex items-center justify-center h-screen bg-[var(--ctink-bg)]">
        <div className="w-6 h-6 border-2 border-[var(--ctink-accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return children;
}