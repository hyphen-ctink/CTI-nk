'use client';

import { useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';

// [백엔드 연동 시 주석 해제]
// import api from '@/lib/api';

/**
 * 자동 세션 만료 훅 (UINFR-SEC-002)
 * - 사용자 조작(마우스 이동, 키 입력, 클릭, 스크롤)이 없을 경우
 *   timeoutMs 경과 후 자동 로그아웃 처리
 * @param {number} timeoutMs - 만료 기준 시간 (기본값: 30분)
 */
export function useAutoLogout(timeoutMs = 30 * 60 * 1000) {
  const router = useRouter();
  const timer = useRef(null);

  useEffect(() => {
    const handleLogout = async () => {
      sessionStorage.clear();
      // [백엔드 연동 시 주석 해제] 서버 세션 명시적 무효화
      // try {
      //   await api.post('/ctink/auth/logout');
      // } catch {
      //   // 로그아웃 API 실패해도 클라이언트는 로그인 페이지로 이동
      // }
      router.replace('/login');
    };

    const reset = () => {
      clearTimeout(timer.current);
      timer.current = setTimeout(handleLogout, timeoutMs);
    };

    const events = ['mousemove', 'keydown', 'click', 'scroll'];
    events.forEach((e) => window.addEventListener(e, reset));
    reset(); // 초기 타이머 시작

    return () => {
      events.forEach((e) => window.removeEventListener(e, reset));
      clearTimeout(timer.current);
    };
  }, [timeoutMs, router]);
}