'use client';

import Sidebar from '@/components/common/Sidebar';
import AuthGuard from '@/components/common/AuthGuard';
import { useAutoLogout } from '@/hooks/useAutoLogout';

/**
 * Dashboard 레이아웃
 * - 모든 /dashboard 하위 페이지에 공통 적용
 * - AuthGuard: sessionStorage에 role 없으면 /login으로 리다이렉트
 * - useAutoLogout: 무활동 30분 경과 시 자동 로그아웃 (UINFR-SEC-002)
 */
export default function DashboardLayout({ children }) {
  useAutoLogout();

  return (
    <AuthGuard>
      <div className="flex h-screen bg-[var(--ctink-bg)] overflow-hidden">
        <Sidebar />
        <main className="flex-1 h-screen overflow-y-auto">
          {children}
        </main>
      </div>
    </AuthGuard>
  );
}