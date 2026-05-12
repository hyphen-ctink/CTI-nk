import AuthGuard from '@/components/common/AuthGuard';

/**
 * Members 페이지 레이아웃
 * - ADMIN 전용 페이지
 * - USER 계정으로 직접 접근 시 /overview로 리다이렉트
 */
export default function MembersLayout({ children }) {
  return (
    <AuthGuard requiredRole="ADMIN">
      {children}
    </AuthGuard>
  );
}