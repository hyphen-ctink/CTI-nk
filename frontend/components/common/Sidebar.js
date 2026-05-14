'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import api from '@/lib/api';
import ProfileModal from '@/components/common/ProfileModal';
import { LayoutDashboard, Shield, Activity, ShieldCheck, BellRing, Users, PanelLeft, PanelLeftClose } from 'lucide-react';
import { useState, useEffect } from 'react';
import { toast } from 'sonner';

const NAV_ITEMS_ADMIN = [
  { label: 'Overview',   href: '/overview',    icon: LayoutDashboard },
  { label: 'Rule',       href: '/rule',        icon: Shield          },
  { label: 'System Log', href: '/system-log',  icon: Activity        },
  { label: 'IDS Log',    href: '/ids-log',     icon: ShieldCheck     },
  { label: 'Request',    href: '/request',     icon: BellRing        },
  { label: 'Members',    href: '/members',     icon: Users           },
];

const NAV_ITEMS_USER = [
  { label: 'Overview',   href: '/overview',   icon: LayoutDashboard },
  { label: 'Rule',       href: '/rule',       icon: Shield          },
  { label: 'System Log', href: '/system-log', icon: Activity        },
  { label: 'IDS Log',    href: '/ids-log',    icon: ShieldCheck     },
  { label: 'Request',    href: '/request',    icon: BellRing        },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();

  const [role, setRole] = useState('USER');

  useEffect(() => {
    setRole(sessionStorage.getItem('role')); 
  }, []);

  const navItems = role !== null && role === 'ADMIN' ? NAV_ITEMS_ADMIN : NAV_ITEMS_USER;

  const [isCollapsed, setIsCollapsed] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const handleLogout = async () => {
    try {
      await api.post('/ctink/auth/logout');
      sessionStorage.clear();
      router.replace('/login');
    } catch (e) {
      const status = e.response?.status;
      if (status === 401) {
        // 인터셉터에서 이미 처리 (sessionStorage.clear + /login 이동)
      } else {
        console.error('로그아웃 실패:', e);
        toast.error('로그아웃 중 오류가 발생했습니다.');
      }
    }
  };

  return (
    <>
    <aside
      className="h-screen flex flex-col shrink-0"
      style={{
        width: isCollapsed ? '56px' : '208px',
        transition: 'width 0.2s ease',
        backgroundColor: 'var(--ctink-sidebar-bg)',
        borderRight: '1px solid var(--ctink-card)',
        overflow: 'hidden',
      }}
    >
      {/* 로고 */}
      <div
        style={{
          paddingLeft: '20px',
          paddingRight: '20px',
          paddingTop: '18px',
          paddingBottom: '10px',
          borderBottom: '1px solid var(--ctink-border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: isCollapsed ? 'center' : 'space-between',
        }}
      >
        {!isCollapsed && (
          <>
            <span style={{ fontSize: '30px', fontWeight: 800, color: 'var(--ctink-text)', letterSpacing: '-0.3px', whiteSpace: 'nowrap' }}>
              CTI-nk
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setProfileOpen(true)}
                className="p-1 rounded"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ctink-text-muted)', transition: 'color 0.15s' }}
                onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--ctink-accent)')}
                onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--ctink-text-muted)')}
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                  <circle cx="12" cy="7" r="4" />
                </svg>
              </button>
            </div>
          </>
        )}

        {/* 토글 버튼 */}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: 'var(--ctink-text-muted)',
            padding: '4px',
            display: 'flex',
            alignItems: 'center',
            transition: 'color 0.15s',
            flexShrink: 0,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--ctink-accent)')}
          onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--ctink-text-muted)')}
        >
          {isCollapsed ? <PanelLeft size={16} /> : <PanelLeftClose size={16} />}
        </button>
      </div>

      {/* 네비게이션 */}
      {role !== null && (
        <nav style={{ flex: 1, padding: '16px 12px' }}>
          {navItems.map((item) => {
            const isActive = pathname === item.href || pathname.startsWith(item.href + '/');
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                style={{
                  position: 'relative',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: isCollapsed ? 'center' : 'flex-start',
                  gap: isCollapsed ? '0' : '8px',
                  padding: isCollapsed ? '7px' : '7px 12px',
                  marginBottom: '2px',
                  borderRadius: '6px',
                  fontSize: '15px',
                  fontWeight: isActive ? 800 : 600,
                  color: isActive ? 'var(--ctink-accent)' : 'var(--ctink-text)',
                  backgroundColor: isActive ? 'var(--ctink-accent-bg)' : 'transparent',
                  textDecoration: 'none',
                  transition: 'background-color 0.15s, color 0.15s',
                }}
                onMouseEnter={(e) => { if (!isActive) e.currentTarget.style.backgroundColor = 'var(--ctink-hover)'; }}
                onMouseLeave={(e) => { if (!isActive) e.currentTarget.style.backgroundColor = 'transparent'; }}
              >
                {isActive && !isCollapsed && (
                  <div
                    style={{
                      position: 'absolute',
                      left: '2px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      width: '4px',
                      height: '80%',
                      backgroundColor: 'var(--ctink-accent)',
                      borderRadius: '4px',
                    }}
                  />
                )}
                <Icon size={isCollapsed ? 17 : 20} strokeWidth={isActive ? 3 : 2} />
                {!isCollapsed && item.label}
              </Link>
            );
          })}
        </nav>
      )}

      {/* 로그아웃 - 접혔을 때 숨김 */}
      {!isCollapsed && (
        <div style={{ padding: '16px 20px', borderTop: '1px solid var(--ctink-border)' }}>
          <button
            onClick={handleLogout}
            style={{
              fontSize: '13px',
              fontWeight: 600,
              color: 'var(--ctink-text-light)',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: 0,
              transition: 'color 0.15s',
              whiteSpace: 'nowrap',
            }}
            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--ctink-text-muted)')}
            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--ctink-text-light)')}
          >
            로그아웃
          </button>
        </div>
      )}
    </aside>

      {profileOpen && (
        <ProfileModal onClose={() => setProfileOpen(false)} />
      )}
    </>
  );
}