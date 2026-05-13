'use client';

import { useState, useEffect, useRef } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { ShieldAlert, FileText, Bell, Radio } from 'lucide-react';
import api from '@/lib/api';

// ── 공격 유형 레이블 ────────────────────────────
const ATTACK_TYPE_LABELS = {
  ransomware:          '랜섬웨어',
  phishing:            '피싱 공격',
  ddos:                'DDoS',
  credential_stuffing: '크리덴셜 스터핑',
  web_attack:          '웹페이지 취약점',
  other:               '기타',
};

// ── 처리 상태별 레이블 및 색상 ──────────────────
const PROCESS_STATUS = {
  collected:  { label: '수집 완료', color: 'rgba(17, 45, 78, 0.5)',  bg: 'rgba(17, 45, 78, 0.06)'  },
  processing: { label: '처리 중',   color: '#3F72AF',                bg: 'rgba(63, 114, 175, 0.1)' },
  applying:   { label: '적용 중',   color: '#5068A9',                bg: 'rgba(80, 104, 169, 0.1)' },
  done:       { label: '완료',      color: '#2d7a4f',                bg: 'rgba(45, 122, 79, 0.1)'  },
  failed:     { label: '실패',      color: '#c0392b',                bg: 'rgba(192, 57, 43, 0.1)'  },
  removed:    { label: '제거됨',    color: 'rgba(17, 45, 78, 0.35)', bg: 'rgba(17, 45, 78, 0.04)'  },
};

// ── 도넛 차트 공격 유형별 색상 ──────────────────
const CHART_COLORS = {
  ransomware:          '#b05c5c',
  phishing:            '#c4845a',
  ddos:                '#7c6faa',
  credential_stuffing: '#112D4E',
  web_attack:          '#3F72AF',
  other:               '#c8d6ea',
};

// ─────────────────────────────────────────────────
// [백엔드 연동 시 아래 MOCK_DATA 블록 전체 삭제]
// ─────────────────────────────────────────────────
const MOCK_DATA = {
  threat_count: 437,
  threat_count_diff: 15,
  rule_count: 89,
  rule_count_diff: -3,
  pending_count: 12,
  platform_status: [
    { platform_id: 1,  name: 'GitHub_SecurityOnion', last_collected_at: '2025-04-01T09:00:00' },
    { platform_id: 2,  name: 'GitHub_Velociraptor',  last_collected_at: '2025-04-01T08:30:00' },
    { platform_id: 3,  name: 'GitHub_CiscoTalos',    last_collected_at: '2025-04-01T07:55:00' },
    { platform_id: 4,  name: 'GitHub_Stamparm',      last_collected_at: '2025-03-31T22:10:00' },
    { platform_id: 5,  name: 'GitHub_ESET',          last_collected_at: '2025-03-31T18:40:00' },
    { platform_id: 6,  name: 'GitHub_Aquasecurity',  last_collected_at: '2025-03-31T15:20:00' },
    { platform_id: 7,  name: 'Reddit_threatintel',   last_collected_at: '2025-04-01T06:30:00' },
    { platform_id: 8,  name: 'Reddit_blueteamsec',   last_collected_at: '2025-03-31T23:50:00' },
    { platform_id: 9,  name: 'Reddit_NetSec',        last_collected_at: null                  },
    { platform_id: 10, name: 'Reddit_CyberSecurity', last_collected_at: '2025-03-31T12:00:00' },
    { platform_id: 11, name: 'Medium_ANYRUN',        last_collected_at: null                  },
    { platform_id: 12, name: 'OTX_AlienVault',       last_collected_at: '2025-04-01T09:15:00' },
  ],
  recent_threats: [
    { cti_id: 1,  title: 'LockBit 3.0 변종',      attack_type: 'ransomware',          process_status: 'done',       collected_at: '2025-04-01T14:32:00' },
    { cti_id: 2,  title: 'GS25 크리덴셜 스터핑',    attack_type: 'credential_stuffing', process_status: 'done',       collected_at: '2025-04-01T13:51:00' },
    { cti_id: 3,  title: 'SKT 유사 피싱 캠페인',    attack_type: 'phishing',            process_status: 'failed',     collected_at: '2025-04-01T13:20:00' },
    { cti_id: 4,  title: 'Apache Struts2 RCE',    attack_type: 'web_attack',          process_status: 'done',       collected_at: '2025-04-01T12:47:00' },
    { cti_id: 5,  title: 'DNS Query Flooding',    attack_type: 'ddos',                process_status: 'applying',   collected_at: '2025-04-01T12:10:00' },
    { cti_id: 6,  title: '채용 공고 스피어피싱',     attack_type: 'phishing',            process_status: 'processing', collected_at: '2025-04-01T11:38:00' },
    { cti_id: 7,  title: 'Mirai 봇넷 변종',        attack_type: 'ddos',                process_status: 'collected',  collected_at: '2025-04-01T10:55:00' },
    { cti_id: 8,  title: 'KB국민카드 피싱 사이트',   attack_type: 'phishing',            process_status: 'collected',  collected_at: '2025-04-01T10:21:00' },
    { cti_id: 9,  title: 'LG U+ 고객 정보 유출',   attack_type: 'credential_stuffing', process_status: 'processing', collected_at: '2025-04-01T09:44:00' },
    { cti_id: 10, title: 'WannaCry 변종 탐지',     attack_type: 'ransomware',          process_status: 'done',       collected_at: '2025-04-01T09:12:00' },
  ],
  attack_type_distribution: [
    { attack_type: 'ransomware',          count: 122 },
    { attack_type: 'phishing',            count: 96  },
    { attack_type: 'ddos',                count: 79  },
    { attack_type: 'credential_stuffing', count: 74  },
    { attack_type: 'web_attack',          count: 66  },
    { attack_type: 'other',               count: 0   },
  ],
};
// ─────────────────────────────────────────────────
// [백엔드 연동 시 삭제 끝]
// ─────────────────────────────────────────────────

// ── 유틸: ISO 문자열 → MM/DD HH:mm 형식 ─────────
function formatTime(isoString) {
  const date = new Date(isoString);
  const m   = String(date.getMonth() + 1).padStart(2, '0');
  const d   = String(date.getDate()).padStart(2, '0');
  const h   = String(date.getHours()).padStart(2, '0');
  const min = String(date.getMinutes()).padStart(2, '0');
  return `${m}/${d} ${h}:${min}`;
}

// ── 유틸: Date 객체 → YYYY-MM-DD 형식 ───────────
function formatDate(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

// ── 통계 요약 카드 ──────────────────────────────
// diff가 undefined이면 증감 텍스트를 표시하지 않음 (확인 필요 건수 카드에서 사용)
function StatCard({ label, value, diff, icon: Icon, color }) {
  const prevValue = value - diff;
  const pct = prevValue > 0 ? Math.abs((diff / prevValue) * 100).toFixed(1) : null;
  const trendText =
    diff > 0 ? (pct !== null ? `▲ ${diff}건 (+${pct}%)` : `▲ ${diff}건`) :
    diff < 0 ? (pct !== null ? `▼ ${Math.abs(diff)}건 (-${pct}%)` : `▼ ${Math.abs(diff)}건`) :
               '— 변동 없음';

  return (
    <div style={{
      backgroundColor: 'var(--ctink-background)',
      borderRadius: '12px',
      padding: '24px 28px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      boxShadow: '0 1px 4px rgba(17, 45, 78, 0.08)',
    }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>{label}</span>
        <span style={{ fontSize: '36px', fontWeight: 800, color: 'var(--ctink-accent)', lineHeight: 1 }}>
          {value?.toLocaleString() ?? '-'}
        </span>
        {diff !== undefined && (
          <span style={{ fontSize: '12px', color: 'var(--ctink-text-muted)' }}>
            {trendText}
          </span>
        )}
      </div>
      {Icon && (
        <div style={{
          width: '56px',
          height: '56px',
          borderRadius: '12px',
          backgroundColor: `${color}18`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Icon size={28} color={color} strokeWidth={1.8} />
        </div>
      )}
    </div>
  );
}

// ── 플랫폼 수집 현황 카드 ──────────────────────
// 점 인디케이터로 플랫폼을 순환하며 마지막 수집 시각을 표시
function PlatformStatusCard({ platforms = [] }) {
  const [page, setPage] = useState(0);
  const total = platforms.length;
  const current = platforms[page];

  // 플랫폼 데이터가 없을 때 (API 최초 응답 전 등)
  if (total === 0) {
    return (
      <div style={{
        backgroundColor: 'var(--ctink-background)',
        borderRadius: '12px',
        padding: '16px 24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        boxShadow: '0 1px 4px rgba(17, 45, 78, 0.08)',
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>플랫폼 수집 현황</span>
          <span style={{ fontSize: '13px', color: 'var(--ctink-text-light)' }}>수집 중...</span>
        </div>
        <div style={{
          width: '56px', height: '56px',
          borderRadius: '12px',
          backgroundColor: 'rgba(63, 114, 175, 0.09)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Radio size={28} color="#3F72AF" strokeWidth={1.8} />
        </div>
      </div>
    );
  }

  return (
    <div style={{
      backgroundColor: 'var(--ctink-background)',
      borderRadius: '12px',
      padding: '16px 24px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      boxShadow: '0 1px 4px rgba(17, 45, 78, 0.08)',
    }}>
      {/* 좌측: 플랫폼명 + 수집 시각 + 점 인디케이터 */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>플랫폼 수집 현황</span>
        {current && (
          <>
            <span style={{
              fontSize: '15px',
              fontWeight: 800,
              color: 'var(--ctink-text)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              maxWidth: '200px',
            }}>
              {current.name}
            </span>
            <span style={{
              fontSize: '12px',
              color: current.last_collected_at ? 'var(--ctink-text-muted)' : 'var(--ctink-text-light)',
            }}>
              {current.last_collected_at ? formatTime(current.last_collected_at) : '미수집'}
            </span>
          </>
        )}

        {/* 이전/다음 화살표 + 점 인디케이터 */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
          <button
            onClick={() => setPage((p) => (p === 0 ? total - 1 : p - 1))}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: '20px', height: '20px',
              border: 'none', backgroundColor: 'transparent',
              cursor: 'pointer', padding: 0,
              color: 'var(--ctink-text)', fontSize: '14px',
            }}
          >
            &#8249;
          </button>

          {platforms.map((_, i) => (
            <button
              key={i}
              onClick={() => setPage(i)}
              style={{
                width: i === page ? '16px' : '6px',
                height: '6px',
                borderRadius: '999px',
                border: 'none',
                backgroundColor: i === page ? 'var(--ctink-accent)' : 'var(--ctink-card)',
                cursor: 'pointer',
                padding: 0,
                transition: 'width 0.2s ease, background-color 0.2s ease',
              }}
            />
          ))}

          <button
            onClick={() => setPage((p) => (p === total - 1 ? 0 : p + 1))}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: '20px', height: '20px',
              border: 'none', backgroundColor: 'transparent',
              cursor: 'pointer', padding: 0,
              color: 'var(--ctink-text)', fontSize: '14px',
            }}
          >
            &#8250;
          </button>
        </div>
      </div>

      {/* 우측: 아이콘 뱃지 */}
      <div style={{
        width: '56px', height: '56px',
        borderRadius: '12px',
        backgroundColor: 'rgba(63, 114, 175, 0.09)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0,
      }}>
        <Radio size={28} color="#3F72AF" strokeWidth={1.8} />
      </div>
    </div>
  );
}

// ── 반응형 CSS + 스피너 애니메이션 ──────────────
// 1100px 이하: 상단 카드 2열, 하단 섹션 단일 열
//  600px 이하: 상단 카드 1열
const RESPONSIVE_STYLES = `
  .overview-stat-grid   { grid-template-columns: repeat(4, 1fr); }
  .overview-bottom-grid { grid-template-columns: 2fr 1fr; }

  @media (max-width: 1100px) {
    .overview-stat-grid   { grid-template-columns: repeat(2, 1fr); }
    .overview-bottom-grid { grid-template-columns: 1fr; }
  }
  @media (max-width: 600px) {
    .overview-stat-grid { grid-template-columns: 1fr; }
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
  }
`;

// ── 폴링 주기 ───────────────────────────────────
const POLLING_INTERVAL = 30_000; // 30초

// ── 메인 컴포넌트 ───────────────────────────────
export default function OverviewPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const isInitialLoad = useRef(true);
  const hasData = useRef(false);
  const today = new Date();

  useEffect(() => {
    const fetchOverview = async () => {
      try {
        // 최초 호출 시에만 로딩 스피너 표시 (폴링 갱신 시에는 데이터만 교체)
        if (isInitialLoad.current) {
          setLoading(true);
          isInitialLoad.current = false;
        }

        // ─────────────────────────────────────────
        // [백엔드 연동 시] 아래 두 줄 주석 해제
        // const response = await api.get('/ctink/overview');
        // setData(response.data);

        // [백엔드 연동 시] 아래 두 줄 삭제
        await new Promise((r) => setTimeout(r, 300));
        setData(MOCK_DATA);
        // ─────────────────────────────────────────

        setError(null); // 이전 에러가 있었다면 갱신 성공 시 초기화
        hasData.current = true;
      } catch (err) {
        // 401(세션 만료)은 api.js 인터셉터에서 전역 처리 (window.location.href = '/login')
        if (err.response?.status !== 401) {
          // 최초 로드 실패 시에만 전체 에러 UI 표시
          // 폴링 갱신 실패 시에는 기존 데이터를 유지 (대시보드가 에러 화면으로 교체되는 것 방지)
          if (!hasData.current) {
            setError('데이터를 불러오지 못했습니다.');
          }
        }
      } finally {
        setLoading(false);
      }
    };

    fetchOverview();
    const intervalId = setInterval(fetchOverview, POLLING_INTERVAL);
    return () => clearInterval(intervalId); // 언마운트 시 인터벌 정리
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: '300px', backgroundColor: 'var(--ctink-bg)', gap: '16px' }}>
        <style>{RESPONSIVE_STYLES}</style>
        <div style={{
          width: '36px', height: '36px',
          borderRadius: '50%',
          border: '3px solid var(--ctink-card)',
          borderTopColor: 'var(--ctink-accent)',
          animation: 'spin 0.8s linear infinite',
        }} />
        <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>불러오는 중...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: '300px', backgroundColor: 'var(--ctink-bg)' }}>
        <span style={{ fontSize: '13px', color: '#c0392b' }}>{error}</span>
      </div>
    );
  }

  // count가 0인 항목은 도넛 차트에서 제외
  const chartData  = (data?.attack_type_distribution ?? []).filter((d) => d.count > 0);
  const totalCount = chartData.reduce((sum, d) => sum + d.count, 0);

  return (
    <div style={{ padding: '32px', backgroundColor: 'var(--ctink-bg)', minHeight: '100vh' }}>
      <style>{RESPONSIVE_STYLES}</style>

      {/* 헤더 */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '17px' }}>
        <h1 style={{ fontSize: '27px', fontWeight: 800, color: 'var(--ctink-text)', margin: 0 }}>Overview</h1>
        <span style={{ fontSize: '12px', color: 'var(--ctink-text-light)' }}>{formatDate(today)} 기준</span>
      </div>

      {/* 통계 요약 카드 4개 */}
      <div className="overview-stat-grid" style={{ display: 'grid', gap: '16px', marginBottom: '20px' }}>
        <StatCard label="최근 7일간 수집된 위협 수"      value={data?.threat_count}  diff={data?.threat_count_diff}  icon={ShieldAlert} color="#d97706" />
        <StatCard label="최근 7일간 생성된 탐지 정책 수"  value={data?.rule_count}    diff={data?.rule_count_diff}    icon={FileText}    color="#3F72AF" />
        <StatCard label="확인 필요 건수"                value={data?.pending_count}                                  icon={Bell}        color="#c0392b" />
        <PlatformStatusCard platforms={data?.platform_status ?? []} />
      </div>

      {/* 하단: 최근 위협 목록(좌) + 공격 유형 분포 차트(우) */}
      <div className="overview-bottom-grid" style={{ display: 'grid', gap: '16px' }}>

        {/* 최근 위협 목록 */}
        <div style={{
          backgroundColor: 'var(--ctink-background)',
          borderRadius: '12px',
          overflow: 'hidden',
          boxShadow: '0 1px 4px rgba(17, 45, 78, 0.08)',
        }}>
          <div style={{
            padding: '20px 24px',
            borderBottom: '1px solid var(--ctink-border)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: '17px', fontWeight: 800, color: 'var(--ctink-text)' }}>Recent Threat List</span>
            <span style={{ fontSize: '11px', color: 'var(--ctink-text-light)' }}>{formatDate(today)} 기준</span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '480px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--ctink-border)' }}>
                  {['위협명', '유형', '상태', '시간'].map((col, i) => (
                    <th key={col} style={{
                      backgroundColor: 'var(--ctink-card)',
                      opacity: 0.7,
                      padding: '10px 20px',
                      textAlign: i === 3 ? 'right' : 'left',
                      fontSize: '13px',
                      fontWeight: 800,
                      color: 'var(--ctink-text)',
                      whiteSpace: 'nowrap',
                    }}>
                      {col}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(data?.recent_threats ?? []).map((threat, idx) => {
                  // 정의되지 않은 상태값에 대한 fallback (bg 포함)
                  const status = PROCESS_STATUS[threat.process_status] ?? {
                    label: threat.process_status,
                    color: 'var(--ctink-text-muted)',
                    bg:    'rgba(17, 45, 78, 0.06)',
                  };
                  return (
                    <tr
                      key={threat.cti_id}
                      style={{
                        borderBottom: idx < (data?.recent_threats?.length ?? 0) - 1 ? '1px solid var(--ctink-border)' : 'none',
                        cursor: 'pointer',
                        transition: 'background-color 0.1s',
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--ctink-hover)')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <td
                        title={threat.title}
                        style={{
                          padding: '12px 20px',
                          fontSize: '14px',
                          color: 'var(--ctink-text)',
                          maxWidth: '200px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {threat.title}
                      </td>
                      <td style={{ padding: '12px 20px', fontSize: '14px', color: 'var(--ctink-text-muted)', whiteSpace: 'nowrap' }}>
                        {ATTACK_TYPE_LABELS[threat.attack_type] ?? (threat.attack_type || '-')}
                      </td>
                      <td style={{ padding: '12px 20px', whiteSpace: 'nowrap' }}>
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '999px',
                          fontSize: '14px',
                          color: status.color,
                          backgroundColor: status.bg,
                        }}>
                          {status.label}
                        </span>
                      </td>
                      <td style={{ padding: '12px 20px', fontSize: '14px', color: 'var(--ctink-text-light)', textAlign: 'right', whiteSpace: 'nowrap' }}>
                        {formatTime(threat.collected_at)}
                      </td>
                    </tr>
                  );
                })}

                {/* 위협 데이터가 없을 때 */}
                {(data?.recent_threats ?? []).length === 0 && (
                  <tr>
                    <td colSpan={4} style={{ padding: '48px 32px', textAlign: 'center' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                        <ShieldAlert size={32} color="var(--ctink-text-muted)" strokeWidth={1.5} style={{ opacity: 0.4 }} />
                        <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>수집된 위협 정보가 없습니다.</span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* 공격 유형 분포 도넛 차트 */}
        <div style={{
          backgroundColor: 'var(--ctink-background)',
          borderRadius: '12px',
          padding: '20px 20px 16px',
          boxShadow: '0 1px 4px rgba(17, 45, 78, 0.08)',
          display: 'flex',
          flexDirection: 'column',
        }}>
          <span style={{ fontSize: '17px', fontWeight: 800, color: 'var(--ctink-text)', marginBottom: '4px' }}>
            Threat Status
          </span>

          {/* 수집된 위협이 없을 때 빈 상태 */}
          {totalCount === 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '200px', gap: '8px' }}>
              <ShieldAlert size={32} color="var(--ctink-text-muted)" strokeWidth={1.5} style={{ opacity: 0.4 }} />
              <span style={{ fontSize: '13px', color: 'var(--ctink-text-muted)' }}>위협 데이터가 없습니다.</span>
            </div>
          ) : (
            <div style={{ position: 'relative', width: '100%', height: '200px', marginTop: '8px', minWidth: 0 }}>
              <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={82}
                    dataKey="count"
                    nameKey="attack_type"
                    startAngle={90}
                    endAngle={-270}
                    stroke="none"
                  >
                    {chartData.map((entry) => (
                      <Cell
                        key={entry.attack_type}
                        fill={CHART_COLORS[entry.attack_type] ?? '#c8d6ea'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value, name) => [`${value}건`, ATTACK_TYPE_LABELS[name] ?? name]}
                    contentStyle={{
                      fontSize: '12px',
                      borderRadius: '6px',
                      border: '1px solid var(--ctink-card)',
                      backgroundColor: 'var(--ctink-bg)',
                      color: 'var(--ctink-text)',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>

              {/* 도넛 차트 중앙 총 위협 수 */}
              <div style={{
                position: 'absolute',
                inset: 0,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                pointerEvents: 'none',
              }}>
                <span style={{ fontSize: '11px', color: 'var(--ctink-text-muted)' }}>총 위협</span>
                <span style={{ fontSize: '22px', color: 'var(--ctink-text)', lineHeight: 1.2 }}>
                  {totalCount.toLocaleString()}
                </span>
              </div>
            </div>
          )}

          {/* 공격 유형별 분포 범례 */}
          <div style={{ marginTop: '12px', borderTop: '1px solid var(--ctink-border)', paddingTop: '12px' }}>
            <p style={{ fontSize: '11px', fontWeight: 600, color: 'var(--ctink-text-muted)', marginBottom: '6px', marginTop: 0 }}>
              공격 유형 분포
            </p>
            {(data?.attack_type_distribution ?? []).map((item) => {
              const pct = totalCount > 0 ? Math.round((item.count / totalCount) * 100) : 0;
              return (
                <div key={item.attack_type} style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '4px 0',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      width: '10px',
                      height: '10px',
                      borderRadius: '50%',
                      backgroundColor: CHART_COLORS[item.attack_type] ?? '#c8d6ea',
                      flexShrink: 0,
                    }} />
                    <span style={{ fontSize: '12px', color: 'var(--ctink-text)' }}>
                      {ATTACK_TYPE_LABELS[item.attack_type] ?? item.attack_type}
                    </span>
                  </div>
                  <span style={{ fontSize: '12px', color: 'var(--ctink-text-muted)' }}>{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </div>
  );
}