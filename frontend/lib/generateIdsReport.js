import {
  Document, Page, Text, View, StyleSheet, Font, pdf, Image,
  Svg, G, Rect, Line, Polyline, Circle, Path,
} from '@react-pdf/renderer';

Font.register({
  family: 'Pretendard',
  fonts: [
    { src: '/fonts/Pretendard-Regular.ttf', fontWeight: 400 },
    { src: '/fonts/Pretendard-Medium.ttf',  fontWeight: 500 },
    { src: '/fonts/Pretendard-Bold.ttf',    fontWeight: 700 },
  ],
});

// 폰트: SVG 내부 Text는 PDF 레이어 폰트를 상속받지 않으므로 별도로 명시
const SVG_FONT = 'Pretendard';

// 색상 팔레트: 수정 시 이 객체에서 일괄 변경
const C = {
  text:        '#112D4E',
  textMuted:   '#516A86',
  textLight:   '#7F97AC',
  accent:      '#3F72AF',
  bg:          '#F9F7F7',
  card:        '#DBE2EF',
  white:       '#FFFFFF',
  alertClr:    '#BA7517',
  blockClr:    '#A32D2D',
  detectClr:   '#3F72AF',
  highClr:     '#1A6B3A',
  mediumClr:   '#BA7517',
  lowClr:      '#A32D2D',
  chart1:      '#3F72AF',
  chart2:      '#86A6DF',
  gridClr:     '#E8ECF2',
  axisClr:     '#C8D2DC',
  coverBg:     '#EEF3FA',
  coverAccent: '#2C5898',
  coverDark:   '#1A3A5C',
  donutHigh:   '#1A6B3A',
  donutMedium: '#BA7517',
  donutLow:    '#A32D2D',
};

// 공격 유형별 도넛 차트 색상: Overview 페이지 CHART_COLORS와 동일하게 유지
const ATTACK_DONUT_COLOR = {
  RANSOMWARE:          '#b05c5c',
  PHISHING:            '#c4845a',
  DDOS:                '#7c6faa',
  CREDENTIAL_STUFFING: '#112D4E',
  WEB_ATTACK:          '#3F72AF', 
  IOC_ONLY:            '#8fa8c8', 
};

// 공격 유형 한글 표시명 (표·총평에서 사용)
const ATTACK_LABEL = {
  RANSOMWARE:          '랜섬웨어',
  CREDENTIAL_STUFFING: '크리덴셜 스터핑',
  PHISHING:            '피싱 공격',
  WEB_ATTACK:          '웹페이지 취약점',
  DDOS:                'DDoS',
  IOC_ONLY:            '침해 지표', 
};
// 공격 유형 축약 표시명 (도넛 범례·요약 배너에서 사용)
const ATTACK_SHORT = {
  RANSOMWARE:          '랜섬웨어',
  PHISHING:            '피싱 공격',
  DDOS:                'DDoS',
  CREDENTIAL_STUFFING: '크리덴셜 스터핑',
  WEB_ATTACK:          '웹페이지 취약점',
  IOC_ONLY:            '침해 지표', 
};
// 바 차트 X축 레이블 (줄바꿈 처리)
const ATTACK_CHART_LINES = {
  RANSOMWARE:          ['랜섬웨어'],
  CREDENTIAL_STUFFING: ['크리덴셜', '스터핑'],
  PHISHING:            ['피싱 공격'],
  WEB_ATTACK:          ['웹페이지', '취약점'],
  DDOS:                ['DDoS'],
  IOC_ONLY:            ['침해 지표'],
};

// 신뢰도 텍스트 색상 (카드 수치에 적용)
const TRUST_COLOR = { HIGH: C.highClr, MEDIUM: C.mediumClr, LOW: C.lowClr };
// 신뢰도 도넛 차트 색상
const DONUT_COLOR = { HIGH: C.donutHigh, MEDIUM: C.donutMedium, LOW: C.donutLow };
// 순위 표시 레이블 (1위~5위)
const RANK_LABEL  = ['1위', '2위', '3위', '4위', '5위'];

// 증감 텍스트 생성 (예: ▲ 6 증가 (+10%))
function trendText(curr, prev) {
  if (curr === 0 && prev === 0) return '변동 없음';
  if (prev === 0) return `+${curr} (신규)`;
  const diff = curr - prev;
  if (diff === 0) return '변동 없음';
  const pct = Math.abs(Math.round((diff / prev) * 100));
  return diff > 0 ? `▲ ${diff} 증가 (+${pct}%)` : `▼ ${Math.abs(diff)} 감소 (-${pct}%)`;
}
// 증감 색상 (보안 맥락: 증가=위험=빨강, 감소=완화=초록)
function trendColor(curr, prev) {
  const diff = curr - prev;
  if (diff > 0) return C.blockClr;
  if (diff < 0) return C.highClr;
  return C.textLight;
}
// 날짜 문자열(YYYY-MM-DD)을 M/D 형식으로 변환
function fmtMonthDay(dateStr) {
  if (!dateStr) return '';
  const parts = dateStr.split('-');
  if (parts.length < 3) return dateStr;
  return `${parseInt(parts[1])}/${parseInt(parts[2])}`;
}
// 한글 주격 조사 판별 (받침 유무에 따라 '이'/'가' 반환)
function subjectParticle(word) {
  if (!word) return '이';
  const code = word.charCodeAt(word.length - 1);
  if (code < 0xAC00 || code > 0xD7A3) return '가';
  return (code - 0xAC00) % 28 > 0 ? '이' : '가';
}
// 정책명 말줄임 처리 (maxLen 초과 시 '…' 추가, 기본 28자)
function truncateName(name, maxLen = 28) {
  if (!name) return '';
  return name.length > maxLen ? name.slice(0, maxLen) + '…' : name;
}
// 총평 문장 생성 (총 탐지 증감·최다 유형·HIGH 신뢰도 비율 3문장 조합)
function buildSummaryText(data) {
  const totalThis = (data.by_rule_type_result ?? []).reduce((acc, r) =>
    acc + (r.alert_count ?? 0) + (r.detected_count ?? 0) + (r.blocked_count ?? 0), 0);
  const totalPrev = (data.by_rule_type_result ?? []).reduce((acc, r) =>
    acc + (r.prev_alert_count ?? 0) + (r.prev_detected_count ?? 0) + (r.prev_blocked_count ?? 0), 0);
  const diff = totalThis - totalPrev;
  const pct  = totalPrev > 0 ? Math.abs(Math.round((diff / totalPrev) * 100)) : 0;

  let s1 = '';
  if (diff > 0)      s1 = `이번 조회 주간(${data.this_week_from} ~ ${data.this_week_to}) 총 ${totalThis}건의 위협이 탐지되어 전주 대비 ${pct}% 증가했습니다.`;
  else if (diff < 0) s1 = `이번 조회 주간(${data.this_week_from} ~ ${data.this_week_to}) 총 ${totalThis}건의 위협이 탐지되어 전주 대비 ${pct}% 감소했습니다.`;
  else               s1 = `이번 조회 주간(${data.this_week_from} ~ ${data.this_week_to}) 총 ${totalThis}건의 위협이 탐지되어 전주와 동일한 수준을 유지했습니다.`;

  const topAttack = [...(data.by_attack_type ?? [])].sort((a, b) => b.count - a.count)[0];
  const s2 = topAttack ? (() => {
    const label = ATTACK_LABEL[topAttack.attack_type] ?? topAttack.attack_type;
    return `${label}${subjectParticle(label)} ${topAttack.count}건으로 가장 많이 탐지됐습니다.`;
  })() : '';

  const trustTotal = (data.by_trust_level ?? []).reduce((a, b) => a + b.count, 0) || 1;
  const highItem   = (data.by_trust_level ?? []).find(t => t.trust_level === 'HIGH');
  const highPct    = highItem ? Math.round((highItem.count / trustTotal) * 100) : 0;
  const s3 = highItem ? `신뢰도 HIGH 비율은 ${highPct}%로 집계됐습니다.` : '';

  return [s1, s2, s3].filter(Boolean).join(' ');
}
// 차트 Y축 최댓값을 보기 좋은 숫자로 올림
function niceMax(val) {
  if (val <= 0) return 10;
  const magnitude = Math.pow(10, Math.floor(Math.log10(val)));
  const step = magnitude >= 10 ? magnitude / 2 : magnitude;
  return Math.ceil(val / step) * step;
}
// 현재 시각을 YYYY-MM-DD HH:MM 형식으로 반환
function nowString() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function polarToCart(cx, cy, r, deg) {
  const rad = (deg - 90) * (Math.PI / 180);
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}
// 도넛 차트용 SVG 호(arc) 경로 계산
function donutArcPath(cx, cy, outerR, innerR, startDeg, endDeg) {
  const end   = endDeg - startDeg >= 360 ? startDeg + 359.99 : endDeg;
  const large = end - startDeg > 180 ? 1 : 0;
  const o1 = polarToCart(cx, cy, outerR, startDeg);
  const o2 = polarToCart(cx, cy, outerR, end);
  const i1 = polarToCart(cx, cy, innerR, end);
  const i2 = polarToCart(cx, cy, innerR, startDeg);
  return `M ${o1.x} ${o1.y} A ${outerR} ${outerR} 0 ${large} 1 ${o2.x} ${o2.y} L ${i1.x} ${i1.y} A ${innerR} ${innerR} 0 ${large} 0 ${i2.x} ${i2.y} Z`;
}

const s = StyleSheet.create({
  coverPage: {
    fontFamily: 'Pretendard', flexDirection: 'column', gap: 0,
    backgroundColor: C.coverBg,
  },
  coverTop: {
    flex: 1, backgroundColor: C.coverBg,
    justifyContent: 'center', alignItems: 'center',
    paddingTop: 72, paddingBottom: 48, marginBottom: 0,
  },
  coverLogoWrap: {
    width: 110, height: 110, borderRadius: 55,
    backgroundColor: C.white,
    justifyContent: 'center', alignItems: 'center',
    marginBottom: 28,
    borderWidth: 2, borderColor: C.card, borderStyle: 'solid',
  },
  coverLogo:      { width: 72, height: 72, objectFit: 'contain' },
  coverAccentBar: { width: 48, height: 4, backgroundColor: C.coverAccent, borderRadius: 2, marginBottom: 18 },
  coverTitle:     { fontSize: 28, fontWeight: 700, color: C.coverAccent, marginBottom: 8, textAlign: 'center' },
  coverSubtitle:  { fontSize: 12, fontWeight: 400, color: C.textMuted, textAlign: 'center' },
  coverBottom: {
    backgroundColor: C.coverDark,
    paddingTop: 28, paddingBottom: 28, paddingLeft: 48, paddingRight: 48,
  },
  coverMetaRow:   { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 14 },
  coverMetaLabel: { fontSize: 8.5, fontWeight: 400, color: 'rgba(255,255,255,0.70)', marginBottom: 4 },
  coverMetaValue: { fontSize: 13, fontWeight: 700, color: C.white },
  coverDivider:   { height: 1, backgroundColor: 'rgba(255,255,255,0.1)', marginBottom: 14 },
  coverGenerated: { fontSize: 8.5, fontWeight: 400, color: 'rgba(255,255,255,0.65)', textAlign: 'right' },

  page: {
    fontFamily: 'Pretendard', fontWeight: 500, fontSize: 9.5,
    color: C.text, backgroundColor: C.bg,
    paddingTop: 34, paddingBottom: 48, paddingLeft: 42, paddingRight: 42,
  },
  footer: {
    position: 'absolute', bottom: 16, left: 42, right: 42,
    flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
    borderTopWidth: 1, borderTopColor: C.card, borderTopStyle: 'solid', paddingTop: 6,
  },
  footerText:  { fontSize: 9, color: C.textLight },
  headerWrap: {
    marginBottom: 16, paddingBottom: 12,
    borderBottomWidth: 2, borderBottomColor: C.accent, borderBottomStyle: 'solid',
  },
  headerTitle: { fontSize: 20, fontWeight: 700, color: C.accent, marginBottom: 4 },
  headerMeta:  { fontSize: 9, color: C.textMuted },
  summaryBanner: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
    backgroundColor: C.white, borderRadius: 5,
    borderWidth: 1, borderColor: C.card, borderStyle: 'solid',
    padding: '7 14', marginBottom: 10,
  },
  summaryItem:    { flex: 1, alignItems: 'center' },
  summaryLabel:   { fontSize: 9, color: C.textMuted },
  summaryValue:   { fontSize: 19, fontWeight: 700, color: C.accent },
  summaryTrend:   { fontSize: 9, marginTop: 1 },
  summaryDivider: { width: 1, height: 28, backgroundColor: C.card },
  summarySubValue:{ fontSize: 12, fontWeight: 700, color: C.accent, marginTop: 2 },
  summaryComment: {
    backgroundColor: C.white, borderRadius: 5,
    borderWidth: 1, borderColor: C.card, borderStyle: 'solid',
    borderLeftWidth: 3, borderLeftColor: C.accent, borderLeftStyle: 'solid',
    padding: '6 12', marginBottom: 16,
  },
  summaryCommentText: { fontSize: 9.5, color: C.text, lineHeight: 1.6 },
  section:      { marginBottom: 14 },
  sectionTitle: {
    fontSize: 12, fontWeight: 700, color: C.text,
    marginBottom: 8, paddingBottom: 5,
    borderBottomWidth: 1, borderBottomColor: C.card, borderBottomStyle: 'solid',
  },
  cardRow: { flexDirection: 'row', gap: 6, marginBottom: 6 },
  card: {
    flex: 1, backgroundColor: C.white, borderRadius: 5, padding: 7,
    borderWidth: 1, borderColor: C.card, borderStyle: 'solid',
  },
  cardLabel: { fontSize: 9, color: C.textMuted, marginBottom: 2, fontWeight: 700 },
  cardValue: { fontSize: 16, fontWeight: 700 },
  cardTrend: { fontSize: 9, marginTop: 2 },
  tableWrap:   { borderRadius: 3, overflow: 'hidden', marginTop: 5 },
  tableHdrRow: { flexDirection: 'row', backgroundColor: C.card },
  tableRow: {
    flexDirection: 'row',
    borderBottomWidth: 1, borderBottomColor: C.card, borderBottomStyle: 'solid',
    backgroundColor: C.white,
  },
  th: { padding: '4 7', paddingRight: 12, fontSize: 9.5, fontWeight: 700, color: C.text },
  td: { padding: '5 7', paddingRight: 12, fontSize: 10,  color: C.text },

  cTableWrap:   { borderRadius: 3, overflow: 'hidden', marginTop: 4 },
  cTableHdrRow: { flexDirection: 'row', backgroundColor: C.card },
  cTableRow: {
    flexDirection: 'row',
    borderBottomWidth: 1, borderBottomColor: C.card, borderBottomStyle: 'solid',
    backgroundColor: C.white,
  },
  cTh: { padding: '4 7', paddingRight: 12, fontSize: 9.5, fontWeight: 700, color: C.text },
  cTd: { padding: '5 7', paddingRight: 12, fontSize: 10,  color: C.text },
  subTitle: {
    fontSize: 9.5, fontWeight: 700, color: C.text, marginBottom: 3,
    paddingLeft: 5,
    borderLeftWidth: 2, borderLeftColor: C.accent, borderLeftStyle: 'solid',
  },
  chartWrap: {
    backgroundColor: C.white, borderRadius: 4,
    borderWidth: 1, borderColor: C.card, borderStyle: 'solid',
    marginBottom: 4, paddingTop: 8, paddingBottom: 2, paddingLeft: 4, paddingRight: 4,
  },
  trustRow:       { flexDirection: 'row', gap: 8, alignItems: 'stretch' },
  trustDonutWrap: {
    backgroundColor: C.white, borderRadius: 5,
    borderWidth: 1, borderColor: C.card, borderStyle: 'solid',
    paddingTop: 6, paddingBottom: 6, paddingLeft: 5, paddingRight: 5,
    alignItems: 'center', justifyContent: 'center',
  },
  trustCardsWrap: { flex: 1, flexDirection: 'column', gap: 4 },
  trustCard: {
    flex: 1,
    backgroundColor: C.white, borderRadius: 5, padding: '5 10',
    borderWidth: 1, borderColor: C.card, borderStyle: 'solid',
    flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between',
  },
  trustCardLeft: { flexDirection: 'row', alignItems: 'center', gap: 7 },
  trustDot:      { width: 8, height: 8, borderRadius: 4 },
});

// 공격 유형별 조회/비교 주간 바 차트 (차트 크기: H 수정 시 mBottom도 확인)
function PdfBarChart({ data }) {
  const W = 511, H = 150;
  const mTop = 12, mRight = 16, mBottom = 42, mLeft = 32;
  const cW = W - mLeft - mRight, cH = H - mTop - mBottom;
  const maxRaw = Math.max(...data.flatMap(d => [d.thisWeek, d.prevWeek]), 1);
  const yMax   = niceMax(maxRaw);
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(t => Math.round(yMax * t));
  const n = data.length, groupW = cW / n;
  const barW = Math.min(groupW * 0.28, 17), gap = 2;
  const xC = (i) => mLeft + groupW * i + groupW / 2;
  const yP = (v) => mTop + cH - Math.max(0, (Math.min(v, yMax) / yMax) * cH);
  const bH = (v) => Math.max(0, (Math.min(v, yMax) / yMax) * cH);

  return (
    <Svg width={W} height={H}>
      {yTicks.map(tick => {
        const y = yP(tick);
        return (
          <G key={tick}>
            <Line x1={mLeft} y1={y} x2={mLeft+cW} y2={y} stroke={C.gridClr} strokeWidth={0.5} />
            <Text x={mLeft-3} y={y+2.5} fontFamily={SVG_FONT} fontSize={9} fill={C.textLight} textAnchor="end">{tick}</Text>
          </G>
        );
      })}
      <Line x1={mLeft} y1={mTop}    x2={mLeft}    y2={mTop+cH} stroke={C.axisClr} strokeWidth={0.75} />
      <Line x1={mLeft} y1={mTop+cH} x2={mLeft+cW} y2={mTop+cH} stroke={C.axisClr} strokeWidth={0.75} />
      {data.map((d, i) => {
        const cx = xC(i);
        const lines = d.lines ?? [d.label];
        return (
          <G key={i}>
            <Rect x={cx-barW-gap} y={yP(d.thisWeek)} width={barW} height={bH(d.thisWeek)} fill={C.chart1} />
            <Rect x={cx+gap}      y={yP(d.prevWeek)} width={barW} height={bH(d.prevWeek)} fill={C.chart2} />
            {lines.map((line, li) => (
              <Text key={li} x={cx} y={mTop+cH+11+li*10}
                fontFamily={SVG_FONT} fontSize={9} fill={C.textMuted} textAnchor="middle">{line}</Text>
            ))}
          </G>
        );
      })}
      <Rect x={W/2-60} y={H-14} width={9} height={9} fill={C.chart1} />
      <Text x={W/2-47} y={H-6}  fontFamily={SVG_FONT} fontSize={9} fill={C.textMuted}>조회 주간</Text>
      <Rect x={W/2+6}  y={H-14} width={9} height={9} fill={C.chart2} />
      <Text x={W/2+19} y={H-6}  fontFamily={SVG_FONT} fontSize={9} fill={C.textMuted}>비교 주간</Text>
    </Svg>
  );
}

// 요일별 탐지 추이 라인 차트 (조회 주간: 실선, 비교 주간: 점선)
function PdfLineChart({ thisWeek, prevWeek }) {
  const days = ['월', '화', '수', '목', '금', '토', '일'];
  const W = 511, H = 160;
  const mTop = 12, mRight = 24, mBottom = 46, mLeft = 32;
  const cW = W - mLeft - mRight, cH = H - mTop - mBottom;
  const tw = thisWeek ?? days.map(() => ({ count: 0 }));
  const pw = prevWeek ?? days.map(() => ({ count: 0 }));
  const yMax   = niceMax(Math.max(...tw.map(d => d.count), ...pw.map(d => d.count), 1));
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(t => Math.round(yMax * t));
  const xP = (i) => mLeft + (cW / (days.length - 1)) * i;
  const yP = (v) => mTop + cH - Math.max(0, (Math.min(v, yMax) / yMax) * cH);
  const thisPoints = tw.map((d, i) => `${xP(i)},${yP(d.count)}`).join(' ');
  const prevPoints = pw.map((d, i) => `${xP(i)},${yP(d.count)}`).join(' ');

  return (
    <Svg width={W} height={H}>
      {yTicks.map(tick => {
        const y = yP(tick);
        return (
          <G key={tick}>
            <Line x1={mLeft} y1={y} x2={mLeft+cW} y2={y} stroke={C.gridClr} strokeWidth={0.5} />
            <Text x={mLeft-3} y={y+2.5} fontFamily={SVG_FONT} fontSize={9} fill={C.textLight} textAnchor="end">{tick}</Text>
          </G>
        );
      })}
      <Line x1={mLeft} y1={mTop}    x2={mLeft}    y2={mTop+cH} stroke={C.axisClr} strokeWidth={0.75} />
      <Line x1={mLeft} y1={mTop+cH} x2={mLeft+cW} y2={mTop+cH} stroke={C.axisClr} strokeWidth={0.75} />
      <Polyline points={thisPoints} fill="none" stroke={C.chart1} strokeWidth={1.5} />
      <Polyline points={prevPoints} fill="none" stroke={C.chart2} strokeWidth={1.5} strokeDasharray="5,3" />
      {days.map((day, i) => (
        <G key={i}>
          <Circle cx={xP(i)} cy={yP(tw[i]?.count ?? 0)} r={2.8} fill={C.chart1} />
          <Circle cx={xP(i)} cy={yP(pw[i]?.count ?? 0)} r={2.8} fill={C.chart2} />
          <Text x={xP(i)} y={mTop+cH+11} fontFamily={SVG_FONT} fontSize={9} fill={C.textMuted} textAnchor="middle">{day}</Text>
        </G>
      ))}
      <Line x1={W/2-70} y1={H-12} x2={W/2-56} y2={H-12} stroke={C.chart1} strokeWidth={1.5} />
      <Circle cx={W/2-63} cy={H-12} r={2.5} fill={C.chart1} />
      <Text x={W/2-52} y={H-9} fontFamily={SVG_FONT} fontSize={9} fill={C.textMuted}>조회 주간</Text>
      <Line x1={W/2+8}  y1={H-12} x2={W/2+22} y2={H-12} stroke={C.chart2} strokeWidth={1.5} strokeDasharray="4,2" />
      <Circle cx={W/2+15} cy={H-12} r={2.5} fill={C.chart2} />
      <Text x={W/2+26} y={H-9} fontFamily={SVG_FONT} fontSize={9} fill={C.textMuted}>비교 주간</Text>
    </Svg>
  );
}

// 공격 유형 분포 도넛 차트 + 범례 (⑤ 섹션 우측 배치)
function PdfAttackDonutChart({ items }) {
  const W = 152, H = 178;
  const cx = 76, cy = 66, outerR = 48, innerR = 28;
  const total = items.reduce((a, b) => a + b.count, 0) || 1;
  const segments = [];
  let cur = 0;
  items.forEach((item) => {
    const angle = (item.count / total) * 360;
    segments.push({ ...item, startDeg: cur, endDeg: cur + angle, color: ATTACK_DONUT_COLOR[item.attack_type] ?? C.textLight });
    cur += angle;
  });
  const legendY0 = 124, legendRowH = 14;
  const col1X = 8, col2X = 80;

  return (
    <Svg width={W} height={H}>
      {segments.map((seg, i) => (
        <Path key={i} d={donutArcPath(cx, cy, outerR, innerR, seg.startDeg, seg.endDeg)} fill={seg.color} />
      ))}
      <Circle cx={cx} cy={cy} r={innerR - 1} fill={C.white} />
      <Text x={cx} y={cy-4} fontFamily={SVG_FONT} fontSize={13} fontWeight={700} fill={C.accent} textAnchor="middle">{total}</Text>
      <Text x={cx} y={cy+8} fontFamily={SVG_FONT} fontSize={7.5} fill={C.textMuted} textAnchor="middle">탐지 분포</Text>
      {segments.map((seg, i) => {
        const col   = i < 3 ? col1X : col2X;
        const row   = i < 3 ? i : i - 3;
        const y     = legendY0 + row * legendRowH;
        const pct   = Math.round((seg.count / total) * 100);
        const label = ATTACK_SHORT[seg.attack_type] ?? seg.attack_type;
        return (
          <G key={i}>
            <Rect x={col} y={y} width={7} height={7} fill={seg.color} />
            <Text x={col+9} y={y+6.5} fontFamily={SVG_FONT} fontSize={8} fill={C.textMuted}>{label} {pct}%</Text>
          </G>
        );
      })}
    </Svg>
  );
}

// 신뢰도 분포 도넛 차트 (③ 섹션 좌측 배치, 범례는 우측 카드로 대체)
function PdfTrustDonutChart({ items }) {
  const W = 112, H = 112;
  const cx = 56, cy = 56, outerR = 44, innerR = 27;
  const total = items.reduce((a, b) => a + b.count, 0) || 1;
  const segments = [];
  let cur = 0;
  items.forEach(item => {
    const angle = (item.count / total) * 360;
    segments.push({ ...item, startDeg: cur, endDeg: cur + angle });
    cur += angle;
  });

  return (
    <Svg width={W} height={H}>
      {segments.map((seg, i) => (
        <Path key={i} d={donutArcPath(cx, cy, outerR, innerR, seg.startDeg, seg.endDeg)}
          fill={DONUT_COLOR[seg.trust_level] ?? C.textLight} />
      ))}
      <Circle cx={cx} cy={cy} r={innerR - 1} fill={C.white} />
      <Text x={cx} y={cy-3} fontFamily={SVG_FONT} fontSize={12} fontWeight={700} fill={C.accent} textAnchor="middle">{total}</Text>
      <Text x={cx} y={cy+8} fontFamily={SVG_FONT} fontSize={7.5} fill={C.textMuted} textAnchor="middle">총 탐지</Text>
    </Svg>
  );
}

// 표지 페이지: 로고, 제목, 조회/비교 주간, 생성 일시
function CoverPage({ data }) {
  return (
    <Page size="A4" style={s.coverPage}>
      <View style={s.coverTop}>
        <View style={s.coverLogoWrap}>
          <Image src="/logo.png" style={s.coverLogo} />
        </View>
        <View style={s.coverAccentBar} />
        <Text style={s.coverTitle}>IDS 탐지 통계 리포트</Text>
        <Text style={s.coverSubtitle}>Cyber Threat Intelligence System · CTI-nk</Text>
      </View>
      <View style={s.coverBottom}>
        <View style={s.coverMetaRow}>
          <View>
            <Text style={s.coverMetaLabel}>조회 주간</Text>
            <Text style={s.coverMetaValue}>{data.this_week_from}  ~  {data.this_week_to}</Text>
          </View>
          <View>
            <Text style={s.coverMetaLabel}>비교 주간</Text>
            <Text style={s.coverMetaValue}>{data.last_week_from}  ~  {data.last_week_to}</Text>
          </View>
        </View>
        <View style={s.coverDivider} />
        <Text style={s.coverGenerated}>생성 일시  {nowString()}</Text>
      </View>
    </Page>
  );
}

// 페이지 푸터: 리포트명 + 기간 + 페이지 번호 (표지 제외, 1/N 형식)
function PageFooter({ data }) {
  return (
    <View style={s.footer} fixed>
      <Text style={s.footerText}>
        CTI-nk IDS 탐지 통계 리포트  |  {data.this_week_from} ~ {data.this_week_to}
      </Text>
      <Text style={s.footerText}
        render={({ pageNumber, totalPages }) => `${pageNumber - 1} / ${totalPages - 1}`} />
    </View>
  );
}

// 본문 상단 헤더: 리포트 제목 + 생성 일시/기간 메타 정보
function PdfHeader({ data }) {
  return (
    <View style={s.headerWrap}>
      <Text style={s.headerTitle}>CTI-nk  IDS 탐지 통계 리포트</Text>
      <Text style={s.headerMeta}>
        생성 일시: {nowString()}    |    조회 주간: {data.this_week_from} ~ {data.this_week_to}    |    비교 주간: {data.last_week_from} ~ {data.last_week_to}
      </Text>
    </View>
  );
}

// 요약 배너: 총 탐지·SNORT·YARA·최다 유형·HIGH 신뢰도 5개 지표
function SummaryBanner({ data }) {
  const totalThis = (data.by_rule_type_result ?? []).reduce((acc, r) =>
    acc + (r.alert_count ?? 0) + (r.detected_count ?? 0) + (r.blocked_count ?? 0), 0);
  const totalPrev = (data.by_rule_type_result ?? []).reduce((acc, r) =>
    acc + (r.prev_alert_count ?? 0) + (r.prev_detected_count ?? 0) + (r.prev_blocked_count ?? 0), 0);
  const snortRow = (data.by_rule_type_result ?? []).find(r => r.rule_type === 'SNORT');
  const yaraRow  = (data.by_rule_type_result ?? []).find(r => r.rule_type === 'YARA');
  const snortSum  = snortRow ? (snortRow.alert_count ?? 0) + (snortRow.detected_count ?? 0) + (snortRow.blocked_count ?? 0) : 0;
  const yaraSum   = yaraRow  ? (yaraRow.alert_count  ?? 0) + (yaraRow.detected_count  ?? 0) + (yaraRow.blocked_count  ?? 0) : 0;
  const snortPrev = snortRow ? (snortRow.prev_alert_count ?? 0) + (snortRow.prev_detected_count ?? 0) + (snortRow.prev_blocked_count ?? 0) : 0;
  const yaraPrev  = yaraRow  ? (yaraRow.prev_alert_count  ?? 0) + (yaraRow.prev_detected_count  ?? 0) + (yaraRow.prev_blocked_count  ?? 0) : 0;
  const topAttack      = [...(data.by_attack_type ?? [])].sort((a, b) => b.count - a.count)[0];
  const topAttackLabel = topAttack ? (ATTACK_SHORT[topAttack.attack_type] ?? topAttack.attack_type) : '-';
  const trustTotal = (data.by_trust_level ?? []).reduce((a, b) => a + b.count, 0) || 1;
  const highItem   = (data.by_trust_level ?? []).find(t => t.trust_level === 'HIGH');
  const highPct    = highItem ? Math.round((highItem.count / trustTotal) * 100) : 0;

  return (
    <View style={s.summaryBanner}>
      <View style={s.summaryItem}>
        <Text style={s.summaryLabel}>조회 주간 총 탐지</Text>
        <Text style={s.summaryValue}>{totalThis}</Text>
        <Text style={[s.summaryTrend, { color: trendColor(totalThis, totalPrev) }]}>
          {trendText(totalThis, totalPrev)}
        </Text>
      </View>
      <View style={s.summaryDivider} />
      <View style={s.summaryItem}>
        <Text style={s.summaryLabel}>SNORT</Text>
        <Text style={[s.summarySubValue, { color: C.text, fontSize: 12 }]}>{snortSum}</Text>
        <Text style={[s.summaryTrend, { color: trendColor(snortSum, snortPrev) }]}>
          {trendText(snortSum, snortPrev)}
        </Text>
      </View>
      <View style={s.summaryDivider} />
      <View style={s.summaryItem}>
        <Text style={s.summaryLabel}>YARA</Text>
        <Text style={[s.summarySubValue, { color: C.text, fontSize: 12 }]}>{yaraSum}</Text>
        <Text style={[s.summaryTrend, { color: trendColor(yaraSum, yaraPrev) }]}>
          {trendText(yaraSum, yaraPrev)}
        </Text>
      </View>
      <View style={s.summaryDivider} />
      <View style={s.summaryItem}>
        <Text style={s.summaryLabel}>최다 탐지 유형</Text>
        <Text style={[s.summarySubValue, { color: C.text, fontSize: 12 }]}>{topAttackLabel}</Text>
        {topAttack && <Text style={[s.summaryLabel, { marginTop: 2 }]}>{topAttack.count}건</Text>}
      </View>
      <View style={s.summaryDivider} />
      <View style={s.summaryItem}>
        <Text style={s.summaryLabel}>HIGH 신뢰도</Text>
        <Text style={[s.summarySubValue, { color: C.highClr }]}>{highPct}%</Text>
        {highItem && <Text style={[s.summaryLabel, { marginTop: 2 }]}>{highItem.count}건</Text>}
      </View>
    </View>
  );
}

// 총평 블록: buildSummaryText()로 생성한 3문장 자동 총평
function SummaryComment({ data }) {
  return (
    <View style={s.summaryComment}>
      <Text style={s.summaryCommentText}>{buildSummaryText(data)}</Text>
    </View>
  );
}

// ① 전체 탐지 현황
function TotalDetectionSection({ data }) {
  const snort = (data.by_rule_type_result ?? []).find(r => r.rule_type === 'SNORT') ?? {};
  const yara  = (data.by_rule_type_result ?? []).find(r => r.rule_type === 'YARA')  ?? {};
  const items = [
    { label: 'SNORT · ALERT',  curr: snort.alert_count    ?? 0, prev: snort.prev_alert_count    ?? 0, color: C.alertClr  },
    { label: 'SNORT · DETECT', curr: snort.detected_count ?? 0, prev: snort.prev_detected_count ?? 0, color: C.detectClr },
    { label: 'SNORT · BLOCK',  curr: snort.blocked_count  ?? 0, prev: snort.prev_blocked_count  ?? 0, color: C.blockClr  },
    { label: 'YARA · ALERT',   curr: yara.alert_count     ?? 0, prev: yara.prev_alert_count     ?? 0, color: C.alertClr  },
    { label: 'YARA · DETECT',  curr: yara.detected_count  ?? 0, prev: yara.prev_detected_count  ?? 0, color: C.detectClr },
    { label: 'YARA · BLOCK',   curr: yara.blocked_count   ?? 0, prev: yara.prev_blocked_count   ?? 0, color: C.blockClr  },
  ];
  return (
    <View style={s.section}>
      <Text style={s.sectionTitle}>① 전체 탐지 현황</Text>
      {[items.slice(0, 3), items.slice(3)].map((row, ri) => (
        <View key={ri} style={s.cardRow}>
          {row.map(item => (
            <View key={item.label} style={[s.card, { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'flex-end' }]}>
              <View>
                <Text style={s.cardLabel}>{item.label}</Text>
                <Text style={[s.cardValue, { color: item.color }]}>{item.curr}</Text>
              </View>
              <Text style={[s.cardTrend, { color: trendColor(item.curr, item.prev) }]}>
                {trendText(item.curr, item.prev)}
              </Text>
            </View>
          ))}
        </View>
      ))}
    </View>
  );
}

// ② 정책 유형별 상위 탐지 정책 Top 5
function TopRulesSection({ data }) {
  return (
    <View style={s.section}>
      <Text style={s.sectionTitle}>④ 정책 유형별 상위 탐지 정책 Top 5</Text>
      {(data.top_rules_by_rule_type ?? []).map(section => (
        <View key={section.rule_type} style={{ marginBottom: 8 }}>
          <Text style={[s.subTitle, { marginTop: 8 }]}>{section.rule_type}</Text>
          <View style={s.tableWrap}>
            <View style={s.tableHdrRow}>
              <Text style={[s.th, { flex: 0.6, textAlign: 'center' }]}>순위</Text>
              <Text style={[s.th, { flex: 4 }]}>정책명</Text>
              <Text style={[s.th, { flex: 2 }]}>공격 유형</Text>
              <Text style={[s.th, { flex: 1, textAlign: 'right' }]}>탐지</Text>
            </View>
            {(section.rules ?? []).length === 0 ? (
              <View style={s.tableRow}>
                <Text style={[s.td, { color: C.textLight }]}>데이터 없음</Text>
              </View>
            ) : (section.rules ?? []).map((r, i) => (
              <View key={i} style={[s.tableRow, i === 0 && { backgroundColor: '#F2F6FC' }]}>
                <Text style={[s.td, { flex: 0.6, textAlign: 'center', color: i === 0 ? C.accent : C.textMuted, fontWeight: i === 0 ? 700 : 400 }]}>
                  {RANK_LABEL[i] ?? `${i + 1}위`}
                </Text>
                <Text style={[s.td, { flex: 4 }]}>{truncateName(r.rule_name)}</Text>
                <Text style={[s.td, { flex: 2, color: C.textMuted }]}>
                  {ATTACK_LABEL[r.attack_type] ?? r.attack_type ?? '-'}
                </Text>
                <Text style={[s.td, { flex: 1, textAlign: 'right', fontWeight: 700 }]}>{r.count}</Text>
              </View>
            ))}
          </View>
        </View>
      ))}
    </View>
  );
}

// ③ 신뢰도별 탐지 건수
function TrustLevelSection({ data }) {
  const items = data.by_trust_level ?? [];
  const total = items.reduce((a, b) => a + b.count, 0) || 1;

  return (
    <View style={[s.section, { marginBottom: 22 }]} wrap={false}>
      <Text style={[s.sectionTitle, { marginBottom: 6 }]}>③ 신뢰도별 탐지 건수</Text>
      <View style={s.trustRow}>
        <View style={s.trustDonutWrap}>
          <PdfTrustDonutChart items={items} />
        </View>
        <View style={s.trustCardsWrap}>
          {items.map(item => {
            const pct = Math.round((item.count / total) * 100);
            return (
              <View key={item.trust_level} style={s.trustCard}>
                <View style={s.trustCardLeft}>
                  <View style={[s.trustDot, { backgroundColor: DONUT_COLOR[item.trust_level] ?? C.textLight }]} />
                  <View>
                    <Text style={[s.cardLabel, { marginBottom: 1 }]}>{item.trust_level}</Text>
                    <Text style={[s.cardValue, { fontSize: 13, color: TRUST_COLOR[item.trust_level] ?? C.text }]}>
                      {item.count}건
                    </Text>
                  </View>
                </View>
                <View style={{ alignItems: 'flex-end' }}>
                  <Text style={[s.cardLabel, { fontSize: 9.5, fontWeight: 700, color: C.textMuted, marginBottom: 1 }]}>
                    {pct}%
                  </Text>
                  <Text style={[s.cardTrend, { color: trendColor(item.count, item.prev_count) }]}>
                    {trendText(item.count, item.prev_count)}
                  </Text>
                </View>
              </View>
            );
          })}
        </View>
      </View>
    </View>
  );
}

// ④ 요일별 탐지 추이
function DateTrendSection({ data }) {
  const days = ['월', '화', '수', '목', '금', '토', '일'];
  const tw = data.by_date      ?? [];
  const pw = data.prev_by_date ?? [];

  return (
    <View style={[s.section, { marginBottom: 0 }]} wrap={false}>
      <Text style={s.sectionTitle}>② 요일별 탐지 추이 (조회 주간 vs 비교 주간)</Text>
      <View style={s.chartWrap}>
        <PdfLineChart thisWeek={tw} prevWeek={pw} />
      </View>
      <View style={s.tableWrap}>
        <View style={s.tableHdrRow}>
          <Text style={[s.th, { flex: 0.8, textAlign: 'center' }]}>요일</Text>
          <Text style={[s.th, { flex: 1.7 }]}>조회 주간 날짜</Text>
          <Text style={[s.th, { flex: 1.2, textAlign: 'right' }]}>탐지 건수</Text>
          <Text style={[s.th, { flex: 1.7 }]}>비교 주간 날짜</Text>
          <Text style={[s.th, { flex: 1.2, textAlign: 'right' }]}>탐지 건수</Text>
          <Text style={[s.th, { flex: 2.8 }]}>증감</Text>
        </View>
        {days.map((day, i) => {
          const curr = tw[i]?.count ?? 0;
          const prev = pw[i]?.count ?? 0;
          return (
            <View key={i} style={s.tableRow}>
              <Text style={[s.td, { flex: 0.8, textAlign: 'center', fontWeight: 700 }]}>{day}</Text>
              <Text style={[s.td, { flex: 1.7, color: C.textMuted }]}>{fmtMonthDay(tw[i]?.date)}</Text>
              <Text style={[s.td, { flex: 1.2, textAlign: 'right', fontWeight: 700 }]}>{curr}</Text>
              <Text style={[s.td, { flex: 1.7, color: C.textMuted }]}>{fmtMonthDay(pw[i]?.date)}</Text>
              <Text style={[s.td, { flex: 1.2, textAlign: 'right', color: C.textMuted }]}>{prev}</Text>
              <Text style={[s.td, { flex: 2.8, color: trendColor(curr, prev) }]}>{trendText(curr, prev)}</Text>
            </View>
          );
        })}
      </View>
    </View>
  );
}

// ⑤ 공격 유형별 탐지 건수 현황
function AttackTypeSection({ data }) {
  const barData = (data.by_attack_type ?? []).map(item => ({
    lines:    ATTACK_CHART_LINES[item.attack_type] ?? [ATTACK_LABEL[item.attack_type] ?? item.attack_type],
    thisWeek: item.count,
    prevWeek: item.prev_count,
  }));

  return (
    <View style={s.section} break={true}>
      <Text style={s.sectionTitle}>⑤ 공격 유형별 탐지 건수 현황</Text>
      <View style={s.chartWrap}>
        <PdfBarChart data={barData} />
      </View>
      <View style={{ flexDirection: 'row', gap: 8, alignItems: 'flex-start', marginTop: 4 }} wrap={false}>
        <View style={{ flex: 1 }}>
          <View style={s.tableWrap}>
            <View style={s.tableHdrRow}>
              <Text style={[s.th, { flex: 3 }]}>공격 유형</Text>
              <Text style={[s.th, { flex: 1.5, textAlign: 'right' }]}>조회 주간</Text>
              <Text style={[s.th, { flex: 1.5, textAlign: 'right' }]}>비교 주간</Text>
              <Text style={[s.th, { flex: 2.5 }]}>증감</Text>
            </View>
            {(data.by_attack_type ?? []).map(item => (
              <View key={item.attack_type} style={s.tableRow}>
                <Text style={[s.td, { flex: 3 }]}>{ATTACK_LABEL[item.attack_type] ?? item.attack_type}</Text>
                <Text style={[s.td, { flex: 1.5, textAlign: 'right', fontWeight: 700 }]}>{item.count}</Text>
                <Text style={[s.td, { flex: 1.5, textAlign: 'right', color: C.textMuted }]}>{item.prev_count}</Text>
                <Text style={[s.td, { flex: 2.5, color: trendColor(item.count, item.prev_count) }]}>
                  {trendText(item.count, item.prev_count)}
                </Text>
              </View>
            ))}
          </View>
        </View>
        <View style={[s.chartWrap, { marginBottom: 0 }]}>
          <PdfAttackDonutChart items={data.by_attack_type ?? []} />
        </View>
      </View>
      <Text style={[s.sectionTitle, { marginTop: 14, fontSize: 10 }]}>유형별 상위 탐지 정책 Top 5</Text>
      {(data.top_rules_by_attack_type ?? []).map((section, si) => (
        <View key={section.attack_type} wrap={false}>
          <Text style={[s.subTitle, { marginTop: si === 0 ? 3 : 12 }]}>
            {ATTACK_LABEL[section.attack_type] ?? section.attack_type} — 상위 탐지 정책
          </Text>
          <View style={s.cTableWrap}>
            <View style={s.cTableHdrRow}>
              <Text style={[s.cTh, { flex: 0.6, textAlign: 'center' }]}>순위</Text>
              <Text style={[s.cTh, { flex: 1 }]}>정책 유형</Text>
              <Text style={[s.cTh, { flex: 4 }]}>정책명</Text>
              <Text style={[s.cTh, { flex: 1, textAlign: 'right' }]}>탐지</Text>
            </View>
            {(section.rules ?? []).map((r, i) => (
              <View key={i} style={[s.cTableRow, i === 0 && { backgroundColor: '#F2F6FC' }]}>
                <Text style={[s.cTd, { flex: 0.6, textAlign: 'center', color: i === 0 ? C.accent : C.textMuted, fontWeight: i === 0 ? 700 : 400 }]}>
                  {RANK_LABEL[i] ?? `${i + 1}위`}
                </Text>
                <Text style={[s.cTd, { flex: 1 }]}>{r.rule_type}</Text>
                <Text style={[s.cTd, { flex: 4 }]}>{truncateName(r.rule_name, 50)}</Text>
                <Text style={[s.cTd, { flex: 1, textAlign: 'right', fontWeight: 700 }]}>{r.count}</Text>
              </View>
            ))}
          </View>
        </View>
      ))}
    </View>
  );
}

function ReportDocument({ data }) {
  return (
    <Document title="CTI-nk IDS 탐지 통계 리포트" author="CTI-nk">
      <CoverPage data={data} />
      <Page size="A4" style={s.page}>
        <PdfHeader data={data} />
        <SummaryBanner data={data} />
        <SummaryComment data={data} />
        <TotalDetectionSection data={data} />
        <DateTrendSection data={data} />
        <TrustLevelSection data={data} />
        <TopRulesSection data={data} />
        <AttackTypeSection data={data} />
        <PageFooter data={data} />
      </Page>
    </Document>

  );
}

export async function generateIdsReport(data) {
  const blob   = await pdf(<ReportDocument data={data} />).toBlob();
  const url    = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href     = url;
  anchor.download = `CTInk_IDS_Report_${(data.this_week_from ?? '').replace(/-/g, '')}-${(data.this_week_to ?? '').replace(/-/g, '')}.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}