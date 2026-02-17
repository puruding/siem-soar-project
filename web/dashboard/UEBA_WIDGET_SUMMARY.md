# UEBA Widget Implementation Summary

## Files Created/Modified

### 1. Created: `src/features/dashboard/components/UEBAWidget.tsx` (22KB)

A comprehensive UEBA analytics widget with three tabs:

#### Features Implemented:

**Overview Tab:**
- 4 summary statistics cards:
  - Total detections (총 탐지)
  - Critical alerts count
  - Average anomaly score (평균 점수)
  - Active entities count (활성 Entity)
- Donut chart showing anomaly type distribution
  - 10 anomaly types mapped to Korean labels
  - Color-coded by severity
- Recent anomaly detections list (최근 5개)
  - Entity ID with type icon (👤 user, 💻 host, 🌐 ip)
  - Severity badge
  - Anomaly type in Korean
  - Risk score percentage
  - Relative timestamp

**Entities Tab:**
- Top 10 high-risk entities ranked by risk score
- Each item shows:
  - Rank number (1-10)
  - Entity type icon and ID
  - Total anomaly count
  - Critical anomaly count (if any)
  - Risk score (color-coded: red 80%+, orange 60%+, yellow 40%+, green <40%)
  - Last detection timestamp

**Timeline Tab:**
- 24-hour detection timeline (line chart with area fill)
- Hourly detection statistics:
  - Maximum detections in an hour
  - Average detections per hour
  - Total detections in 24h

#### Technical Implementation:

**UI Components Used:**
- Card, CardHeader, CardTitle, CardContent
- Badge (with severity variants)
- Tabs, TabsList, TabsTrigger, TabsContent
- ScrollArea (for scrollable lists)

**Charts (ECharts):**
- Donut chart for anomaly type distribution
- Line/area chart for timeline view
- Dark theme compatible (hsl color system)
- Hover effects and tooltips

**Mock Data:**
- 6 sample anomaly events
- 8 sample entity risk profiles
- 24 hours of timeline data

**Color Scheme:**
- Critical: #ff2d55 (red)
- High: #ff6b35 (orange)
- Medium: #ffc107 (yellow)
- Low: #17c3b2 (teal)

### 2. Modified: `src/features/dashboard/components/Dashboard.tsx`

Added UEBA Analytics section between "Traditional Charts Row" and "Alerts and Cases Row":

```tsx
{/* UEBA Analytics Section */}
<div className="space-y-4">
  <div className="flex items-center gap-2">
    <Brain className="w-5 h-5 text-primary" />
    <h2 className="text-lg font-semibold">UEBA Analytics</h2>
    <Badge variant="secondary" className="text-xs">
      ML-Powered
    </Badge>
    <div className="flex-1 h-px bg-border ml-4" />
  </div>
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <UEBAWidget />
    {/* Future expansion space */}
    <div className="metric-card flex items-center justify-center text-muted-foreground">
      <div className="text-center">
        <Brain className="w-12 h-12 mx-auto mb-2 opacity-50" />
        <p>Entity Risk Analysis</p>
        <p className="text-xs">Coming Soon</p>
      </div>
    </div>
  </div>
</div>
```

**Imports Added:**
- `import { UEBAWidget } from './UEBAWidget';`
- `Brain` icon from lucide-react

## Anomaly Types Mapped to Korean

| English Key | Korean Label |
|------------|--------------|
| unusual_time | 비정상 시간대 |
| unusual_location | 비정상 위치 |
| unusual_volume | 비정상 볼륨 |
| credential_anomaly | 인증 이상 |
| lateral_movement | 측면 이동 |
| privilege_escalation | 권한 상승 |
| data_exfiltration | 데이터 유출 |
| account_compromise | 계정 침해 |
| insider_threat | 내부자 위협 |
| sequence_anomaly | 시퀀스 이상 |

## Visual Design

- **Dark theme compatible**: Uses hsl() color system
- **Hover effects**: Cards glow on hover with border color change
- **Smooth transitions**: 200ms duration for all transitions
- **Responsive grid**: Single column on mobile, 2 columns on large screens
- **Accessibility**: Proper semantic HTML, ARIA labels via shadcn/ui components

## Data Structure

### UEBAAnomalyData Interface
```typescript
interface UEBAAnomalyData {
  id: string;                           // UEBA-001
  entityId: string;                     // john.doe@company.com
  entityType: 'user' | 'host' | 'ip';
  anomalyType: string;                  // unusual_time
  score: number;                        // 0.0 ~ 1.0
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: string;                   // ISO 8601
  explanation: string;                  // 한글 설명
}
```

### EntityRiskData Interface
```typescript
interface EntityRiskData {
  entityId: string;
  entityType: 'user' | 'host' | 'ip';
  riskScore: number;                    // 0.0 ~ 1.0
  anomalyCount: number;
  lastDetectedAt: string;
  criticalCount: number;
}
```

## Integration Points for Backend

When integrating with real backend APIs, replace mock data with:

1. **Anomalies endpoint**: `GET /api/ueba/anomalies?limit=10&sort=-detectedAt`
2. **Entity risks endpoint**: `GET /api/ueba/entities/top-risk?limit=10`
3. **Timeline endpoint**: `GET /api/ueba/timeline?hours=24`

## Next Steps (Future Enhancements)

1. **Right column placeholder**: "Entity Risk Analysis" widget
   - Entity behavior baseline visualization
   - Peer group comparison
   - Risk trend chart (7-day sparkline)

2. **Real-time updates**: WebSocket integration for live anomaly feed

3. **Drill-down**: Click on anomaly to open detailed investigation panel

4. **Filtering**: Add severity/entity type filters to each tab

5. **Export**: Add CSV/JSON export for compliance reporting

## Verification

✅ TypeScript compilation: No errors in UEBA or Dashboard files
✅ Component structure: Follows existing patterns (SeverityDistribution, TopAlerts)
✅ Styling: Uses existing design system (tailwind classes, hsl colors)
✅ Icons: Uses lucide-react icons consistently
✅ Accessibility: Leverages shadcn/ui semantic components
