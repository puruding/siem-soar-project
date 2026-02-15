import { NavLink, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils';
import {
  LayoutDashboard,
  AlertTriangle,
  FolderKanban,
  Terminal,
  Workflow,
  Settings,
  Bot,
  ChevronLeft,
  ChevronRight,
  Circle,
  Activity,
  Zap,
  Package,
  FileCode,
  Server,
  ShieldAlert,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { useState } from 'react';

const navItems = [
  {
    title: 'Dashboard',
    icon: LayoutDashboard,
    href: '/dashboard',
    description: 'Security overview',
  },
  {
    title: 'Alerts',
    icon: AlertTriangle,
    href: '/alerts',
    description: 'Security alerts',
    badge: 127,
  },
  {
    title: 'Cases',
    icon: FolderKanban,
    href: '/cases',
    description: 'Incident management',
    badge: 12,
  },
  {
    title: 'Query',
    icon: Terminal,
    href: '/query',
    description: 'Data exploration',
  },
  {
    title: 'Playbooks',
    icon: Workflow,
    href: '/playbooks',
    description: 'Automation workflows',
  },
  {
    title: 'AI Copilot',
    icon: Bot,
    href: '/copilot',
    description: 'AI assistant',
  },
  {
    title: 'Products',
    icon: Package,
    href: '/products',
    description: 'Product management',
  },
  {
    title: 'Parsers',
    icon: FileCode,
    href: '/parsers',
    description: 'Log parsers',
  },
  {
    title: 'Assets',
    icon: Server,
    href: '/assets',
    description: 'Asset inventory',
  },
  {
    title: 'Rules',
    icon: ShieldAlert,
    href: '/rules',
    description: 'Detection rules',
  },
];

const bottomItems = [
  {
    title: 'Settings',
    icon: Settings,
    href: '/settings',
  },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  return (
    <aside
      className={cn(
        'relative flex flex-col h-full bg-[#1F2527] border-r-2 border-[#2D3339] transition-all duration-300 shadow-xl z-20',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Accent border */}
      <div className="absolute top-0 right-0 bottom-0 w-0.5 bg-gradient-to-b from-transparent via-[#00A4A6]/40 to-transparent" />

      {/* Navigation */}
      <nav className="flex-1 py-6 px-3 space-y-2 overflow-y-auto scrollbar-thin scrollbar-thumb-[#2D3339] scrollbar-track-transparent">
        {navItems.map((item) => {
          const isActive = location.pathname.startsWith(item.href);
          return (
            <Tooltip key={item.href} delayDuration={0}>
              <TooltipTrigger asChild>
                <NavLink
                  to={item.href}
                  className={cn(
                    'relative flex items-center gap-3 px-3 py-2.5 rounded-sm transition-all duration-200 group border',
                    isActive
                      ? 'bg-[#00A4A6]/15 text-white border-[#00A4A6]/50 shadow-[0_0_15px_rgba(0,164,166,0.15)]'
                      : 'text-[#9BA7B4] hover:text-white hover:bg-white/5 border-transparent hover:border-[#2D3339]',
                    collapsed && 'justify-center px-2'
                  )}
                >
                  {/* Active indicator bar */}
                  {isActive && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-8 bg-[#00A4A6] rounded-r shadow-[0_0_8px_rgba(0,164,166,0.6)]" />
                  )}

                  {/* Icon */}
                  <div className="relative">
                    <item.icon
                      className={cn(
                        'w-5 h-5 shrink-0 transition-colors',
                        isActive && 'text-[#00A4A6]'
                      )}
                    />
                    {/* Animated ring for active item */}
                    {isActive && (
                      <div className="absolute inset-0 rounded-full border-2 border-[#00A4A6] opacity-30 scale-150 animate-ping" />
                    )}
                  </div>

                  {/* Label & Badge */}
                  {!collapsed && (
                    <>
                      <span className={cn(
                        'flex-1 font-medium text-sm tracking-wide',
                        isActive && 'font-bold'
                      )}>
                        {item.title}
                      </span>
                      {item.badge && (
                        <span className={cn(
                          'flex items-center justify-center min-w-[24px] h-5 px-1.5 rounded text-[10px] font-bold font-mono',
                          isActive
                            ? 'bg-[#00A4A6] text-white shadow-[0_0_8px_rgba(0,164,166,0.4)]'
                            : 'bg-[#2D3339] text-[#9BA7B4]'
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}

                  {/* Collapsed badge indicator */}
                  {collapsed && item.badge && (
                    <div className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-[#DC4E41] shadow-[0_0_6px_rgba(220,78,65,0.6)]" />
                  )}
                </NavLink>
              </TooltipTrigger>
              {collapsed && (
                <TooltipContent side="right" className="bg-[#1F2527] border-[#2D3339] shadow-xl">
                  <div className="flex flex-col gap-1">
                    <p className="font-bold text-white text-sm">{item.title}</p>
                    <p className="text-xs text-[#9BA7B4]">{item.description}</p>
                    {item.badge && (
                      <div className="flex items-center gap-1.5 pt-1 border-t border-[#2D3339] mt-1">
                        <Circle className="w-2 h-2 fill-[#DC4E41] text-[#DC4E41]" />
                        <span className="text-xs font-mono text-white">{item.badge} active</span>
                      </div>
                    )}
                  </div>
                </TooltipContent>
              )}
            </Tooltip>
          );
        })}
      </nav>

      {/* System Status Panel */}
      {!collapsed && (
        <div className="px-3 pb-4">
          <div className="relative p-4 rounded-sm bg-[#171D21] border border-[#2D3339] overflow-hidden">
            {/* Animated background gradient */}
            <div className="absolute inset-0 bg-gradient-to-br from-[#00A4A6]/5 to-transparent opacity-50" />

            <div className="relative z-10">
              <div className="flex items-center justify-between mb-3">
                <span className="text-[10px] text-[#9BA7B4] uppercase tracking-widest font-mono font-bold">
                  System Status
                </span>
                <div className="flex items-center gap-1.5">
                  <Activity className="w-3 h-3 text-[#00A4A6] animate-pulse" />
                  <span className="text-xs text-[#00A4A6] font-bold uppercase tracking-wide">
                    Operational
                  </span>
                </div>
              </div>

              {/* Metrics grid */}
              <div className="grid grid-cols-2 gap-3">
                <div className="flex flex-col">
                  <span className="text-[10px] text-[#9BA7B4] uppercase tracking-wider mb-0.5">
                    EPS
                  </span>
                  <div className="flex items-baseline gap-1">
                    <span className="text-lg font-bold text-white font-mono leading-none">
                      45.2
                    </span>
                    <span className="text-xs text-[#9BA7B4] font-mono">K</span>
                  </div>
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] text-[#9BA7B4] uppercase tracking-wider mb-0.5">
                    Latency
                  </span>
                  <div className="flex items-baseline gap-1">
                    <span className="text-lg font-bold text-white font-mono leading-none">
                      12
                    </span>
                    <span className="text-xs text-[#9BA7B4] font-mono">ms</span>
                  </div>
                </div>
              </div>

              {/* Performance bar */}
              <div className="mt-3 pt-3 border-t border-[#2D3339]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-[#9BA7B4] uppercase tracking-wider">
                    Performance
                  </span>
                  <span className="text-[10px] text-[#00A4A6] font-mono font-bold">
                    98%
                  </span>
                </div>
                <div className="h-1.5 bg-[#2D3339] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-[#00A4A6] to-[#5CC05C] shadow-[0_0_8px_rgba(0,164,166,0.4)] rounded-full transition-all duration-500"
                    style={{ width: '98%' }}
                  />
                </div>
              </div>
            </div>

            {/* Corner accent */}
            <div className="absolute top-0 right-0 w-16 h-16 bg-gradient-to-br from-[#00A4A6]/10 to-transparent rounded-bl-full" />
          </div>
        </div>
      )}

      {/* Collapsed system status indicator */}
      {collapsed && (
        <div className="px-3 pb-4">
          <Tooltip delayDuration={0}>
            <TooltipTrigger asChild>
              <div className="flex items-center justify-center w-10 h-10 rounded-sm bg-[#171D21] border border-[#2D3339]">
                <Zap className="w-4 h-4 text-[#00A4A6]" />
              </div>
            </TooltipTrigger>
            <TooltipContent side="right" className="bg-[#1F2527] border-[#2D3339]">
              <div className="flex flex-col gap-1">
                <p className="font-bold text-white text-sm">System Status</p>
                <div className="flex items-center gap-1.5 text-xs">
                  <Circle className="w-2 h-2 fill-[#00A4A6] text-[#00A4A6]" />
                  <span className="text-[#00A4A6]">Operational</span>
                </div>
                <div className="pt-1 mt-1 border-t border-[#2D3339] text-xs space-y-0.5">
                  <div className="flex justify-between gap-2">
                    <span className="text-[#9BA7B4]">EPS:</span>
                    <span className="text-white font-mono">45.2K</span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#9BA7B4]">Latency:</span>
                    <span className="text-white font-mono">12ms</span>
                  </div>
                </div>
              </div>
            </TooltipContent>
          </Tooltip>
        </div>
      )}

      {/* Bottom items */}
      <div className="px-3 pb-3 pt-3 border-t-2 border-[#2D3339]">
        {bottomItems.map((item) => (
          <Tooltip key={item.href} delayDuration={0}>
            <TooltipTrigger asChild>
              <NavLink
                to={item.href}
                className={cn(
                  'flex items-center gap-3 px-3 py-2 rounded-sm transition-colors text-[#9BA7B4] hover:text-white hover:bg-white/5 border border-transparent hover:border-[#2D3339]',
                  collapsed && 'justify-center px-2'
                )}
              >
                <item.icon className="w-5 h-5 shrink-0" />
                {!collapsed && (
                  <span className="font-medium text-sm tracking-wide">{item.title}</span>
                )}
              </NavLink>
            </TooltipTrigger>
            {collapsed && (
              <TooltipContent side="right" className="bg-[#1F2527] border-[#2D3339]">
                {item.title}
              </TooltipContent>
            )}
          </Tooltip>
        ))}
      </div>

      {/* Collapse toggle button */}
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-3 top-6 w-6 h-6 rounded-full bg-[#1F2527] border-2 border-[#2D3339] hover:bg-[#2D3339] hover:border-[#00A4A6]/40 text-[#9BA7B4] hover:text-white shadow-lg transition-all duration-200 z-30"
      >
        {collapsed ? (
          <ChevronRight className="w-3.5 h-3.5" />
        ) : (
          <ChevronLeft className="w-3.5 h-3.5" />
        )}
      </Button>
    </aside>
  );
}
