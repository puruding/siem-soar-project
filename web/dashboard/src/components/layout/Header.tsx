import { Bell, Search, Moon, Sun, User, Shield, AlertCircle, Activity } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { useThemeStore } from '@/stores/themeStore';
import { NavLink } from 'react-router-dom';
import { cn } from '@/lib/utils';

const navItems = [
  { label: 'Dashboard', href: '/dashboard' },
  { label: 'Alerts', href: '/alerts' },
  { label: 'Cases', href: '/cases' },
  { label: 'Query', href: '/query' },
  { label: 'Playbooks', href: '/playbooks' },
];

export function Header() {
  const { theme, setTheme } = useThemeStore();

  return (
    <header className="relative flex items-center h-14 px-4 bg-[#1F2527] border-b-2 border-[#00A4A6]/30 shadow-lg">
      {/* Accent line */}
      <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-[#00A4A6] to-transparent opacity-60" />

      {/* Logo + Brand */}
      <div className="flex items-center gap-3 pr-6 border-r border-border/50">
        <div className="relative flex items-center justify-center w-9 h-9 rounded bg-[#00A4A6]/10 border border-[#00A4A6]/40 shadow-[0_0_15px_rgba(0,164,166,0.2)]">
          <Shield className="w-5 h-5 text-[#00A4A6]" />
          <div className="absolute inset-0 rounded bg-[#00A4A6]/5 blur-sm" />
        </div>
        <div className="flex flex-col leading-none">
          <span className="text-sm font-bold tracking-wider text-white uppercase font-mono">
            SOC
          </span>
          <span className="text-[10px] text-[#00A4A6] uppercase tracking-widest font-mono">
            Command
          </span>
        </div>
      </div>

      {/* Horizontal Navigation */}
      <nav className="flex items-center gap-1 px-6">
        {navItems.map((item) => (
          <NavLink
            key={item.href}
            to={item.href}
            className={({ isActive }) =>
              cn(
                'relative px-4 py-1.5 text-sm font-medium transition-all duration-200 rounded-sm',
                isActive
                  ? 'text-white bg-[#00A4A6]/20 border border-[#00A4A6]/40 shadow-[0_0_10px_rgba(0,164,166,0.15)]'
                  : 'text-[#9BA7B4] hover:text-white hover:bg-white/5'
              )
            }
          >
            {({ isActive }) => (
              <>
                {item.label}
                {isActive && (
                  <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1/2 h-0.5 bg-[#00A4A6] rounded-full" />
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Search bar */}
      <div className="flex-1 max-w-md px-6">
        <div className="relative group">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#9BA7B4] group-focus-within:text-[#00A4A6] transition-colors" />
          <Input
            type="search"
            placeholder="Search alerts, IOCs, queries..."
            className="pl-10 pr-12 h-9 bg-[#171D21] border border-[#2D3339] focus:border-[#00A4A6]/50 focus:ring-1 focus:ring-[#00A4A6]/30 text-sm placeholder:text-[#9BA7B4]/60"
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[10px] font-mono bg-[#2D3339] border border-[#2D3339] rounded text-[#9BA7B4] group-focus-within:border-[#00A4A6]/40 transition-colors">
            /
          </kbd>
        </div>
      </div>

      {/* Status indicators */}
      <div className="flex items-center gap-4 px-6 border-l border-border/50">
        {/* Live status */}
        <div className="flex items-center gap-2 px-3 py-1 rounded bg-[#171D21] border border-[#2D3339]">
          <Activity className="w-3.5 h-3.5 text-[#00A4A6] animate-pulse" />
          <span className="text-xs font-mono text-[#9BA7B4] uppercase tracking-wider">
            Live
          </span>
        </div>

        {/* Alert count */}
        <div className="flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-[#DC4E41]" />
          <div className="flex flex-col leading-none">
            <span className="text-xs font-mono font-bold text-white">127</span>
            <span className="text-[10px] font-mono text-[#9BA7B4] uppercase">Alerts</span>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 pl-6 border-l border-border/50">
        {/* Theme toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
          className="h-9 w-9 text-[#9BA7B4] hover:text-white hover:bg-white/5"
        >
          {theme === 'dark' ? (
            <Sun className="w-4 h-4" />
          ) : (
            <Moon className="w-4 h-4" />
          )}
        </Button>

        {/* Notifications */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="relative h-9 w-9 text-[#9BA7B4] hover:text-white hover:bg-white/5"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-[#DC4E41] text-[10px] font-bold text-white shadow-[0_0_10px_rgba(220,78,65,0.6)]">
                3
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-[360px] bg-[#1F2527] border-[#2D3339] shadow-2xl">
            <DropdownMenuLabel className="flex items-center justify-between px-4 py-3 border-b border-[#2D3339]">
              <span className="text-sm font-bold text-white uppercase tracking-wide">Notifications</span>
              <Badge variant="outline" className="text-[10px] font-mono border-[#00A4A6]/40 text-[#00A4A6]">
                3 New
              </Badge>
            </DropdownMenuLabel>
            <DropdownMenuItem className="flex flex-col items-start gap-2 px-4 py-3 border-l-2 border-[#DC4E41] bg-[#DC4E41]/5 hover:bg-[#DC4E41]/10 focus:bg-[#DC4E41]/10">
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#DC4E41] shadow-[0_0_6px_rgba(220,78,65,0.6)]" />
                  <span className="text-xs font-bold text-white uppercase tracking-wide">Critical Alert</span>
                </div>
                <span className="text-[10px] font-mono text-[#9BA7B4]">2m ago</span>
              </div>
              <p className="text-xs text-[#9BA7B4] pl-4">
                Ransomware detection on endpoint DESKTOP-A1B2C3
              </p>
            </DropdownMenuItem>
            <DropdownMenuItem className="flex flex-col items-start gap-2 px-4 py-3 border-l-2 border-[#F79836] bg-[#F79836]/5 hover:bg-[#F79836]/10 focus:bg-[#F79836]/10">
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#F79836] shadow-[0_0_6px_rgba(247,152,54,0.6)]" />
                  <span className="text-xs font-bold text-white uppercase tracking-wide">Case Updated</span>
                </div>
                <span className="text-[10px] font-mono text-[#9BA7B4]">15m ago</span>
              </div>
              <p className="text-xs text-[#9BA7B4] pl-4">
                Case #1234 assigned to your team
              </p>
            </DropdownMenuItem>
            <DropdownMenuItem className="flex flex-col items-start gap-2 px-4 py-3 border-l-2 border-[#00A4A6] bg-[#00A4A6]/5 hover:bg-[#00A4A6]/10 focus:bg-[#00A4A6]/10">
              <div className="flex items-center justify-between w-full">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#00A4A6] shadow-[0_0_6px_rgba(0,164,166,0.6)]" />
                  <span className="text-xs font-bold text-white uppercase tracking-wide">Playbook Complete</span>
                </div>
                <span className="text-[10px] font-mono text-[#9BA7B4]">1h ago</span>
              </div>
              <p className="text-xs text-[#9BA7B4] pl-4">
                Endpoint isolation playbook executed successfully
              </p>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* User menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="relative h-9 w-9 rounded-full p-0 hover:bg-white/5">
              <Avatar className="h-9 w-9 border-2 border-[#00A4A6]/30">
                <AvatarImage src="/avatars/user.png" alt="@analyst" />
                <AvatarFallback className="bg-[#00A4A6]/20 text-[#00A4A6] text-xs font-bold">
                  SA
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-64 bg-[#1F2527] border-[#2D3339]" align="end" forceMount>
            <DropdownMenuLabel className="border-b border-[#2D3339] pb-3">
              <div className="flex flex-col space-y-1">
                <p className="text-sm font-bold text-white">
                  Security Analyst
                </p>
                <p className="text-xs text-[#9BA7B4] font-mono">
                  analyst@soc.local
                </p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator className="bg-[#2D3339]" />
            <DropdownMenuItem className="text-[#9BA7B4] hover:text-white hover:bg-white/5 focus:bg-white/5 focus:text-white">
              <User className="mr-2 h-4 w-4" />
              <span>Profile</span>
            </DropdownMenuItem>
            <DropdownMenuItem className="text-[#DC4E41] hover:text-[#DC4E41] hover:bg-[#DC4E41]/10 focus:bg-[#DC4E41]/10 focus:text-[#DC4E41]">
              <span>Log out</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
