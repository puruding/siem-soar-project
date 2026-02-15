import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { TooltipProvider } from '@/components/ui/tooltip';
import { ChevronRight } from 'lucide-react';

// Breadcrumb mapping for navigation context
const breadcrumbMap: Record<string, string[]> = {
  '/dashboard': ['Home', 'Dashboard'],
  '/alerts': ['Home', 'Alerts'],
  '/cases': ['Home', 'Cases'],
  '/query': ['Home', 'Query'],
  '/playbooks': ['Home', 'Playbooks'],
  '/copilot': ['Home', 'AI Copilot'],
  '/settings': ['Home', 'Settings'],
};

export function Layout() {
  const location = useLocation();
  const breadcrumbs = breadcrumbMap[location.pathname] || ['Home'];

  return (
    <TooltipProvider>
      <div className="flex h-screen bg-[#171D21] overflow-hidden">
        {/* Diagonal grid pattern background */}
        <div className="fixed inset-0 pointer-events-none opacity-[0.02]">
          <div
            className="w-full h-full"
            style={{
              backgroundImage: `linear-gradient(45deg, #00A4A6 1px, transparent 1px),
                                linear-gradient(-45deg, #00A4A6 1px, transparent 1px)`,
              backgroundSize: '20px 20px',
            }}
          />
        </div>

        {/* Subtle vignette */}
        <div className="fixed inset-0 pointer-events-none bg-gradient-radial from-transparent via-transparent to-black/30" />

        {/* Sidebar */}
        <Sidebar />

        {/* Main content area */}
        <div className="flex flex-col flex-1 overflow-hidden relative">
          {/* Header */}
          <Header />

          {/* Breadcrumb navigation */}
          {breadcrumbs.length > 1 && (
            <div className="flex items-center gap-2 px-6 py-3 bg-[#1F2527]/30 backdrop-blur-sm border-b border-[#2D3339]/50">
              {breadcrumbs.map((crumb, index) => (
                <div key={crumb} className="flex items-center gap-2">
                  <span
                    className={
                      index === breadcrumbs.length - 1
                        ? 'text-sm font-medium text-white font-mono'
                        : 'text-sm text-[#9BA7B4] hover:text-white transition-colors cursor-pointer font-mono'
                    }
                  >
                    {crumb}
                  </span>
                  {index < breadcrumbs.length - 1 && (
                    <ChevronRight className="w-3.5 h-3.5 text-[#2D3339]" />
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Main content with Splunk 15px standard margin */}
          <main className="flex-1 overflow-auto relative">
            {/* Content wrapper with standard Splunk spacing */}
            <div className="p-[15px] h-full">
              {/* Inner container with subtle border for content definition */}
              <div className="h-full rounded-sm border border-[#2D3339]/30 bg-[#171D21]/50 backdrop-blur-sm overflow-auto">
                <div className="p-[15px]">
                  <Outlet />
                </div>
              </div>
            </div>

            {/* Decorative corner accents */}
            <div className="absolute top-0 left-0 w-32 h-32 bg-gradient-to-br from-[#00A4A6]/5 to-transparent pointer-events-none" />
            <div className="absolute bottom-0 right-0 w-32 h-32 bg-gradient-to-tl from-[#00A4A6]/5 to-transparent pointer-events-none" />
          </main>
        </div>
      </div>
    </TooltipProvider>
  );
}
