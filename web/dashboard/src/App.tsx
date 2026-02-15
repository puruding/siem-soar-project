import { Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from '@/components/ui/toaster';
import { Layout } from '@/components/layout/Layout';
import { Dashboard } from '@/features/dashboard/components/Dashboard';
import { AlertList } from '@/features/alerts/components/AlertList';
import { CaseList } from '@/features/cases/components/CaseList';
import { CaseDetail } from '@/features/cases/components/CaseDetail';
import { QueryConsole } from '@/features/query/components/QueryConsole';
import { PlaybookList } from '@/features/playbooks/components/PlaybookList';
import { PlaybookEditor } from '@/features/playbooks/components/PlaybookEditor';
import { useThemeStore } from '@/stores/themeStore';
import { useEffect } from 'react';

function App() {
  const theme = useThemeStore((state) => state.theme);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.classList.toggle('light', theme === 'light');
  }, [theme]);

  return (
    <>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="alerts" element={<AlertList />} />
          <Route path="cases" element={<CaseList />} />
          <Route path="cases/:id" element={<CaseDetail />} />
          <Route path="query" element={<QueryConsole />} />
          <Route path="playbooks" element={<PlaybookList />} />
          <Route path="playbooks/:id" element={<PlaybookEditor />} />
          <Route path="playbooks/new" element={<PlaybookEditor />} />
        </Route>
      </Routes>
      <Toaster />
    </>
  );
}

export default App;
