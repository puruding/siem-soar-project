import { useQuery } from '@tanstack/react-query';

interface DashboardStats {
  activeAlerts: number;
  eps: number;
  openCases: number;
  detectionRate: number;
}

async function fetchDashboardStats(): Promise<DashboardStats> {
  // Simulated API call - in production, replace with actual API
  await new Promise((resolve) => setTimeout(resolve, 500));

  return {
    activeAlerts: 127,
    eps: 45200,
    openCases: 12,
    detectionRate: 94.7,
  };
}

export function useDashboardData() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: fetchDashboardStats,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  return {
    stats: data ?? {
      activeAlerts: 0,
      eps: 0,
      openCases: 0,
      detectionRate: 0,
    },
    isLoading,
    error,
    refetch,
  };
}
