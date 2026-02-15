import {
  Server,
  Monitor,
  Router,
  Container,
  Cloud,
  Cpu,
  HelpCircle,
  FolderTree,
} from 'lucide-react';
import type { Asset } from '../types';

interface AssetTypeIconProps {
  type: Asset['type'] | 'group';
  className?: string;
}

const iconMap: Record<Asset['type'] | 'group', React.ComponentType<{ className?: string }>> = {
  server: Server,
  workstation: Monitor,
  network_device: Router,
  container: Container,
  cloud_instance: Cloud,
  iot: Cpu,
  other: HelpCircle,
  group: FolderTree,
};

export function AssetTypeIcon({ type, className = 'w-4 h-4' }: AssetTypeIconProps) {
  const Icon = iconMap[type] || HelpCircle;
  return <Icon className={className} />;
}

export function getAssetTypeLabel(type: Asset['type']): string {
  const labels: Record<Asset['type'], string> = {
    server: 'Server',
    workstation: 'Workstation',
    network_device: 'Network Device',
    container: 'Container',
    cloud_instance: 'Cloud Instance',
    iot: 'IoT Device',
    other: 'Other',
  };
  return labels[type] || 'Unknown';
}
