import { useMemo } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { X, Pause, Play, BarChart3, List, AlertCircle } from 'lucide-react';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { useProcessingStore } from '../../stores/processingStore';
import { MetricsBar } from './MetricsBar';
import { ItemProgressList } from './ItemProgressList';
import { FailedItemsPanel } from './FailedItemsPanel';

interface ProcessingMonitorProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ProcessingMonitor({ isOpen, onClose }: ProcessingMonitorProps) {
  const { activeNodeId, nodes, pauseProcessing, resumeProcessing } = useProcessingStore(
    useShallow((state) => ({
      activeNodeId: state.activeNodeId,
      nodes: state.nodes,
      pauseProcessing: state.pauseProcessing,
      resumeProcessing: state.resumeProcessing,
    }))
  );

  const activeNode = activeNodeId ? nodes.get(activeNodeId) : null;

  const failedItems = useMemo(() => {
    if (!activeNode) return [];
    return activeNode.items.filter(item => item.status === 'failed');
  }, [activeNode]);

  const handleTogglePause = () => {
    if (!activeNodeId) return;
    if (activeNode?.isPaused) {
      resumeProcessing(activeNodeId);
    } else {
      pauseProcessing(activeNodeId);
    }
  };

  const handleRetryItem = (itemId: string) => {
    // TODO: Implement retry logic
    console.log('Retry item:', itemId);
  };

  const handleRetryAll = () => {
    // TODO: Implement retry all logic
    console.log('Retry all failed items');
  };

  if (!activeNode) {
    return (
      <Sheet open={isOpen} onOpenChange={onClose}>
        <SheetContent side="right" className="w-full sm:max-w-2xl bg-gray-900 border-gray-800">
          <SheetHeader>
            <SheetTitle className="text-gray-100">Processing Monitor</SheetTitle>
          </SheetHeader>
          <div className="flex flex-col items-center justify-center h-[calc(100vh-8rem)] text-gray-400">
            <BarChart3 className="w-16 h-16 mb-4 text-gray-600" />
            <p className="text-sm">No active processing</p>
            <p className="text-xs text-gray-500 mt-1">
              Start a bulk execution to see real-time monitoring
            </p>
          </div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <Sheet open={isOpen} onOpenChange={onClose}>
      <SheetContent side="right" className="w-full sm:max-w-2xl bg-gray-900 border-gray-800 overflow-hidden flex flex-col">
        <SheetHeader className="flex-shrink-0">
          <div className="flex items-center justify-between">
            <SheetTitle className="text-gray-100">
              Processing Monitor
            </SheetTitle>
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              className="h-8 w-8"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
          <div className="flex items-center justify-between pt-2">
            <div>
              <p className="text-sm font-medium text-gray-300">{activeNode.nodeName}</p>
              <p className="text-xs text-gray-500">Node ID: {activeNode.nodeId}</p>
            </div>
            <Button
              variant={activeNode.isPaused ? 'default' : 'outline'}
              size="sm"
              onClick={handleTogglePause}
              className="gap-2"
            >
              {activeNode.isPaused ? (
                <>
                  <Play className="w-4 h-4" />
                  Resume
                </>
              ) : (
                <>
                  <Pause className="w-4 h-4" />
                  Pause
                </>
              )}
            </Button>
          </div>
        </SheetHeader>

        <div className="flex-1 overflow-hidden flex flex-col mt-4">
          <Tabs defaultValue="overview" className="flex-1 flex flex-col">
            <TabsList className="w-full grid grid-cols-3 bg-gray-800 flex-shrink-0">
              <TabsTrigger value="overview" className="gap-2 data-[state=active]:bg-gray-700">
                <BarChart3 className="w-4 h-4" />
                Overview
              </TabsTrigger>
              <TabsTrigger value="items" className="gap-2 data-[state=active]:bg-gray-700">
                <List className="w-4 h-4" />
                All Items
              </TabsTrigger>
              <TabsTrigger value="failed" className="gap-2 data-[state=active]:bg-gray-700">
                <AlertCircle className="w-4 h-4" />
                Failed ({failedItems.length})
              </TabsTrigger>
            </TabsList>

            <div className="flex-1 overflow-hidden mt-4">
              <TabsContent value="overview" className="h-full overflow-auto m-0">
                <div className="space-y-6 pb-6">
                  <MetricsBar metrics={activeNode.metrics} />

                  {/* Quick Stats */}
                  <div className="space-y-3">
                    <h3 className="text-sm font-medium text-gray-300">Quick Stats</h3>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="px-4 py-3 bg-gray-800/50 rounded-lg border border-gray-700">
                        <div className="text-xs text-gray-400 mb-1">Total Items</div>
                        <div className="text-2xl font-mono font-bold text-gray-100">
                          {activeNode.metrics.totalItems}
                        </div>
                      </div>
                      <div className="px-4 py-3 bg-gray-800/50 rounded-lg border border-gray-700">
                        <div className="text-xs text-gray-400 mb-1">Success Rate</div>
                        <div className="text-2xl font-mono font-bold text-[#5CC05C]">
                          {activeNode.metrics.processedItems > 0
                            ? ((activeNode.metrics.successCount / activeNode.metrics.processedItems) * 100).toFixed(1)
                            : '0.0'}%
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Recent Failed Items */}
                  {failedItems.length > 0 && (
                    <div className="space-y-3">
                      <h3 className="text-sm font-medium text-gray-300">Recent Failures</h3>
                      <FailedItemsPanel
                        failedItems={failedItems.slice(0, 5)}
                        onRetryItem={handleRetryItem}
                      />
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="items" className="h-full m-0">
                <ItemProgressList
                  items={activeNode.items}
                  containerHeight={window.innerHeight - 300}
                />
              </TabsContent>

              <TabsContent value="failed" className="h-full overflow-auto m-0">
                <FailedItemsPanel
                  failedItems={failedItems}
                  onRetryItem={handleRetryItem}
                  onRetryAll={handleRetryAll}
                />
              </TabsContent>
            </div>
          </Tabs>
        </div>
      </SheetContent>
    </Sheet>
  );
}
