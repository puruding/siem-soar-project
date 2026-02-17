import { Play, Pause, Square, RotateCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import type { ExecutionState } from '../../types/execution.types';

interface ExecutionControlsProps {
  executionId: string;
  status: ExecutionState['status'];
  onPause?: () => void;
  onResume?: () => void;
  onCancel?: () => void;
  onReset?: () => void;
}

export function ExecutionControls({
  status,
  onPause,
  onResume,
  onCancel,
  onReset,
}: ExecutionControlsProps) {
  const isRunning = status === 'running';
  const isPaused = status === 'paused';
  const isCompleted = status === 'completed' || status === 'failed' || status === 'cancelled';
  const isIdle = status === 'idle';

  return (
    <div className="flex items-center gap-2">
      {/* Play/Resume Button */}
      {(isPaused || isIdle) && (
        <Button
          size="sm"
          variant="default"
          onClick={onResume}
          disabled={isIdle}
          title={isPaused ? 'Resume execution' : 'Start execution'}
        >
          <Play className="w-4 h-4" />
          {isPaused ? 'Resume' : 'Play'}
        </Button>
      )}

      {/* Pause Button */}
      {isRunning && (
        <Button
          size="sm"
          variant="secondary"
          onClick={onPause}
          title="Pause execution"
        >
          <Pause className="w-4 h-4" />
          Pause
        </Button>
      )}

      {/* Stop/Cancel Button */}
      {(isRunning || isPaused) && (
        <Button
          size="sm"
          variant="destructive"
          onClick={onCancel}
          title="Cancel execution"
        >
          <Square className="w-4 h-4" />
          Stop
        </Button>
      )}

      {/* Reset Button */}
      {isCompleted && (
        <Button
          size="sm"
          variant="outline"
          onClick={onReset}
          title="Reset execution"
        >
          <RotateCcw className="w-4 h-4" />
          Reset
        </Button>
      )}
    </div>
  );
}
