'use client';

import { useCallback, useEffect, useReducer, useRef } from 'react';
import { parseNdjsonStream } from '@/lib/ndjson';
import { initialScanState, scanReducer } from '@/lib/scan-state';
import type { ScanRequest } from '@/lib/protocol';
import type { ScanState } from '@/lib/scan-state';

export type UseScan = {
  state:  ScanState;
  start:  (request: ScanRequest, label: string) => void;
  cancel: () => void;
};

const NETWORK_ERROR = 'The scan could not reach the server. Check your connection and try again.';

export function useScan(): UseScan {
  const [state, dispatch] = useReducer(scanReducer, initialScanState);
  const controller = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    if (controller.current) {
      controller.current.abort();
      controller.current = null;
      dispatch({ type: 'cancelled' });
    }
  }, []);

  const start = useCallback((request: ScanRequest, label: string) => {
    // Starting a scan cancels any scan still running.
    controller.current?.abort();
    const ctl = new AbortController();
    controller.current = ctl;
    dispatch({ type: 'reset', target: label });

    void (async () => {
      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(request),
          signal: ctl.signal,
        });
        if (!res.ok || !res.body) {
          let message = 'The scan was rejected.';
          try {
            const body = (await res.json()) as { error?: unknown };
            if (typeof body.error === 'string') message = body.error;
          } catch {
            /* keep the generic message */
          }
          dispatch({ type: 'failed', message });
          return;
        }
        for await (const r of parseNdjsonStream(res.body)) {
          if (ctl.signal.aborted) return;
          if (r.ok) dispatch({ type: 'event', event: r.event });
          else dispatch({ type: 'failed', message: r.error });
        }
        if (controller.current === ctl) controller.current = null;
      } catch (err) {
        if (ctl.signal.aborted) return;
        dispatch({ type: 'failed', message: NETWORK_ERROR });
        void err;
      }
    })();
  }, []);

  useEffect(() => () => controller.current?.abort(), []);

  return { state, start, cancel };
}
