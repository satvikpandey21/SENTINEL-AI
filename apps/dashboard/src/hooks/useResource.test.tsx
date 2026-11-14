import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useResource } from './useResource';
describe('bounded resource lifecycle', () => {
  it('loads once and provides an explicit retry after errors', async () => {
    const load = vi
      .fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ count: 12 });
    const { result } = renderHook(() => useResource('data', load));
    await waitFor(() => expect(result.current.error).toBeInstanceOf(Error));
    act(() => result.current.refresh());
    await waitFor(() => expect(result.current.data).toEqual({ count: 12 }));
    expect(load).toHaveBeenCalledTimes(2);
  });
  it('cancels obsolete requests and ignores late results', async () => {
    let finish!: (value: string) => void;
    let signal!: AbortSignal;
    const old = vi.fn((value: AbortSignal) => {
      signal = value;
      return new Promise<string>((resolve) => {
        finish = resolve;
      });
    });
    const next = vi.fn().mockResolvedValue('current');
    const { result, rerender } = renderHook(
      ({ id }) => useResource(id, id === 'old' ? old : next),
      { initialProps: { id: 'old' } },
    );
    rerender({ id: 'next' });
    expect(signal.aborted).toBe(true);
    await waitFor(() => expect(result.current.data).toBe('current'));
    await act(async () => finish('obsolete'));
    expect(result.current.data).toBe('current');
  });
  it('does not request disabled resources', () => {
    const load = vi.fn();
    const { result } = renderHook(() => useResource('disabled', load, { enabled: false }));
    expect(load).not.toHaveBeenCalled();
    expect(result.current.loading).toBe(false);
  });
  it('polls at a bounded interval and pauses in hidden tabs', async () => {
    vi.useFakeTimers();
    let visible = true;
    vi.spyOn(document, 'visibilityState', 'get').mockImplementation(() =>
      visible ? 'visible' : 'hidden',
    );
    const load = vi.fn().mockResolvedValue('observed');
    renderHook(() => useResource('poll', load, { pollMs: 60000 }));
    await act(async () => {});
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000);
    });
    expect(load).toHaveBeenCalledTimes(2);
    visible = false;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(120000);
    });
    expect(load).toHaveBeenCalledTimes(2);
    visible = true;
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
    });
    expect(load).toHaveBeenCalledTimes(3);
  });
});
