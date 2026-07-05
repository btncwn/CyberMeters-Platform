/**
 * Utility to programmatically prefetch lazy-loaded components
 * leveraging the browser's idle time or mouse interactions.
 */
export const preloadComponent = (importFn) => {
  if (typeof window === 'undefined') return;
  
  const trigger = () => {
    importFn().catch(() => {
      // Silently catch network drops; Phase 1 error boundary will handle runtime failures
    });
  };

  if ('requestIdleCallback' in window) {
    window.requestIdleCallback(trigger, { timeout: 2000 });
  } else {
    setTimeout(trigger, 50);
  }
};
