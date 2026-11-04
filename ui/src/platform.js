// Keep the original profile available for upstream regression tests/builds.
export const MIKROTIK = import.meta.env.VITE_ROUTER_PLATFORM === 'mikrotik'
export const PRODUCT_NAME = MIKROTIK ? 'MikroTik Insights Plus' : 'Insights Plus'
