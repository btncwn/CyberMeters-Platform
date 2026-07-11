import '@testing-library/jest-dom/vitest'

// Node 22+ defines global `localStorage`/`sessionStorage` getters that return
// undefined unless --localstorage-file is set. In vitest's jsdom environment
// window === globalThis and those Node getters shadow jsdom's storage, so both
// test code and component code (bare `localStorage`) would see undefined.
// Replace them with a small in-memory Storage — deterministic and test-scoped.
class MemoryStorage {
  #map = new Map()
  get length() { return this.#map.size }
  key(i) { return [...this.#map.keys()][i] ?? null }
  getItem(k) { return this.#map.has(String(k)) ? this.#map.get(String(k)) : null }
  setItem(k, v) { this.#map.set(String(k), String(v)) }
  removeItem(k) { this.#map.delete(String(k)) }
  clear() { this.#map.clear() }
}

for (const key of ['localStorage', 'sessionStorage']) {
  Object.defineProperty(globalThis, key, {
    value: new MemoryStorage(),
    configurable: true,
    writable: true,
  })
}

// jsdom ships neither IntersectionObserver nor matchMedia; components that use
// them (scroll-reveal, prefers-reduced-motion) would throw on render. Provide
// inert, deterministic stand-ins so those components mount cleanly in tests.
if (!globalThis.IntersectionObserver) {
  globalThis.IntersectionObserver = class {
    constructor(cb) { this._cb = cb }
    observe() {}
    unobserve() {}
    disconnect() {}
    takeRecords() { return [] }
  }
}
if (!globalThis.matchMedia) {
  globalThis.matchMedia = (query) => ({
    matches: false, media: query, onchange: null,
    addEventListener() {}, removeEventListener() {},
    addListener() {}, removeListener() {}, dispatchEvent() { return false },
  })
}

// Storage persists between tests in the same file — start every test clean.
beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
})
