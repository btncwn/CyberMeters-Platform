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

// Storage persists between tests in the same file — start every test clean.
beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
})
