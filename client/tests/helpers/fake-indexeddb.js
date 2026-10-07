class FakeRequest {
  constructor() {
    this.result = undefined;
    this.error = null;
    this.onsuccess = null;
    this.onerror = null;
    this.onupgradeneeded = null;
    this.onblocked = null;
    this.transaction = null;
  }
}

class FakeObjectStore {
  constructor(keyPath = null) {
    this.keyPath = keyPath;
    this.data = new Map();
  }

  _schedule(fn) {
    setTimeout(fn, 0);
  }

  put(value, key) {
    const request = new FakeRequest();
    const storeKey = key !== undefined ? key : this.keyPath ? value?.[this.keyPath] : undefined;
    this._schedule(() => {
      if (storeKey === undefined || storeKey === null) {
        request.error = new Error('Missing object store key');
        if (request.onerror) request.onerror({ target: request });
        return;
      }
      this.data.set(storeKey, Array.isArray(value) ? [...value] : { ...value });
      if (request.onsuccess) request.onsuccess({ target: request });
    });
    return request;
  }

  get(key) {
    const request = new FakeRequest();
    this._schedule(() => {
      const value = this.data.get(key);
      request.result = value === undefined ? undefined : { ...value };
      if (request.onsuccess) request.onsuccess({ target: request });
    });
    return request;
  }

  delete(key) {
    const request = new FakeRequest();
    this._schedule(() => {
      this.data.delete(key);
      if (request.onsuccess) request.onsuccess({ target: request });
    });
    return request;
  }

  clear() {
    const request = new FakeRequest();
    this._schedule(() => {
      this.data.clear();
      if (request.onsuccess) request.onsuccess({ target: request });
    });
    return request;
  }

  getAll() {
    const request = new FakeRequest();
    this._schedule(() => {
      request.result = Array.from(this.data.values()).map((value) => ({ ...value }));
      if (request.onsuccess) request.onsuccess({ target: request });
    });
    return request;
  }
}

class FakeDatabase {
  constructor(stores) {
    this.stores = stores;
    this.objectStoreNames = {
      contains: (name) => stores.has(name)
    };
    this.closed = false;
  }

  createObjectStore(name, options = {}) {
    const store = new FakeObjectStore(options.keyPath ?? null);
    this.stores.set(name, store);
    return store;
  }

  transaction(name, _mode = 'readonly') {
    const stores = this.stores;
    return {
      objectStore(storeName) {
        if (!stores.has(storeName)) {
          throw new Error(`Store not found: ${storeName}`);
        }
        return stores.get(storeName);
      },
      abort() {}
    };
  }

  close() {
    this.closed = true;
  }
}

export function createFakeIndexedDB() {
  const databases = new Map();
  return {
    open(name, version = 1) {
      const request = new FakeRequest();
      setTimeout(() => {
        let record = databases.get(name);
        let isNew = false;
        if (!record) {
          record = { stores: new Map() };
          databases.set(name, record);
          isNew = true;
        }
        const db = new FakeDatabase(record.stores);
        request.result = db;
        if (isNew && request.onupgradeneeded) {
          request.onupgradeneeded({ target: request, oldVersion: 0, newVersion: version });
        }
        if (request.onsuccess) request.onsuccess({ target: request });
      }, 0);
      return request;
    },
    _databases: databases
  };
}

export function installFakeIndexedDB() {
  const api = createFakeIndexedDB();
  globalThis.indexedDB = api;
  return api;
}
