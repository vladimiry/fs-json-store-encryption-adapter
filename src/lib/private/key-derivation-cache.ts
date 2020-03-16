import {CacheMap} from "@hscmap/cache-map";

import {KeyDerivationOptions} from "src/lib/key-derivation";

export class KeyDerivationCache {
    private readonly cache: CacheMap<string, Buffer>;

    constructor(keyDerivationCacheLimit = 100) {
        this.cache = new CacheMap<string, Buffer>(keyDerivationCacheLimit);
    }

    private static buildKey(key: KeyDerivationOptions): string {
        return JSON.stringify(key);
    }

    public get(key: KeyDerivationOptions): Buffer | undefined {
        return this.cache.get(KeyDerivationCache.buildKey(key));
    }

    public set(key: KeyDerivationOptions, value: Buffer): void {
        this.cache.set(KeyDerivationCache.buildKey(key), value);
    }
}
