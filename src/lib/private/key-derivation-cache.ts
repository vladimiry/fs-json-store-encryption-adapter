import {CacheMap} from "@hscmap/cache-map";
import {KeyDerivationOptions} from "../key-derivation";

export class KeyDerivationCache {
    private static buildKey(key: KeyDerivationOptions): string {
        return JSON.stringify(key);
    }

    private cache: CacheMap<string, Buffer>;

    constructor(keyDerivationCacheLimit: number = 100) {
        this.cache = new CacheMap<string, Buffer>(keyDerivationCacheLimit);
    }

    public get(key: KeyDerivationOptions) {
        return this.cache.get(KeyDerivationCache.buildKey(key));
    }

    public set(key: KeyDerivationOptions, value: Buffer) {
        this.cache.set(KeyDerivationCache.buildKey(key), value);
    }
}
