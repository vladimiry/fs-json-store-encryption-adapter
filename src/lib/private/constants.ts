// all built-in encryption implementations require 32 bytes lenght key
export const KEY_BYTES_32 = 32;

export const SALT_BYTES_16 = 16;

export const BASE64_ENCODING: BufferEncoding = "base64";

export type Omit<T, E extends keyof T> = { [K in Exclude<keyof T, E>]: T[K] };

export type PartialByKeys<T, PK extends keyof T> = Omit<T, PK> & { [K in PK]?: T[K] };
