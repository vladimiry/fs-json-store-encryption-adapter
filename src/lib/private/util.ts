import * as sodium from "sodium-native";

export function randomBytes(saltBytes: number) {
    const salt = Buffer.allocUnsafe(saltBytes);

    sodium.randombytes_buf(salt);

    return salt;
}

// TODO TS: make "in" operator work as type guard
// https://github.com/Microsoft/TypeScript/issues/10485
// https://github.com/Microsoft/TypeScript/pull/15256
export const hasKey = <K extends string>(o: {}, k: K): o is { [_ in K]: {} } => typeof o === "object" && k in o;

export function assert(t: any, m?: string) {
    if (!t) {
        throw new Error(m || "AssertionError");
    }
    return t;
}
