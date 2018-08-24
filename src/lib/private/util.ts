import sodium from "sodium-native";

export function randomBytes(saltBytes: number) {
    const salt = Buffer.allocUnsafe(saltBytes);
    sodium.randombytes_buf(salt);
    return salt;
}

export function assert(t: any, m?: string) {
    if (!t) {
        throw new Error(m || "AssertionError");
    }
    return t;
}
