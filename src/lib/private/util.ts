export function assert(t: any, m?: string) {
    if (!t) {
        throw new Error(m || "AssertionError");
    }
    return t;
}
