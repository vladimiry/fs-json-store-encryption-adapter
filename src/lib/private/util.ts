import {inspect} from "util";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function assert<T extends any>(t: T, message?: string): T {
    if (!t) {
        throw new Error(message || "AssertionError");
    }
    return t;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function assertEqual<T extends any>(actual: T, expected: T, message?: string): void {
    if (actual !== expected) {
        throw new Error(
            [
                `Values are not equal: ${inspect({expected, actual})}.`,
                message || "",
            ].join(" "),
        );
    }
}
