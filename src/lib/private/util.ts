import {inspect} from "util";

export function assert<T>(t: T, message?: string): T {
    if (!t) {
        throw new Error(message || "AssertionError");
    }
    return t;
}

export function assertEqual<T>(actual: T, expected: T, message?: string): void {
    if (actual !== expected) {
        throw new Error(
            [
                `Values are not equal: ${inspect({expected, actual})}.`,
                message || "",
            ].join(" "),
        );
    }
}
