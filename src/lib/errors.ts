import {BaseError} from "make-error-cause";

const appendCauseMessage = (message?: string): string => {
    const suffix = `(print "cause" prop of error to see its origin)`;
    return message
        ? ` ${message} ${suffix}`
        : suffix;
}

export class EncryptionError extends BaseError {
    constructor(message: string, cause?: Error) {
        super(message + appendCauseMessage(cause?.message), cause);
    }
}

export class DecryptionError extends BaseError {
    constructor(message: string, cause?: Error) {
        super(message + appendCauseMessage(cause?.message), cause);
    }
}
