import {BaseError} from "make-error-cause";

export class EncryptionError extends BaseError {
    constructor(message: string, cause?: Error) {
        super(message, cause);
    }
}

export class DecryptionError extends BaseError {
    constructor(message: string, cause?: Error) {
        super(message, cause);
    }
}
