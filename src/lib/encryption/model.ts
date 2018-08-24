import {EncryptionOptions} from ".";
import {Omit} from "../private/constants";

export interface EncryptionModuleImpl<T extends EncryptionOptions["type"] = EncryptionOptions["type"]> {
    optionsPresets: Record<string, Extract<EncryptionOptions, { type: T }>["options"]>;

    encrypt(
        key: Buffer,
        inputData: Buffer,
        rule: Omit<Extract<EncryptionOptions, { type: T }>, "data">,
    ): Promise<{ cipher: Buffer, rule: EncryptionOptions }>;

    decrypt(
        key: Buffer,
        inputData: Buffer,
        rule: Extract<EncryptionOptions, { type: T }>,
    ): Promise<Buffer>;
}
