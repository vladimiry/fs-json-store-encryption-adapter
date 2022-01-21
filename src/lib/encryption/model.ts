import {EncryptionOptions} from "./";
import {Omit} from "src/lib/private/constants";

export interface EncryptionModuleImpl<T extends EncryptionOptions["type"] = EncryptionOptions["type"]> {
    optionsPresets: Readonly<Record<string, Extract<EncryptionOptions, { type: T }>["options"]>>;

    encrypt(
        key: Buffer,
        inputData: Buffer,
        rule: Omit<Extract<EncryptionOptions, { type: T }>, "data">,
    ): Promise<Readonly<{ cipher: Buffer; rule: EncryptionOptions }>>;

    decrypt(
        key: Buffer,
        inputData: Buffer,
        rule: Extract<EncryptionOptions, { type: T }>,
    ): Promise<Buffer>;
}
