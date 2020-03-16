import * as Model from "./model";
import * as cryptoImpl from "./impl/crypto";
import * as sodiumCryptoSecretboxEasyImpl from "./impl/sodium-crypto-secretbox-easy";
import {DecryptionError, EncryptionError} from "src/lib/errors";
import {assert} from "src/lib/private/util";

export type Type = "crypto" | "sodium.crypto_secretbox_easy";

export type EncryptionPresets =
    | Readonly<{ type: "crypto"; preset: keyof typeof cryptoImpl.optionsPresets }>
    | Readonly<{ type: "sodium.crypto_secretbox_easy"; preset: keyof typeof sodiumCryptoSecretboxEasyImpl.optionsPresets }>;

export type EncryptionOptions =
    | Readonly<{ type: "crypto"; options: cryptoImpl.Options; data: cryptoImpl.Data }>
    | Readonly<{ type: "sodium.crypto_secretbox_easy"; options: sodiumCryptoSecretboxEasyImpl.Options; data: sodiumCryptoSecretboxEasyImpl.Data }>;

export const implementations: Readonly<Record<Type, Model.EncryptionModuleImpl>> = {
    "crypto": cryptoImpl,
    "sodium.crypto_secretbox_easy": sodiumCryptoSecretboxEasyImpl,
};

// eslint-disable-next-line @typescript-eslint/explicit-function-return-type
export const resolveEncryption = (resolveInput: EncryptionPresets | EncryptionOptions) => {
    const implementation = implementations[resolveInput.type];

    assert(implementation, `Unsupported encryption implementation "${JSON.stringify(resolveInput)}"`);

    return {
        // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
        async encrypt(key: Buffer, data: Buffer) {
            const {type, preset} = resolveInput as EncryptionPresets;
            const options = implementation.optionsPresets[preset];

            assert(options, `Failed to resolve encryption options (${JSON.stringify({type, preset})})`);

            try {
                return await implementation.encrypt(key, data, {type, options});
            } catch (error) {
                throw new EncryptionError(`Encryption failed (${JSON.stringify({type, preset})})`, error);
            }
        },
        // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
        async decrypt(key: Buffer, data: Buffer) {
            const rule = resolveInput as EncryptionOptions;

            try {
                return await implementation.decrypt(key, data, rule);
            } catch (error) {
                throw new DecryptionError(`Decryption failed (${JSON.stringify(rule)})`, error);
            }
        },
    };
};
