import combineErrors from "combine-errors";

import * as cryptoImpl from "./impl/crypto";
import * as Model from "./model";
import * as sodiumCryptoSecretboxEasyImpl from "./impl/sodium-crypto-secretbox-easy";
import {assert} from "../private/util";
import {FailedDecryptionError} from "../errors";

export type Type = "crypto" | "sodium.crypto_secretbox_easy";

export type EncryptionPresets =
    | { type: "crypto"; preset: keyof typeof cryptoImpl.optionsPresets; }
    | { type: "sodium.crypto_secretbox_easy"; preset: keyof typeof sodiumCryptoSecretboxEasyImpl.optionsPresets; };

export type EncryptionOptions =
    | { type: "crypto", options: cryptoImpl.Options, data: cryptoImpl.Data }
    | { type: "sodium.crypto_secretbox_easy", options: sodiumCryptoSecretboxEasyImpl.Options, data: sodiumCryptoSecretboxEasyImpl.Data };

export const implementations: Record<Type, Model.EncryptionModuleImpl> = {
    "crypto": cryptoImpl,
    "sodium.crypto_secretbox_easy": sodiumCryptoSecretboxEasyImpl,
};

export const resolveEncryption = (resolveInput: EncryptionPresets | EncryptionOptions) => {
    const implementation = implementations[resolveInput.type];

    assert(implementation, `Unsupported encryption implementation "${JSON.stringify(resolveInput)}"`);

    return {
        async encrypt(key: Buffer, data: Buffer) {
            const {type, preset} = resolveInput as EncryptionPresets;
            const options = implementation.optionsPresets[preset];

            assert(options, `Failed to resolve encryption options (${JSON.stringify({type, preset})})`);

            try {
                return await implementation.encrypt(key, data, {type, options});
            } catch (error) {
                throw combineErrors([
                    new FailedDecryptionError(`Encryption failed (${JSON.stringify({type, preset})})`),
                    error,
                ]);
            }
        },
        async decrypt(key: Buffer, data: Buffer) {
            const rule = resolveInput as EncryptionOptions;

            try {
                return await implementation.decrypt(key, data, rule);
            } catch (error) {
                throw combineErrors([
                    new FailedDecryptionError(`Decryption failed (${JSON.stringify(rule)})`),
                    error,
                ]);
            }
        },
    };
};
