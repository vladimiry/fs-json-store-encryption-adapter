import * as combineErrors from "combine-errors";

import {FailedDecryptionError} from "../errors";
import {assert} from "../private/util";
import * as Model from "./model";
import * as crypto from "./impl/crypto";
import * as sodiumCryptoSecretboxEasy from "./impl/sodium-crypto-secretbox-easy";

export type Type = "crypto" | "sodium.crypto_secretbox_easy";

export type EncryptionPresets =
    | { type: "crypto"; preset: keyof typeof crypto.optionsPresets; }
    | { type: "sodium.crypto_secretbox_easy"; preset: keyof typeof sodiumCryptoSecretboxEasy.optionsPresets; };

export type EncryptionOptions =
    | { type: "crypto", options: crypto.Options, data: crypto.Data }
    | { type: "sodium.crypto_secretbox_easy", options: sodiumCryptoSecretboxEasy.Options, data: sodiumCryptoSecretboxEasy.Data };

export const bundles: Record<Type, Model.Bundle> = {
    "crypto": crypto,
    "sodium.crypto_secretbox_easy": sodiumCryptoSecretboxEasy,
};

export const resolveEncryption = (opts: EncryptionPresets | EncryptionOptions) => {
    const bundle = bundles[opts.type];

    assert(bundle, `Unsupported encryption implementation "${JSON.stringify(opts)}"`);

    return {
        async encrypt({type, preset}: EncryptionPresets, key: Buffer, inputData: Buffer) {
            const options = bundle.optionsPresets[preset];

            assert(options, `Failed to resolve encryption options (${JSON.stringify({type, preset})})`);

            try {
                return await bundle.encrypt(key, inputData, {type, options});
            } catch (error) {
                throw combineErrors([
                    new FailedDecryptionError(`Encryption failed (${JSON.stringify({type, preset})})`),
                    error,
                ]);
            }
        },
        async decrypt(rule: EncryptionOptions, key: Buffer, inputData: Buffer) {
            try {
                return await bundle.decrypt(key, inputData, rule);
            } catch (error) {
                throw combineErrors([
                    new FailedDecryptionError(`Decryption failed (${JSON.stringify(rule)})`),
                    error,
                ]);
            }
        },
    } as Model.Implementation;
};
