import * as Model from "./model";
import * as pbkdfImpl from "./impl/pbkdf2";
import * as sodiumCryptoPwhashImpl from "./impl/sodium-crypto-pwhash";
import {assert} from "../private/util";

export type Type = "pbkdf2" | "sodium.crypto_pwhash";

export type KeyDerivationPresets =
    | { type: "pbkdf2"; preset: keyof typeof pbkdfImpl.optionsPresets; }
    | { type: "sodium.crypto_pwhash"; preset: keyof typeof sodiumCryptoPwhashImpl.optionsPresets; };

export type KeyDerivationOptions =
    | { type: "pbkdf2", options: pbkdfImpl.Options, data: pbkdfImpl.Data }
    | { type: "sodium.crypto_pwhash", options: sodiumCryptoPwhashImpl.Options, data: sodiumCryptoPwhashImpl.Data };

export const implementations: Record<Type, Model.KeyDerivationModuleImpl> = {
    "pbkdf2": pbkdfImpl,
    "sodium.crypto_pwhash": sodiumCryptoPwhashImpl,
};

export const resolveKeyDerivation = (opts: KeyDerivationPresets | KeyDerivationOptions) => {
    const implementation: Model.KeyDerivationModuleImpl<typeof opts.type> = implementations[opts.type];

    assert(implementation, `Unsupported key derivation implementation "${JSON.stringify(opts)}"`);

    return {
        async deriveKey(password: string) {
            if ("preset" in opts) {
                const options = implementation.optionsPresets[opts.preset];

                assert(options, `Failed to resolve key derivation options (${JSON.stringify(opts)})`);

                return await implementation.deriveKey(password, {type: opts.type, options});
            } else {
                return await implementation.deriveKey(password, opts);
            }
        },
    };
};
