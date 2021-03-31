import * as Model from "./model";
import * as pbkdfImpl from "./impl/pbkdf2";
import * as sodiumCryptoPwhashImpl from "./impl/sodium-crypto-pwhash";
import {assert} from "src/lib/private/util";

export type Type = "pbkdf2" | "sodium.crypto_pwhash";

export type KeyDerivationPresets =
    | Readonly<{ type: "pbkdf2"; preset: keyof typeof pbkdfImpl.optionsPresets }>
    | Readonly<{ type: "sodium.crypto_pwhash"; preset: keyof typeof sodiumCryptoPwhashImpl.optionsPresets }>;

export type KeyDerivationOptions =
    | Readonly<{ type: "pbkdf2"; options: pbkdfImpl.Options; data: pbkdfImpl.Data }>
    | Readonly<{ type: "sodium.crypto_pwhash"; options: sodiumCryptoPwhashImpl.Options; data: sodiumCryptoPwhashImpl.Data }>;

export const implementations: Readonly<Record<Type, Model.KeyDerivationModuleImpl>> = {
    "pbkdf2": pbkdfImpl,
    "sodium.crypto_pwhash": sodiumCryptoPwhashImpl,
};

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export const resolveKeyDerivation = (opts: KeyDerivationPresets | KeyDerivationOptions) => {
    const implementation: Model.KeyDerivationModuleImpl<typeof opts.type> = implementations[opts.type];

    assert(implementation, `Unsupported key derivation implementation "${JSON.stringify(opts)}"`);

    return {
        // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
        async deriveKey(password: string) {
            if ("preset" in opts) {
                const options = implementation.optionsPresets[opts.preset];

                assert(options, `Failed to resolve key derivation options (${JSON.stringify(opts)})`);

                return implementation.deriveKey(password, {type: opts.type, options});
            } else {
                return implementation.deriveKey(password, opts);
            }
        },
    };
};
