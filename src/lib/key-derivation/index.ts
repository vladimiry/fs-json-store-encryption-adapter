import {assert, hasKey} from "../private/util";
import * as Model from "./model";
import * as pbkdfBundle from "./impl/pbkdf2";
import * as sodiumCryptoPwhashBundle from "./impl/sodium-crypto-pwhash";

export type Type = "pbkdf2" | "sodium.crypto_pwhash";

export type KeyDerivationPresets =
    | { type: "pbkdf2"; preset: keyof typeof pbkdfBundle.optionsPresets; }
    | { type: "sodium.crypto_pwhash"; preset: keyof typeof sodiumCryptoPwhashBundle.optionsPresets; };

export type KeyDerivationOptions =
    | { type: "pbkdf2", options: pbkdfBundle.Options, data: pbkdfBundle.Data }
    | { type: "sodium.crypto_pwhash", options: sodiumCryptoPwhashBundle.Options, data: sodiumCryptoPwhashBundle.Data };

export const bundles: Record<Type, Model.Bundle> = {
    "pbkdf2": pbkdfBundle,
    "sodium.crypto_pwhash": sodiumCryptoPwhashBundle,
};

export const resolveKeyDerivation = (opts: KeyDerivationPresets | KeyDerivationOptions) => {
    const bundle = bundles[opts.type];

    assert(bundle, `Unsupported key derivation implementation "${JSON.stringify(opts)}"`);

    return {
        async deriveKey(password: string) {
            if (hasKey(opts, "preset")) {
                const options = bundle.optionsPresets[opts.preset];

                assert(options, `Failed to resolve key derivation options (${JSON.stringify(opts)})`);

                return await bundle.deriveKey(password, {type: opts.type, options});
            } else {
                return await bundle.deriveKey(password, opts);
            }
        },
    } as Model.Implementation;
};
