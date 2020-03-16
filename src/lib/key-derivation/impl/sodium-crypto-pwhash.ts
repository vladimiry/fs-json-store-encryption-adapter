import {promisify} from "util";
import {randomBytes} from "crypto";

import sodium from "src/lib/private/sodium-native-loader";
import {BASE64_ENCODING} from "src/lib/private/constants";
import {KeyDerivationModuleImpl} from "src/lib/key-derivation/model";

const defaultAlgorithmOptions = {
    keyBytes: sodium.crypto_generichash_KEYBYTES,
    saltBytes: sodium.crypto_pwhash_SALTBYTES,
    algorithm: sodium.crypto_pwhash_ALG_DEFAULT,
} as const;

function resolveRuleData(
    rule: Parameters<KeyDerivationModuleImpl<"sodium.crypto_pwhash">["deriveKey"]>[1],
): Exclude<(typeof rule)["data"], undefined> {
    const {saltBytes} = rule.options;

    if (!rule.data) {
        return {
            saltBase64: randomBytes(saltBytes).toString(BASE64_ENCODING),
        };
    }

    return {
        saltBase64: Buffer
            .from(rule.data.saltBase64, BASE64_ENCODING)
            // "fs-json-store-encryption-adapter < v2" used wrong salt size constant value (24 instead of 16)
            // there is no issue here since "sodium-native" was trunking it down to 16 internally
            // and "sodium-native < v3" didn't have a runtime salt size check bunt since v3 such runtime check got internally enabled
            // so in order to the data encrypted with "fs-json-store-encryption-adapter < v2" gets decrypted we limit/slice
            // the previously generated and saved salt by "defaultAlgorithmOptions.saltBytes = sodium.crypto_pwhash_SALTBYTES" value
            .slice(0, defaultAlgorithmOptions.saltBytes)
            .toString(BASE64_ENCODING)
    };
}

export const deriveKey: KeyDerivationModuleImpl<"sodium.crypto_pwhash">["deriveKey"] = async (password, rule) => {
    const {keyBytes, opsLimit, memLimit, algorithm} = rule.options;
    const data = resolveRuleData(rule);
    const salt = Buffer.from(data.saltBase64, BASE64_ENCODING);
    const key = Buffer.allocUnsafe(keyBytes);

    await promisify(sodium.crypto_pwhash_async)(
        key,
        Buffer.from(password),
        salt,
        opsLimit,
        memLimit,
        algorithm,
    );

    return {key, rule: {...rule, data}};
};

export const optionsPresets = {
    "mode:interactive|algorithm:default": {
        ...defaultAlgorithmOptions,
        opsLimit: Math.max(sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, 2),
        memLimit: Math.max(sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE, 67108864),
    },
    "mode:moderate|algorithm:default": {
        ...defaultAlgorithmOptions,
        opsLimit: Math.max(sodium.crypto_pwhash_OPSLIMIT_MODERATE, 3),
        memLimit: Math.max(sodium.crypto_pwhash_MEMLIMIT_MODERATE, 268435456),
    },
    "mode:sensitive|algorithm:default": {
        ...defaultAlgorithmOptions,
        opsLimit: Math.max(sodium.crypto_pwhash_OPSLIMIT_SENSITIVE, 4),
        memLimit: Math.max(sodium.crypto_pwhash_MEMLIMIT_SENSITIVE, 1073741824),
    },
} as const;

export interface Options {
    readonly keyBytes: number;
    readonly saltBytes: number;
    readonly opsLimit: number;
    readonly memLimit: number;
    readonly algorithm: number;
}

export interface Data {
    readonly saltBase64: string;
}
