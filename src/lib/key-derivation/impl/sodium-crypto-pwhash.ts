import sodium from "sodium-native";
import {promisify} from "util";
import {randomBytes} from "crypto";

import {BASE64_ENCODING} from "../../private/constants";
import {KeyDerivationModuleImpl} from "../model";

export const deriveKey: KeyDerivationModuleImpl<"sodium.crypto_pwhash">["deriveKey"] = async (password, rule) => {
    const {keyBytes, opsLimit, memLimit, algorithm, saltBytes} = rule.options;
    const data = rule.data || {saltBase64: randomBytes(saltBytes).toString(BASE64_ENCODING)};
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

const defaultAlgorithmOptions = {
    keyBytes: sodium.crypto_secretbox_KEYBYTES,
    saltBytes: sodium.crypto_secretbox_NONCEBYTES,
    algorithm: sodium.crypto_pwhash_ALG_DEFAULT,
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
};

export interface Options {
    keyBytes: number;
    saltBytes: number;
    opsLimit: number;
    memLimit: number;
    algorithm: number;
}

export interface Data {
    saltBase64: string;
}
