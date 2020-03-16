import {randomBytes} from "crypto";

import sodium from "src/lib/private/sodium-native-loader";
import {BASE64_ENCODING} from "src/lib/private/constants";
import {DecryptionError} from "src/lib/errors";
import {EncryptionModuleImpl} from "src/lib/encryption/model";

export const encrypt: EncryptionModuleImpl<"sodium.crypto_secretbox_easy">["encrypt"] = async (key, inputData, rule) => {
    const {nonceBytes} = rule.options;
    const data = {nonceBase64: randomBytes(nonceBytes).toString(BASE64_ENCODING)};
    const nonce = Buffer.from(data.nonceBase64, BASE64_ENCODING);
    const cipher = Buffer.allocUnsafe(inputData.byteLength + sodium.crypto_box_MACBYTES);

    sodium.crypto_secretbox_easy(cipher, inputData, nonce, key);

    return {cipher, rule: {...rule, data}};
};

export const decrypt: EncryptionModuleImpl<"sodium.crypto_secretbox_easy">["decrypt"] = async (key, inputData, rule) => {
    const nonce = Buffer.from(rule.data.nonceBase64, BASE64_ENCODING);
    const decipher = Buffer.allocUnsafe(inputData.byteLength - sodium.crypto_box_MACBYTES);

    if (!sodium.crypto_secretbox_open_easy(decipher, inputData, nonce, key)) {
        throw new DecryptionError(`"sodium.crypto_secretbox_open_easy" decryption has failed`);
    }

    return decipher;
};

export const optionsPresets = {
    "algorithm:default": {
        nonceBytes: sodium.crypto_box_NONCEBYTES,
    },
} as const;

export interface Options {
    readonly nonceBytes: number;
}

export interface Data {
    readonly nonceBase64: string;
}
