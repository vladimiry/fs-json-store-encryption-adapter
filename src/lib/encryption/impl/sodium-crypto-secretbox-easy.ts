import * as sodium from "sodium-native";

import {BASE64_ENCODING} from "../../private/constants";
import {randomBytes} from "../../private/util";
import * as Model from "../model";

export async function encrypt(key: Buffer, inputData: Buffer, rule: Model.Rule<Options, Data>) {
    const {nonceBytes} = rule.options;
    const data = {nonceBase64: randomBytes(nonceBytes).toString(BASE64_ENCODING)};
    const nonce = Buffer.from(data.nonceBase64, BASE64_ENCODING);
    const cipher = Buffer.allocUnsafe(inputData.byteLength + sodium.crypto_secretbox_MACBYTES);

    sodium.crypto_secretbox_easy(cipher, inputData, nonce, key);

    return {cipher, rule: {...rule, data}};
}

export async function decrypt(key: Buffer, inputData: Buffer, rule: Model.FilledRule<Options, Data>) {
    const nonce = Buffer.from(rule.data.nonceBase64, BASE64_ENCODING);
    const decipher = Buffer.allocUnsafe(inputData.byteLength - sodium.crypto_secretbox_MACBYTES);

    if (!sodium.crypto_secretbox_open_easy(decipher, inputData, nonce, key)) {
        throw new Error("Decryption has failed");
    }

    return decipher;
}

export const optionsPresets = {
    "algorithm:default": {
        nonceBytes: sodium.crypto_secretbox_NONCEBYTES,
    },
};

export interface Options extends Model.Options {
    nonceBytes: number;
}

export interface Data extends Model.Data {
    nonceBase64: string;
}
