import {createCipheriv, createDecipheriv} from "crypto";

import {BASE64_ENCODING, SALT_BYTES_16} from "../../private/constants";
import * as Model from "../model";
import {randomBytes} from "../../private/util";

export async function encrypt(key: Buffer, inputData: Buffer, rule: Model.Rule<Options, Data>) {
    const {ivBytes, algorithm} = rule.options;
    const data = {ivBase64: randomBytes(ivBytes).toString(BASE64_ENCODING)};
    const iv = Buffer.from(data.ivBase64, BASE64_ENCODING);
    const cipherIv = createCipheriv(algorithm, key, iv);
    const cipher = Buffer.concat([cipherIv.update(inputData), cipherIv.final()]);

    return {cipher, rule: {...rule, data}};
}

export async function decrypt(key: Buffer, inputData: Buffer, rule: Model.FilledRule<Options, Data>) {
    const {algorithm} = rule.options;
    const iv = Buffer.from(rule.data.ivBase64, BASE64_ENCODING);
    const decipherIv = createDecipheriv(algorithm, key, iv);

    return Buffer.concat([decipherIv.update(inputData), decipherIv.final()]);
}

export const optionsPresets = {
    "algorithm:aes-256-cbc": {
        ivBytes: SALT_BYTES_16,
        algorithm: "aes-256-cbc",
    },
};

export interface Options extends Model.Options {
    ivBytes: number;
    algorithm: string;
}

export interface Data extends Model.Data {
    ivBase64: string;
}
