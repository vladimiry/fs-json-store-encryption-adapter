import {pbkdf2} from "crypto";
import {promisify} from "util";

import {BASE64_ENCODING, KEY_BYTES_32, SALT_BYTES_16} from "../../private/constants";
import {KeyDerivationModuleImpl} from "../model";
import {randomBytes} from "../../private/util";

export const deriveKey: KeyDerivationModuleImpl<"pbkdf2">["deriveKey"] = async (password, rule) => {
    const {keyBytes, iterations, digest, saltBytes} = rule.options;
    const data = rule.data || {saltBase64: randomBytes(saltBytes).toString(BASE64_ENCODING)};
    const salt = Buffer.from(data.saltBase64, BASE64_ENCODING);
    const key = await promisify(pbkdf2)(password, salt, iterations, keyBytes, digest);

    return {key, rule: {...rule, data}};
};

const sha256DigestOptions = {
    keyBytes: KEY_BYTES_32,
    saltBytes: SALT_BYTES_16,
    digest: "sha256",
};

export const optionsPresets = {
    "mode:interactive|digest:sha256": {
        ...sha256DigestOptions,
        iterations: 128000,
    },
    "mode:moderate|digest:sha256": {
        ...sha256DigestOptions,
        iterations: 384000,
    },
    "mode:sensitive|digest:sha256": {
        ...sha256DigestOptions,
        iterations: 1152000,
    },
};

export interface Options {
    keyBytes: number;
    saltBytes: number;
    iterations: number;
    digest: string;
}

export interface Data {
    saltBase64: string;
}
