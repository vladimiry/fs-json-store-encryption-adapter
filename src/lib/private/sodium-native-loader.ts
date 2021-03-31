import sodium from "sodium-native"; // eslint-disable-line no-restricted-imports

import {assertEqual} from "./util";

export const crypto_pwhash_SALTBYTES: number = (sodium as unknown as { crypto_pwhash_SALTBYTES: number }).crypto_pwhash_SALTBYTES;

assertEqual(crypto_pwhash_SALTBYTES, 16, `Unexpected "crypto_pwhash_SALTBYTES" value`);
assertEqual(sodium.crypto_box_MACBYTES, 16, `Unexpected "crypto_box_MACBYTES" value`);
assertEqual(sodium.crypto_box_NONCEBYTES, 24, `Unexpected "crypto_box_NONCEBYTES" value`);
assertEqual(sodium.crypto_generichash_KEYBYTES, 32, `Unexpected "crypto_generichash_KEYBYTES" value`);
assertEqual(sodium.crypto_pwhash_ALG_DEFAULT, 2, `Unexpected "crypto_pwhash_ALG_DEFAULT" value`);

export default {
    ...sodium,
    crypto_pwhash_SALTBYTES,
} as const;
