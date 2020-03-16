import randomString from "randomstring";
import test from "ava";

import {EncryptionAdapter, PasswordBasedPreset} from "../../lib";

test("keyDerivationCache", async (t) => {
    async function calcTime(keyDerivationCache: boolean): Promise<number> {
        const password = randomString.generate();
        const data = Buffer.from("secret data");
        const preset: PasswordBasedPreset = {
            keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:moderate|algorithm:default"},
            encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
        };
        const adapter = new EncryptionAdapter({password, preset}, {keyDerivationCache});
        const start = Number(new Date());
        const encrypted = await adapter.write(data);
        await adapter.read(encrypted);
        await adapter.read(encrypted);
        await adapter.read(encrypted);
        return Number(new Date()) - start;
    }

    const noCacheTime = await calcTime(false);
    const cacheTime = await calcTime(true);
    const noCacheLongerTimes = noCacheTime / cacheTime;
    const value = 3;

    t.true(
        noCacheLongerTimes > value,
        `run without cache should take at least ${value} times longer than using cache, ${JSON.stringify({noCacheTime, cacheTime})}`,
    );
});
