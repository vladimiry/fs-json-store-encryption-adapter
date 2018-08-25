import fs from "fs";
import path from "path";
import randomString from "randomstring";
import test from "ava";
import {randomBytes} from "crypto";

import {Encryption, EncryptionAdapter, Errors, KeyDerivation, PasswordBasedPreset} from "../../dist";
import {ENCRYPTED_PRESETS_DUMPS, forEachPreset, resolveSkippedPresets} from "./util";
// tslint:disable-next-line:no-import-zones
import {KEY_BYTES_32} from "../lib/private/constants";

test("core", async (t) => {
    const preset: { keyDerivation: KeyDerivation.KeyDerivationPresets; encryption: Encryption.EncryptionPresets } = {
        keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:interactive|algorithm:default"},
        encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
    };
    const data = Buffer.from("super secret data 123" + randomString.generate());
    const password = randomString.generate();
    const instance = new EncryptionAdapter({password, preset});

    // iteration 1
    const encryptedData = await instance.write(data);
    t.notDeepEqual(encryptedData, data, "encrypted and original data buffers should not match");
    t.true(encryptedData.toString().indexOf(data.toString()) === -1, "encrypted text should not contain the original text");
    const decryptedData = await instance.read(encryptedData);
    t.deepEqual(decryptedData, data);
    t.deepEqual(await new EncryptionAdapter({password, preset}).read(encryptedData), data, "read using new adapter instance");

    // iteration 2
    const encryptedDataIteration2 = await instance.write(data);
    const decryptedDataIteration2 = await instance.read(encryptedDataIteration2);
    t.notDeepEqual(encryptedDataIteration2, encryptedData,
        "same data encrypted with the same password should differ from the data encrypted on the previous iteration (random salt)");
    t.deepEqual(decryptedDataIteration2, decryptedData);

    // new instance with the same preset
    const instance2 = new EncryptionAdapter({password, preset});
    const encryptedData2 = await instance2.write(data);
    const decryptedData2 = await instance2.read(encryptedData2);
    t.deepEqual(decryptedData2, decryptedData);
    t.notDeepEqual(encryptedData2, encryptedData,
        "same data encrypted with the same password should differ from encrypted with previous adapter instance (random salt)");

    // instance with different preset, same password: should be able to read all the data previously encrypted with the same password
    const instance3DiffOpts = new EncryptionAdapter({
        password,
        preset: {
            keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:sensitive|algorithm:default"},
            encryption: {type: "crypto", preset: "algorithm:aes-256-cbc"},
        },
    });
    t.deepEqual(await instance3DiffOpts.read(encryptedData), data);
    t.deepEqual(await instance3DiffOpts.read(encryptedDataIteration2), data);
    t.deepEqual(await instance3DiffOpts.read(encryptedData2), data);

    // instance with same preset, but different password should fail with "DecryptionError"
    await t.throwsAsync(
        new EncryptionAdapter({password: randomString.generate(), preset}).read(encryptedData),
        Errors.DecryptionError,
    );
    await t.throwsAsync(
        new EncryptionAdapter({password: randomString.generate(), preset}).read(encryptedDataIteration2),
        Errors.DecryptionError,
    );
    await t.throwsAsync(
        new EncryptionAdapter({password: randomString.generate(), preset}).read(encryptedData2),
        Errors.DecryptionError,
    );
});

// run with all presets combinations
// tslint:disable-next-line:no-floating-promises
(async () => {
    const set = new Set();

    await forEachPreset(async (preset: PasswordBasedPreset) => {
        const adapterBuilders = [
            {
                title: "password based",
                input: {password: randomString.generate(), preset},
            },
            {
                title: "key based",
                input: {key: randomBytes(KEY_BYTES_32), preset: {encryption: preset.encryption}},
            },
        ];

        for (const adapterBuilder of adapterBuilders) {
            const uniqueOptions = JSON.stringify(adapterBuilder.input.preset);

            if (!set.has(uniqueOptions)) {
                set.add(uniqueOptions);

                test.serial(`${adapterBuilder.title} write/read: ${JSON.stringify(adapterBuilder.input)}"`, async (t) => {
                    const instance = new EncryptionAdapter(adapterBuilder.input);
                    const data = Buffer.from(randomString.generate());
                    const encryptedData = await instance.write(data);
                    const decryptedData = await instance.read(encryptedData);
                    const encryptedData2 = await instance.write(data);
                    const decryptedData2 = await instance.read(encryptedData);

                    t.deepEqual(decryptedData, data);
                    t.deepEqual(decryptedData2, data);
                    t.notDeepEqual(encryptedData2, encryptedData);
                });
            }
        }
    });
})();

// regression decrypting
// tslint:disable-next-line:no-floating-promises
(async () => {
    const {dumpsOutputDirectory, dataBuffer} = ENCRYPTED_PRESETS_DUMPS;

    if (!fs.existsSync(dumpsOutputDirectory)) {
        return;
    }

    for (const versionDirectory of fs.readdirSync(dumpsOutputDirectory)) {
        const directory = path.join(dumpsOutputDirectory, versionDirectory);
        const password: any = fs.existsSync(path.join(directory, "password.txt"))
            ? fs.readFileSync(path.join(directory, "password.txt")).toString().trim()
            : null;
        const key: any = fs.existsSync(path.join(directory, "key.bin"))
            ? fs.readFileSync(path.join(directory, "key.bin"))
            : null;

        if (!password && !key) {
            throw new Error("No password/key to decrypt data with");
        }

        for (const fileName of fs.readdirSync(directory)) {
            if (fileName.endsWith("password.txt") || fileName.endsWith("key.bin")) {
                continue;
            }

            const skippingPresets = resolveSkippedPresets(fileName);

            if (skippingPresets.length) {
                // tslint:disable-next-line:no-console
                console.log(`skipping "${JSON.stringify(skippingPresets)}" presets processing for file: ${fileName}`);
                continue;
            }

            test(`regression decrypting ${versionDirectory}: ${fileName}`, async (t) => {
                const encryptedData = fs.readFileSync(path.join(directory, fileName));
                const adapter = EncryptionAdapter.default(fileName.endsWith(".key.bin") ? {key} : {password});
                const decryptedData = await adapter.read(encryptedData);

                t.deepEqual(decryptedData, dataBuffer);
            });
        }
    }
})();

// TODO test: iterate using wrong/"any" options
// TODO test: empty password
