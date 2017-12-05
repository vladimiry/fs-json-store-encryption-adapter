import * as fs from "fs";
import * as path from "path";
import * as randomString from "randomstring";
import {test} from "ava";

import {Encryption, EncryptionAdapter, Errors, KeyDerivation, Options} from "dist";
import {ENCRYPTED_PRESETS_DUMPS, forEachPreset} from "./util";

test("core", async (t) => {
    const options: { keyDerivation: KeyDerivation.KeyDerivationPresets; encryption: Encryption.EncryptionPresets } = {
        keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:interactive|algorithm:default"},
        encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
    };
    const data = Buffer.from("super secret data 123" + randomString.generate());
    const password = randomString.generate();
    const instance = new EncryptionAdapter(password, options);

    // iteration 1
    const encryptedData = await instance.write(data);
    t.notDeepEqual(encryptedData, data, "encrypted and original data buffers should not match");
    t.true(encryptedData.toString().indexOf(data.toString()) === -1, "encrypted text should not contain the original text");
    const decryptedData = await instance.read(encryptedData);
    t.deepEqual(decryptedData, data);
    t.deepEqual(await new EncryptionAdapter(password, options).read(encryptedData), data, "read using new adapter instance");

    // iteration 2
    const encryptedDataIteration2 = await instance.write(data);
    const decryptedDataIteration2 = await instance.read(encryptedDataIteration2);
    t.notDeepEqual(encryptedDataIteration2, encryptedData,
        "same data encrypted with the same password should differ from the data encrypted on the previous iteration (random salt)");
    t.deepEqual(decryptedDataIteration2, decryptedData);

    // new instance with the same options
    const instance2 = await new EncryptionAdapter(password, options);
    const encryptedData2 = await instance2.write(data);
    const decryptedData2 = await instance2.read(encryptedData2);
    t.deepEqual(decryptedData2, decryptedData);
    t.notDeepEqual(encryptedData2, encryptedData,
        "same data encrypted with the same password should differ from encrypted with previous adapter instance (random salt)");

    // instance with different options, same password: should be able to read all the data previously encrypted with the same password
    const instance3DiffOpts = await new EncryptionAdapter(password, {
        keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:sensitive|algorithm:default"},
        encryption: {type: "crypto", preset: "algorithm:aes-256-cbc"},
    });
    t.deepEqual(await instance3DiffOpts.read(encryptedData), data);
    t.deepEqual(await instance3DiffOpts.read(encryptedDataIteration2), data);
    t.deepEqual(await instance3DiffOpts.read(encryptedData2), data);

    // instance with same options, but different password: should fail
    await t.throws(new EncryptionAdapter(randomString.generate(), options).read(encryptedData));
    await t.throws(new EncryptionAdapter(randomString.generate(), options).read(encryptedDataIteration2));
    const err = await t.throws(new EncryptionAdapter(randomString.generate(), options).read(encryptedData2));
    // t.is(err.errors[0].constructor.name, Errors.FailedDecryptionError.name);
    t.true(err.errors[0] instanceof Errors.FailedDecryptionError);
});

// run with all presets combinations
(async () => {
    const iterationsCount = await forEachPreset(async (options: Options) => {
        test(`presets write/read: ${JSON.stringify(options)}"`, async (t) => {
            const instance = new EncryptionAdapter(randomString.generate(), options);
            const data = Buffer.from(randomString.generate());
            const encryptedData = await instance.write(data);
            const decryptedData = await instance.read(encryptedData);
            const encryptedData2 = await instance.write(data);
            const decryptedData2 = await instance.read(encryptedData);

            t.deepEqual(decryptedData, data);
            t.deepEqual(decryptedData2, data);
            t.notDeepEqual(encryptedData2, encryptedData);
        });
    });
    const expectedIterationsCount = 12;

    test("presets write/read: iterations count", async (t) => {
        t.is(iterationsCount, expectedIterationsCount, "expected iterations count");
    });
})();

// regression decrypting
(async () => {
    const {dumpsOutputDirectory, dataBuffer} = ENCRYPTED_PRESETS_DUMPS;

    if (!fs.existsSync(dumpsOutputDirectory)) {
        return;
    }

    for (const versionDirectory of fs.readdirSync(dumpsOutputDirectory)) {
        const directory = path.join(dumpsOutputDirectory, versionDirectory);

        for (const fileName of fs.readdirSync(directory)) {
            test(`regression decrypting v${versionDirectory}: ${fileName}`, async (t) => {
                const encryptedData = fs.readFileSync(path.join(directory, fileName));
                const decryptedData = await EncryptionAdapter.default(versionDirectory).read(encryptedData);

                t.deepEqual(decryptedData, dataBuffer);
            });
        }
    }
})();

// TODO test: iterate using wrong/"any" options
// TODO test: empty password
