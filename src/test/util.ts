import fs from "fs";
import mkdirp from "mkdirp";
import path from "path";
import randomString from "randomstring";
import {promisify} from "util";
import {randomBytes} from "crypto";

import {Encryption, EncryptionAdapter, KeyDerivation, PasswordBasedPreset} from "lib";
// tslint:disable-next-line:no-import-zones
import {KEY_BYTES_32} from "lib/private/constants";

export async function forEachPreset(action: (preset: PasswordBasedPreset, iterationIndex: number) => Promise<void>) {
    const keyDerivationBundles = KeyDerivation.implementations as any;
    const encryptionBundles = Encryption.implementations as any;
    let iterationIndex = 0;

    Object.keys(keyDerivationBundles).forEach((keyDerivationType) => {
        Object.keys(keyDerivationBundles[keyDerivationType].optionsPresets).forEach((keyDerivationPreset) => {
            Object.keys(encryptionBundles).forEach((encryptionType) => {
                Object.keys(encryptionBundles[encryptionType].optionsPresets).forEach(async (encryptionPreset) => {
                    const preset: any = {
                        keyDerivation: {type: keyDerivationType, preset: keyDerivationPreset},
                        encryption: {type: encryptionType, preset: encryptionPreset},
                    };
                    const stringifyedPasswordBasedPreset = JSON.stringify(preset);
                    const skippingPresets = resolveSkippedPresets(stringifyedPasswordBasedPreset);

                    iterationIndex++;

                    if (skippingPresets.length) {
                        // tslint:disable-next-line:no-console
                        console.log(`skipping "${JSON.stringify(skippingPresets)}" presets processing: ${stringifyedPasswordBasedPreset}`);
                        return;
                    }

                    await action(preset, iterationIndex);
                });
            });
        });
    });

    return iterationIndex;
}

export function resolveSkippedPresets(scanValue: string): string[] {
    return String(process.env.TEST_SKIP_PRESETS)
        .split(",")
        .map((envPreset) => envPreset.trim())
        .filter((envPreset) => String(scanValue).toLowerCase().indexOf(envPreset) !== -1);
}

export const ENCRYPTED_PRESETS_DUMPS = Object.freeze({
    dataBuffer: Buffer.from("super secret data 123"),
    dumpsOutputDirectory: path.resolve(process.cwd(), "./src/test/fixtures/encrypted-presets-dumps"),
});

if (process.env.GENERATE_ENCRYPTED_PRESETS_DUMPS) {
    // tslint:disable-next-line:no-floating-promises
    (async () => {
        const {dumpsOutputDirectory, dataBuffer} = ENCRYPTED_PRESETS_DUMPS;
        const packageJSON = require(path.join(process.cwd(), "package.json"));
        const versionDirectory = safeFsCharacters(packageJSON.version);
        const outputDirectory = path.resolve(dumpsOutputDirectory, versionDirectory);
        mkdirp.sync(outputDirectory);

        const key = randomBytes(KEY_BYTES_32);
        const password = randomString.generate(KEY_BYTES_32);
        await promisify(fs.writeFile)(path.join(outputDirectory, "password.txt"), password);
        await promisify(fs.writeFile)(path.join(outputDirectory, "key.bin"), key);

        await forEachPreset(async (preset: PasswordBasedPreset) => {
            const passwordBasedFile = path.join(
                outputDirectory,
                safeFsCharacters([
                    preset.keyDerivation.type,
                    preset.keyDerivation.preset,
                    preset.encryption.type,
                    preset.encryption.preset,
                ].join("--")) + ".bin",
            );
            // tslint:disable-next-line:no-console
            console.log(`writing ${passwordBasedFile}`);
            await promisify(fs.writeFile)(passwordBasedFile, await new EncryptionAdapter({password, preset}).write(dataBuffer));

            const keyBasedFile = path.join(
                outputDirectory,
                safeFsCharacters([
                    preset.encryption.type,
                    preset.encryption.preset,
                ].join("--")) + ".key.bin",
            );
            // tslint:disable-next-line:no-console
            console.log(`writing ${keyBasedFile}`);
            await promisify(fs.writeFile)(keyBasedFile, await new EncryptionAdapter({
                key,
                preset: {encryption: preset.encryption},
            }).write(dataBuffer));
        });
    })();
}

function safeFsCharacters(str: string) {
    return str.replace(/[^A-Za-z0-9\-]/g, "_");
}
