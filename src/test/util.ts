import fs from "fs";
import {mkdirp} from "mkdirp";
import path from "path";
import {promisify} from "util";
import {randomBytes} from "crypto";
import randomString from "randomstring";

import {Encryption, EncryptionAdapter, KeyDerivation, PasswordBasedPreset} from "../../lib";
import {KEY_BYTES_32} from "../../lib/private/constants";

function safeFsCharacters(str: string): string {
    return str.replace(/[^A-Za-z0-9-]/g, "_");
}

export async function forEachPreset(
    action: (preset: PasswordBasedPreset, iterationIndex: number) => Promise<void>,
): Promise<number> {
    const keyDerivationBundles = KeyDerivation.implementations as any; // eslint-disable-line @typescript-eslint/no-explicit-any
    const encryptionBundles = Encryption.implementations as any; // eslint-disable-line @typescript-eslint/no-explicit-any
    let iterationIndex = 0;

    for (const keyDerivationType of Object.keys(keyDerivationBundles)) {
        for (const keyDerivationPreset of Object.keys(keyDerivationBundles[keyDerivationType].optionsPresets)) {
            for (const encryptionType of Object.keys(encryptionBundles)) {
                for (const encryptionPreset of Object.keys(encryptionBundles[encryptionType].optionsPresets)) {
                    const preset: any = { // eslint-disable-line @typescript-eslint/no-explicit-any
                        keyDerivation: {type: keyDerivationType, preset: keyDerivationPreset},
                        encryption: {type: encryptionType, preset: encryptionPreset},
                    };
                    iterationIndex++;
                    await action(preset, iterationIndex);
                }
            }
        }
    }

    return iterationIndex;
}

export const ENCRYPTED_PRESETS_DUMPS = Object.freeze({
    dataBuffer: Buffer.from("super secret data 123"),
    dumpsOutputDirectory: path.resolve(process.cwd(), "./src/test/fixtures/encrypted-presets-dumps"),
});

if (process.env.GENERATE_ENCRYPTED_PRESETS_DUMPS) {
    (async () => { // eslint-disable-line @typescript-eslint/explicit-function-return-type, @typescript-eslint/no-floating-promises
        const {dumpsOutputDirectory, dataBuffer} = ENCRYPTED_PRESETS_DUMPS;
        // eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
        const packageJSON = require(path.join(process.cwd(), "package.json"));
        const versionDirectory = safeFsCharacters(packageJSON.version);
        const outputDirectory = path.resolve(dumpsOutputDirectory, versionDirectory);
        
        await mkdirp(outputDirectory);

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
            // eslint-disable-next-line no-console
            console.log(`writing ${passwordBasedFile}`);
            await promisify(fs.writeFile)(passwordBasedFile, await new EncryptionAdapter({password, preset}).write(dataBuffer));

            const keyBasedFile = path.join(
                outputDirectory,
                safeFsCharacters([
                    preset.encryption.type,
                    preset.encryption.preset,
                ].join("--")) + ".key.bin",
            );
            // eslint-disable-next-line no-console
            console.log(`writing ${keyBasedFile}`);
            await promisify(fs.writeFile)(keyBasedFile, await new EncryptionAdapter({
                key,
                preset: {encryption: preset.encryption},
            }).write(dataBuffer));
        });
    })();
}
