import fs from "fs";
import path from "path";
import mkdirp from "mkdirp";

import {Encryption, EncryptionAdapter, KeyDerivation, Options} from "dist";

export async function forEachPreset(action: (options: Options, iterationIndex: number) => Promise<void>) {
    const keyDerivationBundles = KeyDerivation.bundles as any;
    const encryptionBundles = Encryption.bundles as any;
    let iterationIndex = 0;

    Object.keys(keyDerivationBundles).forEach((keyDerivationType) => {
        Object.keys(keyDerivationBundles[keyDerivationType].optionsPresets).forEach((keyDerivationPreset) => {
            Object.keys(encryptionBundles).forEach((encryptionType) => {
                Object.keys(encryptionBundles[encryptionType].optionsPresets).forEach(async (encryptionPreset) => {
                    const options: any = {
                        keyDerivation: {type: keyDerivationType, preset: keyDerivationPreset},
                        encryption: {type: encryptionType, preset: encryptionPreset},
                    };
                    const stringifyedOptions = JSON.stringify(options);
                    const skippingPresets = resolveSkippedPresets(stringifyedOptions);

                    iterationIndex++;

                    if (skippingPresets.length) {
                        // tslint:disable:no-console
                        console.log(`skipping "${JSON.stringify(skippingPresets)}" presets processing: ${stringifyedOptions}`);
                        // tslint:enable:no-console
                        return;
                    }

                    await action(options, iterationIndex);
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
    (async () => {
        const {dumpsOutputDirectory, dataBuffer} = ENCRYPTED_PRESETS_DUMPS;
        const packageJSON = require(path.join(process.cwd(), "package.json"));
        const versionDirectory = safeFsCharacters(packageJSON.version);
        const outputDirectory = path.resolve(dumpsOutputDirectory, versionDirectory);

        mkdirp.sync(outputDirectory);

        await forEachPreset(async (options: Options) => {
            const file = path.join(
                outputDirectory,
                safeFsCharacters([
                    options.keyDerivation.type,
                    options.keyDerivation.preset,
                    options.encryption.type,
                    options.encryption.preset,
                ].join("--")) + ".bin",
            );
            const instance = new EncryptionAdapter(versionDirectory, options);
            const encryptedData = await instance.write(dataBuffer);

            // tslint:disable:no-console
            console.log(`writing ${file}`);
            // tslint:enable:no-console

            await require("util").promisify(fs.writeFile)(file, encryptedData);
        });
    })();
}

function safeFsCharacters(str: string) {
    return str.replace(/[^A-Za-z0-9\-]/g, "_");
}
