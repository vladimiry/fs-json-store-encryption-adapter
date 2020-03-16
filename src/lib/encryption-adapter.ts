import {EncryptionOptions, EncryptionPresets, resolveEncryption} from "./encryption";
import {KeyDerivationCache} from "./private/key-derivation-cache";
import {KeyDerivationOptions, KeyDerivationPresets, resolveKeyDerivation} from "./key-derivation";

const HEADER_END_MARK_BUFFER = Buffer.from([0o0]);

export class EncryptionAdapter {
    private readonly encryptionPreset: EncryptionPresets;
    private readonly resolveDecryptionKey: ((header: PasswordBasedFileHeader | KeyBasedFileHeader) => Promise<{ key: Buffer }>);
    private readonly resolveEncryptionKeyData: () => Promise<{ key: Buffer; keyDerivation?: KeyDerivationOptions }>;

    constructor(
        input: { password: string; preset: PasswordBasedPreset } | { key: Buffer; preset: KeyBasedPreset },
        options: { keyDerivationCache: boolean; keyDerivationCacheLimit?: number } = {keyDerivationCache: false},
    ) {
        this.encryptionPreset = input.preset.encryption;

        if ("password" in input) {
            const keyDerivationCache = options.keyDerivationCache ? new KeyDerivationCache(options.keyDerivationCacheLimit) : null;

            // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
            this.resolveDecryptionKey = async (header) => {
                if (!("keyDerivation" in header)) {
                    throw new Error(`Header doesn't contain the "keyDerivation" section`);
                }

                const keyFromCache = keyDerivationCache && keyDerivationCache.get(header.keyDerivation);

                if (keyFromCache) {
                    return {key: keyFromCache};
                }

                const {key, rule: keyDerivation} = await resolveKeyDerivation(header.keyDerivation).deriveKey(input.password);

                if (keyDerivationCache) {
                    keyDerivationCache.set(keyDerivation, key);
                }

                return {key};
            };
            // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
            this.resolveEncryptionKeyData = async () => {
                const {key, rule: keyDerivation} = await resolveKeyDerivation(input.preset.keyDerivation).deriveKey(input.password);

                if (keyDerivationCache) {
                    keyDerivationCache.set(keyDerivation, key);
                }

                return {key, keyDerivation};
            };
        } else {
            // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
            this.resolveDecryptionKey = async () => ({key: input.key});
            // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
            this.resolveEncryptionKeyData = async () => ({key: input.key});
        }
    }

    public static default(input: { password: string } | { key: Buffer }): EncryptionAdapter {
        const preset: PasswordBasedPreset = {
            keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:moderate|algorithm:default"},
            encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
        };
        return new EncryptionAdapter("password" in input
            ? {password: input.password, preset}
            : {key: input.key, preset: {encryption: preset.encryption}},
        );
    }

    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    public async read(data: Buffer) {
        const headerBytesSize = data.indexOf(HEADER_END_MARK_BUFFER);
        const headerBuffer = data.slice(0, headerBytesSize);
        const cipherBuffer = data.slice(headerBytesSize + 1);
        const header: PasswordBasedFileHeader | KeyBasedFileHeader = JSON.parse(headerBuffer.toString());
        const {key} = await this.resolveDecryptionKey(header);
        const {encryption} = header;

        return resolveEncryption(encryption).decrypt(key, cipherBuffer);
    }

    // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
    public async write(data: Buffer) {
        const keyData = await this.resolveEncryptionKeyData();
        const {cipher, rule: encryption} = await resolveEncryption(this.encryptionPreset).encrypt(keyData.key, data);
        const header: PasswordBasedFileHeader | KeyBasedFileHeader = {keyDerivation: keyData.keyDerivation, encryption};

        return Buffer.concat([
            Buffer.from(JSON.stringify(header)),
            HEADER_END_MARK_BUFFER,
            cipher,
        ]);
    }
}

export interface PasswordBasedPreset {
    readonly keyDerivation: KeyDerivationPresets;
    readonly encryption: EncryptionPresets;
}

export type KeyBasedPreset = Pick<PasswordBasedPreset, "encryption">;

export interface PasswordBasedFileHeader {
    readonly keyDerivation: KeyDerivationOptions;
    readonly encryption: EncryptionOptions;
}

export type KeyBasedFileHeader = Pick<PasswordBasedFileHeader, "encryption">;
