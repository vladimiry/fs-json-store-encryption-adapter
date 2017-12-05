import {KeyDerivationPresets, resolveKeyDerivation} from "./key-derivation";
import {EncryptionPresets, resolveEncryption} from "./encryption";

const HEADER_END_MARK_BUFFER = Buffer.from([0o0]);

export class EncryptionAdapter {
    public static default = (password: string) => new EncryptionAdapter(password, {
        keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:interactive|algorithm:default"},
        encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
    })

    constructor(private readonly password: string, private readonly opts: Options) {}

    public async read(data: Buffer) {
        const headerBytesSize = data.indexOf(HEADER_END_MARK_BUFFER);
        const headerBuffer = data.slice(0, headerBytesSize);
        const cipherBuffer = data.slice(headerBytesSize + 1);
        const {keyDerivation, encryption}: FileHeader = JSON.parse(headerBuffer.toString());
        const {key} = await resolveKeyDerivation(keyDerivation).deriveKey(this.password);

        return await resolveEncryption(encryption).decrypt(encryption, key, cipherBuffer);
    }

    public async write(data: Buffer) {
        const {key, rule: keyDerivation} = await resolveKeyDerivation(this.opts.keyDerivation).deriveKey(this.password);
        const {cipher, rule: encryption} = await resolveEncryption(this.opts.encryption).encrypt(this.opts.encryption, key, data);
        const header: FileHeader = {keyDerivation, encryption};

        return Buffer.concat([
            Buffer.from(JSON.stringify(header)),
            HEADER_END_MARK_BUFFER,
            cipher,
        ]);
    }
}

export interface Options {
    keyDerivation: KeyDerivationPresets;
    encryption: EncryptionPresets;
}

interface FileHeader {
    keyDerivation: { type: any; options: any; data: any; };
    encryption: { type: any; options: any; data: any; };
}
