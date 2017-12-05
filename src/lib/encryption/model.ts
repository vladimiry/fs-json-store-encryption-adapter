import {EncryptionOptions, EncryptionPresets} from ".";

export interface Bundle<O = Options, D = Data> {
    optionsPresets: Record<string, O>;

    encrypt(key: Buffer, inputData: Buffer, rule: Rule<O, D>): Promise<{ cipher: Buffer, rule: FilledRule<O, D> }>;

    decrypt(key: Buffer, inputData: Buffer, rule: FilledRule<O, D>): Promise<Buffer>;
}

export interface Implementation<O = Options, D = Data> {
    encrypt(opts: EncryptionPresets, key: Buffer, inputData: Buffer): Promise<{ cipher: Buffer, rule: FilledRule<O, D> }>;

    decrypt(opts: EncryptionOptions, key: Buffer, inputData: Buffer): Promise<Buffer>;
}

export interface Rule<O, D> {
    type: string;
    options: O;
    data?: D;
}

export interface FilledRule<O, D> extends Rule<O, D> {
    data: D;
}

// tslint:disable:no-empty-interface

export interface Options {}

export interface Data {}

// tslint:enable:no-empty-interface
