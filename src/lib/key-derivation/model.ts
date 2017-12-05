export interface Bundle<O = Options, D = Data> {
    optionsPresets: Record<string, O>;

    deriveKey(password: string, rule: Rule<O, D>): Result<O, D>;
}

export interface Implementation<O = Options, D = Data> {
    deriveKey(password: string): Result<O, D>;
}

export type Result<O, D> = Promise<{ key: Buffer, rule: FilledRule<O, D> }>;

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
