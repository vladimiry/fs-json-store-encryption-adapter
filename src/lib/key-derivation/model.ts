import {KeyDerivationOptions} from "./";
import {PartialByKeys} from "src/lib/private/constants";

export interface KeyDerivationModuleImpl<T extends KeyDerivationOptions["type"] = KeyDerivationOptions["type"]> {
    optionsPresets: Readonly<Record<string, Extract<KeyDerivationOptions, { type: T }>["options"]>>;

    deriveKey(
        password: string,
        rule: PartialByKeys<Extract<KeyDerivationOptions, { type: T }>, "data">,
    ): Promise<Readonly<{ key: Buffer; rule: KeyDerivationOptions }>>;
}
