import {KeyDerivationOptions} from ".";
import {PartialByKeys} from "../private/constants";

export interface KeyDerivationModuleImpl<T extends KeyDerivationOptions["type"] = KeyDerivationOptions["type"]> {
    optionsPresets: Record<string, Extract<KeyDerivationOptions, { type: T }>["options"]>;

    deriveKey(
        password: string,
        rule: PartialByKeys<Extract<KeyDerivationOptions, { type: T }>, "data">,
    ): Promise<{ key: Buffer, rule: KeyDerivationOptions }>;
}
