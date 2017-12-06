# fs-json-store-encryption-adapter

is an encryption adapter for the [fs-json-store](https://github.com/vladimiry/fs-json-store) module.

[![Build Status: Linux / MacOS](https://travis-ci.org/vladimiry/fs-json-store-encryption-adapter.svg?branch=master)](https://travis-ci.org/vladimiry/fs-json-store-encryption-adapter) [![Build status: Windows](https://ci.appveyor.com/api/projects/status/8ia8inx76ctamhmb?svg=true)](https://ci.appveyor.com/project/vladimiry/fs-json-store-encryption-adapter)

## Features
- Predefined presets.
- Switching between built-in node's `crypto` and `libsodium` (like Argon2 key derivation function) implementations.
- Keeping all the needed options in the produced buffer in along with the encrypted data itself.
- Random `salting` is enabled for every key derivation and encryption execution, which helps against the lookup tables and rainbow tables hash cracking attacks. It's more helpful in a multi user environment though.

## Implementation Notes
- Module executes a native [libsodium](https://github.com/jedisct1/libsodium) code with help of the [sodium-native](https://github.com/sodium-friends/sodium-native) bindings library. It's supposed to work faster than the WebAssembly versions.
- Module can be used as a general purpose `Buffer` encryption library, adapter simply implements the following interface:
```typescript
export interface Adapter {
    write(data: Buffer): Promise<Buffer>;
    read(data: Buffer): Promise<Buffer>;
}
```

## Supported Presets

### `key derivation`
- **`type`**: `sodium.crypto_pwhash`
  - **`preset`**: `mode:interactive|algorithm:default` - default algorithm as for now is `Argon2id`.
  - **`preset`**: `mode:moderate|algorithm:default`
  - **`preset`**: `mode:sensitive|algorithm:default`
- **`type`**: `pbkdf2`
  - **`preset`**: `mode:interactive|digest:sha256`
  - **`preset`**: `mode:moderate|digest:sha256`
  - **`preset`**: `mode:sensitive|digest:sha256`

### `encryption`
- **`type`**: `sodium.crypto_secretbox_easy`
  - **`preset`**: `algorithm:default`
- **`type`**: `crypto`
  - **`preset`**: `algorithm:aes-256-cbc`

You should not rely on the `types / presets` respective inner values, but only on the `types / presets` names listed above. Presets values can be changed in the code in any time (for example, increasing key derivation work factor), but that won't break the decryption of the previously encrypted data since adapter stores all the encryption options in the same buffer and so decryption can be reproduced even if values of the presets have been changed in the code with new module release.

## Usage Examples

Using TypeScript and async/await:

```typescript
import {Model, Store} from "fs-json-store";
import {EncryptionAdapter} from "fs-json-store-encryption-adapter";

interface DataModel extends Partial<Model.StoreEntity> {
    someProperty: string;
}

const password = process.env.STORE_PASSWORD;

if (!password) {
    throw new Error("Empty password is not allowed");
}

// data file example
(async () => {
    const store = new Store<DataModel>({
        file: "./data.bin",
        adapter: new EncryptionAdapter(
            password,
            {
                keyDerivation: {type: "sodium.crypto_pwhash", preset: "mode:interactive|algorithm:default"},
                encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
            },
        ),
    });
    const data = await store.write({someProperty: "super secret data"}); // writes encrypted data into the `./data.bin` file
    console.log(data); // prints stored data
    console.log(await store.read()); // reads and prints stored data
})();

// standalone example using default options
(async () => {
    const adapter = EncryptionAdapter.default(password);
    const dataBuffer = Buffer.from("super secret data");
    const encryptedDataBuffer = await adapter.write(dataBuffer);
    const decryptedDataBuffer = await adapter.read(encryptedDataBuffer);
    console.log(decryptedDataBuffer.toString()); // prints `super secret data`
})();
```

Using JavaScript and Promises:

```javascript
const {Store} = require("fs-json-store");
const {EncryptionAdapter} = require("fs-json-store-encryption-adapter");

const password = process.env.STORE_PASSWORD;

if (!password) {
    throw new Error("Empty password is not allowed");
}


// data file example
(() => {
    const store = new Store({
        file: "./data.bin",
        adapter: new EncryptionAdapter(
            password,
            {
                keyDerivation: {type: "pbkdf2", preset: "mode:interactive|digest:sha256"},
                encryption: {type: "sodium.crypto_secretbox_easy", preset: "algorithm:default"},
            },
        ),
    });

    store
        .write({someProperty: "super secret data"}) // writes encrypted data into the `./data.bin` file
        .then((data) => console.log(data)) // prints stored data
        .then(() => store.read()) // reads stored data
        .then(console.log); // prints stored data
})();

// standalone example using default options
(() => {
    const adapter = EncryptionAdapter.default(password);

    adapter
        .write(Buffer.from("super secret data"))
        .then((encryptedDataBuffer) => adapter.read(encryptedDataBuffer))
        .then((decryptedDataBuffer) => console.log(decryptedDataBuffer.toString())); // prints `super secret data`
})();
```
