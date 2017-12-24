# AES

Software implementation of the Advanced Encryption Standard (AES) algorithm.
This library supports encryption and decryption in 128-bit, 192-bit, and
256-bit key schedules and can use either ECB or CBC mode.

## Setup

Resolve dependencies from `shard.yml`:
```bash
crystal deps
```

Run project unit tests to verify functionality:
```bash
crystal spec
```

Generate project documentation:
```bash
crystal doc
```

You can use this library in projects by passing a byte array. This means you
may have to call an appropriate conversion function in the language.

Example:
```crystal
# Create a new AES utility instance, providing the key and arguments
u = AES::Utils.new(key, AES::Mode::CBC, AES::Process::Encrypt)

# Pass the plaintext and resulting cipher text
ciphertext = u.process(plaintext)
```

An example is located in `sample/encrypt_aes.cr` which can be run by invoking
the `crystal` interpreter on the file.

To run the included files with ASCII characters representing hexadecimal
values, the following conversion is required:
```crystal
p = [] of Int32
plaintext.split("").each_slice(2) {|x| p << x.join("").to_i(16)}
```

## Implementation Decisions

- `FiniteField` stores everything as a `UInt8` (byte). Ideally, every
  computation would be performed on the byte level, but literals in Crystal
  are of type `Int32` and the type system strictly prevents interleaving of
  different integer types. In production, readability would be sacrificed for
  memory efficiency and `UInt8` casts would occur throughout the code.
- The AES specification defines functions as using words, but for the
  majority of the time, operations (like SBox substitutions), are conducted
  on the byte-level. As a general rule, everything is treated as an array of
  bytes, rather than words.
- The `FiniteField` struct defines arithmetic operations for Galois Field
  Multiplication in GF(2^8)
- AES helper functions often serve as double-purpose for encryption and
  decryption processes
