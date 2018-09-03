# simple-crypt
Very simple way to crypt strings (do not use to crypt sensitive data)

### Usage

`$sc = new SimpleCrypt('my-salt', 'iv');`

#### Encrypt
`$encrypted = $sc->encrypt('TEST');`

#### Decrypt
`$decrypted = $sc->decrypt($encrypted);`

#### Static
`$enc = SimpleCrypt::enc('TEST');`

`$dec = SimpleCrypt::dec($enc);`

#### Cipher ( [https://github.com/defuse/php-encryption](https://github.com/defuse/php-encryption))
`$enc = SimpleCrypt::encCipher('TEST','MyLongASCIIKey');`

`$dec = SimpleCrypt::decCipher($enc,'MyLongASCIIKey);`
