# Cryptos Encoder 2.1

Encryption and decryption of files using bit noise superposition and permutation.

## Usage.

`python3 cryptos2.1.py [-h] (-e | -d) -c file (-b16 | -b64) -i input_file -o output_file`

The cipher file must contain one line of cipher in decimal or hexadecimal. For example.

`1234567890123456789012345678901234567890`

`0x1234567890ABCDEF01234567890ABCDEF`

`0X1234567890ABCDEF01234567890ABCDEF`

It is possible use multiline cipher notation. For example.

```12345678
90123456
78901234
56789012
34567890```

```0x1234567890ABCD
EF01234567890ABC
DEF```

```0X1234567890ABCD
EF01234567890ABC
DEF```

Encryption from source to encrypted output file.

`python3 cryptos2.1.py -e -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.1.py -e -c cipher_file -b64 -i input_file -o output_file`

Decryption from encrypted input file to source output file.

`python3 cryptos2.1.py -d -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.1.py -d -c cipher_file -b64 -i input_file -o output_file`
