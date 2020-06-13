# Cryptos Encoder 2.3

Encryption and decryption of files using bit noise superposition and permutation with multiplication or transform to numeral system with secret base.

## Usage.

`python3 cryptos2.3.py [-h] [-v] (-e | -d) (-mpn | -cns) -c cipher_file (-b16 | -b64) -i input_file -o output_file`

The cipher file must contain one line of cipher in decimal, hexadecimal, octal or binary. For example.

`1234567890123456789012345678901234567890`

`0x1234567890ABCDEF01234567890ABCDEF`

`0X1234567890ABCDEF01234567890ABCDEF`

`0o123456701234567012345670123456701`

`0O123456701234567012345670123456701`

`0b101010101010101010101010101010101`

`0B101010101010101010101010101010101`

It is possible use multiline cipher notation. For example.

```
12345678
90123456
78901234
56789012
34567890
```
```
0x1234567890ABCD
EF01234567890ABC
DEF
```
```
0X1234567890ABCD
EF01234567890ABC
DEF
```

## Options

-h, --help              show help message and exit.
-v, --verification      print more information.
-e, --encryption        encryption action.
-d, --decryption        decryption action.
-mpn, --mulprimenul     permutation, noise, multiplication method. It is recommended for small volumes of information, approximately a few key lengths or little.
-cns, --ciphersystem    cipher numeral system method. It is recommended for small volumes of information, many times overhad the key length and more.
-c file, --cipher file  file with hipher key.
-b16, --io_base16       base16 input or output file. It it recommended for key generation option.
-b64, --io_base64       base64 input or output file.
-i file, --input file   input file.
-o file, --output file  output file.

## Examples

Encryption from source to encrypted output file.

`python3 cryptos2.3.py -e -mpn -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.3.py -e -mpn -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.3.py -e -cns -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.3.py -e -cns -c cipher_file -b64 -i input_file -o output_file`

Decryption from encrypted input file to source output file.

`python3 cryptos2.3.py -d -mpn -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.3.py -d -mpn -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.3.py -d -cns -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.3.py -d -cns -c cipher_file -b64 -i input_file -o output_file`
