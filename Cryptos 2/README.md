# Cryptos Encoder 2

Encryption and decryption of files using bit noise superposition and permutation.

## Usage.

The cipher file must contain one line of cipher in decimal or hexadecimal. For example.

`1234567890123456789012345678901234567890`

`0x1234567890ABCDEF01234567890ABCDEF`

`0X1234567890ABCDEF01234567890ABCDEF`

Encryption from source to encrypted output file.

`python3 cryptos2.py -e -c cipher_file -i input_file -o output_file`

Decryption from encrypted input file to source output file.

`python3 cryptos2.py -d -c cipher_file -i input_file -o output_file`
