# Cryptos Encoder 2.5

Encryption and decryption of files using bit noise superposition and permutation with division.

## Usage.

`python3 cryptos2.5.py [-h] [-v] (-e | -d) (-dig | -txt | -bin) -c cipher_file (-b16 | -b64 | -b256) -i input_file -o output_file`

The digital cipher file must contain one line of cipher in decimal, hexadecimal, octal or binary. For example.

`1234567890123456789012345678901234567890`

`0x1234567890ABCDEF01234567890ABCDEF`

`0X1234567890ABCDEF01234567890ABCDEF`

`0o123456701234567012345670123456701`

`0O123456701234567012345670123456701`

`0b101010101010101010101010101010101`

`0B101010101010101010101010101010101`

It is possible use multiline digital cipher notation. For example.

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

The text cipher file must contain any text. For example.

`This is a chifer`

Of course, it is possible use of multiline text.

```
This is a chifer,
very long cipher
text.
```
## Options

**-h, --help:** show help message and exit.  
**-v, --verification:** print more information.  
**-e, --encryption:** encryption action.  
**-d, --decryption:** decryption action.  
**-dig, --digital:** digital key.  
**-txt, --text:** text key.  
**-bin, --binary:** binary key. It is recommended using of files up to 10 kilobytes.  
**-c file, --cipher file:** file with cipher key.  
**-b16, --io_base16:** base16 input or output file. It it recommended for key generation option.  
**-b64, --io_base64:** base64 input or output file.  
**-b256, --io_base256:** binary input or output file.  
**-i file, --input file:** input file.  
**-o file, --output file:** output file.  

## Examples

Encryption from source to encrypted output file.

`python3 cryptos2.5.py [-v] -e -dig -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -dig -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -dig -c cipher_file -b256 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -txt -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -txt -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -txt -c cipher_file -b256 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -bin -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -bin -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -e -bin -c cipher_file -b256 -i input_file -o output_file`

Decryption from encrypted input file to source output file.

`python3 cryptos2.5.py [-v] -d -dig -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -dig -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -dig -c cipher_file -b256 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -txt -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -txt -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -txt -c cipher_file -b256 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -bin -c cipher_file -b16 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -bin -c cipher_file -b64 -i input_file -o output_file`

`python3 cryptos2.5.py [-v] -d -bin -c cipher_file -b256 -i input_file -o output_file`
