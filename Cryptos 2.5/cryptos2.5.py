from argparse import ArgumentParser
from base64 import b16decode, b16encode, b64decode, b64encode
from functools import reduce
from secrets import token_bytes


def bits_few(key):
    zeros = 0
    ones = 0
    while (key):
        if key & 1:
            ones += 1
        else:
            zeros += 1

        key >>= 1

    count = zeros + ones
    few_zeros = (100 * zeros // count < 30)
    few_ones = (100 * ones // count < 30)
    if few_zeros:
        print('It is too few zeros in the encryption key!',
              'Please try change chipher key by adding more zeros.')

    if few_ones:
        print('It is too few ones in the encryption key!',
              'Please try change chipher key by adding more non zero bytes.')

    if args.verification:
        print(f'Chipher kes {count} lehgth consists of {zeros} zeros and {ones} ones.')

    return any([few_zeros, few_ones])

def byte_length(x):
    return (x.bit_length() + 7) // 8

def get_salt(s):
    sum_s = sum(s)
    salt = (((len(s) << sum_s.bit_length()) + sum_s) << 8) + reduce(lambda x, y: x ^ y, s)
    mul_s = reduce(lambda x, y: (x * y) % ch, filter(lambda x: x > 1, s))

    return (salt << mul_s.bit_length()) + mul_s


def int_sqrt(x):
    z, zp = 2, 4
    while x - z * z > zp - x:
        z, zp = zp, zp * zp
    zn = lambda y: (y + x // y) // 2
    z1 = zn(z)
    z2 = zn(z1)
    while z1 != z and z2 != z:
        z, z1, z2 = z1, z2, zn(z2)
        z = min([z1, z2])
        z1, z2 = z, z + 1
    if abs(x - z1 * z1) < abs(x - z2 * z2):
        return z1
    else:
        return z2


def noise(s, salt=None):
    if salt is None:
        z = len(s)
    else:
        z = salt

    if z > 1:
        while z < ch:
            z *= z
    else:
        z = ch % 256

    i = j = k = 0
    sl = len(s)
    while k < sl:
        z %= ch
        xbl = z.bit_length() // 8
        xb = z.to_bytes(xbl + 1, 'little')[:-1]
        j = min(sl - k, xbl)
        for i in range(0, j):
            s[k] ^= xb[i]
            k += 1

        if z == 0:
            z = ch * ch + 1
        else:
            z *= z ^ (ch >> (ch.bit_length() - z.bit_length()))


def shuffle(s, sc=None):
    if len(s) < 2:
        return

    if sc is None:
        sc = s

    salt = get_salt(sc)
    z, k = ch % salt, len(s) - 1
    while z < ch:
        z *= z

    while k > 0:
        z %= salt
        rmd = z
        while k > 0 and rmd > k:
            n = rmd % (k + 1)
            s[k], s[n] = s[n], s[k]
            k -= 1
            rmd //= (k + 1)
        if z == 0:
            z = salt * salt + 1
        else:
            z *= z ^ (salt >> (salt.bit_length() - z.bit_length()))


def tokenize(s, token=None):
    if token is None:
        token = list(token_bytes(key_len))

    s, salt = list((8 + len(s)).to_bytes(8, 'big')) + s, get_salt(token)
    noise(s, salt)

    return token + s + [1] + list(token_bytes(2 * key_len + salt % int_sqrt(len(s) + key_len)))


def unshuffle(sch):
    sc = list(range(len(sch)))
    shuffle(sc, sch)
    s = [0] * len(sc)
    for k in range(len(sc)):
        s[sc[k]] = sch[k]

    return s


def untokenize(s):
    token, s = s[:key_len], s[key_len:]
    noise(s, get_salt(token))

    return s[8:int.from_bytes(s[:8], 'big')]


parser = ArgumentParser(description='Encription or decryption file by specifed cipher.')
parser.add_argument('-v', '--verification', action='store_true', help='Print more information')
parser.add_argument('-s', '--silent', action='store_true', help='Silent mode')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', "--encryption", action="store_true", help='Encryption file')
group.add_argument('-d', "--decryption", action="store_true", help='Decryption file')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-dig', "--digital", action="store_true", help='Digital cipher')
group.add_argument('-txt', "--text", action="store_true", help='Text cipher')
group.add_argument('-bin', "--binary", action="store_true", help='Binary cipher')
parser.add_argument('-c', '--cipher', metavar='file', type=str, required=True, help='Cipher file')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-b16', "--io_base16", action="store_true", help='base16 input or output file')
group.add_argument('-b64', "--io_base64", action="store_true", help='base64 input or output file')
group.add_argument('-b256', "--io_base256", action="store_true", help='Binary input or output file')
parser.add_argument('-i', '--input', metavar='file', type=str, required=True, help='Input file')
parser.add_argument('-o', '--output', metavar='file', type=str, required=True, help='Output file')

args = parser.parse_args()

## Common part

if args.digital:
    with open(args.cipher) as f:
        ch = int(''.join(map(lambda s: s.strip(), f.readlines())), 0)
elif args.text:
    with open(args.cipher) as f:
        ch = int.from_bytes(bytes(f.read(), 'utf-8'), 'big')
elif args.binary:
    with open(args.cipher, 'rb') as f:
        ch = int.from_bytes(f.read(), 'big')

if ch.bit_length() < 64:
    exit('It is too short key!')

if bits_few(ch):
    exit('It is too weak key!')

key_len = byte_length(ch)

## Encription

if args.encryption:
    with open(args.input, 'rb') as f:
        s = list(f.read())

    s = tokenize(s)
    s = int.from_bytes(s, 'big') // ch
    s = list(s.to_bytes(byte_length(s), 'big'))
    noise(s)
    shuffle(s)
    s = bytes(s)
    if args.io_base16 or args.io_base64:
        if args.io_base16:
            s = b16encode(s).decode()
        elif args.io_base64:
            s = b64encode(s).decode()

        with open(args.output, 'w') as f:
            f.writelines('\n'.join(s[i:i + 64] for i in range(0, len(s), 64)))

    elif args.io_base256:
        with open(args.output, 'wb') as f:
            f.write(s)

    if not args.silent:
        print('Encryption completed!')

## Decription

elif args.decryption:
    if args.io_base16 or args.io_base64:
        with open(args.input) as f:
            s = ''.join(map(lambda x: x.strip(), f.readlines()))

        if args.io_base16:
            s = b16decode(s)
        elif args.io_base64:
            s = b64decode(s)

    elif args.io_base256:
        with open(args.input, 'rb') as f:
            s = list(f.read())

    s = unshuffle(s)
    noise(s)
    s = int.from_bytes(s, 'big') * ch
    s = list(s.to_bytes(byte_length(s), 'big'))
    s = untokenize(s)
    with open(args.output, 'wb') as f:
        f.write(bytes(s))

    if not args.silent:
        print('Decryption completed!')
