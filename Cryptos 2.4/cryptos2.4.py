from argparse import ArgumentParser
from base64 import b16decode, b16encode, b64decode, b64encode
from functools import reduce
from random import sample
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


def byte_length(z):
    return (z.bit_length() + 7) // 8


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


def rebase(s, base):
    sb = b''
    if args.mersenne:
        basis, z = [1], base
        sn = int.from_bytes([1] + s, 'big')
        while z <= sn:
            basis.append(z)
            z *= z

        basis.reverse()
        for b in basis:
            sk = sn // b
            skl = byte_length(sk)
            sb += (4 + skl).to_bytes(4, 'big') + sk.to_bytes(skl, 'big')
            sn %= b

    elif args.chunked:
        cl = byte_length(base)
        tbl = 2 * cl - len(s) % cl - 2
        s = (tbl + 2).to_bytes(2, 'little') + token_bytes(tbl) + bytes(s)
        rb = s[:cl]
        for k in range(cl, len(s), cl):
            sn = int.from_bytes(rb + s[k:k + cl], 'big')
            sk = sn // base
            skl = byte_length(sk)
            sb += (4 + skl).to_bytes(4, 'big') + sk.to_bytes(skl, 'big')
            rb = sn % base
            rb = rb.to_bytes(byte_length(rb), 'big')

        sb += (4 + len(rb)).to_bytes(4, 'big') + rb

    return list(sb)


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

    s = list((8 + len(s)).to_bytes(8, 'big')) + s
    noise(s, get_salt(token))
    return token + s + list(token_bytes(get_salt(s) % int_sqrt(len(s) + key_len)))


def unrebase(s, base):
    sb, parts = bytes(s), []
    i, j, sbl = 0, 0, len(sb)
    if args.mersenne:
        basis, z = [1], base
        while j < sbl:
            j = i + int.from_bytes(sb[i:i + 4], 'big')
            parts.append(int.from_bytes(sb[i + 4:j], 'big'))
            basis.append(z)
            z *= z
            i = j

        basis.pop()
        basis.reverse()
        sn = sum(map(lambda x, y: x * y, basis, parts))

        return list(sn.to_bytes(byte_length(sn), 'big'))[1:]

    if args.chunked:
        sn, cl = b'', byte_length(base)
        while j < sbl:
            j = i + int.from_bytes(sb[i:i + 4], 'big')
            parts.append(int.from_bytes(sb[i + 4:j], 'big'))
            i = j

        parts.reverse()
        rb = parts[0]
        for k in range(1, len(parts)):
            sk = parts[k] * base + rb
            skb = sk.to_bytes(byte_length(sk), 'big')
            sn, rb = skb[-cl:] + sn, int.from_bytes(skb[:-cl], 'big')

        sn = rb.to_bytes(cl, 'big') + sn

        return list(sn)[int.from_bytes(sn[:2], 'little'):]


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
    return (token, s[8:int.from_bytes(s[:8], 'big')])


parser = ArgumentParser(description='Encription or decryption file by specifed cipher.')
parser.add_argument('-v', '--verification', action='store_true', help='Print more information')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', "--encryption", action="store_true", help='Encryption file')
group.add_argument('-d', "--decryption", action="store_true", help='Decryption file')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-mrs', "--mersenne", action="store_true", help='Mersenne like encryption base')
group.add_argument('-cnk', "--chunked", action="store_true", help='Chunked system of encryption')
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

key_len = max((ch.bit_length() + 15) // 8, 4)

## Encription

if args.encryption:
    with open(args.input, 'rb') as f:
        s = list(f.read())
        if args.mersenne and len(s) > 100000:
            print('Mersenne like algorithm encription can spend a lot of time on files over 100 kilobytes!')

    s = tokenize(s)
    noise(s)
    shuffle(s)

    chs = list(token_bytes(key_len))
    while chs[0] == 0:
        chs = chs[1:] + [0]

    s = rebase(s, pow(int.from_bytes(chs, 'big'), 2, ch))
    s = tokenize(s, chs)
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
    chs, s = untokenize(s)
    s = unrebase(s, pow(int.from_bytes(chs, 'big'), 2, ch))
    s = unshuffle(s)
    noise(s)
    token, s = untokenize(s)
    with open(args.output, 'wb') as f:
        f.write(bytes(s))

    print('Decryption completed!')
