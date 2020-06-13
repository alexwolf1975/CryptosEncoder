from argparse import ArgumentParser
from base64 import b16decode, b16encode, b64decode, b64encode
from functools import reduce


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


def list_mul(s, n):
    return list((int.from_bytes(s, 'big') * n).to_bytes(len(s) + key_len, byteorder='big'))


def list_div(s, n):
    return list((int.from_bytes(s, 'big') // n).to_bytes(len(s) - key_len, byteorder='big'))


def nearest_mod(s, mode):
    if mode == 'encode':
        z = len(s) + key_len
    elif mode == 'decode':
        z = len(s)

    if z < 2:
        z = 2

    while z < ch:
        z *= z

    return z % ch


def nearest_prime(s, mode):
    z = nearest_mod(s, mode)
    composite, k = True, 0
    print('Prime multiplier generation')
    while composite:
        k += 1
        print(f'Checking multiplier #{k}')
        for p in primes:
            if z % p == 0:
                z += 1
                break
        else:
            composite = False

        if not composite:
            composite = True
            for kf in range(len(primes)):
                if kf % 100 == 0:
                    print(f'Ferma test is {kf // 100}% completed')
                if pow(primes[kf], z - 1, z) != 1:
                    z += 1
                    break
            else:
                composite = False

        if not composite:
            print('Simple multiplier found!')

    return z


def noise(s):
    z = len(s)
    if z > 1:
        while z < ch:
            z *= z
    else:
        z = ch % 256

    for k in range(len(s)):
        z %= ch
        s[k] ^= z % 256
        if z == 0:
            z = ch * ch + 1
        else:
            z *= z ^ (ch >> (ch.bit_length() - z.bit_length()))


def options():
    if args.mulprimenul:
        opt = '-pnm'
    elif args.ciphersystem:
        opt = '-cns'

    if args.io_base16:
        opt += ' -b16'
    elif args.io_base64:
        opt += ' -b64'

    return opt


def rebase(s, base):
    sn = int.from_bytes(s, 'big')
    sb = []
    while sn > 0:
        sb.append(f'{(sn % base):X}')
        sn //= base

    return list(bytes(':'.join(sb), 'utf-8'))


def shuffle(s, sc=None):
    if len(s) < 2:
        return

    if sc == None:
        sc = s

    sum_sc = sum(sc)
    salt = (((len(sc) << sum_sc.bit_length()) + sum_sc) << 8) + reduce(lambda x, y: x ^ y, sc)
    mul_sc = reduce(lambda x, y: (x * y) % ch, filter(lambda x: x > 1, sc))
    z = salt = (salt << mul_sc.bit_length()) + mul_sc
    while z < ch:
        z *= z

    for k in range(len(s) - 1, -1, -1):
        z %= ch
        n = z % salt % (k + 1)
        s[k], s[n] = s[n], s[k]
        if z == 0:
            z = ch * ch + 1
        else:
            z *= z ^ (ch >> (ch.bit_length() - z.bit_length()))


def unrebase(s, base):
    sb = list(map(lambda n: int(n, 16), bytes(s).decode().split(':')))
    sb.reverse()
    sn = 0
    for x in sb:
        sn *= base
        sn += x

    return list(sn.to_bytes((sn.bit_length() + 7) // 8, byteorder='big'))


def unshuffle(sch):
    sc = list(range(len(sch)))
    shuffle(sc, sch)
    s = [0] * len(sc)
    for k in range(len(sc)):
        s[sc[k]] = sch[k]

    return s


parser = ArgumentParser(description='Encription or decryption file by specifed cipher.')
parser.add_argument('-v', '--verification', action='store_true', help='Print more information')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', "--encryption", action="store_true", help='Encryption file')
group.add_argument('-d', "--decryption", action="store_true", help='Decryption file')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-mpn', "--mulprimenul", action="store_true", help='Permutation, noise, multiplication')
group.add_argument('-cns', "--ciphersystem", action="store_true", help='Cipher numeral system')
parser.add_argument('-c', '--cipher', metavar='file', type=str, required=True, help='Chipher file')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-b16', "--io_base16", action="store_true", help='base16 input or output file')
group.add_argument('-b64', "--io_base64", action="store_true", help='base64 input or output file')
parser.add_argument('-i', '--input', metavar='file', type=str, required=True, help='Input file')
parser.add_argument('-o', '--output', metavar='file', type=str, required=True, help='Output file')

args = parser.parse_args()

## Get first 10000 prime numbers

N = 104729

primes = list(range(1, N + 1, 2))

i = 3
while i * i <= N:
    if primes[i // 2] > 0:
        for j in range(i * i, N + 1, i):
            if j % 2 > 0:
                primes[j // 2] = 0

    i += 2

primes[0] = 2

primes = list(filter(lambda x: x > 0, primes))

## Common part

with open(args.cipher) as f:
    ch = int(''.join(map(lambda s: s.strip(), f.readlines())), 0)

key_len = max((ch.bit_length() + 15) // 8, 4)

if bits_few(ch):
    exit('It is too weak key')

chs = list(ch.to_bytes((ch.bit_length() + 7) // 8, byteorder='big'))
while chs == 0:
    chs = chs[1:] + [0]

chs = int.from_bytes(chs, 'big')

## Encription

if args.encryption:
    with open(args.input, 'rb') as f:
        s = list(f.read())

    noise(s)
    shuffle(s)
    if args.mulprimenul:
        s = list_mul(s, nearest_prime(s, 'encode'))
    elif args.ciphersystem:
        s = rebase(s, chs)

    noise(s)
    shuffle(s)
    s = bytes(s)
    if args.io_base16:
        s = b16encode(s).decode()
    elif args.io_base64:
        s = b64encode(s).decode()

    with open(args.output, 'w') as f:
        f.write(f'{options()}\n')
        f.writelines('\n'.join(s[i:i + 64] for i in range(0, len(s), 64)))

    print('Completed!')

## Decription

elif args.decryption:
    with open(args.input) as f:
        print('This file has been encrypted with {:s} options.'.format(f.readline().strip()))
        s = ''.join(map(lambda x: x.strip(), f.readlines()))

    if args.io_base16:
        s = b16decode(s)
    elif args.io_base64:
        s = b64decode(s)

    s = unshuffle(s)
    noise(s)
    if args.mulprimenul:
        s = list_div(s, nearest_prime(s, 'decode'))
    elif args.ciphersystem:
        s = unrebase(s, chs)

    s = unshuffle(s)
    noise(s)
    with open(args.output, 'wb') as f:
        f.write(bytes(s))

    print('Completed!')
