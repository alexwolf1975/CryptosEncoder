from argparse import ArgumentParser
from base64 import b16decode, b16encode, b64decode, b64encode
from functools import reduce


def list_mul(s, n):
    for k in range(len(s)):
        s[k] *= n

    for k in range(-1, -len(s), -1):
        s[k - 1] += s[k] >> 8
        s[k] %= 256


def list_div(s, n):
    m = 0
    for k in range(0, len(s)):
        m = (m << 8) + s[k]
        s[k] = m // n
        m %= n

    s.reverse()

    for k in range(key_len):
        s.pop()

    s.reverse()


def nearest_prime(s):
    z = len(s)
    while z < ch:
        z *= z

    z %= ch
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
    if z < 1:
        return

    if z < 2:
        yield ch % 256
        return

    while z < ch:
        z *= z

    for k in range(n):
        z %= ch
        yield z % 256
        if z == 0:
            z = ch * ch + 1
        else:
            z *= z ^ (ch >> (ch.bit_length() - z.bit_length()))


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


def unshuffle(sch):
    sc = list(range(len(sch)))
    shuffle(sc, sch)
    s = [0] * len(sc)
    for k in range(len(sc)):
        s[sc[k]] = sch[k]

    return s


parser = ArgumentParser(description='Encription or decryption file by specifed cipher.')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', "--encryption", action="store_true", help='encryption file')
group.add_argument('-d', "--decryption", action="store_true", help='decryption file')
parser.add_argument('-c', '--cipher', metavar='file', type=str, required=True, help='chipher file')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-b16', "--io_base16", action="store_true", help='base16 input or output file')
group.add_argument('-b64', "--io_base64", action="store_true", help='base64 input or output file')
parser.add_argument('-i', '--input', metavar='file', type=str, required=True, help='input file')
parser.add_argument('-o', '--output', metavar='file', type=str, required=True, help='output file')

args = parser.parse_args()

## Get first 10000 prime numbers

n = 104729

primes = list(range(1, n + 1, 2))

i = 3
while i * i <= n:
    if primes[i // 2] > 0:
        for j in range(i * i, n + 1, i):
            if j % 2 > 0:
                primes[j // 2] = 0

    i += 2

primes[0] = 2

primes = list(filter(lambda x: x > 0, primes))

## Common part

with open(args.cipher) as f:
    ch = int(''.join(map(lambda s: s.strip(), f.readlines())), 0)

key_len = max((ch.bit_length() - 1) // 8 + 2, 4)

## Encription

if args.encryption:
    with open(args.input, 'rb') as f:
        s = list(f.read())

    s = list(map(lambda x, y: x ^ y, s, noise(s)))
    shuffle(s)
    s = [0] * key_len + s
    list_mul(s, nearest_prime(s))
    s = list(map(lambda x, y: x ^ y, s, noise(s)))
    shuffle(s)
    s = bytes(s)

    if args.io_base16:
        base = '-b16'
        s = b16encode(s).decode()
    elif args.io_base64:
        base = '-b64'
        s = b64encode(s).decode()

    with open(args.output, 'w') as f:
        f.write(f'{base}\n')
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
    s = list(map(lambda x, y: x ^ y, s, noise(s)))
    list_div(s, nearest_prime(s))
    s = unshuffle(s)
    s = list(map(lambda x, y: x ^ y, s, noise(s)))
    with open(args.output, 'wb') as f:
        f.write(bytes(s))

    print('Completed!')
