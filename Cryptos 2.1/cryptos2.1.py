from argparse import ArgumentParser
from base64 import b16decode, b16encode, b64decode, b64encode
from secrets import randbits
from time import localtime

def pop(s, k):
    s[-1], s[k] = s[k], s[-1]

    return s.pop()

def shuffle(n):
    z = n
    while z < ch:
        z *= z
        k = n
    while k > 0:
        z %= ch
        yield z % k
        k -= 1
        if z == 0:
            z = ch * ch + 1
        else:
            z *= z ^ (ch >> (ch.bit_length() - z.bit_length()))

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

with open(args.cipher) as f:
    ch = eval(''.join(map(lambda s: s.strip(), f.readlines())))

## Encription
    
if args.encryption:

    with open(args.input, 'rb') as f:
        s = f.read()

    s = list(map(lambda c: (c, randbits(8)), s))

    s = [i ^ j for i, j in s] + [j for i, j in s] \
        if sum([i + j for i, j in s]) % 2 == 0 else \
        [j for i, j in s] + [i ^ j for i, j in s]

    s = bytes(map(lambda x: pop(s, x), shuffle(len(s))))

    if args.io_base16:
        base = '-b16'
        s = b16encode(s).decode()
    elif args.io_base64:
        base = '-b64'
        s = b64encode(s).decode()

    with open(args.output, 'w') as f:
        f.write(base + '\n')
        f.writelines('\n'.join(s[i:i + 64] for i in range(0, len(s), 64)))

## Decription

elif args.decryption:
    with open(args.input) as f:
        print('This file has been encrypted with {:s} option.'.format(f.readline().strip()))
        sch = ''.join(map(lambda x: x.strip(), f.readlines()))

    if args.io_base16:
        sch = b16decode(sch)
    elif args.io_base64:
        sch = b64decode(sch)

    s = list(range(len(sch)))

    sc = list(map(lambda x: pop(s, x), shuffle(len(s))))

    s = [0] * len(sc)

    for k in range(len(sc)):
        s[sc[k]] = sch[k]

    with open(args.output, 'wb') as f:
        f.write(b''.join(map(lambda x, y: (x ^ y).to_bytes(1, 'big'), s[0:len(s) // 2], s[len(s) // 2:])))
