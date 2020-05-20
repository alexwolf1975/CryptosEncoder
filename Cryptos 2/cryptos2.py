from argparse import ArgumentParser
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
group.add_argument('-e', "--encryption", action="store_true")
group.add_argument('-d', "--decryption", action="store_true")
parser.add_argument('-c', '--cipher', metavar='file', type=str, required=True, help='chipher file')
parser.add_argument('-i', '--input', metavar='file', type=str, required=True, help='input file')
parser.add_argument('-o', '--output', metavar='file', type=str, required=True, help='output file')

args = parser.parse_args()

with open(args.cipher) as f:
    ch = eval(f.read().strip())

## Encription
    
if args.encryption:

    with open(args.input, 'rb') as f:
        s = f.read()

    s = list(map(lambda c: (c, randbits(8)), s))

    s = [i ^ j for i, j in s] + [j for i, j in s] \
        if sum([i + j for i, j in s]) % 2 == 0 else \
        [j for i, j in s] + [i ^ j for i, j in s]

    with open(args.output, 'w') as f:
        f.write(''.join(map(lambda x: '{:02X}'.format(pop(s, x)), shuffle(len(s)))))

## Decription

elif args.decryption:
    with open(args.input) as f:
        sch = f.read()

    s = list(range(len(sch) // 2))

    sc = list(map(lambda x: pop(s, x), shuffle(len(s))))

    s = [0] * len(sc)

    for k in range(len(sc)):
        s[sc[k]] = int(sch[k * 2:k * 2 + 2], 16)

    with open(args.output, 'wb') as f:
        f.write(b''.join(map(lambda x, y: (x ^ y).to_bytes(1, 'big'), s[0:len(s) // 2], s[len(s) // 2:])))
