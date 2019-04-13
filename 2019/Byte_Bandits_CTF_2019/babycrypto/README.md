# babycrypto

Crypto, 300 points.

## Description

*Start with this one!
`nc 13.233.66.116 5000`*

```python
#!/usr/bin/python3 -u
import os
from binascii import hexlify, unhexlify

flag = open("./flag","rb").read()

class bb(object):
  def __init__(self, key):
    self.meh = [x for x in range(256)]
    j = 0
    for i in range(256):
      j = (j + self.meh[i] + key[i%len(key)])&0xff
      self.meh[i], self.meh[j] = self.meh[j], self.meh[i]
    self.cat = 0
    self.mouse = 0

  def crypt(self, string):
    out = []
    for c in string:
      self.cat = (self.cat+1)&0xff
      self.mouse = (self.cat+self.meh[self.cat])&0xff
      self.meh[self.cat], self.meh[self.mouse] = self.meh[self.mouse], self.meh[self.cat]
      k = self.meh[ (self.meh[self.cat]+self.meh[self.mouse])&0xff ]//2
      out.append((c+k)&0xff)
    return bytearray(out)


cipher = bb(os.urandom(32))

while True:
  print("Commands: \n(e)ncrypt msg or (p)rint flag")
  choice = input()

  if choice == 'e':
    message = input()
    print(hexlify(cipher.crypt(unhexlify(message))))
  elif choice == 'p':
    print(hexlify(cipher.crypt(flag)))
  else:
    print("meh!")
```

## Solution

So I'm not sure about this task's title and description since only 4 teams managed to solve it, and I'm also not sure why there were only 4 solves since it was pretty simple.

We are given a service which runs the given Python script. We are able to encrypt messages and print an encrypted version of the flag:

```
Commands:
(e)ncrypt msg or (p)rint flag
e
61626364
b'dba4abb9'
Commands:
(e)ncrypt msg or (p)rint flag
p
b'73bf75c1d4a8ac5fd1cc9bd9388290906dadc7388298789b97879291598bd3d58582c8787c89c1d6af882b'
```

It looks like the service initializes some kind of cryptographic stream with a random 32-byte key.

The algorithm looks a lot like RC4, except for two (not so) small details: addition is used instead of XOR, and the keystream byte is divided by 2 before being used.

Knowing about RC4 was not needed to solve this challenge, you just have to understand that the random key is used to produce a pseudo-random infinite stream of bytes that is used to encrypt plaintexts, here using addition modulo 256 instead of XOR.

Asking for the flag twice will encrypt it twice, but the keystream will be at a different position so the output is different.

```
Commands:
(e)ncrypt msg or (p)rint flag
p
b'ba9acd8cfab0c47b8ebaf4af6dc450656ba8798f7cadd6c47acebaae9789c3b777d2bd8f697bcff2add369'
Commands:
(e)ncrypt msg or (p)rint flag
p
b'6c767a8cb94c9848957dc282a6c75aa2cc8fdf9b9cb2f1788c698ca8b08b6dc24da1d87b5371a0a7ea9e3f'
```

Obviously, the weakness lies in the division by 2 of k in the crypt method. What this means is that k can only take values in 0, ..., 127 before it is added to our plaintext byte.

Since we know the flag will be a readable ASCII string, this reduces the amount of possibilities for a plaintext character.
For instance, if we consider this encrypted version of the flag:

```
ba9acd8cfab0c47b8ebaf4af6dc450656ba8798f7cadd6c47acebaae9789c3b777d2bd8f697bcff2add369
```

...it starts with 0xBA, and if we note p[0] the first character of the flag, we have `p[0] + k = 0xBA`.

As k can only take values between 0 and 127, we know p[0] can only take values between 0x3B and 0xBA, and since we assume it is readable ASCII, we know p[0] is somewhere between 0x3B and 0x7F.

Now we can do this for every byte of the plaintext but there's still too many possibilities... We cannot retrieve the flag like that.

Of course, the idea was to exploit the fact that we can encrypt the flag several times. For each byte, the higher its encrypted value is, the smallest the space of possibilities for the associated plaintext character is.

Therefore, each time we ask for a new encrypted flag, there is a probability that we're reducing the number of flag candidates. If we're asking for enough encrypted flags, we can thus reconstruct it with a high probability.

Here's the exploit:

```python
from binascii import unhexlify as unhex
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('13.233.66.116', 5000))
s.recv(4096)

L = []
charset = b'{}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

count = 0
while True:
    s.send(b'p\n')
    res = s.recv(4096)
    try:
        res = unhex(res.split(b'\n')[0].split(b"'")[1])
    except:
        continue
    L.append(res)

    plaintext = b''
    for i in range(43):
        for o in charset:
            good = True
            for k in range(len(L)):
                q = (L[k][i] - o) & 255
                if q >= 128:
                    good = False
                    break
            if good:
                plaintext += bytes([o])
                break

    print(count, plaintext)
    count += 1
```

The flag is retrieved in about 400 requests:

```
0 b'{{{{{{A{{{{{0{A{A{{{{{{{{A{{0{{{{{A{AA{{{{A'
1 b'{{{{{AA0{{{{0{A{H{{A{A{{{G{{0{{{A{A{AA{{{{0'
2 b'{{{A{AA0{{{{0{A{H{{A{A{{{G{{0{{{0{AAAA{{{{0'
3 b'{{{a{AA0{{{a0{A{M{VA{A{{{Z{{0{{I0{SAAA{{{{0'
4 b'{{{a{AA0{{{a0{A{M{VA{A{{{Z{{0{{I0{SAAA{{{{0'
5 b'd{Za{0A0{{{a0{A{M{VA{A{{aZ{{0{{I0{SYAA{{{{0'
6 b'd{Za{0A0{{{a0{A{M{VA{AnJaZ{{0{AI0{SYAA{{{{0'
7 b'dAZa{0W0{Q{a0{A{M{VA{AnJaZ{{0{TU0{SYAA{{{{'
8 b'eDZa{0W0{Q{a0{0{M{V0{AnJaZ{{0{TU0{aYAA{{{{'
9 b'eDZa{0W0{Q{c0{0{M{V0{AnJaZ{{0{TU0baYAA{{{{'
10 b'eDZa{0b0YQ{c0{0{M{V0{AnJaZ{{0{Xa0baY0A{{{{'
11 b'eDZa{0b0YQ{c2{0{M{V0{AqJaZ{{0{Xa0baY0A{{{{'

[...]

130 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
131 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
132 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
133 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
134 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
135 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
136 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
137 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
138 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'
139 b'flaf{3r2_dyn3l1c_pb0x0s_a_sh0nga0f_a14utx}'

[...]

444 b'flag{4r3_dyn4m1c_sb0x3s_a_th0ng_0f_b34uty}'
445 b'flag{4r3_dyn4m1c_sb0x3s_a_th0ng_0f_b34uty}'
446 b'flag{4r3_dyn4m1c_sb0x3s_a_th1ng_0f_b34uty}'
```

Enjoy!
