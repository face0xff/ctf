# Go Cipher
### Crypto, 1000 points

In this challenge, we were given a Go source file which allows to encrypt or decrypt data using a 24-byte key. Our goal was to decrypt `flag.txt.enc` without knowing the key.

#### Description of the algorithm

The interesting part of the code is the `encrypt` function:

```Go
func encrypt(plaintext []byte, key []byte) string {
  x := uint64(binary.LittleEndian.Uint64(key[0:]))
  y := uint64(binary.LittleEndian.Uint64(key[8:]))
  z := uint64(binary.LittleEndian.Uint64(key[16:]))

  keyid := md5.Sum(key)
  r := keyid[:]
  for _, e := range plaintext {
    t := (e - byte(x)) ^ byte(y) ^ byte(z)
    r = append(r, t)
    x = bits.RotateLeft64(x, -1)
    y = bits.RotateLeft64(y, 1)
    z = bits.RotateLeft64(z, 1)
  }
  return hex.EncodeToString(r)
}
```

The idea is that our 24-byte key is split into 3 chunks of 8 bytes each, and then converted into 64-bit integers `x`, `y` and `z`.

The key is then hashed into md5 and the ciphertext starts with this hash (16 bytes). As far as my understanding went, the sole purpose of this md5 is to ensure a key is correct before trying to decrypt, and it isn't really exploitable to crack the key.

The encryption algorithm is quite simple; if `e` is a byte of the plaintext, then it will be encrypted into `(e - byte(x)) ^ byte(y) ^ byte(z)`, where `byte(a)` denotes the 8 least significant bits of `a` (in other words, `a & 0xFF`). After each iteration, x is rotated 1 bit to the right, and y, z are rotated 1 bit to the left.


#### Exploitation of the algorithm

Right off the bat, we can notice it is useless to look for two separate variables y and z. Indeed, their roles are perfectly symmetric and the values of x, y and z are never interchanged throughout the encryption. From an attacker's point of view, it is thus equivalent to let `u = y ^ z` and `t = (e - byte(x)) ^ byte(u)`, `u` being rotated 1 bit to the left each iteration.

My idea was that we only have to brute-force the first byte of `x` and `u` (65536 possibilities *maximum*), and for each valid possibility, because of the 1-bit rotation mechanism, each iteration that follows we only have to find out whether the next bit for `x` and `u` is 0 or 1, which leaves 4 possibilities *maximum*. We can then explore the tree describing every possible plaintext with a recursive algorithm.

But how do we narrow down the possibilities? Well, since the encrypted flag has a pretty small size (47 bytes), we expect it to be normal text, so all we have to do is check if the potential decrypted byte at each iteration is readable ASCII. We also know that the flag will look like `flag-[hex chars]`, so we can look out for the string "flag-" in each tree path.

Let's sum up the steps of the attack:
* Choose a set `abc` of characters you expect the plaintext to be made of
* Skip the 16 first bytes of the encrypted flag `flag`
* Start with an "empty" `x` and `u`, and an empty plaintext `out`
* Start by brute-forcing the values (p, q) of the lower byte of `x` and `u`:
    * If `(flag[0] ^ q) + p)` is in `abc`, go deeper and append this value to `out`
* Then brute-force the next bit of `x` and `y`:
    * Compute the new value (p, q) of the lower byte of `x` and `u` after the bit rotation
    * If `(flag[0] ^ q) + p)` is in `abc`, go deeper and append this value to `out`
* If a path reaches the end (length of the ciphertext), check if it has "flag-" in it and display it!


Here is a Python implementation of the attack:

```python
flag = "9e108b46c49f48b25591375a0ed7716a952a25e0b1d1242e4587f9e9c119e3b7f4d3d063b9a5cdf298e2b2a4a9b42835febde85f690ca6997100351ebdb17b"
flag = bytes.fromhex(flag)[16:]

printable = [ord(x) for x in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJLMNOPQRSTUVWXYZ- 0123456789,.?!\n"]

def rec(key_x, key_y, out):
    i = len(out)
    if i == len(flag):
        if b"flag-" in out:
            print(out)
    elif i == 0:
        for x in range(256):
            for y in range(256):
                if ((flag[i] ^ y) + x) & 0xff in printable:
                    rec(x, y, out + bytes([((flag[i] ^ y) + x) & 0xff]))
    else:
        for p in range(2):
            for q in range(2):
                x = (p << 7) | (key_x >> 1)
                y = ((key_y << 1) & 0xff) | q
                if ((flag[i] ^ y) + x) & 0xff in printable:
                    rec(x, y, out + bytes([((flag[i] ^ y) + x) & 0xff]))

rec(0, 0, b"")
```



It takes only a few seconds for the flag to show up:

```
[...]
b'Yes, you did it! flag-742CF8ED6A2BF55807C.5ADta'
b'Yes, you did it! flag-742CF8ED6A2BF55807B0194T!'
b'Yes, you did it! flag-742CF8ED6A2BF55807B0194T '
b'Yes, you did it! flag-742CF8ED6A2BF55807B14719\n'
b'Yes, you did it! flag-742CF8ED6A2BF55807B135-Az'
b'Yes, you did it! flag-742CF8ED6A3DJ-EWq2u3pvcxF'
[...]
```

#### Conclusion

Go Cipher was pretty fun and simple, and I really enjoy those kinds of crypto tasks. This is also the first time I'm writing up for my new team *SHRECS*! We ended up 37th on the Square CTF 2019, which is nice but I wish we could have scored more, if we were less busy.

Enjoy!
