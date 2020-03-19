# RSA-OTP

## Crypto, 210 points

### Description

*RSA is kinda bad but I strengthened it with the unbreakable one time pad!*

*nc crypto.2020.chall.actf.co 20600*

*Author: lamchcl*

chall.py:

```python
from Crypto.Util.number import bytes_to_long
from Crypto.Random.random import getrandbits # cryptographically secure random get pranked
from Crypto.PublicKey import RSA
from secret import d, flag
# 1024-bit rsa is unbreakable good luck
n = 136018504103450744973226909842302068548152091075992057924542109508619184755376768234431340139221594830546350990111376831021784447802637892581966979028826938086172778174904402131356050027973054268478615792292786398076726225353285978936466029682788745325588134172850614459269636474769858467022326624710771957129
e = 0x10001
key = RSA.construct((n,e,d))

f = bytes_to_long(bytes(flag,'utf-8'))
print("Encrypted flag:")
print(key.encrypt(f,0)[0])

def otp(m):
	# perfect secrecy ahahahaha
	out = ""
	for i in bin(m)[2:]:
		out+=str(int(i)^getrandbits(1))
	return out

while 1:
	try:
		i = int(input("Enter message to sign: "))
		assert(0 < i < n)
		print("signed message (encrypted with unbreakable otp):")
		print(otp(key.decrypt(i)))
	except:
		print("bad input, exiting")
		break
```

### Solution

First, I would like to point out that I am not sure whether I have the correct solution for this challenge because I could only retrieve 58 characters of the flag out of the 70.

I am going to explain my method anyway because I thought it was interesting.

#### First contact with the oracle

In this challenge, we are given a public RSA key and an encrypted flag. An oracle allows us to decrypt integers (between 1 and n-1), but we are only sent back a XOR of the decrypted message with a random stream of bits. In other words, no way to find the plaintext back.

So what kind of information does the decryption give us at all? Well, the only thing we know from what the server sends back is the **length** of the decrypted message (in bits).

For instance, let's try feeding the server with the encrypted flag itself:

```
$ nc crypto.2020.chall.actf.co 20600
Encrypted flag:
17482644844951175640843255713372869422739097498066773957636359990466096121278949693816080016671592558403643716793132479255285512907247513385850323834210899918531077167485767118313722022095603863840851451191536627814100144146010392752308431038754246815068245448456643024387011488032896209253644172833489422733
Enter message to sign: 17482644844951175640843255713372869422739097498066773957636359990466096121278949693816080016671592558403643716793132479255285512907247513385850323834210899918531077167485767118313722022095603863840851451191536627814100144146010392752308431038754246815068245448456643024387011488032896209253644172833489422733
signed message (encrypted with unbreakable otp):
0010110100011011100010010110111000100011000010111011110100001100010011010001100111001101010100101000101110011010100101101001001010100110011000101111000111010101010111010010001001110111011010010100101111011001111000111111101011110101011111100000110001000111100010100011100110101110100001110110001100010001110010001101111111001110011110000010000001010111010011010101101101111010100110011000101001001101111111010101001111010011011001101100111101000010100010001100011000000001111001001110011001101101011001100000100000001101100011111100100001101100010011111010101
```

This gives us the length of the plaintext, which is **559 bits**. This is bad, because n is 1024 bits :)

#### Exploiting the lack of padding

Okay, so we know we should play with binary lengths to try and get information about the flag.

Let's move on directly to the main idea with a simple example.

Let's choose an integer m, for instance $$m=43$$, and look at $$2m = 86$$ and $$3m = 129$$.

$$2m$$ has a length of 2 digits (in base 10), and $$3m$$ has a length of 3. From this, we can deduce $$m \lt 50$$ (otherwise $$2m \geq 100$$) and also that $$m \geq 34$$ (otherwise $$3m \lt 100$$).

Therefore, looking at lengths of multiples of a number gives us a **bounding** of this number. The bounds can be increasingly accurate with bigger factors.

We can apply the same principle to the flag by looking at binary lengths.

#### Running the attack

Let $$m$$ be the plaintext flag and $$c$$ the encrypted flag (which we know about).

Let's choose a factor $$k$$ and compute $$k' = k^e\mod{n}$$, which is the encrypted $$k$$. We can now compute $$ck' \equiv m^e k^e \equiv {(mk)}^e \mod{n}$$ and feed it to the oracle.

What the oracle will answer is the length of $$mk$$... as long as $$mk$$ is not too big (it should not be bigger than $$n$$). Luckily, we know about the length of $$m$$ (559 bits) so we know that we can go up to around 465 bits for $$k$$.

Let $$u$$ be that length. We now know that $$2^{u - 1} \leq km \leq 2^u-1$$, which means $$2^{u - 1}/k \leq m \leq (2^u-1)/k$$.

Testing with some examples, we find out that the factors which give the best bounds are the ones around when $$u$$ changes value. So what we are going to do is a dichotomic search to find when $$u$$ changes value from 1023 bits to 1024 bits. $$k = 2^{464}$$ and $$k = \frac{1}{2}(2^{464} + 2^{465})$$ yield $$u = 1023$$ and $$u = 1024$$ respectively, so we can start with these as lower and upper bounds for a dichotomic search.

All there remains to do now is to implement the attack. After a few minutes of launching it...

```
$ python rsa.py
k >= 59542628294296116473800606342185331454250300267505095498259677116877970482249557878881570874471511290737665769985325296315154565416112619520
k <= 71451153953155339768560727610622397745100360321006114597911612540253564578699469454657885049365813548885198923982390355578185478499335143424
b'3333333333333333333333333333333333333333333333333333333333333333333333'
b'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

k >= 59542628294296116473800606342185331454250300267505095498259677116877970482249557878881570874471511290737665769985325296315154565416112619520
k <= 65496891123725728121180666976403864599675330294255605048085644828565767530474513666769727961918662419811432346983857825946670021957723881472
b']\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t'
b'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

k >= 62519759709010922297490636659294598026962815280880350273172660972721869006362035772825649418195086855274549058484591561130912293686918250496
k <= 65496891123725728121180666976403864599675330294255605048085644828565767530474513666769727961918662419811432346983857825946670021957723881472
b']\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t]\x17E\xd1t'
b'a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a'

k >= 62519759709010922297490636659294598026962815280880350273172660972721869006362035772825649418195086855274549058484591561130912293686918250496
k <= 64008325416368325209335651817849231313319072787567977660629152900643818268418274719797688690056874637542990702734224693538791157822321065984
b'_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0_A}\x05\xf4\x17\xd0'
b'a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a\x86\x18a'

[...]

k >= 62606626634666857169962576496954328573681192124427072668906299463448781600005761352512899051732400786172667561506921142654444651242031108608
k <= 62606626634666857169962576496954328573681192124427072668906299463448781600005761352512899051732400786172667561506921142654444651242031108609
b'actf{this_is_not_what_i_meant_when_i_told_you_to_use_rsa_w.p\x03G\xb9\xb2)\xcf\xee\x16\xd1m'
b'actf{this_is_not_what_i_meant_when_i_told_you_to_use_rsa_wx\x89\x0c\xf9\x85/\xa1\xf1y\xe9\x90\x8c'
```

Oops... we're not accurate enough to retrieve the end of the flag. At this point I don't know if there's a way extend this attack to finish properly.

I just decided to guess the flag based on the challenge, and managed to guess correctly: `actf{this_is_not_what_i_meant_when_i_told_you_to_use_rsa_with_padding}`.

Enjoy!

### Script

```python
from Crypto.Util.number import long_to_bytes as ltb
import socket

c = 17482644844951175640843255713372869422739097498066773957636359990466096121278949693816080016671592558403643716793132479255285512907247513385850323834210899918531077167485767118313722022095603863840851451191536627814100144146010392752308431038754246815068245448456643024387011488032896209253644172833489422733
n = 136018504103450744973226909842302068548152091075992057924542109508619184755376768234431340139221594830546350990111376831021784447802637892581966979028826938086172778174904402131356050027973054268478615792292786398076726225353285978936466029682788745325588134172850614459269636474769858467022326624710771957129
e = 0x10001

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('crypto.2020.chall.actf.co', 20600))

s.recv(4096)

ka = 2**464
kb = (2**465 + ka) // 2

flag_lower_bound = 0
flag_upper_bound = n

while True:
    k = (ka + kb) // 2
    
    # k * flag encrypted
    kflag = (c * pow(k, e, n)) % n
    s.send(str(kflag).encode() + b'\n')
    
    # binary length of k * flag
    u = len(s.recv(4096).split(b'\n')[1])
    
    if u == 1024:
        kb = k
    else:
        ka = k
    
    lower_bound = 2**(u-1) // k
    upper_bound = 2**u // k
    if lower_bound > flag_lower_bound:
        flag_lower_bound = lower_bound
    if upper_bound < flag_upper_bound:
        flag_upper_bound = upper_bound

    print("k >= %s" % ka)
    print("k <= %s" % kb)
    print(ltb(flag_lower_bound))
    print(ltb(flag_upper_bound))
    print()
    
    if kb - ka <= 1:
        break

s.close()
```

