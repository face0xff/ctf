# Agents
## Crypto, 110 points

### Description

```
nc crypto-agents.ctfz.one 9543
```

In this challenge, we had to deal with a service in which we could:

* ask for an base64-encoded encrypted message. We were also given a random username. The server tells us we should forward this encrypted message in a second step, and that we don't have to worry about IV and key which are randomly generated and already sent over.
* send a base64-encoded encrypted message. The server asks for our username and decrypts the message, but does not send us its decrypted contents. We can only send an encrypted message once with our generated username.

When we try to send back the encrypted message that the server sends us, we get back something that looks like "Thank you, but you are not trusted".

### Solution

The hint for this challenge was **AES OFB**. The encryption scheme for this mode, *Output Feedback*, is described as follows:

![OFB](ofb.png)

The IV and the key (linked to our username) are enough for the server to compute a stream of bytes, by blocks of 16 bytes. This stream is then XORed to the plaintext to get the ciphertext. The decryption is pretty much identical: the ciphertext is XORed with the stream to get the plaintext.

Thus, an interesting property is that flipping a bit in the ciphertext at a certain position will flip the bit at the same position in the plaintext, and conversely.

We can imagine the goal of the challenge is to be seen as "trustworthy", and whether we are trusted or not may be hardcoded inside the plaintext.

If we send over the ciphertext but altering, for instance, the first byte, we will a get a **invalid JSON** message. Interesting! At this point we may guess that the plaintext is a JSON and that a certain key in it specifies whether we are trusted or not. But how can we know its structure?

The idea was, for a given byte, to brute-force it until we got the **invalid JSON** message, which would mean either the plaintext was changed into a `"` (double quote) or a `\` (backslash). Indeed, having a JSON such as `{"key":"value"}` changed into `{"k"y":"value"}` or `{"k\y":"value"}` would make it invalid. From this point, we can recover the value of the plaintext's byte at this position because `p = p' XOR c XOR c'`, where p is the actual value of the plaintext, c the original ciphertext and c' the modified ciphertext (the byte we have brute-forced).

This way we can retrieve strings, be them keys or values. On the other hand, when we bit-flip something else in the JSON such as curly brackets, double quotes or colons, it is very likely it breaks it. With that logic in mind and some automation, we can recover some parts of the plaintext:

```
{"trusted":?,"n":?????????...???????????,"e":?????}
```

If we assume the value of *trusted* is initially `0` and we try to change it to `1`, we get a new message: "Thank you, I can rely on you. Here is the top secret message, encrypted using the RSA key you sent: [...]".

Great, we are trusted. Now we have pretty much two possibilities:
* find a way to retrieve the values of the integers in the JSON. We spent a lot of time on this and couldn't find a method. It might be possible with a decent amount of requests and some statistical thought process, but all our efforts are shattered because the value of `n` changes every single time.
* try and tweak the JSON to make the server send us something we know how to deal with.

Indeed, if we assume the server really uses the RSA key we actually sent, we could change either `n` or `e` so that it becomes easier for us. Changing `n` is complicated because it requires knowing parts of it, which we don't. However, `e` has few digits, and we can even guess its value is 65537 since it's the most common value in RSA for the exponent.

From now we can, for example, use our formula to change `65537` to `1____` (`_` being spaces) so that the resulting JSON is still valid and `e` is set to 1. The server will then send back to us `M = C**e mod n = C mod n = C`.

![Message](agents_message.jpg)

Convert it to ASCII:

![Flag](agents_flag.jpg)

Enjoy!


### Script

```python
import socket
from base64 import b64encode as b64e
from base64 import b64decode as b64d

xor = lambda s, t: b''.join(bytes([x ^ y]) for x, y in zip(s, t))

def replace(cipher, index, old, new):
  c = b64d(cipher)
  return b64e(
    c[:index] +
    xor(xor(old, new), c[index:index + len(new)]) +
    c[index + len(new):]
  )

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('crypto-agents.ctfz.one', 9543))

s.recv(4096)
s.send(b'1')

name = s.recv(4096).split(b' name "')[1].split(b'"')[0]
cipher = s.recv(4096).split(b'\n\n')[0]

s.send(b'2')
s.recv(4096)

s.send(name)
s.recv(4096)

# {"trusted":0,"n":123123...123123,"e":65537}
cipher = replace(cipher, 11, b'0', b'1')
cipher = replace(cipher, len(b64d(cipher)) - 6, b'65537', b'1    ')

s.send(cipher)
msg = s.recv(4096)

print(msg)
print(s.recv(4096))

s.close()
```

