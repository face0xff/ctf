# Macaron \(crypto, 200\)

## Description du challenge

```text
Le but du challenge est de trouver une contrefaçon sur le code d'authentification de message Macaron.

Service : nc challenges1.france-cybersecurity-challenge.fr 2005
```

## Solution

On nous donne le code d'un serveur sur lequel on peut signer des messages :

```python
#!/usr/bin/env python3

import os
from hashlib import sha256
import hmac
import sys
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from flag import flag

class Macaron():
    def __init__(self, k1 = os.urandom(16), k2 = os.urandom(16)):
        self.ctr = 0
        self.k1  = k1
        self.k2  = k2

    def tag(self, input):
        m = pad(input, 2 * 30)
        nb_blocks = len(m) // 30

        tag_hash = bytearray(32)
        nonce_block = long_to_bytes(self.ctr, 2)
        prev_block = nonce_block + m[:30]
        tag_nonce = nonce_block
        self.ctr += 1

        for i in range(nb_blocks - 1):
            nonce_block = long_to_bytes(self.ctr, 2)
            next_block = nonce_block + m[30*(i+1):30*(i+2)]
            big_block = prev_block + next_block
            digest = hmac.new(self.k1, big_block, sha256).digest()
            tag_hash = bytearray([x ^ y for (x,y) in zip(tag_hash, digest)])
            prev_block = next_block
            tag_nonce  = tag_nonce + nonce_block
            self.ctr += 1

        tag_hash = hmac.new(self.k2, tag_hash, sha256).digest()
        return tag_hash, tag_nonce

    def verify(self, input, tag):
        m = pad(input, 2 * 30)
        tag_hash, tag_nonce = tag

        nb_blocks_m = len(m) // 30
        nb_blocks_nonce = len(tag_nonce) // 2

        if nb_blocks_nonce != nb_blocks_m:
            return False

        if len(tag_nonce) % 2 != 0 or len(tag_hash) % 32 != 0:
            return False

        tag_hash_ = bytearray(32)
        prev_block = tag_nonce[:2] + m[:30]

        for i in range(nb_blocks_m - 1):
            next_block =  tag_nonce[2*(i+1):2*(i+2)] + m[30*(i+1):30*(i+2)]
            big_block = prev_block + next_block
            digest = hmac.new(self.k1, big_block, sha256).digest()
            tag_hash_ = bytearray([x ^ y for (x,y) in zip(tag_hash_, digest)])
            prev_block = next_block

        tag_hash_recomputed = hmac.new(self.k2, tag_hash_, sha256).digest()
        return (tag_hash == tag_hash_recomputed)

def menu():
    print("Commands are:")
    print("|-> t tag a message")
    print("|-> v verify a couple (message, tag)")
    print("|-> q Quit")

if __name__ == "__main__":

    L = []
    macaron = Macaron()
    while len(L) <= 32:

        try:
            menu()
            cmd = input(">>> ")

            if len(cmd) == 0 or cmd not in ['t', 'v', 'q']:
                continue

            if cmd == 'q':
                break

            if cmd == 't':
                print("Input the message:")
                message = str.encode(input(">>> "))
                if not len(message):
                    print("Error: the message must not be empty.")
                    continue

                tag = macaron.tag(message)
                print("Tag hash:  {}".format(tag[0].hex()))
                print("Tag nonce: {}".format(tag[1].hex()))
                L.append(message)

            elif cmd == 'v':
                print("Input the message to verify:")
                message = str.encode(input(">>> "))
                if not len(message):
                    print("Error: the message must not be empty.")
                    continue

                print("Input the associated tag hash:")
                tag_hash = bytearray.fromhex(input(">>> "))

                print("Input the associated tag nonce:")
                tag_nonce = bytearray.fromhex(input(">>> "))

                check = macaron.verify(message, (tag_hash, tag_nonce))
                if check:
                    if message not in L:
                        print("Congrats!! Here is the flag: {}".format(flag))
                    else:
                        print("Tag valid, but this message is not new.")
                else:
                    print("Invalid tag. Try again")

        except:
            print("Error: check your input.")
            continue
```

Une signature consiste en un couple \(tag\_hash, tag\_nonce\). Si on arrive à fournir au serveur un message signé sans qu'on ait généré sa signature avant, c'est gagné.

Le serveur initialise trois données :

* Un compteur _ctr_ à 0
* Deux clés _k1_ et _k2_ pseudo-aléatoires a priori inexploitables

La signature fonctionne de la façon suivante :

* Padder le message _m_ pour avoir une taille multiple de 60 octets \(standard PKCS, donc si on envoie un message de la bonne taille, un bloc entier de padding sera ajouté, garantissant l'unicité du message paddé\)
* On commence à construire tag\_nonce à l'aide du compteur sur 2 octets en big endian \(par exemple, 0 devient "0000", 1 devient "0001"\)
* On initialise tag\_hash \(32 octets\) à 0
* Pour chaque bloc de 30 octets de _m_, on construit un _big\_block_ qui est la concaténation de deux sous-blocs :
  * Le premier sous-bloc est le _next\_block_ de l'itération précédente \(si c'est la première itération, alors il s'agit du premier _tag\_nonce_ concaténé aux 30 premiers octets du message\)
  * Le deuxième sous-bloc, _next\_block_ est donné par la concaténation du nouveau _nonce_ \(compteur incrémenté\) et des 30 octets suivants de _m_.
* Ce _big\_block_ est passé dans un HMAC avec la clé _k1_
* _tag\_hash_ est mis à jour en étant XORé avec ce HMAC
* On rajoute le nouveau nonce à _tag\_nonce_
* A la fin, _tag\_hash_ est un HMAC de lui-même avec la clé _k2_ et on le renvoie aux côtés de _tag\_nonce_

**Un exemple** pour y voir plus clair. Supposons que le compteur soit à 0 et que je veuille signer le message `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` \(60 caractères\).

Mon message est d'abord paddé : on rajoute 60 octets de valeur ASCII 60, c'est-à-dire le caractère `<`. _m_ ressemble donc à `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<`.

Le tag\_nonce est initialisé à "0000". On découpe notre message en blocs de 30 octets :

```text
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

Les HMAC calculés seront ceux de :

```text
\x00\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
\x00\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00\x02<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\x00\x02<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\x00\x03<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

Ces trois HMAC seront XORés entre eux, puis le résultat passera dans un nouveau HMAC avec une clé différente. Le _tag\_nonce_ renvoyé sera `0000000100020003`.

Un petit schéma :

![](https://i.imgur.com/cZCYGBL.png)

Passons désormais à l'exploitation. Comment construire un message qui donnera un _tag\_hash_ que l'on prévoir à l'avance ?

Il est évident que l'on ne pourra pas recalculer un _tag\_hash_, puisque l'on a pas la clé _k2_ \(et aussi parce que le HMAC c'est assez bien foutu donc pas d'attaque de type hash-length extension\).

L'idée serait donc de soumettre un message au serveur, d'obtenir un hash, et d'essayer de construire un message différent qui donne le même hash, en se concentrant sur l'idée d'obtenir une valeur identique _avant_ le calcul du dernier HMAC.

A ce moment-là, on peut avoir l'intuition : pour avoir deux messages identiques à partir d'un XOR de plusieurs valeurs, il suffit de rajouter par exemple deux valeurs identiques, dont le XOR va s'annuler.

La faiblesse lors de la vérification de la signature consiste en le fait que l'on peut non seulement envoyer des nonce non-ordonnés, mais surtout les **réutiliser**.

Sans plus attendre, voici ma solution. On demande au serveur à signer le message `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

Son découpage en blocs est le suivant :

```text
\0\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
\0\5<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
```

Le calcul effectué par le serveur est :

```text
    hmac(\0\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) #
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) #
XOR hmac(\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) #
XOR hmac(\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<) #
XOR hmac(\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\0\5<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<) #
```

Rajoutons deux blocs qui s'annulent au milieu :

```text
    hmac(\0\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) #
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) .
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) .
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) #
XOR hmac(\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) #
XOR hmac(\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<) #
XOR hmac(\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\0\5<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<) #
```

Seul problème à régler : les blocs ne se recouvrent pas \(construction avec les _previous\_block_ et _next\_block_\). En effet, il faut que la fin de ce qui rentre dans le deuxième HMAC coïncide avec le début de ce qui rentre dans le troisième HMAC.

Pour cela, il suffit d'intercaler deux autres blocs de la façon suivante :

```text
    hmac(\0\0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) #
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) .
XOR hmac(\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) .
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) .
XOR hmac(\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) .
XOR hmac(\0\1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) #
XOR hmac(\0\2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) #
XOR hmac(\0\3bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<) #
XOR hmac(\0\4<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\0\5<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<) #
```

Les 4 blocs rajoutés au total s'annulent car 2 à 2 identiques, et respectent bien le suivi des sous-blocs. Tout est bon !

```text
$ nc challenges1.france-cybersecurity-challenge.fr 2005
Commands are:
|-> t tag a message
|-> v verify a couple (message, tag)
|-> q Quit
>>> t
Input the message:
>>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Tag hash:  3baec174ae8d9af05f83650b377f49d51b8ebb3a97cfc147cc81eaab043d3dc3
Tag nonce: 000000010002000300040005
Commands are:
|-> t tag a message
|-> v verify a couple (message, tag)
|-> q Quit
>>> v
Input the message to verify:
>>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Input the associated tag hash:
>>> 3baec174ae8d9af05f83650b377f49d51b8ebb3a97cfc147cc81eaab043d3dc3
Input the associated tag nonce:
>>> 0000000100020001000200010002000300040005                        
Congrats!! Here is the flag: FCSC{529d5fb1ea316b2627c16190060af9f70dc420438afa7e8eb71d144a54a0}
```

