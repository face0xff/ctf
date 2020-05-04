### Merry (crypto, 500)

#### Description du challenge

```
Un serveur a été conçu pour utiliser un algorithme d'échange de clés avec ses clients. Cet algorithme génère et garde le même bi-clé pour plusieurs requêtes. Il notifie aussi ses clients quand l'échange a échoué et que la clé partagée n'est pas la même. Votre but est de retrouver la clé secrète du bi-clé généré par le serveur.

Service : nc challenges1.france-cybersecurity-challenge.fr 2001

Note : La version de Python utilisée par le serveur est 3.5.3 (default, Sep 27 2018, 17:25:39) [GCC 6.3.0 20170516]
```

#### Solution

Le challenge a pour tag *post-quantum* mais il ne faut pas se laisser impressionner, aucune connaissance en crytographie quantique n'est nécessaire pour résoudre ce challenge. Il faut juste savoir faire du calcul matriciel de base :smiley: 

Voici le code du serveur :

```python
import sys
import numpy as np
from flag import flag
from zlib import compress, decompress
from base64 import b64encode as b64e, b64decode as b64d

class Server:
    def __init__(self, q, n, n_bar, m_bar):
        self.q     = q
        self.n     = n
        self.n_bar = n_bar
        self.m_bar = m_bar
        self.__S_a = np.matrix(np.random.randint(-1, 2, size = (self.n, self.n_bar)))
        self.__E_a = np.matrix(np.random.randint(-1, 2, size = (self.n, self.n_bar)))
        self.A     = np.matrix(np.random.randint( 0, q, size = (self.n, self.n)))
        self.B     = np.mod(self.A * self.__S_a + self.__E_a, self.q)

    ### Private methods
    def __decode(self, mat):
        def recenter(x):
            if x > self.q // 2:
                return x - self.q
            else:
                return x

        def mult_and_round(x):
            return round((x / (self.q / 4)))

        out = np.vectorize(recenter)(mat)
        out = np.vectorize(mult_and_round)(out)
        return out

    def __decaps(self, U, C):
        key_a = self.__decode(np.mod(C - np.dot(U, self.__S_a), self.q))
        return key_a

    ### Public methods
    def pk(self):
        return self.A, self.B

    def check_exchange(self, U, C, key_b):
        key_a = self.__decaps(U, C)
        return (key_a == key_b).all()

    def check_sk(self, S_a, E_a):
        return (S_a == self.__S_a).all() and (E_a == self.__E_a).all()

def menu():
    print("Possible actions:")
    print("  [1] Key exchange")
    print("  [2] Get flag")
    print("  [3] Exit")
    return int(input(">>> "))

if __name__ == "__main__":

    q     = 2 ** 11
    n     = 280
    n_bar = 4
    m_bar = 4

    server = Server(q, n, n_bar, m_bar)

    A, B = server.pk()
    print("Here are the server public parameters:")
    print("A = {}".format(b64e(compress(A.tobytes())).decode()))
    print("B = {}".format(b64e(compress(B.tobytes())).decode()))

    nbQueries = 0
    while True:
        try:
            choice = menu()
            if choice == 1:
                nbQueries += 1
                print("Key exchange #{}".format(nbQueries), file = sys.stderr)
                U     = np.reshape(np.frombuffer(decompress(b64d(input("U = "))), dtype = np.int64), (m_bar, n))
                C     = np.reshape(np.frombuffer(decompress(b64d(input("C = "))), dtype = np.int64), (m_bar, n_bar))
                key_b = np.reshape(np.frombuffer(decompress(b64d(input("key_b = "))), dtype = np.int64), (m_bar, n_bar))

                if server.check_exchange(U, C, key_b):
                    print("Success, the server and the client share the same key!")
                else:
                    print("Failure.")

            elif choice == 2:
                S_a = np.reshape(np.frombuffer(decompress(b64d(input("S_a = "))), dtype = np.int64), (n, n_bar))
                E_a = np.reshape(np.frombuffer(decompress(b64d(input("E_a = "))), dtype = np.int64), (n, n_bar))

                if server.check_sk(S_a, E_a):
                    print("Correct key, congratulations! Here is the flag: {}".format(flag))
                else:
                    print("Sorry, this is not the correct key.")
                    print("Bye bye.")
                    exit(1)

            elif choice == 3:
                print("Bye bye.")
                break

        except:
            pass
```

L'idée est que l'on peut demander autant de fois que l'on veut au serveur un "key exchange", qui est un oracle à réponse binaire. Le but du challenge est de déterminer deux paramètres privés $S_a$ et $E_a$.

A l'initialisation, le serveur pose $q = 2^{11}$, $n = 280$, $n_{bar} = m_{bar} = 4$ et génère deux clés privées $S_a$ et $E_a$ à valeurs dans $\{-1,0,1\}$ (oui, 2 est exclu, le randint de numpy n'agit pas comme le randint vanilla... !!). $S_a$ et $E_a$ sont de dimensions $(n, n_{bar})$.

Enfin, $A$ et $B$ sont deux matrices publiques. $A$ est générée aléatoirement à valeurs dans $\{0, \:..., \: q\}$ et est de taille $(n, n)$ ; $B$ satisfait la relation suivante :

$$ B := (A S_a + E_a) \: \mod{q}$$

Étudions maintenant *check_exchange*. Le serveur nous demande $U$, une matrice $(m_{bar}, n)$, $C$, une matrice $(m_{bar}, n_{bar})$, et $\text{key}_b$, une matrice aussi $(m_{bar}, n_{bar})$.

Il vérifie alors si :

$$ \text{decode}((C - U S_a) \mod{q}) = \text{key}_b $$

*decode* est une fonction qui recentre les valeurs de la matrice autour de 0 (pour qu'elles passent entre $-q/2$ et $q/2$ environ) puis les divise par $q/4$ et les arrondit, ce qui donne une matrice à valeurs dans $\{-2, -1, 0, 1, 2\}$.

Si l'on arrive à retrouver $S_a$, il sera aisé de calculer $E_a$. Alors comment choisir les paramètres pour faire fuiter de l'information sur $S_a$ ?

Ma solution (il y a certainement plusieurs techniques) est de poser $C = 0$ et de choisir $U = \lambda E_{1, j}$, où $\lambda$ est un coefficient entier à paramétrer et $E_{i,j}$ sont les matrices de la base canonique (des zéros partout, sauf un 1 en $(i, j)$).

Ainsi, on aura :

$$C - U S_a = -U S_a = -\lambda E_{1, j} S_a = \begin{bmatrix} & -\lambda S_{a, j} & \\ & 0 & \\ & 0 & \\ & 0 & \end{bmatrix} \in \mathcal{M}_{4, 4}(\{ 0, \:..., \: q - 1\}) \: \mod{q}$$

où $S_{a, j}$ est la *j*-ème ligne de $S_a$ (qui contient 4 valeurs entre -1 et 1).

Les valeurs subissant dans *decode* la division par $q/4$, on voit l'importance du facteur $\lambda$. En effet, sans, les coefficients $0$ et $1$ de la matrice obtenue se feraient arrondir à 0 et on ne pourrait plus les distinguer.

Je pose maintenant $\lambda = q/4 = 512$ qui donne des résultats intéressants. En effet, en raisonnant coefficient par coefficient dans la matrice, on a, en partant d'un coefficient de $S_{a,j}$ :

* $0$ reste $0$, est recentré en $0$ et est arrondi à $0$
* $1$ devient $-512 \equiv 1536\:\mod{q}$, est recentré en $-512$ et est arrondi à $-1$
* $-1$ devient $512$, est recentré en $512$ et est arrondi à $1$

Il suffit donc de prendre l'opposé du résultat pour obtenir la valeur d'origine. Il ne reste plus qu'à challenger l'oracle en brute-forçant toutes les matrices $4 \times 4$ dont la première ligne est à valeurs dans $\{-1, 0, 1\}$ (donc $3^4 = 81$ requêtes dans le pire cas) jusqu'à ce qu'on nous réponde succès, ce qui nous permet d'identifier une ligne de $S_a$.

On répète cela $n = 280$ fois (soit $22680$ requêtes dans le pire cas) et on a réussi à déterminer $S_a$. Il ne reste plus qu'à utiliser :

$$ E_a \equiv B - A S_a \: \mod{q} $$

et à soumettre la réponse $(S_a, \:E_a)$ au serveur.

Voici l'exploit :

```python
from pwn import *
import numpy as np
from zlib import compress, decompress
from base64 import b64encode as b64e, b64decode as b64d
from itertools import product

q = 2 ** 11
n = 280
n_bar = 4

LAMBDA = 512

s = remote('challenges1.france-cybersecurity-challenge.fr', 2001)

msg = s.recvuntil(b'Possible actions')
s.recv(1024)

A = msg.split(b'A = ')[1].split(b'\n')[0]
B = msg.split(b'B = ')[1].split(b'\n')[0]

A = np.reshape(np.frombuffer(decompress(b64d(A)), dtype = np.int64), (n, n))
B = np.reshape(np.frombuffer(decompress(b64d(B)), dtype = np.int64), (n, n_bar))

__S_a = np.zeros((n, n_bar), dtype = np.int64)

s.send(b'1\n')

for k in range(n):
  U = np.zeros((n_bar, n), dtype = np.int64)
  C = np.zeros((n_bar, n_bar), dtype = np.int64)
  
  U[0][k] = LAMBDA
  
  U = b64e(compress(U.tobytes()))
  C = b64e(compress(C.tobytes()))
  
  for c in product([-1, 0, 1], repeat=n_bar):
    CMP = np.zeros((n_bar, n_bar), dtype = np.int64)
    for i in range(n_bar):
      CMP[0][i] = c[i]
    CMP = b64e(compress(CMP.tobytes()))
    
    s.recv(1024)
    s.send(U + b'\n')

    s.recv(1024)
    s.send(C + b'\n')
    
    s.recv(1024)
    s.send(CMP + b'\n')

    msg = s.recv(1024)
    s.send(b'1\n')

    if b'Success' in msg:
      break
  
  for i in range(n_bar):
    __S_a[k][i] = -c[i]
  
  print("[+] Ligne %s: %s" % (k, repr(__S_a[k])))  

__E_a = np.mod(B - np.dot(A, __S_a), q)

def t(x):
  if x == q - 1:
    return -1
  return x

__S_a = b64e(compress(np.vectorize(t)(__S_a).tobytes()))
__E_a = b64e(compress(np.vectorize(t)(__E_a).tobytes()))

print(__S_a)
print(__E_a)

s.interactive()
s.close()
```

L'exploit est un peu long, il y a peut-être moyen de faire plus court en répartissant un peu plus l'information à travers les requêtes mais cette méthode est suffisante donc je n'ai pas cherché.

La séquelle de cette épreuve, *Pippin*, se résolvait de façon exactement similaire, mais il fallait remarquer que $S_a$ avait sur chaque ligne exactement 2 "0", 1 "1" et 1 "-1", ce qui réduit les possibilités et permet de passer en dessous de 3000 requêtes.

Enjoy !
