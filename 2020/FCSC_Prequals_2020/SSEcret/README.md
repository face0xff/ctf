### SSEcret (reverse, 500)

#### Description du challenge

```
Trouvez le secret qui affichera le flag.
```

#### Solution

Un autre crackme très sympathique et à rebondissements.

```
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abc 
[1]    10875 segmentation fault (core dumped)  ./ssecret.bin abc
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abcd
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abcde
[1]    10890 segmentation fault (core dumped)  ./ssecret.bin abcde
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abcdef   
[1]    10898 segmentation fault (core dumped)  ./ssecret.bin abcdef
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abcdef
g[1]    10906 segmentation fault (core dumped)  ./ssecret.bin abcdef
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abcdefg
[1]    10923 segmentation fault (core dumped)  ./ssecret.bin abcdefg
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin abcdefgh
```

Étonnant, le binaire semble segfault lorsque l'entrée n'est pas de longueur multiple de 4. Sinon, il n'affiche juste rien. Le but est donc de lui faire cracher le flag. Sans plus attendre, laissons place à Ghidra. Quelques variables ont été renommées pour la lisibilité :

```c
undefined8 main(int argc,undefined8 *argv)

{
  char cVar1;
  undefined8 uVar2;
  ulong uVar3;
  char *pcVar4;
  long in_FS_OFFSET;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (argc == 2) {
    uVar3 = 0xffffffffffffffff;
    pcVar4 = (char *)argv[1];
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != 0);
    uVar2 = FUN_00400860((char *)argv[1],~uVar3 - 1,&local_18);
    FUN_00601050(uVar2,local_18);
  }
  else {
    __printf_chk(1,"Usage: %s <secret>\n",*argv);
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

La fonction *main* calcule la longueur de notre argument et appelle la fonction `FUN_00400860`. Je passe sur les détails parce que ce n'est pas la partie intéressante ; cette fonction décode notre entrée comme de la **base64**, renvoie son adresse et stocke sa taille en octets une fois décodée dans `local_18`.

La fonction `FUN_00601050` est appelée avec l'adresse de notre mot de passe décodée et sa longueur.

```c
void FUN_00601050(undefined auParm1 [16],undefined *puParm2,long lParm3)

{
  int iVar1;
  undefined8 uVar2;
  ulong uVar3;
  undefined *puVar4;
  undefined8 uVar5;
  ulong uVar6;
  undefined4 uVar7;
  undefined auVar8 [16];
  undefined auVar9 [16];
  undefined auVar10 [16];
  undefined auVar11 [16];
  undefined auVar12 [16];
  undefined auVar13 [16];
  long lVar14;
  
  puVar4 = (undefined *)0x603c50;
  if (0xf < lParm3) {
                    /* WARNING: Load size is inaccurate */
    auParm1 = *(undefined *)puParm2;
    auVar9 = pinsrq(ZEXT816(0),0x8000000000000000,1);
    auVar8 = pinsrq(ZEXT816(0xdcd26c8c431d185),0x9cbf4b9eb8ff5fd5,1);
    uVar2 = vmovq_avx(auVar8 & auParm1);
    uVar5 = vpextrq_avx(auVar8 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    auVar8 = (undefined  [16])0x0;
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar9;
    }
    auVar10 = psrlq(auVar9,1);
    auVar9 = pinsrq(ZEXT816(0xeffb0f6af6379591),0xf79a5f5f0cc2a086,1);
    uVar2 = vmovq_avx(auVar9 & auParm1);
    uVar5 = vpextrq_avx(auVar9 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar8 ^ auVar10;
    }
    auVar10 = psrlq(auVar10,1);
    auVar9 = pinsrq(ZEXT816(0xa066690c6259f360),0xed5861bedc01ac55,1);
    uVar2 = vmovq_avx(auVar9 & auParm1);
    uVar5 = vpextrq_avx(auVar9 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar8 ^ auVar10;
    }
    auVar10 = psrlq(auVar10,1);
    auVar9 = pinsrq(ZEXT816(0x95b3ec4628105ece),0x9332a77e095bc150,1);
    uVar2 = vmovq_avx(auVar9 & auParm1);
    uVar5 = vpextrq_avx(auVar9 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar8 ^ auVar10;
    }
    auVar10 = psrlq(auVar10,1);
    auVar9 = pinsrq(ZEXT816(0x6fc606493188abf3),0xc801ea2bcfa14908,1);
    uVar2 = vmovq_avx(auVar9 & auParm1);
    uVar5 = vpextrq_avx(auVar9 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar8 ^ auVar10;
    }
    auVar10 = psrlq(auVar10,1);
    auVar9 = pinsrq(ZEXT816(0xd6783f0c8ae2a13c),0xae0cf5cf140ff887,1);
    uVar2 = vmovq_avx(auVar9 & auParm1);
    uVar5 = vpextrq_avx(auVar9 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar8 ^ auVar10;
    }
    
    [...]
    
    auVar10 = psrlq(auVar10,1);
    auVar9 = pinsrq(ZEXT816(0xfe949c491cf37734),0xc4d08f025d93925e,1);
    uVar2 = vmovq_avx(auVar9 & auParm1);
    uVar5 = vpextrq_avx(auVar9 & auParm1,1);
    uVar3 = popcnt(uVar2);
    uVar6 = popcnt(uVar5);
    if ((uVar3 & 1) != (uVar6 & 1)) {
      auVar8 = auVar8 ^ auVar10;
    }
    psrlq(auVar10,1);
    auVar9 = pinsrq(ZEXT816(0xf72389798f7ca4f4),0x62e9eed78a671820,1);
    iVar1 = vpmovmskb_avx(CONCAT412(-(uint)(SUB164(auVar8 >> 0x60,0) == SUB164(auVar9 >> 0x60,0)),
                                    CONCAT48(-(uint)(SUB164(auVar8 >> 0x40,0) ==
                                                    SUB164(auVar9 >> 0x40,0)),
                                             CONCAT44(-(uint)(SUB164(auVar8 >> 0x20,0) ==
                                                             SUB164(auVar9 >> 0x20,0)),
                                                      -(uint)(SUB164(auVar8,0) == SUB164(auVar9,0)))
                                            )));
    if (iVar1 == 0xffff) goto LAB_006039f3;
  }
  syscall();
LAB_006039f3:
  auVar8 = (undefined  [16])0x0;
  do {
    auVar9 = aeskeygenassist(auParm1,1);
    uVar7 = SUB164(auVar9 >> 0x60,0);
    auVar9 = pslldq(auParm1,4);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar9 = auParm1 ^ auVar9 ^ auVar10 ^ auVar11 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar8 ^ auParm1,auVar9);
    auVar10 = aeskeygenassist(auVar9,2);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,4);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,8);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,0x10);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,0x20);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,0x40);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,0x80);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,0x1b);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
             CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7)));
    auVar13 = aesenc(auVar13,auVar9);
    auVar10 = aeskeygenassist(auVar9,0x36);
    uVar7 = SUB164(auVar10 >> 0x60,0);
    auVar10 = pslldq(auVar9,4);
    auVar11 = pslldq(auVar10,4);
    auVar12 = pslldq(auVar11,4);
    auVar9 = aesenclast(auVar13,auVar9 ^ auVar10 ^ auVar11 ^ auVar12 ^
                                CONCAT412(uVar7,CONCAT48(uVar7,CONCAT44(uVar7,uVar7))));
                    /* WARNING: Load size is inaccurate */
                    /* WARNING: Store size is inaccurate */
    *(undefined *)puVar4 = *(undefined *)puVar4 ^ auVar9;
    lVar14 = SUB168(auVar8,0) + 1;
    puVar4 = puVar4 + 0x10;
    iVar1 = vpmovmskb_avx(CONCAT412(-(uint)(SUB164(auVar8 >> 0x60,0) == 0),
                                    CONCAT48(-(uint)(SUB164(auVar8 >> 0x40,0) == 0),
                                             CONCAT44(-(uint)((int)((ulong)lVar14 >> 0x20) == 0),
                                                      -(uint)((int)lVar14 == 0x2c0)))));
    auVar8 = CONCAT88(SUB168(auVar8 >> 0x40,0),lVar14);
  } while (iVar1 != 0xffff);
  return;
}

```

J'ai grandement élagué le code pour pas que ce soit trop lourd. La structure de la fonction est la suivante :

* On vérifie que notre mot de passe fait au moins 16 octets
* 128 blocs très similaires qui font des calculs à l'aide de notre entrée et de constantes 128 bits
* Une vérification à la fin de tous ces blocs (juste avant le *syscall*) mettant aussi en jeu une constante 128 bits
* Si la vérification est passée, alors une routine semble déchiffrer quelque chose à l'aide de notre mot de passe, qui agit comme une clé AES 128 bits.

Après un moment sous IDA à suivre l'exécution du programme en analysant assidument les registres XMM, on arrive à reconstituer la logique suivante.

```c
auParm1 = *(undefined *)puParm2;
auVar9 = pinsrq(ZEXT816(0),0x8000000000000000,1);
auVar8 = pinsrq(ZEXT816(0xdcd26c8c431d185),0x9cbf4b9eb8ff5fd5,1);
uVar2 = vmovq_avx(auVar8 & auParm1);
uVar5 = vpextrq_avx(auVar8 & auParm1,1);
uVar3 = popcnt(uVar2);
uVar6 = popcnt(uVar5);
auVar8 = (undefined  [16])0x0;
if ((uVar3 & 1) != (uVar6 & 1)) {
  auVar8 = auVar9;
}
```

Ce premier bloc vient charger auVar9 avec la valeur 0x80000000000000000000000000000000. C'est une initialisation que l'on ne retrouve plus dans les blocs suivants ; à la place, on y retrouvera à chaque fois un décalage de 1 bit vers la droite, autrement dit à l'itération *i* cette variable vaudra l'entier binaire 128 bits qui possède un unique 1 en *i*-ème position (de poids fort à poids faible).

Il charge ensuite auVar8 avec une constante 128 bits, ici 85 D1 31 C4 C8 26 CD 0D D5 5F FF B8 9E 4B BF 9C (telle qu'affichée dans le débugger d'IDA, en **little-endian**).

auParm1 contient les 16 premiers octets de notre entrée, vus comme un entier 128 bits. Un *ET logique* est effectué entre notre entrée et la constante formée. Enfin, la fonction `popcnt` permet de compter le nombre de bits à 1 dans un registre. Cela est fait en deux étapes à travers les registres 64 bits, mais la finalité est la même : si le *XOR* (ou l'addition des bits modulo 2...) des bits constituant le résultat du ET logique vaut 1, alors on rentre dans le *if*, qui va initialiser auVar8 à auVar9.

Le contenu de ce *if* fait probablement plus de sens dans les blocs suivants :

```c
if ((uVar3 & 1) != (uVar6 & 1)) {
  auVar8 = auVar8 ^ auVar10;
}
```

auVar8 est XORé avec auVar10, ce qui est équivalent à mettre le *i*-ème bit à 1 dans auVar8.

Ainsi, le résultat de ces 128 blocs est la formation d'un entier 128 bits *c* tel que c[i] est la somme modulo 2 des bits de (key & a[i]), où *a* est la *i*-ème constante magique.

Le dernier bloc (le "129ème") est un peu illisible avec les CONCAT et les SUB de Ghidra et est plus clair en assembleur :

```asm
                     LAB_006039ae                                    XREF[1]:     006039a8(j)  
006039ae 66 0f 73        PSRLQ      XMM2,0x1
         d2 01
006039b3 48 b8 f4        MOV        RAX,-0x8dc768670835b0c ; 0xf72389798f7ca4f4
         a4 7c 8f 
         79 89 23 f7
006039bd 48 bb 20        MOV        RBX,0x62e9eed78a671820
         18 67 8a 
         d7 ee e9 62
006039c7 66 48 0f        MOVQ       XMM4,RAX
         6e e0
006039cc 66 48 0f        PINSRQ     XMM4,RBX,0x1
         3a 22 e3 01
006039d3 66 0f 76 dc     PCMPEQD    XMM3,XMM4
006039d7 48 31 c0        XOR        RAX,RAX
006039da c5 f9 d7 c3     VPMOVMSKB  EAX,XMM3
006039de 35 ff ff        XOR        EAX,0xffff
         00 00
006039e3 85 c0           TEST       EAX,EAX
006039e5 74 0c           JZ         LAB_006039f3
                     LAB_006039e7                                    XREF[1]:     00601064(j)  
006039e7 48 c7 c0        MOV        RAX,0x3c
         3c 00 00 00
006039ee 48 31 ff        XOR        RDI,RDI
006039f1 0f 05           SYSCALL
```

A l'aide de PCMPEQD, on compare deux registres XMM, à savoir celui contenant *c* et une constante chargée, ici F4 A4 ... E9 62.

Bien ! Il ne reste plus qu'à reformuler ça mathématiquement (le chall a le tag "maths" après tout, même si ça reste assez léger à mon sens 🧐). Chaque bloc peut être reformulé de la façon suivante :

$$\langle \: a_i \: | \: x \: \rangle \equiv c_i \: \mod{2}$$

où $$x$$ est l'inconnue (notre password), $$(a_i)_{0 \leq i \lt 128}$$ les constantes magiques et $$(c_i)_{0 \leq i \lt 128}$$ les bits de la valeur magique de comparaison finale. $$x$$ et $$(a_i)$$ sont des vecteurs 128 bits qui codent l'entier qu'ils représentent.

On a 128 équations de ce genre, que l'on peut donc reformuler globalement ainsi :

$$Ax \equiv C \: \mod{2}$$

où $$A$$ est la matrice de bits dont les lignes sont les $$a_i$$, et $$C$$ le vecteur colonne des $$c_i$$.

Cette équation se résout en trois lignes de Sage :

```python
R = IntegerModRing(2)
M = Matrix(R, [...])
b = vector(R, [...])
print(M.solve_right(b))
```

Il ne reste plus qu'à coder un petit script pour parser le code afin de récupérer toutes les valeurs magiques et c'est gagné !

Je passe les détails : on trouve une solution, on la décodé en binaire puis ré-encode en base64 et on obtient `eqFUxbL2zNoSFXuPo3P64A==`. On la passe au binaire pour obtenir le flag :

```
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$ ./ssecret.bin eqFUxbL2zNoSFXuPo3P64A==
╭─face0xff@aniesu-chan /den/ctf/fcsc  
╰─$
```

Mince... que s'est-il passé ?

On lance IDA et on débug pour voir pourquoi ça n'a pas marché. On se rend compte qu'en fait si, ça a marché ; la condition est bien passée et on n'a pas emprunté le *syscall* exit. On rentre dans la routine de déchiffrement AES et là on commence à voir venir la couille...

La routine AES déchiffre un **nouveau bloc de code** du programme et va jump dessus. Pas très grave me direz vous, il suffit d'analyser ce que fait ce nouveau bloc de code, éventuellement trouver la façon dont est générée le flag sur le passage et c'est plié.

Sauf que le bloc de code généré ressemble **exactement** à la fonction principale initiale, aux constantes magiques près. Ce nouveau code utilise les 16 prochains octets de notre mot de passe. 

On effectue un rapide calcul, et on se rend compte qu'il y a en fait environ 127 blocs de code obfusqué de même longueur que la première fonction dans le binaire, soit au total 128 problèmes de ce type à résoudre. Il va falloir scripter intelligemment... !

Je passe sur les détails, il s'agit de parser le binaire directement pour récupérer les valeurs magiques, résoudre l'équation matricielle, utiliser le morceau de clé trouvé pour déchiffrer le prochain bloc de code et répéter. Les difficultés principales résidaient dans le parsing correct du binaire (j'ai passé beaucoup de temps à débugger une regex erronnée) et dans la compréhension de la routine de déchiffrement, qui est certes du AES classique, mais il faut bien identifier ce qu'on chiffre avec quelle clé à chaque itération. Il s'agissait en fait d'AES en mode CTR (avec le compteur "canonique" si je puis dire).

```python
import re, struct
from Crypto.Cipher import AES
from binascii import hexlify as tohex, unhexlify as unhex
from base64 import b64encode
from os import system

def bin_array(b):
  B = []
  for j in range(len(b)):
    for i in range(8):
      B.append((b[j] >> (7 - i)) & 1)
  return B

def from_bin(s):
  q = ''.join(c for c in s if c in '01')
  return bytes([int(q[i:i + 8], 2) for i in range(0, len(q), 8)])

class Counter(object):
  def __init__(self):
    self.c = 0
  
  def counter(self):
    v = struct.pack('<Q', self.c % 2 ** 64) + struct.pack('<Q', (self.c >> 64) % (2 ** 64))
    self.c += 1
    return v

f = open('ssecret.bin', 'rb').read()[0x1050:]
f = [f[i:i + 0x2c00] for i in range(0, len(f), 0x2c00)][:128]

secret = b''

for k in range(128):

  blob = f[k]
  print(blob[:100])
  blob = re.split(rb'[\x22\x73][\xd3\xd2]\x01\x48\xb8', blob)[1:]
  res = bin_array(blob[-1][:8] + blob[-1][10:10 + 8])

  A = []
  C = []
  j = 0
  for b in blob[:-1]:
    if b.startswith(b'\x00\x00\x00\x00\x00\x00\x00\x80'):
      continue
    A.append(bin_array(b[:8] + b[10:10 + 8]))
    C.append(res[127 - (7 - (j % 8)) - 8 * (j // 8)])
    j += 1

  # Ax = C mod 2
  # Sage script generation
  with open('ssecret.sage', 'w') as sagefile:
    sagefile.write("""R = IntegerModRing(2)
M = Matrix(R, %s)
b = vector(R, %s)
print(M.solve_right(b))""" % (repr(A), repr(C)))

  system("sage ssecret.sage > ssecret.sage.sol")

  with open('ssecret.sage.sol', 'r') as sol:
    sage_output = sol.read()
  
  key = from_bin(sage_output)
  
  secret += key
  print('[%s] Secret: %s' % (k, b64encode(secret).decode()))

  counter = Counter()
  cipher = AES.new(key, AES.MODE_CTR, counter=counter.counter)
  f[k + 1] = cipher.encrypt(f[k + 1])

```

Le script met un peu de temps à s'exécuter (2 minutes sur ma machine), probablement à cause des appels à Sage... (je ne connais pas bien Sage donc je ne sais pas s'il y a un moyen plus simple de "wrapper" tout ça, j'ai juste vu que je pouvais exécuter le script en ligne de commande donc j'ai foncé là-dessus).

On trouve alors enfin le (long) mot de passe à la 128ème itération, et on prie pour qu'il n'y ait pas une étape supplémentaire à la fin :

```
$ ./ssecret.bin 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                        
Well done! Here is the flag: FCSC{b0f6cfda0049a03d65d6b9e3e3ecf5b990c24ffe27784b7d553fcdc2f45a8ad4}
```

Enjoy !
