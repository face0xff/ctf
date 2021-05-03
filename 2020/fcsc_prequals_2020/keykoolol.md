# Keykoolol \(reverse, 500\)

## Description du challenge

```text
On vous demande d'écrire un générateur d'entrées valides pour ce binaire, puis de le valider sur les entrées fournies par le service distant afin d'obtenir le flag.

Service : nc challenges2.france-cybersecurity-challenge.fr 3000
```

## Solution

Ce crackme était une aventure intense et pleine de rebondissements. J'ai du passer environ 8 heures non-stop dessus pour le résoudre. Il y a probablement quelques cracks qui l'ont poutrée beaucoup plus vite, donc je suis curieux de connaître les méthodes qui permettaient d'accélérer le processus de résolution. Quoi qu'il en soit, je suis fier de constater le fruit de mon acharnement et de ma persévérance sur cette longue épreuve !

Rentrons dans le vif du sujet : on nous donne un ELF 64 bits qui nous demande un _username_ ainsi qu'un _serial_ associé :

```text
$ ./keykoolol
[+] Username: abc
[+] Serial:   0123
[!] Incorrect serial.
```

Lançons le binaire dans Ghidra. La fonction _main_ ne paraît pas dépaysante, ce qui est rassurant.

```c
undefined8 FUN_00100730(void)

{
  char cVar1;
  size_t sVar2;
  ulong uVar3;
  ulong uVar4;
  char *__s;
  long in_FS_OFFSET;
  byte bVar5;
  char local_420 [512];
  char local_220 [512];
  long local_20;

  bVar5 = 0;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  __printf_chk(1,"[+] Username: ");
  fgets(local_420,0x200,stdin);
  sVar2 = strcspn(local_420,"\n");
  local_420[sVar2] = 0;
  __printf_chk(1,"[+] Serial:   ");
  fgets(local_220,0x200,stdin);
  sVar2 = strcspn(local_220,"\n");
  local_220[sVar2] = 0;
  uVar3 = 0xffffffffffffffff;
  __s = local_220;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *__s;
    __s = __s + (ulong)bVar5 * -2 + 1;
  } while (cVar1 != 0);
  uVar4 = 0xffffffffffffffff;
  __s = local_420;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *__s;
    __s = __s + (ulong)bVar5 * -2 + 1;
  } while (cVar1 != 0);
  uVar3 = FUN_0010096a(&DAT_001024e0,0x400,local_420,~uVar4 - 1,local_220,~uVar3 - 1);
  __s = "[!] Incorrect serial.";
  if ((int)uVar3 != 0) {
    puts("[>] Valid serial!");
    __s = "[>] Now connect to the remote server and generate serials for the given usernames.";
  }
  puts(__s);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

La ligne importante est la suivante, où j'ai renommé les arguments :

```c
r = FUN_0010096a(&DAT_001024e0, 0x400, username, len_username, serial, len_serial);
```

Pour gagner, il faut que cet appel renvoie autre chose que 0. `0x001024e0` est l'adresse d'un grand tableau de 0x400 = 1024 octets hardcodés dans le binaire et qui ne font _a priori_ pas encore sens.

On rentre dans la fonction, et là c'est le drame. D'abord, une petite capture du flow graph largement dézoomé sous IDA :

![](https://i.imgur.com/z3iEj6Q.png)

A ce moment-là c'est simple : on baisse les bras et on va tenter d'autres épreuves 😁

Puis on revient à nouveau dessus en se disant qu'elle vaut quand même 500 points et qu'une fois passée l'étape de tout bien lire ce qu'il se passe, elle doit être franchement faisable.

Examinons d'abord le prologue de cette fonction. J'ai renommé _data_ la référence au bloc de 1024 octets qui et passé en argument.

```c
bVar16 = 0;
lVar10 = 0x10;
puVar13 = &DAT_00303040;
while (lVar10 != 0) {
  lVar10 = lVar10 + -1;
  *puVar13 = 0;
  puVar13 = puVar13 + 1;
}
lVar10 = 0x200;
uVar11 = (uint)data_len & 0xfffffff0;
puVar13 = &DAT_00303080;
while (lVar10 != 0) {
  lVar10 = lVar10 + -1;
  *puVar13 = 0;
  puVar13 = puVar13 + 1;
}
lVar10 = __memcpy_chk(&DAT_00303080,data,data_len,0x800);
_DAT_00303060 = uVar11 + 0x10;
_DAT_00303064 = (uint)username_len;
_DAT_00303068 = uVar11 + 0x20 + (_DAT_00303064 & 0xfffffff0);
uVar9 = (ulong)DAT_0030302c;
bVar4 = false;
puVar14 = (undefined *)((ulong)_DAT_00303060 + lVar10);
while (iVar15 = DAT_00305880, username_len != 0) {
  username_len = username_len + -1;
  *puVar14 = *username;
  username = username + (ulong)bVar16 * -2 + 1;
  puVar14 = puVar14 + (ulong)bVar16 * -2 + 1;
}
_DAT_0030306c = (uint)serial_len;
_DAT_00303070 = _DAT_00303068 + 0x10 + (_DAT_0030306c & 0xfffffff0);
bVar3 = false;
bVar2 = false;
puVar14 = (undefined *)((ulong)_DAT_00303068 + lVar10);
while (uVar11 = DAT_00303030, serial_len != 0) {
  serial_len = serial_len + -1;
  *puVar14 = *serial;
  serial = serial + (ulong)bVar16 * -2 + 1;
  puVar14 = puVar14 + (ulong)bVar16 * -2 + 1;
}
```

Ce qu'il y a à retenir de ce prologue, c'est que :

* Un espace de 0x10 \* 4 = 64 octets nuls est réservé en 0x00303040
* Le contenu de _data_ est copié en 0x00303080
* Notre _username_ et _serial_ sont copiés après le bloc alloué à _data_ :
  * _username_ est en 0x00303080 + 0x400 + 0x10
  * _serial_ est en 0x00303080 + 0x400 + 0x10 + username\_len + 0x20

Ensuite vient ce qui ressemble à un monstrueux _switch case_, qui débute par :

```c
uVar1 = *(uint *)(data_ + (ulong)uVar11);
uVar5 = uVar1 >> 0x18;
```

Le switch case est effectué sur la valeur de _uVar5_. _uVar11_ est un compteur, qui avance la plupart du temps de 4 en 4 \(on lit des mots de 32 bits à chaque fois donc\). Là ça commence à mettre la puce à l'oreille... Je vais renommer _uVar11_ "pc", _uVar1_ "opcode" et _uVar5_ "type" 😁

Voici un court extrait maintenant de quelques entrées du _switch case_ :

```c
if (type == 0) {
  (&DAT_00303040)[(ulong)(opcode >> 0x14)] = (&DAT_00303040)[(ulong)(opcode >> 0x10 & 0xf)];
  uVar4 = pc + 4;
}
else {
  if (type == 0x1f) {
    _DAT_00303054 = _DAT_00303054 ^ 0xf7e1560a;
    uVar4 = pc + 4;
  }
  else {
    if (type == 0x20) {
      _DAT_00303048 = _DAT_00303048 ^ 0x6ddc660c;
      uVar4 = pc + 4;
    }
    else {
      if (type == 0x21) {
        _DAT_00303074 = _DAT_00303074 ^ 0x13e40c56;
        uVar4 = pc + 4;
      }
[...]
```

En effet, en fonction de la variable _type_, on va effectuer des opérations différentes, et on va incrémenter le _pc_ de 4. Tout est clair dès à présent ; il s'agit là d'une mini machine virtuelle 32 bits qui lit et interprète un jeu d'instructions \(qui ressemble un peu à du RISC ?\). Le _pc_ \(Program Counter\) donne la position courante dans la lecture de _data_ qui n'est rien d'autre que le bytecode du programme que l'on exécute. La zone de 64 octets initialement nuls en 0x00303040 représenta, nous le verrons, les 16 registres du processeur et enfin la zone après les 1024 octets du programme, en 0x00303480, sert à des fins de mémoire \(comme une _heap_\).

Le type d'un _opcode_ est donné par `opcode >> 0x18`, autrement ses 8 bits de poids fort, d'où le _switch case_ à 256 entrées.

Analysons l'extrait. Pour type = 0, on prend `opcode >> 0x14` et `opcode >> 0x10 & 0xf`, autrement dit les 4 bits et 4 bits suivant le type de l'opcode, et ces valeurs \(entre 0 et 15 donc en décimal\) sont des indices de registres \(situés en 0x00303040\). Cette instruction effectue donc ce qui s'apparente à un `mov` tel que l'on le noterait en assembleur classique x86 par exemple.

Les autres types \(0x1f, 0x20, 0x21\) semblent prendre un certain registre donné, et le XORer avec une constante donnée.

En fait, si l'on analyse tout le code, on se rend compte que ces étranges instructions de XOR très arbitraires occupent tous les types de 0x1f à 0xfd, ce qui diminue pas mal le nombre d'instructions réelles. On pourra coder un script pour extraire toutes ces instructions de XOR à partir du code généré par Ghidra.

Quant-aux autres instructions, il convient de les étudier chacune à la main. C'est un travail fastidieux et je vais directement passer à l'explication de l'ISA.

Tout d'abord, on pose quelques notations :

```text
type_op  k    m    p    q
00000000 0000 0000 0000 000000000000
-----------------s ssss

s = pour les opérations de shift (5 bits)
. = concaténation de bits
```

Ensuite on détaille chaque type d'opcode. J'appelle `text` la mémoire composée du programme et du _heap_, indicée à partir de zéro \(début du programme\). La fonction `swap_endianness` change le boutisme d'un mot de 32 bits, par exemple 0x11223344 devient 0x44332211. La fonction `AES` est en réalité l'instruction x86 _aesenc_, qui n'effectue qu'**un seul "round"** de chiffrement \(j'ai perdu beaucoup de temps là-dessus !\).

```text
00 -> reg[k] = reg[m]
01 -> reg[k] = text[reg[m]]
02 -> reg[k] = m.p (8 bits)
03 -> text[reg[k]] = reg[m]
04 -> text[reg[k]] = text[reg[m]]
05 -> text[reg[k]] = m . p (8 bits)
06 -> sauvegarde PC+4; pc = k.m.p.q; (CALL)
07 -> jump_flag = reg[k] - reg[m] (CMP between two registers)
08 -> jump_flag = reg[k] - m.p (CMP with immediate)
09 -> jump to k.m.p.q if jump_flag = 0 (JE)
0a -> jump to k.m.p.q if jump_flag != 0 (JNE)
0b -> reg[k] = reg[k] + reg[m]
0c -> reg[k] = reg[k] + m.p
0d -> reg[k] = reg[k] * reg[m]
0e -> reg[k] = reg[k] * m.p
0f -> reg[k] += 1
10 -> reg[k] = reg[k] % reg[m]
11 -> reg[k] = reg[k] % m.p
12 -> reg[k] = reg[k] ^ reg[m]
13 -> reg[k] = reg[k] ^ m.p
14 -> jump to k.m.p.q if jump_flag < 0 (JL)
15 -> jump to k.m.p.q if jump_flag > 0 (JG)
16 -> reg[k] = reg[k] - reg[m]
17 -> reg[k] = reg[k] - m.p
18 -> jump to k.m.p.q
19 -> reg[k] = reg[k] >> s
1a -> reg[k] = PC + 4
1b -> reg[k] = swap_endianness(text[reg[m]])
1c -> text[reg[k]] = swap_endianness(reg[m])
1d -> reg[k] = reg[k] << s
1e -> text[reg[k]] = AES(text[reg[m]], text[reg[p]])
1f -> fd : reg[something] ^= some hardcoded value
fe -> récupère l'adresse de retour et jump (RET)
ff -> fin du prog et retourne reg[0]
```

Bon, eh bien il semblerait que nous avons maintenant toutes les clés en main pour... s'amuser à coder un interpréteur, ainsi qu'un désassembleur !

Je passe sur les détails et je vous montre directement mon script. Cela allant de soi, la résolution ne se déroulant pas comme voulue, il a fallu aussi coder un débugger minimaliste \(affichage des registres, de la mémoire et des breakpoints\).

```python
from binascii import hexlify as tohex, unhexlify as unhex
import re, struct, sys
import aes as crypto # Tiré de https://github.com/p4-team/crypto-commons/blob/master/crypto_commons/symmetrical/aes.py

disassembly_mode = False
debug_mode = False

if len(sys.argv) > 1 and sys.argv[1] == '--disassembly':
  disassembly_mode = True
if len(sys.argv) > 1 and sys.argv[1] == '--debug':
  debug_mode = True
  disassembly_mode = True

decode = lambda u: (u[3] << 24) | (u[2] << 16) | (u[1] << 8) | u[0]

# Contient un dump du C généré par Ghidra pour la fonction principale
code = open('code.txt', 'r').read()

code = code.replace(' ', '').replace('\t', '').replace('\n', '')
s = re.findall(r'if\(type\_op\=\=((?:0x)?[0-9a-f]{1,3})\)\{(?:\_)?DAT\_003030[0-9a-f]{2}\=(?:\_)?DAT\_003030([0-9a-f]{2})\^0x([0-9a-f]{1,8})\;', code)

xor_opcodes = {}
for opcode, reg_i, magic in s:
  xor_opcodes[eval(opcode)] = ((int(reg_i, 16) - 0x40) // 4, int(magic, 16))

def dis(pc, ins):
  print('{:04x}'.format(pc) + ' ' + ins)

def read(text, offset):
  return decode(text[offset:offset + 4])

def read128(text, offset):
  return b''.join(bytes([text[offset + i]]) for i in range(16))

def write(text, offset, value):
  text[offset] = value & 0xff
  text[offset + 1] = (value >> 8) & 0xff
  text[offset + 2] = (value >> 16) & 0xff
  text[offset + 3] = (value >> 24) & 0xff

def write_bytes(text, offset, value):
  for i in range(len(value)):
    text[offset + i] = value[i]

def swap(x):
  return ((x & 0xff) << 24) | (((x >> 8) & 0xff) << 16) | (((x >> 16) & 0xff) << 8) | ((x >> 24) & 0xff)

text = "6e 18 b0 17 c9 f5 bf 08 74 00 00 0a 37 52 0a 00 98 95 1c 00 74 03 00 06 88 1c 00 08 74 00 00 0a 3f 9e 08 00 56 94 1c 00 ad 06 18 0c c6 0f 20 02 88 02 00 06 89 97 0c 00 7c 02 08 0c c9 73 1c 00 5b 00 19 0c 7c 00 00 06 fa 1b 0c 00 f7 01 10 00 a7 f3 1f 0c 4b 19 10 0c fc 00 00 06 5a 41 0c 00 09 95 1c 00 8e 08 18 0c 28 0b 26 02 e8 02 00 06 64 34 7b ff 05 0c 00 02 af b4 68 ff de 24 f2 1a 05 88 f4 0c fd 5c dd 12 c0 49 df 13 b9 82 d0 1d 5a 3a de 13 ea 8f d0 1d c1 2f dd 13 37 86 d0 1d c0 1f dc 13 02 c4 ef 1b 64 91 ed 12 0a 33 fe 1c db 8a e1 1d 40 81 e1 19 28 fe e7 08 c8 00 00 15 1a 46 f0 0c a4 00 00 18 be e2 e2 c3 b8 2b f2 c1 04 a2 f0 c0 29 de f2 cf c7 18 fd d2 c1 5b c0 c2 f5 30 e5 ce 4c ec e7 c9 0c e3 d2 c8 fc d7 d9 ce 08 b2 cf ce 38 e3 d2 d9 5e 3d 4c 3f 4e 65 ff 1a c0 85 f4 0c eb 87 dd 12 bf 15 da 13 f2 82 d0 1d c3 2c db 13 be 80 d0 1d f0 32 dc 13 1c 8d d0 1d 88 49 dd 13 6f 26 ef 1b 54 13 ed 12 1f ad fe 1c cc 8d e1 1d d8 80 e1 19 23 f2 e7 08 48 01 00 15 44 44 f0 0c 24 01 00 18 11 07 a3 d4 ab bd a5 d8 54 f2 b3 d4 54 bb 33 d6 44 b0 93 d6 66 8d 83 d4 7a 9c 86 df a5 59 f7 d5 03 a0 82 d4 0d b4 86 df d6 f6 80 d7 21 2b 96 db 27 b5 92 dc 25 b3 c3 dd fd b3 c3 cc 75 78 f3 d4 97 b8 f6 d8 3a f3 83 d4 c0 13 94 d4 9b f2 90 ca d2 81 f3 d4 35 bf f7 d8 39 99 85 d4 37 b8 82 d8 b9 e4 94 d4 51 ba 96 d8 50 f4 90 ca 9e 13 f3 d4 19 bd f0 d8 51 33 85 d4 aa be 82 d8 dd 87 94 d4 27 be 97 d8 53 fc 90 ca 7b e7 f3 d4 15 b4 f1 d8 b5 e9 83 d4 63 b1 80 d8 35 d9 94 d4 a6 bc 90 d8 20 fc 90 ca f1 b8 f3 d4 c0 bd f2 d8 41 b3 85 d4 cb 4c 94 d4 d9 b6 91 d8 d1 f0 90 ca 83 17 f2 d4 b7 87 85 d4 e6 65 94 d4 36 b3 92 d8 ff f9 90 ca 31 7c 34 db 6d b3 31 dc 89 b0 c3 dd f9 b3 c3 cc 83 ee 5a 2a 34 f0 0f 0f 85 eb 02 0f 7f 82 0a 0f 44 7d 00 0f 9a 88 03 0f 1a ba 0f 0f 8b 89 0f 0f f4 2d 09 0f 97 0a 08 0f 66 55 0f 0f b3 23 0c 0f fb d6 0b 0f 33 83 09 0f 3f 94 0a 0f e3 c1 00 0f 5f c8 00 0f 88 d4 07 0f 23 5c 06 0f 43 de 0e 0f 25 fa af 62 7c 94 2c cf 8d a5 9c bc 67 70 de f4 c6 7e 70 01 e2 0c 70 08 98 02 00 0a e4 02 00 18 c5 0c 60 02 9b 85 37 00 54 65 36 0b 58 d6 30 0e e7 50 32 13 4b f6 3f 11 9c 4d 46 00 a3 a9 42 0b a6 06 41 11 7e 8a 41 0b f5 ff 54 01 0e 42 53 12 65 92 45 03 57 e2 69 0f ac 0e 61 08 9c 02 00 0a 7c ca 07 0f 99 f1 25 0f 88 02 00 06 fe 32 5b fe e8 59 fd 1a 2f 83 f4 0c 27 b8 dd 12 b0 a8 da 13 36 82 d0 1d 6b bc db 13 b5 84 d0 1d 28 cb dc 13 de 88 d0 1d 39 d2 dd 13 37 3d ef 1b e5 59 ed 12 0c 7d fe 1c 5e 89 e1 1d 74 8f e1 19 c9 f6 e7 08 34 03 00 15 16 4a f0 0c 10 03 00 18 9f bb fc df 30 78 8c dd 32 dc 9d dd b8 dd 8f d6 ad 2c 9f d6 da 35 88 dc 59 b0 99 dc 14 fe 89 da c6 b8 cc d7 81 24 fa d2 f9 6a fe da 92 b8 cc d7 56 ae cc df da b8 cc c5 dd b1 cc df e5 79 c6 23 36 01 30 02 01 c9 20 00 0a 27 23 0b 5f 56 22 01 1c 09 20 08 f0 03 00 09 af 99 23 08 a4 03 00 15 89 09 23 08 f8 03 00 14 7c 08 23 17 b8 03 00 18 68 67 26 08 f8 03 00 15 3e 17 26 08 f8 03 00 14 f9 73 25 17 3a 47 43 00 25 22 40 11 a4 1c 40 08 d4 03 00 09 b5 0c 21 0e 86 93 52 00 e8 03 00 18 29 d6 25 12 59 80 43 00 55 19 40 19 b6 02 41 0b c3 39 42 03 d7 54 35 0f 78 03 00 18 1b 13 00 02 fc 03 00 18 dc 00 00 02 a0 a1 31 fe"
text = [int(x, 16) for x in text.split(' ')]

reg = [0] * 16

if debug_mode or not disassembly_mode:
  username = input('Username: ').encode()
  serial = input('Serial: ').encode()

  text += [0] * 0x400 # Heap

  write_bytes(text, 0x400 + 0x20 + 0x10, serial)

  reg[8] = 0x400 + 0x10 # Adresse username
  reg[9] = len(username)
  write_bytes(text, reg[8], username)

  reg[10] = 0x400 + 0x20 + (reg[9] & 0xfffffff0) # Adresse serial
  reg[11] = len(serial)
  write_bytes(text, reg[10], serial)

  reg[12] = reg[10] + 0x10 + (reg[11] & 0xfffffff0) # Adresse something

pc = 0
save_pc = []
jump_flag = 0

breakpoints = []
no_stop = False

while (debug_mode or not disassembly_mode) or (pc < len(text)):
  type_op = decode(text[pc:pc + 4])
  opcode = type_op >> 24
  k = (type_op >> 20) & 0xf
  m = (type_op >> 16) & 0xf
  p = (type_op >> 12) & 0xf
  q = type_op & 0xfff
  kmpq = type_op & 0xffffff
  imm = (m << 4) | p
  s = (type_op >> 0xc) & 0x1f

  if no_stop and pc in breakpoints:
    no_stop = False

  if debug_mode and not no_stop:
    print("Regs: %s" % (','.join('{:08x}'.format(_) for _ in reg)))
    print("Heap: %s" % tohex(bytes(text[0x400:0x400+0x300])))

  if opcode == 0x00:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] = reg[m]
    pc += 4

  elif opcode == 0x01:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov r%s, (char) [r%s]' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] = read(text, reg[m]) & 0xff
    pc += 4

  elif opcode == 0x02:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      reg[k] = imm
    pc += 4

  elif opcode == 0x03:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov [r%s], (char) r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      write_bytes(text, reg[k], bytes([reg[m] & 0xff]))
    pc += 4

  elif opcode == 0x04:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov [r%s], [r%s]' % (k, m))
    if debug_mode or not disassembly_mode:
      write(text, reg[k], read(text, reg[m]))
    pc += 4

  elif opcode == 0x05:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov [r%s], (char) %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      write_bytes(text, reg[k], bytes([reg[m] & 0xff]))
    pc += 4

  elif opcode == 0x06:
    if disassembly_mode and not no_stop:
      dis(pc, 'call %s' % ('{:04x}'.format(kmpq)))
      pc += 4
    if debug_mode or not disassembly_mode:
      save_pc.append(pc + 4)
      pc = kmpq

  elif opcode == 0x07:
    if disassembly_mode and not no_stop:
      dis(pc, 'cmp r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      jump_flag = reg[k] - reg[m]
    pc += 4

  elif opcode == 0x08:
    if disassembly_mode and not no_stop:
      dis(pc, 'cmp r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      jump_flag = reg[k] - imm
    pc += 4

  elif opcode == 0x09:
    if disassembly_mode and not no_stop:
      dis(pc, 'je %s' % ('{:04x}'.format(kmpq)))
      if not debug_mode:
        pc += 4
    if debug_mode or not disassembly_mode:
      if jump_flag == 0:
        pc = kmpq
      else:
        pc += 4

  elif opcode == 0x0a:
    if disassembly_mode and not no_stop:
      dis(pc, 'jne %s' % ('{:04x}'.format(kmpq)))
      if not debug_mode:
        pc += 4
    if debug_mode or not disassembly_mode:
      if jump_flag != 0:
        pc = kmpq
      else:
        pc += 4

  elif opcode == 0x0b:
    if disassembly_mode and not no_stop:
      dis(pc, 'add r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] + reg[m]) & 0xffffffff
    pc += 4

  elif opcode == 0x0c:
    if disassembly_mode and not no_stop:
      dis(pc, 'add r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] + imm) & 0xffffffff
    pc += 4

  elif opcode == 0x0d:
    if disassembly_mode and not no_stop:
      dis(pc, 'mul r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] * reg[m]) & 0xffffffff
    pc += 4

  elif opcode == 0x0e:
    if disassembly_mode and not no_stop:
      dis(pc, 'mul r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] * imm) & 0xffffffff
    pc += 4

  elif opcode == 0x0f:
    if disassembly_mode and not no_stop:
      dis(pc, 'inc r%s' % k)
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] + 1) & 0xffffffff
    pc += 4

  elif opcode == 0x10:
    if disassembly_mode and not no_stop:
      dis(pc, 'mod r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] %= reg[m]
    pc += 4

  elif opcode == 0x11:
    if disassembly_mode and not no_stop:
      dis(pc, 'mod r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      reg[k] %= imm
    pc += 4

  elif opcode == 0x12:
    if disassembly_mode and not no_stop:
      dis(pc, 'xor r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] ^= reg[m]
    pc += 4

  elif opcode == 0x13:
    if disassembly_mode and not no_stop:
      dis(pc, 'xor r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      reg[k] ^= imm
    pc += 4

  elif opcode == 0x14:
    if disassembly_mode and not no_stop:
      dis(pc, 'jl %s' % ('{:04x}'.format(kmpq)))
      if not debug_mode:
        pc += 4
    if debug_mode or not disassembly_mode:
      if jump_flag < 0:
        pc = kmpq
      else:
        pc += 4

  elif opcode == 0x15:
    if disassembly_mode and not no_stop:
      dis(pc, 'jg %s' % ('{:04x}'.format(kmpq)))
      if not debug_mode:
        pc += 4
    if debug_mode or not disassembly_mode:
      if jump_flag > 0:
        pc = kmpq
      else:
        pc += 4

  elif opcode == 0x16:
    if disassembly_mode and not no_stop:
      dis(pc, 'sub r%s, r%s' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] - reg[m]) % 2**32
    pc += 4

  elif opcode == 0x17:
    if disassembly_mode and not no_stop:
      dis(pc, 'sub r%s, %s' % (k, imm))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] - imm) % 2**32
    pc += 4

  elif opcode == 0x18:
    if disassembly_mode and not no_stop:
      dis(pc, 'jmp %s' % ('{:04x}'.format(kmpq)))
      pc += 4
    if debug_mode or not disassembly_mode:
      pc = kmpq

  elif opcode == 0x19:
    if disassembly_mode and not no_stop:
      dis(pc, 'shr r%s, %s' % (k, s))
    if debug_mode or not disassembly_mode:
      reg[k] >>= s
    pc += 4

  elif opcode == 0x1a:
    if disassembly_mode and not no_stop:
      dis(pc, 'loadpc r%s' % k)
    if debug_mode or not disassembly_mode:
      reg[k] = pc + 4
    pc += 4

  elif opcode == 0x1b:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov r%s, swap([r%s])' % (k, m))
    if debug_mode or not disassembly_mode:
      reg[k] = swap(read(text, reg[m]))
    pc += 4

  elif opcode == 0x1c:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov [r%s], swap(r%s)' % (k, m))
    if debug_mode or not disassembly_mode:
      write(text, reg[k], swap(reg[m]))
    pc += 4

  elif opcode == 0x1d:
    if disassembly_mode and not no_stop:
      dis(pc, 'shl r%s, %s' % (k, s))
    if debug_mode or not disassembly_mode:
      reg[k] = (reg[k] << s) & 0xffffffff
    pc += 4

  elif opcode == 0x1e:
    if disassembly_mode and not no_stop:
      dis(pc, 'mov [r%s], aes([r%s], [r%s])' % (k, m, p))
    if debug_mode or not disassembly_mode:
      cipher = crypto.AES()
      write_bytes(text, reg[k], cipher.AESENC(read128(text, reg[m]), read128(text, reg[p])))
    pc += 4

  elif opcode in xor_opcodes.keys():
    reg_i, value = xor_opcodes[opcode]
    if disassembly_mode and not no_stop:
      dis(pc, 'xor r%s, %s' % (reg_i, hex(value)))
    if debug_mode or not disassembly_mode:
      reg[reg_i] ^= value
    pc += 4

  elif opcode == 0xfe:
    if disassembly_mode and not no_stop:
      dis(pc, 'ret\n')
      pc += 4
    if debug_mode or not disassembly_mode:
      pc = save_pc.pop()

  elif opcode == 0xff:
    if disassembly_mode and not no_stop:
      dis(pc, 'end\n')
      pc += 4
    if debug_mode or not disassembly_mode:
      break

  else:
    print("[-] %s: opcode %s not supported" % (pc, hex(opcode)))
    break

  if debug_mode and not no_stop:
    while True:
      command = input('> ')
      if command == '' or command == 'n':
        break
      elif command == 'c':
        no_stop = True
        break
      elif command[:2] == 'b ':
        breakpoints.append(int(command[2:], 16))
      else:
        print('Unknown command')

if not disassembly_mode or debug_mode:
  print('[+] Program ended with %s' % reg[0])
```

Voici le code désassemblé généré :

```text
0000 sub r11, 1
0004 cmp r11, 255
0008 jne 0074
000c mov r0, r10
0010 mov r1, r12
0014 call 0374
0018 cmp r0, 1
001c jne 0074
0020 mov r0, r8
0024 mov r1, r12
0028 add r1, 128
002c mov r2, 0
0030 call 0288
0034 mov r0, r12
0038 add r0, 128
003c mov r1, r12
0040 add r1, 144
0044 call 007c
0048 mov r0, r12
004c mov r1, r0
0050 add r1, 255
0054 add r1, 1
0058 call 00fc
005c mov r0, r12
0060 mov r1, r12
0064 add r1, 128
0068 mov r2, 96
006c call 02e8
0070 end

0074 mov r0, 0
0078 end

007c loadpc r15
0080 add r15, 72
0084 xor r13, r13
0088 xor r13, 244
008c shl r13, 8
0090 xor r13, 227
0094 shl r13, 8
0098 xor r13, 210
009c shl r13, 8
00a0 xor r13, 193
00a4 mov r14, swap([r15])
00a8 xor r14, r13
00ac mov [r15], swap(r14)
00b0 shl r14, 24
00b4 shr r14, 24
00b8 cmp r14, 127
00bc jg 00c8
00c0 add r15, 4
00c4 jmp 00a4
00c8 xor r12, 0x4110a870
00cc xor r11, 0xe2c7c3c3
00d0 xor r3, 0x3a7ac323
00d4 xor r0, 0x92201356
00d8 xor r10, 0x2934e85a
00dc xor r9, 0x93048f8b
00e0 xor r13, 0xe46099e2
00e4 xor r14, 0xd6632aca
00e8 xor r4, 0xd3bda74e
00ec xor r13, 0xe46099e2
00f0 xor r13, 0xe46099e2
00f4 xor r14, 0xbfb56256
00f8 xor r3, 0xf5acad7d
00fc loadpc r15
0100 add r15, 72
0104 xor r13, r13
0108 xor r13, 161
010c shl r13, 8
0110 xor r13, 178
0114 shl r13, 8
0118 xor r13, 195
011c shl r13, 8
0120 xor r13, 212
0124 mov r14, swap([r15])
0128 xor r14, r13
012c mov [r15], swap(r14)
0130 shl r14, 24
0134 shr r14, 24
0138 cmp r14, 127
013c jg 0148
0140 add r15, 4
0144 jmp 0124
0148 xor r9, 0x93da34fd
014c xor r2, 0xd24eba88
0150 xor r9, 0x93da34fd
0154 xor r1, 0x71e85cfb
0158 xor r1, 0x71e85cfb
015c xor r9, 0x93da34fd
0160 xor r7, 0xb0f84472
0164 xor r8, 0xfcb4cd4a
0168 xor r9, 0x93da34fd
016c xor r7, 0xb0f84472
0170 xor r6, 0xf71a0cab
0174 xor r0, 0xaca57ad
0178 xor r13, 0xd05cd042
017c xor r5, 0xe4573279
0180 xor r3, 0x19f0505b
0184 xor r9, 0x93da34fd
0188 xor r2, 0xd24eba88
018c xor r9, 0x93da34fd
0190 xor r9, 0x93da34fd
0194 xor r10, 0xbc777df5
0198 xor r9, 0x93da34fd
019c xor r2, 0xd24eba88
01a0 xor r9, 0x93da34fd
01a4 xor r2, 0xd24eba88
01a8 xor r9, 0x93da34fd
01ac xor r2, 0xd24eba88
01b0 xor r10, 0xbc777df5
01b4 xor r9, 0x93da34fd
01b8 xor r2, 0xd24eba88
01bc xor r9, 0x93da34fd
01c0 xor r2, 0xd24eba88
01c4 xor r9, 0x93da34fd
01c8 xor r2, 0xd24eba88
01cc xor r10, 0xbc777df5
01d0 xor r9, 0x93da34fd
01d4 xor r2, 0xd24eba88
01d8 xor r9, 0x93da34fd
01dc xor r2, 0xd24eba88
01e0 xor r9, 0x93da34fd
01e4 xor r2, 0xd24eba88
01e8 xor r10, 0xbc777df5
01ec xor r9, 0x93da34fd
01f0 xor r2, 0xd24eba88
01f4 xor r9, 0x93da34fd
01f8 xor r9, 0x93da34fd
01fc xor r2, 0xd24eba88
0200 xor r10, 0xbc777df5
0204 xor r9, 0x93da34fd
0208 xor r9, 0x93da34fd
020c xor r9, 0x93da34fd
0210 xor r2, 0xd24eba88
0214 xor r10, 0xbc777df5
0218 xor r0, 0xaca57ad
021c xor r13, 0xd05cd042
0220 xor r5, 0xe4573279
0224 xor r3, 0x19f0505b
0228 xor r0, 0x480035e4
022c inc r0
0230 inc r0
0234 inc r0
0238 inc r0
023c inc r0
0240 inc r0
0244 inc r0
0248 inc r0
024c inc r0
0250 inc r0
0254 inc r0
0258 inc r0
025c inc r0
0260 inc r0
0264 inc r0
0268 inc r0
026c inc r0
0270 inc r0
0274 inc r0
0278 xor r6, 0x7e0233a2
027c xor r0, 0x92201356
0280 xor r6, 0x66601391
0284 xor r15, 0x727c2426
0288 mov r7, (char) [r0]
028c cmp r7, 0
0290 jne 0298
0294 jmp 02e4
0298 mov r6, 0
029c mov r3, r7
02a0 add r3, r6
02a4 mul r3, 13
02a8 xor r3, 37
02ac mod r3, 255
02b0 mov r4, r6
02b4 add r4, r2
02b8 mod r4, 16
02bc add r4, r1
02c0 mov r5, (char) [r4]
02c4 xor r5, r3
02c8 mov [r4], (char) r5
02cc inc r6
02d0 cmp r6, 16
02d4 jne 029c
02d8 inc r0
02dc inc r2
02e0 call 0288
02e4 ret

02e8 loadpc r15
02ec add r15, 72
02f0 xor r13, r13
02f4 xor r13, 170
02f8 shl r13, 8
02fc xor r13, 187
0300 shl r13, 8
0304 xor r13, 204
0308 shl r13, 8
030c xor r13, 221
0310 mov r14, swap([r15])
0314 xor r14, r13
0318 mov [r15], swap(r14)
031c shl r14, 24
0320 shr r14, 24
0324 cmp r14, 127
0328 jg 0334
032c add r15, 4
0330 jmp 0310
0334 xor r7, 0xb0f84472
0338 xor r5, 0xe4573279
033c xor r5, 0xe4573279
0340 xor r1, 0x71e85cfb
0344 xor r1, 0x71e85cfb
0348 xor r13, 0xd05cd042
034c xor r13, 0xd05cd042
0350 xor r14, 0x2802f673
0354 xor r6, 0xf71a0cab
0358 xor r10, 0x2934e85a
035c xor r14, 0x2802f673
0360 xor r6, 0xf71a0cab
0364 xor r7, 0xb0f84472
0368 xor r5, 0xb1653a57
036c xor r7, 0xb0f84472
0370 xor r7, 0x8bb5b038
0374 mov r3, 0
0378 mov r2, r0
037c add r2, r3
0380 mov r2, (char) [r2]
0384 cmp r2, 0
0388 je 03f0
038c cmp r2, 57
0390 jg 03a4
0394 cmp r2, 48
0398 jl 03f8
039c sub r2, 48
03a0 jmp 03b8
03a4 cmp r2, 102
03a8 jg 03f8
03ac cmp r2, 97
03b0 jl 03f8
03b4 sub r2, 87
03b8 mov r4, r3
03bc mod r4, 2
03c0 cmp r4, 1
03c4 je 03d4
03c8 mul r2, 16
03cc mov r5, r2
03d0 jmp 03e8
03d4 xor r2, r5
03d8 mov r4, r3
03dc shr r4, 1
03e0 add r4, r1
03e4 mov [r4], (char) r2
03e8 inc r3
03ec jmp 0378
03f0 mov r0, 1
03f4 jmp 03fc
03f8 mov r0, 0
03fc ret
```

On peut voir qu'il y a des zones étranges où les fameuses opérations XOR sont répétées sans aucun sens. C'est là que j'ai tiqué : **ces instructions ne servent à rien** dans la logique du programme. Elles sont en réalité ici uniquement à des fins d'obfuscation. Prenons par exemple cette routine :

```text
02e8 loadpc r15
02ec add r15, 72
02f0 xor r13, r13
02f4 xor r13, 170
02f8 shl r13, 8
02fc xor r13, 187
0300 shl r13, 8
0304 xor r13, 204
0308 shl r13, 8
030c xor r13, 221
0310 mov r14, swap([r15])
0314 xor r14, r13
0318 mov [r15], swap(r14)
031c shl r14, 24
0320 shr r14, 24
0324 cmp r14, 127
0328 jg 0334
032c add r15, 4
0330 jmp 0310
0334 xor r7, 0xb0f84472
0338 xor r5, 0xe4573279
033c xor r5, 0xe4573279
0340 xor r1, 0x71e85cfb
0344 xor r1, 0x71e85cfb
0348 xor r13, 0xd05cd042
034c xor r13, 0xd05cd042
0350 xor r14, 0x2802f673
0354 xor r6, 0xf71a0cab
0358 xor r10, 0x2934e85a
035c xor r14, 0x2802f673
0360 xor r6, 0xf71a0cab
0364 xor r7, 0xb0f84472
0368 xor r5, 0xb1653a57
036c xor r7, 0xb0f84472
0370 xor r7, 0x8bb5b038
```

Ce qu'on fait ici, c'est qu'on charge la valeur de PC+4 dans r15 et on lui ajoute 72 : r15 contient l'adresse 0x0334. Puis une boucle va venir **déchiffrer** ce tableau de mots à l'aide de swaps et de xors. Difficile donc d'analyser directement ce code de façon statique. Heureusement, je peux maintenant poser des points d'arrêts qui me permettront de suivre le comportement réel du programme en direct !

Aperçu d'un début de session de debug :

![](https://i.imgur.com/soksHRa.png)

Le "main" du programme se décompose en plusieurs calls. Le premier permet de s'assurer que la longueur du serial est de 256 octets. Le deuxième n'est pas très difficile à analyser ; il s'assure que le serial soit en fait de l'hexadécimal et le décode, en le stockant un peu plus loin dans la mémoire. Les trois calls suivants sont des routines obfusquées.

Je passe les étapes de reconstitution de la logique des routines, c'était un travail assez fastidieux car des erreurs pouvaient se cacher à tous les niveaux et n'étaient pas toujours évidentes à corriger \(mauvaise compréhension du binaire et donc de la logique de certaines instructions de l'ISA, erreur d'implémentation, mauvaise compréhension/visualisation des routines...\).

Voici globalement les étapes du programme :

* Le serial doit faire 256 caractères hexadécimaux, puis est décodé
* On dérive une clé de 96 octets à partir de notre username, à l'aide de boucles de multiplications et de xors
* On effectue 32 itérations d'une série de tours de chiffrement AES de différents blocs du serial, dont les clés sont aussi des blocs du serial
* Le résultat obtenu est comparé à la clé de 96 octets dérivée de l'username

Première remarque : y'a 32 octets qui partent dans le vent. Du coup, on peut générer plein de clés valides en paddant le buffer de 96 octets avec des octets arbitraires \(ça tombe bien, le serveur demande à chaque fois deux clés valides pour l'username donné !\)

Deuxième remarque : il faut faire très attention à l'ordre dans lesquels sont faits les _aesenc_ parce que le serial se réécrit par dessus à chaque itération, et il faut le prendre en compte pour l'algo inverse.

Ceci étant dit, il ne reste plus qu'à coder le fameux keygen.

```python
from binascii import unhexlify as unhex, hexlify as tohex
from pwn import *
import aes as crypto

def aesd(a, b):
  aes = crypto.AES()
  return aes.AESDEC(a, b)

def write(text, offset, value):
  for i in range(len(value)):
    text[offset + i] = value[i]

def invert(serial):
  for i in range(32):
    old_serial = serial[:16][:]
    write(serial, 0, aesd(serial[16:16+16], serial[96:96+16]))
    write(serial, 16, aesd(serial[32:32+16], serial[96:96+16]))
    old_serial48 = serial[48:48+16][:]
    write(serial, 48, aesd(serial[64:64+16], serial[112:112+16]))
    write(serial, 32, aesd(old_serial48, serial[48:48+16]))
    write(serial, 64, aesd(serial[80:80+16], serial[112:112+16]))
    write(serial, 80, aesd(old_serial, serial[:16]))

def keygen(username, random=b'\x00'):
  buffer = [0] * 96
  for i in range(len(username)):
    for c in range(16):
      buffer[(i + c) % 16] ^= (((username[i] + c) * 13) ^ 37) % 255
  for i in range(5):
    for j in range(16):
      buffer[(i + 1) * 16 + j] = (((buffer[i * 16 + j] * 3)) ^ 0xff) % 256
  buffer += [ord(random)] * (128 - 96)
  invert(buffer)
  key = tohex(bytes(buffer))
  return key

r = remote('challenges2.france-cybersecurity-challenge.fr', 3000)

while True:
  msg = r.recv(4096)
  print(msg)
  if b'>>> ' not in msg:
    r.recv(4096)
  username = msg.split(b': ')[1].split(b'\n')[0]
  key1 = keygen(username)
  key2 = keygen(username, random=b'\x01')
  r.send(key1 + b'\n')
  print(r.recv(4096))
  r.send(key2 + b'\n')
```

Résultat :

```text
$ python keygenkoo.py                        
[+] Opening connection to challenges2.france-cybersecurity-challenge.fr on port 30
00: Done
b'Give me two valid serials for username: Jame Feldkamp\n>>> '
b'Give me two valid serials for username: Billy Natalie\n>>> '
b'Give me two valid serials for username: Charlotte Adams\n>>> '
b'Give me two valid serials for username: Nickole Muraoka\n>>> '
b'Give me two valid serials for username: Jacob Link\n>>> '
b'Give me two valid serials for username: Stephanie Williams\n>>> '
b'Give me two valid serials for username: Chelsey Hatch\n>>> '
b'Give me two valid serials for username: Bernice Ott\n>>> '
b'Give me two valid serials for username: Richard Harvey\n>>> '
[...]
b'Give me two valid serials for username: hjg48Itso7JNDjjjWVoOI\n>>> '
b'Well done! Here is the flag: FCSC{38b1135bc705b2f1464da07f3052611a91f26a957647a24ceb9607646a19c2dc}\n'
```

Enjoy!

