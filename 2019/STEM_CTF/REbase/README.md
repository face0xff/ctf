# REbase

Binary RE, 400 points

## Description

*You receive an ELF binary which you must unlock with a key. Find the key and it will contain your flag.*

## Solution

So I read writeups about solving the challenge the "correct" way and I wanted to share my own solution which does not require any reverse engineering.

We are given a 64-bit ELF [rebase](rebase). Let's see what's up with it:

```console
╭─face0xff@aniesu-chan ~/stemctf  
╰─$ ./rebase
Usage: ./REbase flag
╭─face0xff@aniesu-chan ~/stemctf  
╰─$ ./rebase zzzzzz
6
tfh5tfh5
ZXFWtmKgDZCyrmC5B+CiVfsyXUCQVfsyZRFzDU4yX2YCD/F5Ih8=
Try Again :(
╭─face0xff@aniesu-chan ~/stemctf  
╰─$ ./rebase MCA{test}
9
ZXFWt2Kse2K8
ZXFWtmKgDZCyrmC5B+CiVfsyXUCQVfsyZRFzDU4yX2YCD/F5Ih8=
Try Again :(
```

So the binary asks for a flag in argument, and outputs
* the length of the flag we provided
* some kind of encrypted version of the flag we provided
* something that is probably the encrypted version of the actual flag.

We can also notice starting our input with `MCA{` makes the first characters of the two ciphers match up. Also, it looks like base64 but 

With some groping around, we can find the password without actually reverse engineering the binary. It is just a bit long to do it manually (but still totally doable). I wrote a script to automatize the process ([rebase.py](rebase.py)).

I am not entirely sure about my script because the farthest it goes only yields this portion of the flag: `MCA{Th15_wUz_EaZy_Pe@Zy_L3m0n_SqU33z`. We can easily deduce the true flag from there, though.

```console
╭─face0xff@aniesu-chan ~/stemctf  
╰─$ ./rebase MCA{Th15_wUz_EaZy_Pe@Zy_L3m0n_SqU33zy}
38
ZXFWtmKgDZCyrmC5B+CiVfsyXUCQVfsyZRFzDU4yX2YCD/F5Ih8=
ZXFWtmKgDZCyrmC5B+CiVfsyXUCQVfsyZRFzDU4yX2YCD/F5Ih8=
Congratulations!
```

Enjoy!
