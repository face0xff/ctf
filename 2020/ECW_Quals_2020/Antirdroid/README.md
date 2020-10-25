# Antirdroid

## Reverse Engineering / 450 points / 14 solves

### Introduction

**Antirdroid** was a fun Android reverse engineering challenge split in 3 steps. I am not that familiar with Android RE and especially with the specific tools for dynamic analysis and debugging, hence why after desperately and unsuccessfully trying to patch the application and make it work on an emulator I decided to give up. I only believe in one god, and its name is **static analysis**.

### Description

*In this challenge, you need to find three flags.*

*Each flag starts with ECW_ and will be displayed in the Android logcat together with a tag indicating the flag number.*

**antirdroid.apk**

### Part 1

In order to decompile the APK, I used [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer).

![](https://i.imgur.com/G3zNtNy.png)

In the `assets/` directory, we can see a file `mnist.tflite` and 12 files `mnist-letter.tflite` with `letter` ranging from `a` to `l`.

In the `com/example/ecw` directory lie two classes named `MainActivity.class` and `FinishActivity.class`.

`MainActivity` contains a few interesting methods:

```java=
public void onActivityResult(int var1, int var2, Intent var3) {
      super.onActivityResult(var1, var2, var3);
      if (var1 == 12 && var2 == 10) {
         String var7;
         label15: {
            LinearLayout var4 = (LinearLayout)this.findViewById(id.base);
            TextView var5 = new TextView(this);
            var5.setText("Congratulation: the final flag is:");
            var4.addView(var5);
            if (var3 != null) {
               var7 = var3.getStringExtra("end_flag");
               if (var7 != null) {
                  break label15;
               }
            }

            var7 = "ERROR, this is not the flag";
         }

         LinearLayout var6 = (LinearLayout)this.findViewById(id.base);
         TextView var8 = new TextView(this);
         var8.setText(var7);
         var6.addView(var8);
         Log.i("FLAG 3", var7);
      }

   }
```

This seems to log the final flag for the third step, so we'll save this for later.

```java=
public void onCreate(Bundle var1) {
      super.onCreate(var1);
      this.setContentView(2131361821);
      ClassLoaderSharing.INSTANCE.setLoader(this.getClassLoader());
      Iterator var69 = CollectionsKt__CollectionsKt.listOf(new String[]{"step_1", "step_2", "step_3"}).iterator();

      while(var69.hasNext()) {
         String var2 = (String)var69.next();

         Field var3;
         FileOutputStream var70;
         boolean var10001;
         try {
            var3 = c.class.getField(var2);
            StringBuilder var4 = new StringBuilder();
            var4.append(var2);
            var4.append(".dex");
            var70 = this.openFileOutput(var4.toString(), 0);
         } catch (Exception var68) {
            var10001 = false;
            continue;
         }
         
         [...]
         
         var71 = this.getResources().openRawResource(var3.getInt((Object)null));

         [...]
```

This seems to read files called `step_1.dex`, `step_2.dex` and `step_3.dex` from *raw resources*. Speaking of which, if you unzip the apk and check in the `res/raw/` folder, you will find these files, but they do not look like valid dex files. Perhaps are they encrypted?

Let's take a look at `FinishActivity` now:

```java=
public final Object invoke() {
      Class var1 = this.b.getClass();
      String var2 = this.b.getSharedPreferences("flag", 0).getString("a", (String)null);
      if (var2 == null) {
         var2 = "fail";
      }

      IvParameterSpec var3 = new IvParameterSpec(new byte[]{-101, 105, -107, -118, -65, 117, -35, 92, -47, -112, -102, -76, 40, -21, 69, 93});
      SecretKeySpec var5 = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(var2.toCharArray(), new byte[]{56, -35, 119, -111, 71, 113, -83, 70, -119, 122, -92, 22, 124, 23, -83, 110}, 65536, 256)).getEncoded(), "AES");
      Cipher var4 = Cipher.getInstance("AES/CBC/PKCS7Padding");
      var4.init(2, var5, var3);
      ClassLoader var6 = ClassLoaderSharing.INSTANCE.getLoader();
      Class var7 = var1;
      if (var6 != null) {
         Class var8 = var6.loadClass(new String(var4.doFinal(Base64.decode("raTLFVkpCb4yP1YXsMdvqr2TjJSxtpiYA0yJLQ2UTPs=", 0)), Charsets.UTF_8));
         var7 = var1;
         if (var8 != null) {
            var7 = var8;
         }
      }

      return var7.getConstructor(Activity.class).newInstance(this.b);
   }
```

Definitely some interesting stuff going on here, we know for sure there's crypto involved now. Some base64 string is decoded then decrypted using AES CBC, but the key seems derived from a certain variable, that is the `a` field in a *shared preferences* object called `flag`. Shared preferences allow to read and save key/value pairs on device storage, which can also be used to keep a global state in the application. We understand that we'll probably get to this bit later in the challenge.

In the `d/c/a/d/` folder, there is an interesting `b.class` file:

```java=
public Object invoke(Object var1) {
      Cursor var288 = (Cursor)var1;
      IntRef var2 = this.c;
      int var3 = var2.element++;
      boolean var4 = false;
      if (var3 == 4) {
         if (this.b == null) {
            throw null;
         }

         Companion var289;
         label2364:
        
         var289 = Result.Companion;
         var1 = Result.constructor-impl(var288.getString(var288.getColumnIndex("data2")));

         Object var291 = var1;
         if (Result.isFailure-impl(var1)) {
            var291 = null;
         }

         String var290 = (String)var291;
         if (var290 != null) {
            MessageDigest var294 = MessageDigest.getInstance("MD5");
            var294.update(var290.getBytes(Charsets.UTF_8));
            Unit var301;
            if (Intrinsics.areEqual((new BigInteger(1, var294.digest())).toString(16), "b71985397688d6f1820685dde534981b")) {
               label2357: {
                  Exception var10000;
                  label2372: {

                     [...]

                     Cipher var7;
                     FileInputStream var8;
                     FileOutputStream var303;
                     MainActivity var306;
                     File var307;
                     
                     IvParameterSpec var299 = new IvParameterSpec(new byte[]{-101, 105, -107, -118, -65, 117, -35, 92, -47, -112, -102, -76, 40, -21, 69, 93});
                     SecretKeyFactory var300 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                     char[] var292 = var290.toCharArray();
                     PBEKeySpec var6 = new PBEKeySpec(var292, new byte[]{56, -35, 119, -111, 71, 113, -83, 70, -119, 122, -92, 22, 124, 23, -83, 110}, 65536, 256);
                     SecretKey var302 = var300.generateSecret(var6);
                     SecretKeySpec var293 = new SecretKeySpec(var302.getEncoded(), "AES");
                     Cipher var304 = Cipher.getInstance("AES/CBC/PKCS7Padding");
                     var304.init(2, var293, var299);
                     this.b.p = var304;
                     var306 = this.b;
                     var7 = this.b.p;
                     var290 = UUID.randomUUID().toString();
                     var307 = new File(var306.getFilesDir(), var290);
                     var8 = var306.openFileInput("step_1.dex");
                     var303 = var306.openFileOutput(var290, 0);

                     
                     byte[] var9;
                     var9 = new byte[4096];

                     while(true) {
                        var3 = var8.read(var9);
                        if (var3 > 0) {
                           byte[] var295;
                           if (var3 == 4096) {
                              var295 = var7.update(var9);
                           } else {
                              var295 = var7.doFinal(var9, 0, var3);
                           }
                           var303.write(var295);
                        }
                     }
                                       
                     [...]

                     label2376: {
                        int var10;
                        String var305;
                        byte[] var312;
                        Method[] var313;
                        try {
                           CloseableKt.closeFinally(var303, (Throwable)null);
                           if (!var307.exists()) {
                              break label2376;
                           }

                           PathClassLoader var308 = new PathClassLoader(var307.getAbsolutePath(), var306.getClassLoader());
                           byte[] var310 = this.b.p.doFinal(Base64.decode("j04vGcW35ZUg23JsqQ+/YA==", 0));
                           var305 = new String(var310, Charsets.UTF_8);
                           var307.getClass().getMethod(var305).invoke(var307);
                           byte[] var309 = this.b.p.doFinal(Base64.decode("WOtre8ObMy2nnFbqn2Kb6w==", 0));
                           String var311 = new String(var309, Charsets.UTF_8);
                           var291 = var308.loadClass(var311).newInstance();
                           var312 = this.b.p.doFinal(Base64.decode("J9vFCBjTjE6YoMI1wVDwjg==", 0));
                           var290 = new String(var312, Charsets.UTF_8);
                           var313 = var291.getClass().getDeclaredMethods();
                           var10 = var313.length;
                        } catch (Exception var273) {
                           var10000 = var273;
                           var10001 = false;
                           break label2372;
                        }

                        for(var3 = 0; var3 < var10; ++var3) {
                           Method var315 = var313[var3];

                           boolean var11;
                           label2295: {
                              label2294: {
                                 if (Intrinsics.areEqual(var315.getName(), var290) && Arrays.equals(var315.getParameterTypes(), new Class[]{Activity.class})) {
                                    break label2294;
                                 }

                                 var11 = false;
                                 break label2295;
                              }

                              var11 = true;
                           }

                           if (var11) {
                              try {
                                 var315.invoke(var291, this.b);
                                 Editor var314 = this.b.getSharedPreferences("flag", 0).edit();
                                 var312 = this.b.p.doFinal(Base64.decode("bjmQcWsAN3k8NxmaYYWvy6L+SDvu3ZlDFMSFvepIycxwZLgw5qGRB5ggJLHpDvW3", 0));
                                 var305 = new String(var312, Charsets.UTF_8);
                                 var314.putString("a", var305).apply();
                                 ((TextView)this.b.q.getValue()).setVisibility(8);
                                 break label2357;
                              } catch (Exception var271) {
                                 var10000 = var271;
                                 var10001 = false;
                                 break label2372;
                              }
                           }
                        }

                        try {
                           NoSuchElementException var316 = new NoSuchElementException("Array contains no element matching the predicate.");
                           throw var316;
                        } catch (Exception var266) {
                           var10000 = var266;
                           var10001 = false;
                           break label2372;
                        }
                     }

                     try {
                        FileNotFoundException var318 = new FileNotFoundException();
                        throw var318;
                     } catch (Exception var265) {
                        var10000 = var265;
                        var10001 = false;
                     }
                  }

                  Exception var317 = var10000;
                  var317.printStackTrace();
                  Toast.makeText(this.b, "Nice try", 0).show();
               }
            }

            var301 = Unit.INSTANCE;
         }

         var4 = true;
      }
      
      return var4;
}
```

I greatly pruned the code because there were a lot of try/catches and stuff that heavily impacted readability.

Here's what we can understand from this piece:

* Some string `var290` is hashed with MD5 and compared to `b71985397688d6f1820685dde534981b`
* `var290` is used to derived an AES key
* The file `step_1.dex` is decrypted with this key
* A few ciphertexts are decrypted too (in base64: `j04vGcW35ZUg23JsqQ+/YA==`, `WOtre8ObMy2nnFbqn2Kb6w==` and `J9vFCBjTjE6YoMI1wVDwjg==`)
* A longer ciphertext (`bjmQcWsAN3k8NxmaYYWvy6L+SDvu3ZlDFMSFvepIycxwZLgw5qGRB5ggJLHpDvW3`) is decrypted and put in the `a` field of the `flag` shared preferences object

All of this is quite approximative, but it doesn't matter; it's enough to make progress.

The md5 reverses to "jean". I found an implementation of PBKDF2WithHmacSHA256 in Python, which I used to decrypt all the ciphertexts:

```python=
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from base64 import b64decode

salt = [56, -35, 119, -111, 71, 113, -83, 70, -119, 122, -92, 22, 124, 23, -83, 110]
salt = list(map(lambda u: u % 256, salt))
salt = bytes(salt)

iv = [-101, 105, -107, -118, -65, 117, -35, 92, -47, -112, -102, -76, 40, -21, 69, 93]
iv = list(map(lambda u: u % 256, iv))
iv = bytes(iv)

def decrypt(blob, passwd):
  key = pbkdf2_hmac(
    hash_name='sha256', 
    password=passwd, 
    salt=salt, 
    iterations=65536, 
    dklen=32,
  )
  aes = AES.new(key, AES.MODE_CBC, iv)
  return aes.decrypt(blob)

C = """j04vGcW35ZUg23JsqQ+/YA==
WOtre8ObMy2nnFbqn2Kb6w==
J9vFCBjTjE6YoMI1wVDwjg==
bjmQcWsAN3k8NxmaYYWvy6L+SDvu3ZlDFMSFvepIycxwZLgw5qGRB5ggJLHpDvW3""".split('\n')

C = list(map(b64decode, C))

for c in C:
  print(decrypt(c, b'jean'))

open('step_1_decoded.dex', 'wb').write(
  decrypt(open('step_1.dex', 'rb'), b'jean')
)

```

Result:

```
b'delete\n\n\n\n\n\n\n\n\n\n'
b'a.a.a.c\t\t\t\t\t\t\t\t\t'
b'a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
b'LuKXSGlN5(%:Vk=alEbl9khIEPBo=mXu;hR7Ez7E\x08\x08\x08\x08\x08\x08\x08\x08'
```

Okay, so the first three plaintexts are not that interesting. Maybe the second one will be the path to the class in the next step. On the other hand, the fourth plaintext looks very interesting. It looks like some kind of key.

Now let's decompile the newly decrypted .dex file!

![](https://i.imgur.com/HoJwXge.png)

```java=
public final Thread a(@NotNull Activity var1) {
      SharedPreferences var2 = var1.getSharedPreferences("save", 0);
      var1.getSharedPreferences("flag", 0).edit().putString("w", "k").apply();
      Toast.makeText(var1, "You made it to step 1", 0).show();
      String var3 = var2.getString("pass1", (String)null);
      LinearLayout var4 = (LinearLayout)var1.findViewById(id.base);
      View var5 = View.inflate(var1, layout.check, (ViewGroup)null);
      Button var6 = (Button)var5.findViewById(id.validation);
      EditText var7 = (EditText)var5.findViewById(id.password);
      var7.setText(var3);
      var4.addView(var5);
      var6.setOnClickListener(new b(var7, var1, var2, this, var1));
      return ThreadsKt.thread$default(false, false, (ClassLoader)null, (String)null, 0, new a.a.a.c.c(var1), 31, (Object)null);
   }
```

Cool, we made it to step1. We can see some weird stuff going on with the `flag` shared preferences object: the value "k" is affected to the key "w"...

In `a/a/a/d.class`, we can see a few potential new ciphertexts:

```java=
public static final String a = "ZnoETjqJ0h3VUtdPQnzkWsqrDFtvsK4BQ+1NJGx38YHXq9QxUEmztU9CsN4vCTbI";
public static final String b = "tvEf77LVcQcHX2FtkIoSBQ==";
public static final String c = "TbQSB6aY7Ye++tVv84UPIA==";
public static final String d = "biPW3PPcH5wQHBNdE6eP2Pg4K9UAZT8guUhpNLV44RzWdYVT91LcP8WgtY+9QrUUKWfW0FIyKHVg3P7AKS9vIQ==";
public static final String e = "n/CG6W9Ilu8muE8UGJM29S/2JV4hw2O/IX8IPBartj7qvWP0MasL7ZujCyHYH1ERYd+NP+IzVaTuRwT+TbCoSA==";
public static final String f = "7wwCGcbnGp/EAusByZQYcYsxSfBxiEHP4GZPjsAHjGLYVryk6yS9xTo6GmF1J6Z6rDvp8XnuBCZ97DmURQx+lvAvrebYDXPEbiVOcSANTk4=";
public static final String g = "EIW2q6l3m0ZvO1G6+QgXDVqiFcGj5tDV9tEtCRHJ6ALV2bwYxBzUvY4S5LuERqdrqm4RGDU3xHXOJr6+buDwIg==";
```

In `a/a/a/e/c.class`, there's a new interesting piece of code:

```java=
if (b.a.a()) {
   String var28 = var1.getSharedPreferences("flag", 0).getString("a", "");
   if (var28 == null) {
      Intrinsics.throwNpe();
   }

   IvParameterSpec var25 = new IvParameterSpec(new byte[]{-101, 105, -107, -118, -65, 117, -35, 92, -47, -112, -102, -76, 40, -21, 69, 93});
   SecretKeySpec var34 = new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(var28.toCharArray(), new byte[]{56, -35, 119, -111, 71, 113, -83, 70, -119, 122, -92, 22, 124, 23, -83, 110}, 65536, 256)).getEncoded(), "AES");
   Cipher var29 = Cipher.getInstance("AES/CBC/PKCS7Padding");
   var29.init(2, var34, var25);
   b.a.a(var29);
}

List var30 = StringsKt.split$default(new String(b.a.a().doFinal(Base64.decode("7wwCGcbnGp/EAusByZQYcYsxSfBxiEHP4GZPjsAHjGLYVryk6yS9xTo6GmF1J6Z6rDvp8XnuBCZ97DmURQx+lvAvrebYDXPEbiVOcSANTk4=", 0)), Charsets.UTF_8), new String[]{"!"}, false, 0, 6, (Object)null);
ArrayList var26 = new ArrayList();
Iterator var31 = var30.iterator();
```

Looks like it's the same crypto as before, but with a different key which is the string contained in the `a` field of `flag`. Luckily, we might know what this key is. Let's try it out:

```python=
C = """ZnoETjqJ0h3VUtdPQnzkWsqrDFtvsK4BQ+1NJGx38YHXq9QxUEmztU9CsN4vCTbI
tvEf77LVcQcHX2FtkIoSBQ==
TbQSB6aY7Ye++tVv84UPIA==
biPW3PPcH5wQHBNdE6eP2Pg4K9UAZT8guUhpNLV44RzWdYVT91LcP8WgtY+9QrUUKWfW0FIyKHVg3P7AKS9vIQ==
n/CG6W9Ilu8muE8UGJM29S/2JV4hw2O/IX8IPBartj7qvWP0MasL7ZujCyHYH1ERYd+NP+IzVaTuRwT+TbCoSA==
7wwCGcbnGp/EAusByZQYcYsxSfBxiEHP4GZPjsAHjGLYVryk6yS9xTo6GmF1J6Z6rDvp8XnuBCZ97DmURQx+lvAvrebYDXPEbiVOcSANTk4=
EIW2q6l3m0ZvO1G6+QgXDVqiFcGj5tDV9tEtCRHJ6ALV2bwYxBzUvY4S5LuERqdrqm4RGDU3xHXOJr6+buDwIg==""".split('\n')

C = list(map(b64decode, C))

for c in C:
  print(decrypt(c, b'LuKXSGlN5(%:Vk=alEbl9khIEPBo=mXu;hR7Ez7E'))
```

Result:

```
b'\xf9\xd8\xbe\xe0O\x8bD\xdcL\x84\xb0X|\xd0\xac\xcc\x19\xcd\xd3V\xa6\xbd}\xc3"\x81\x8e\x08\xc0\xab8\xc7i?\x18\xadV\xff\xb3(6Tf\xf8?\xe3\xac\xdb'
b'\x01\xd8\x96X=\xd0\xb01_\x9dN\xc3\x16&\x0e\xa4'
b'\xe6\xe2\xf7KR\x18\xe5$kN\x802\xbf4\x1d('
b'45:*!3:s!42:b!43:j!31:1!7:d!44:M!28:9!0:p!5:o!18:_!24:5!50:O!\x03\x03\x03'
b'19:i!38:V!49:b!34:b!4:w!23:y!1:a!41:%!16:p!14:t!6:r!13:s!12:_!\x02\x02'
b"8:_!15:e!47:R!35:Z!46:'!51:7!25:B!11:r!26:<!48:C!10:o!27:S!33:r!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
b'22:p!40:V!20:s!2:s!17:1!21::!32:W!29:a!37:.!39:t!30:T!36:U!9:f!\x01'
```

The first three ciphertexts translated to garbage with incorrect PKCS padding, but the four last did yield quite interesting plaintexts.

I instantly had the intuition to split them on "!" and sort the "k:b" pairs by the "k" value:

```python=
q = """45:*!3:s!42:b!43:j!31:1!7:d!44:M!28:9!0:p!5:o!18:_!24:5!50:O!19:i!38:V!49:b!34:b!4:w!23:y!1:a!41:%!16:p!14:t!6:r!13:s!12:_!8:_!15:e!47:R!35:Z!46:'!51:7!25:B!11:r!26:<!48:C!10:o!27:S!33:r!22:p!40:V!20:s!2:s!17:1!21::!32:W!29:a!37:.!39:t!30:T!36:U!9:f"""
q = q.split('!')
Q = [0] * 100
for qq in q:
  if qq.count(':') == 2:
    ch = ':'
    offset = qq.split(':')[0]
  else:
    offset, ch = qq.split(':')
  Q[int(offset)] = ord(ch)

print(bytes(Q))
```

Result : `password_for_step1_is:py5B<S9aT1WrbZU.VtV%bjM*'RCbO7`

Really cool, what if we try this password as a key for the remaining ciphertexts that we weren't able to decrypt earlier?

```python=
C = """ZnoETjqJ0h3VUtdPQnzkWsqrDFtvsK4BQ+1NJGx38YHXq9QxUEmztU9CsN4vCTbI
tvEf77LVcQcHX2FtkIoSBQ==
TbQSB6aY7Ye++tVv84UPIA==""".split('\n')
C = list(map(b64decode, C))

K = b'py5B<S9aT1WrbZU.VtV%bjM*\'RCbO7'
for c in C:
  print(decrypt(c, K))
```

And here we have our first flag!

```
b'ECW_oe8%jXffkWul&#!V@tqB(:V%WP?JUKm@I(2KqIfv\x04\x04\x04\x04'
b'a.a.a.c\t\t\t\t\t\t\t\t\t'
b'a\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

### Part 2

If we try to decrypt `step_2.dex` with the last key (`py5B<S9aT1WrbZU.VtV%bjM*'RCbO7`), we do get a valid dex file again. Let's decompile it.

The `a/a/a/d.class` file contains three new ciphertexts, we're used to it at that point.

```java=
public static final String a = "5sxJURBMWadPV+Qfj2g/WFVWcaLbXoUxyXeiIvpa4pu1SjSj0nqneJeN0tNkKbJx";
public static final String b = "gkZ6pGuoDU6Lz5bc23Y/5ZfI9XPcJd/r1PRrsE1epqc=";
public static final String c = "rbfA5lkSHq0eL4dmwH4gHg==";
```

The `a/a/a/e.class` is the interesting part.

```java=
public final boolean a(@NotNull String var1) {
      boolean var2 = false;
      boolean var3 = var2;
      if (f.a(var1, 4, 0, 2, (Object)null) * f.a(var1, 6, 0, 2, (Object)null) == 4840) {
         var3 = var2;
         if ((char)(f.a(var1, 9, 0, 2, (Object)null) + f.a(var1, 14, 0, 2, (Object)null)) == 217) {
            var3 = var2;
            if (f.a(var1, 6, 0, 2, (Object)null) * f.a(var1, 8, 0, 2, (Object)null) == 9559) {
               var3 = var2;
               if ((char)(f.a(var1, 8, 0, 2, (Object)null) + f.a(var1, 13, 0, 2, (Object)null)) == 141) {
                  var3 = var2;
                  if (f.a(var1, 9, 0, 2, (Object)null) * f.a(var1, 7, 0, 2, (Object)null) == 10494) {
                     var3 = var2;
                     if (f.a(var1, 1, 0, 2, (Object)null) * f.a(var1, 2, 0, 2, (Object)null) == 5346) {
                        var3 = var2;
                        if (f.a(var1, 4, 0, 2, (Object)null) * f.a(var1, 0, 0, 2, (Object)null) == 3360) {
                           var3 = var2;
                           if ((char)(f.a(var1, 10, 0, 2, (Object)null) + f.a(var1, 2, 0, 2, (Object)null)) == 167) {
                              var3 = var2;
                              if (f.a(var1, 9, 0, 2, (Object)null) * f.a(var1, 13, 0, 2, (Object)null) == 6138) {
                                 var3 = var2;
                                 if ((char)(f.a(var1, 12, 0, 2, (Object)null) + f.a(var1, 14, 0, 2, (Object)null)) == 193) {
                                    var3 = var2;
                                    if (f.a(var1, 6, 0, 2, (Object)null) * f.a(var1, 3, 0, 2, (Object)null) == 13794) {
                                       var3 = var2;
                                       if (f.a(var1, 3, 0, 2, (Object)null) * f.a(var1, 10, 0, 2, (Object)null) == 9804) {
                                          var3 = var2;
                                          if (f.a(var1, 7, 0, 2, (Object)null) * f.a(var1, 0, 0, 2, (Object)null) == 8904) {
                                             var3 = var2;
                                             if ((char)(f.a(var1, 7, 0, 2, (Object)null) + f.a(var1, 14, 0, 2, (Object)null)) == 224) {
                                                var3 = var2;
                                                if ((char)(f.a(var1, 9, 0, 2, (Object)null) + f.a(var1, 13, 0, 2, (Object)null)) == 161) {
                                                   var3 = var2;
                                                   if (f.a(var1, 9, 0, 2, (Object)null) * f.a(var1, 14, 0, 2, (Object)null) == 11682) {
                                                      var3 = var2;
                                                      if ((char)(f.a(var1, 10, 0, 2, (Object)null) + f.a(var1, 13, 0, 2, (Object)null)) == 148) {
                                                         var3 = var2;
                                                         if ((char)(f.a(var1, 14, 0, 2, (Object)null) + f.a(var1, 5, 0, 2, (Object)null)) == 216) {
                                                            var3 = var2;
                                                            if ((char)(f.a(var1, 4, 0, 2, (Object)null) + f.a(var1, 6, 0, 2, (Object)null)) == 161) {
                                                               var3 = var2;
                                                               if ((char)(f.a(var1, 6, 0, 2, (Object)null) + f.a(var1, 2, 0, 2, (Object)null)) == 202) {
                                                                  var3 = var2;
                                                                  if (f.a(var1, 9, 0, 2, (Object)null) * f.a(var1, 8, 0, 2, (Object)null) == 7821) {
                                                                     var3 = var2;
                                                                     if (f.a(var1, 14, 0, 2, (Object)null) * f.a(var1, 5, 0, 2, (Object)null) == 11564) {
                                                                        var3 = var2;
                                                                        if (f.a(var1, 9, 0, 2, (Object)null) * f.a(var1, 4, 0, 2, (Object)null) == 3960) {
                                                                           var3 = var2;
                                                                           if ((char)(f.a(var1, 4, 0, 2, (Object)null) + f.a(var1, 8, 0, 2, (Object)null)) == 'w') {
                                                                              var3 = var2;
                                                                              if ((char)(f.a(var1, 6, 0, 2, (Object)null) + f.a(var1, 3, 0, 2, (Object)null)) == 235) {
                                                                                 var3 = var2;
                                                                                 if (f.a(var1, 6, 0, 2, (Object)null) * f.a(var1, 2, 0, 2, (Object)null) == 9801) {
                                                                                    var3 = var2;
                                                                                    if ((char)(f.a(var1, 0, 0, 2, (Object)null) + f.a(var1, 10, 0, 2, (Object)null)) == 170) {
                                                                                       var3 = var2;
                                                                                       if (f.a(var1, 7, 0, 2, (Object)null) * f.a(var1, 10, 0, 2, (Object)null) == 9116) {
                                                                                          var3 = var2;
                                                                                          if ((char)(f.a(var1, 7, 0, 2, (Object)null) + f.a(var1, 10, 0, 2, (Object)null)) == 192) {
                                                                                             var3 = var2;
                                                                                             if ((char)(f.a(var1, 6, 0, 2, (Object)null) + f.a(var1, 8, 0, 2, (Object)null)) == 200) {
                                                                                                var3 = var2;
                                                                                                if (f.a(var1, 11, 0, 2, (Object)null) * f.a(var1, 1, 0, 2, (Object)null) == 6468) {
                                                                                                   var3 = var2;
                                                                                                   if ((char)(f.a(var1, 9, 0, 2, (Object)null) + f.a(var1, 8, 0, 2, (Object)null)) == 178) {
                                                                                                      var3 = var2;
                                                                                                      if ((char)(f.a(var1, 2, 0, 2, (Object)null) + f.a(var1, 14, 0, 2, (Object)null)) == 199) {
                                                                                                         var3 = var2;
                                                                                                         if ((char)(f.a(var1, 7, 0, 2, (Object)null) + f.a(var1, 0, 0, 2, (Object)null)) == 190) {
                                                                                                            var3 = var2;
                                                                                                            if (f.a(var1, 8, 0, 2, (Object)null) * f.a(var1, 5, 0, 2, (Object)null) == 7742) {
                                                                                                               var3 = var2;
                                                                                                               if (f.a(var1, 15, 0, 2, (Object)null) * f.a(var1, 13, 0, 2, (Object)null) == 7316) {
                                                                                                                  var3 = var2;
                                                                                                                  if (f.a(var1, 10, 0, 2, (Object)null) * f.a(var1, 13, 0, 2, (Object)null) == 5332) {
                                                                                                                     var3 = var2;
                                                                                                                     if (f.a(var1, 8, 0, 2, (Object)null) * f.a(var1, 13, 0, 2, (Object)null) == 4898) {
                                                                                                                        var3 = var2;
                                                                                                                        if ((char)(f.a(var1, 6, 0, 2, (Object)null) + f.a(var1, 14, 0, 2, (Object)null)) == 239) {
                                                                                                                           var3 = var2;
                                                                                                                           if ((char)(f.a(var1, 8, 0, 2, (Object)null) + f.a(var1, 5, 0, 2, (Object)null)) == 177) {
                                                                                                                              var3 = var2;
                                                                                                                              if (f.a(var1, 1, 0, 2, (Object)null) * f.a(var1, 4, 0, 2, (Object)null) == 2640) {
                                                                                                                                 var3 = var2;
                                                                                                                                 if ((char)(f.a(var1, 0, 0, 2, (Object)null) + f.a(var1, 3, 0, 2, (Object)null)) == 198) {
                                                                                                                                    var3 = var2;
                                                                                                                                    if ((char)(f.a(var1, 11, 0, 2, (Object)null) + f.a(var1, 1, 0, 2, (Object)null)) == 164) {
                                                                                                                                       var3 = var2;
                                                                                                                                       if (f.a(var1, 10, 0, 2, (Object)null) * f.a(var1, 2, 0, 2, (Object)null) == 6966) {
                                                                                                                                          var3 = var2;
                                                                                                                                          if (f.a(var1, 0, 0, 2, (Object)null) * f.a(var1, 3, 0, 2, (Object)null) == 9576) {
                                                                                                                                             var3 = var2;
                                                                                                                                             if (f.a(var1, 12, 0, 2, (Object)null) * f.a(var1, 14, 0, 2, (Object)null) == 8850) {
                                                                                                                                                var3 = var2;
                                                                                                                                                if (f.a(var1, 6, 0, 2, (Object)null) * f.a(var1, 14, 0, 2, (Object)null) == 14278) {
                                                                                                                                                   var3 = var2;
                                                                                                                                                   if (f.a(var1, 0, 0, 2, (Object)null) * f.a(var1, 10, 0, 2, (Object)null) == 7224) {
                                                                                                                                                      var3 = var2;
                                                                                                                                                      if (f.a(var1, 2, 0, 2, (Object)null) * f.a(var1, 14, 0, 2, (Object)null) == 9558) {
                                                                                                                                                         var3 = var2;
                                                                                                                                                         if ((char)(f.a(var1, 9, 0, 2, (Object)null) + f.a(var1, 7, 0, 2, (Object)null)) == 205) {
                                                                                                                                                            var3 = var2;
                                                                                                                                                            if ((char)(f.a(var1, 8, 0, 2, (Object)null) + f.a(var1, 0, 0, 2, (Object)null)) == 163) {
                                                                                                                                                               var3 = var2;
                                                                                                                                                               if ((char)(f.a(var1, 15, 0, 2, (Object)null) + f.a(var1, 13, 0, 2, (Object)null)) == 180) {
                                                                                                                                                                  var3 = var2;
                                                                                                                                                                  if ((char)(f.a(var1, 1, 0, 2, (Object)null) + f.a(var1, 4, 0, 2, (Object)null)) == 'j') {
                                                                                                                                                                     var3 = var2;
                                                                                                                                                                     if (f.a(var1, 8, 0, 2, (Object)null) * f.a(var1, 0, 0, 2, (Object)null) == 6636) {
                                                                                                                                                                        var3 = var2;
                                                                                                                                                                        if (f.a(var1, 4, 0, 2, (Object)null) * f.a(var1, 8, 0, 2, (Object)null) == 3160) {
                                                                                                                                                                           var3 = var2;
                                                                                                                                                                           if ((char)(f.a(var1, 4, 0, 2, (Object)null) + f.a(var1, 0, 0, 2, (Object)null)) == '|') {
                                                                                                                                                                              var3 = var2;
                                                                                                                                                                              if (f.a(var1, 7, 0, 2, (Object)null) * f.a(var1, 14, 0, 2, (Object)null) == 12508) {
                                                                                                                                                                                 var3 = var2;
                                                                                                                                                                                 if ((char)(f.a(var1, 3, 0, 2, (Object)null) + f.a(var1, 10, 0, 2, (Object)null)) == 200) {
                                                                                                                                                                                    var3 = var2;
                                                                                                                                                                                    if ((char)(f.a(var1, 9, 0, 2, (Object)null) + f.a(var1, 4, 0, 2, (Object)null)) == 139) {
                                                                                                                                                                                       var3 = var2;
                                                                                                                                                                                       if ((char)(f.a(var1, 1, 0, 2, (Object)null) + f.a(var1, 2, 0, 2, (Object)null)) == 147) {
                                                                                                                                                                                          var3 = true;
                                                                                                                                                                                       }
                                                                                                                                                                                    }
                                                                                                                                                                                 }
                                                                                                                                                                              }
                                                                                                                                                                           }
                                                                                                                                                                        }
                                                                                                                                                                     }
                                                                                                                                                                  }
                                                                                                                                                               }
                                                                                                                                                            }
                                                                                                                                                         }
                                                                                                                                                      }
                                                                                                                                                   }
                                                                                                                                                }
                                                                                                                                             }
                                                                                                                                          }
                                                                                                                                       }
                                                                                                                                    }
                                                                                                                                 }
                                                                                                                              }
                                                                                                                           }
                                                                                                                        }
                                                                                                                     }
                                                                                                                  }
                                                                                                               }
                                                                                                            }
                                                                                                         }
                                                                                                      }
                                                                                                   }
                                                                                                }
                                                                                             }
                                                                                          }
                                                                                       }
                                                                                    }
                                                                                 }
                                                                              }
                                                                           }
                                                                        }
                                                                     }
                                                                  }
                                                               }
                                                            }
                                                         }
                                                      }
                                                   }
                                                }
                                             }
                                          }
                                       }
                                    }
                                 }
                              }
                           }
                        }
                     }
                  }
               }
            }
         }
      }
      
      return var3;
   }
```

A huge pyramid of conditions on some string called `var1`!

Let's take a look at the first one:

```java
if (f.a(var1, 4, 0, 2) * f.a(var1, 6, 0, 2) == 4840)
```

I removed the "(Object)null" arguments which are probably useless decompilation artifacts. What does this `f.a` function do now? Let's take a look at the `f.class` file:

```java=
public static final int a(@NotNull String var0, int var1, int var2) {
  Character var3 = StringsKt.getOrNull(var0, var1);
  if (var3 != null) {
     var2 = var3;
  }

  return var2;
}
```

The Kotlin documentation says: *`getOrNull` returns a character at the given index or null if the index is out of bounds of this char sequence*.

Not sure about the extra arguments, but what's highly likely is we are isolating `var1[4]`, `var1[6]` and multiplying them.

I extracted the pyramid of if's in a text file, wrote a script to parse it and directly feed it into z3:

```python=
from z3 import *

dump = open('dump.txt', 'r').read().split('\n')[::2]
variables = [Int('k%s' % i) for i in range(16)]

V = []
V += [variables[i] >= 0 for i in range(16)]
V += [variables[i] < 256 for i in range(16)]

for line in dump:
  i1 = int(line.split(',')[1].replace(' ', ''))
  i2 = int(line.split(',')[5].replace(' ', ''))
  z = line.split('== ')[1].split(')')[0]
  if "'" in z:
    z = ord(z.replace("'", ''))
  else:
    z = int(z)
  op = line.split('l) ')[1].split(' ')[0]
  # print(i1, op, i2, z)
  if op == '+':
    V.append(variables[i1] + variables[i2] == z)
  if op == '*':
    V.append(variables[i1] * variables[i2] == z)
    
solve(V)
```

Output:

```
[k15 = 118,
 k14 = 118,
 k13 = 62,
 k12 = 75,
 k11 = 98,
 k10 = 86,
 k9 = 99,
 k8 = 79,
 k7 = 106,
 k6 = 121,
 k5 = 98,
 k4 = 40,
 k3 = 114,
 k2 = 81,
 k1 = 66,
 k0 = 84]
```

Wonderful, now let's say this is a key and try to decrypt the three given ciphertexts:

```python=
K = [118, 118, 62, 75, 98, 86, 99, 79, 106, 121, 98, 40, 114, 81, 66, 84]
K = bytes(K[::-1])

print(K)

C = """5sxJURBMWadPV+Qfj2g/WFVWcaLbXoUxyXeiIvpa4pu1SjSj0nqneJeN0tNkKbJx
gkZ6pGuoDU6Lz5bc23Y/5ZfI9XPcJd/r1PRrsE1epqc=
rbfA5lkSHq0eL4dmwH4gHg==""".split('\n')
C = list(map(b64decode, C))

for c in C:
  print(decrypt(c, K))
```

Here we have our second flag!

```
b'TBQr(byjOcVbK>vv'
b"ECW_AIU/yMZg3c7(NqGyqu8Iv3j8Oszx+1<>i'7&o(9g\x04\x04\x04\x04"
b'com.example.step_3.Step3\x08\x08\x08\x08\x08\x08\x08\x08'
b'run\r\r\r\r\r\r\r\r\r\r\r\r\r'
```

### Part 3

Once again, the last key that we managed to retrieve is able to decrypt the next step, `step_3.dex`.

![](https://i.imgur.com/z1oyLu5.png)

The most interesting method is inside `FinishImpl.class`:

```java=
private final void classifyDrawing() {
      DrawView var1 = this.drawView;
      Bitmap var7;
      if (var1 != null) {
         var7 = var1.getBitmap();
      } else {
         var7 = null;
      }

      if (var7 != null && this.digitClassifier.isInitialized()) {
         int var2 = this.digitClassifier.getNumber(var7);
         String var3 = "recognized: " + var2;
         System.out.println(var3);
         String var8;
         if (this.digitClassifier.verifyNext(var7, this.index)) {
            if (var2 == -1) {
               Toast.makeText(this.activity, "An error happened", 0).show();
            } else {
               var8 = this.pin;
               this.pin = var8 + var2;
            }
         }

         var2 = this.index + 1;
         this.index = var2;
         if (var2 == 12) {
            try {
               StringBuilder var9 = new StringBuilder();
               String var4 = var9.append(this.password).append(this.pin).toString();
               IvParameterSpec var10 = new IvParameterSpec(new byte[]{-101, 105, -107, -118, -65, 117, -35, 92, -47, -112, -102, -76, 40, -21, 69, 93});
               SecretKeyFactory var11 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
               char[] var15 = var4.toCharArray();
               PBEKeySpec var5 = new PBEKeySpec(var15, new byte[]{56, -35, 119, -111, 71, 113, -83, 70, -119, 122, -92, 22, 124, 23, -83, 110}, 65536, 256);
               SecretKey var16 = var11.generateSecret(var5);
               SecretKeySpec var12 = new SecretKeySpec(var16.getEncoded(), "AES");
               Cipher var17 = Cipher.getInstance("AES/CBC/PKCS7Padding");
               var17.init(2, var12, var10);
               Activity var13 = this.activity;
               Intent var14 = new Intent();
               byte[] var18 = var17.doFinal(Base64.decode("fEd6buSL5HmuH0pTdCJG4ZVCCn/bMC8bun44MKlw6mz2UrtH9Zhz3gMax4X8eGq5", 0));
               var4 = new String(var18, Charsets.UTF_8);
               var14.putExtra("end_flag", var4);
               var13.setResult(10, var14);
               this.activity.finish();
            } catch (Exception var6) {
               var8 = "Wrong pin: " + this.pin;
               System.out.println(var8);
               this.index = 0;
               this.pin = "";
               Toast.makeText(this.activity, "Try again", 0).show();
            }
         }

         if (this.index == 12) {
            this.index = 0;
         }
      }

   }
```

We need to find the key to decrypt `fEd6buSL5HmuH0pTdCJG4ZVCCn/bMC8bun44MKlw6mz2UrtH9Zhz3gMax4X8eGq5`, the final ciphertext that will give us the flag.

The key for this step is constructed as follows:

```java
StringBuilder var9 = new StringBuilder();
String var4 = var9.append(this.password).append(this.pin).toString();
```

It is the concatenation of `password` and `pin`.

Let's take a look at the pin first, since it happens to be constructed right before.

```java=
int var2 = this.digitClassifier.getNumber(var7);
String var3 = "recognized: " + var2;
System.out.println(var3);
String var8;
if (this.digitClassifier.verifyNext(var7, this.index)) {
if (var2 == -1) {
   Toast.makeText(this.activity, "An error happened", 0).show();
} else {
   var8 = this.pin;
   this.pin = var8 + var2;
}
}

var2 = this.index + 1;
this.index = var2;
```

Our intuition (since we still have no clue whatsoever what the application looks like at this point, let's remember that :smiley:) is that there is a way to input hand-drawn digits, and a classifier is used to recognize them. The method `getNumber` returns the most probable digit that was last input, and the pin will be a concatenation of these digits... or at least, those who pass the `verifyNext` test. But what does `verifyNext` do?

```java=
public final boolean verifyNext(@NotNull Bitmap var1, int var2) {
  if (!this.isInitialized) {
     throw new IllegalStateException("TF Lite Interpreter is not initialized yet.".toString());
  } else {
     ByteBuffer var6 = this.convertBitmapToByteBuffer(Bitmap.createScaledBitmap(var1, this.inputImageWidth, this.inputImageHeight, true));
     List var3 = this.interpreters;
     Interpreter var7 = (Interpreter)var3.get(var2 % var3.size());
     float[][] var4 = new float[1][];

     for(var2 = 0; var2 < 1; ++var2) {
        var4[var2] = new float[2];
     }

     var7.run(var6, var4);
     boolean var5;
     if (var4[0][1] > var4[0][0]) {
        var5 = true;
     } else {
        var5 = false;
     }

     return var5;
  }
}
```

This is starting to get spicy. Our digit is converted into a bitmap and fed to an *interpreter* of a certain index. We can see that `this.interpreters` is initialized here:

```java=
for(char var3 = (char)var2; var3 < 'm'; var3 = var8) {
    Interpreter var4 = new Interpreter(this.loadModelFile(var1, "mnist-" + var3 + ".tflite"), new Options());
    int[] var5 = var4.getInputTensor(0).shape();
    int var6 = var5[1];
    this.inputImageWidth = var6;
    int var7 = var5[2];
    this.inputImageHeight = var7;
    this.modelInputSize = var7 * var6 * 4 * 1;
    this.interpreters.add(var4);
    var8 = (char)(var3 + 1);
}
```

So this is where all of this comes from...! The `mnist-letter.tflite` files that we noticed at the beginning are used to create an array of 12 interpreters. 

For the *i*-th digit, we load the *i*-th interpreter, we run it on the bitmap and we get a result `var4`. We can guess the output is 2-dimensions, and we're verifying whether the first scalar is greater than the second:

```java
if (var4[0][1] > var4[0][0]) {
    var5 = true;
}
```

...which probably means these outputs are like "probability that the digit is *something*" and "probability that it is not". It might then very be that each of these files are models that are trained to recognize *one* specific digit!

```shell
$ md5sum mnist-*         
010e5a2494a04f08c0453dbac553c2ba  mnist-a.tflite
6b2903e895d553b1d42a0d8e4b7fa5db  mnist-b.tflite
2ac84ad634cbeaca570997fc467e63da  mnist-c.tflite
be0b0e004cce204541b4f64ffe33ca77  mnist-d.tflite
4838cff830ccbad1aa87eebd1006b072  mnist-e.tflite
ef12eb1551edaabc143d05b95715436f  mnist-f.tflite
2ac84ad634cbeaca570997fc467e63da  mnist-g.tflite
67b11b30528fee5225f456883be13a05  mnist-h.tflite
ef12eb1551edaabc143d05b95715436f  mnist-i.tflite
73e40fee1f151d907795c5a5274e6965  mnist-j.tflite
be0b0e004cce204541b4f64ffe33ca77  mnist-k.tflite
73e40fee1f151d907795c5a5274e6965  mnist-l.tflite
```

We can also notice some of these files are the same, which means they are models for the same digits. This makes the search space smaller if we ever want to bruteforce the pin (don't make fun of me, I tried bruteforce for hours because I had the wrong `password` but we'll get to this later).

The idea now is to download a test set of images and labels from the [MNIST handwritten digit database](http://yann.lecun.com/exdb/mnist/), and for each interpreter, see which letter matches the best. I am not very familiar with tensorflow, but all it takes is some copy/pasting and tweaks:

```python=
import argparse, time, sys
import numpy as np
from PIL import Image
import tflite_runtime.interpreter as tflite

def load_labels(filename):
  with open(filename, 'r') as f:
    return [line.strip() for line in f.readlines()]

f = open('plouf/t10k-images-idx3-ubyte', 'rb').read()
f = f[4+4+4+4:]
imgs = []
for i in range(500):
  imgs.append(
    np.expand_dims(
      np.reshape(
        np.array([(np.float32(x) / 255) for x in f[28 * 28 * i:28 * 28 * (i + 1)]], dtype=np.float32),
        (28, 28)
      ),
      axis=0
    )
  )

f = open('plouf/t10k-labels-idx1-ubyte', 'rb').read()
f = f[4+4:]
labels = []
for i in range(10000):
  labels.append((f[i]))

for letter in 'abcdefghijkl':
  interpreter = tflite.Interpreter(model_path='mnist-%s.tflite' % letter)
  interpreter.allocate_tensors()
  input_details = interpreter.get_input_details()
  output_details = interpreter.get_output_details()
  height = input_details[0]['shape'][1]
  width = input_details[0]['shape'][2]

  scores = [0] * 10

  for (img, label) in zip(imgs, labels):
      interpreter.set_tensor(input_details[0]['index'], img)
      interpreter.invoke()
      output_data = interpreter.get_tensor(output_details[0]['index'])
      results = np.squeeze(output_data)
      top_k = results.argsort()
      if top_k[1] == 1:
        scores[label] += 1
  
  print(letter, scores)
```

Here's the result:

```
a [0, 0, 0, 43, 0, 0, 0, 0, 0, 0]
b [0, 67, 0, 0, 0, 0, 0, 0, 0, 0]
c [0, 0, 0, 0, 52, 0, 0, 0, 0, 0]
d [0, 0, 0, 0, 0, 1, 41, 0, 0, 0]
e [0, 0, 1, 0, 0, 0, 0, 0, 40, 2]
f [0, 0, 0, 1, 0, 48, 0, 0, 0, 0]
g [0, 0, 0, 0, 52, 0, 0, 0, 0, 0]
h [41, 0, 0, 0, 1, 0, 1, 0, 0, 0]
i [0, 0, 0, 1, 0, 48, 0, 0, 0, 0]
j [0, 0, 54, 0, 0, 0, 0, 0, 0, 0]
k [0, 0, 0, 0, 0, 1, 41, 0, 0, 0]
l [0, 0, 54, 0, 0, 0, 0, 0, 0, 0]
```

This gives us the pin `314685405262`!

All is left now is to find `password`. I spent a lot of time on this part because I didn't realize Bytecode Viewer had failed to decompile a few methods, which made me miss very important pieces that were used to construct this variable, because these were not exported when you asked the software to export all the classes.

Either way, here's where `this.password` is generated:

```java=
SharedPreferences var2 = this.activity.getSharedPreferences("flag", 0);
byte var3 = 97;

char var8;
for(char var4 = (char)var3; var4 <= 'z'; var4 = var8) {
 String var5 = var2.getString(String.valueOf(var4), (String)null);
 if (var5 != null) {
    String var6 = this.password;
    this.password = var6 + var5;
 }

 var8 = (char)(var4 + 1);
}
```

We're looking for keys in the `flag` object, from 'a' to 'z'. If the key exists, we append the value associated with this key in `this.password` (which is initialized as an empty string).

So now we need to retrace our own steps and find all the places where the `flag` object was edited (not only `putString`, but also `delete`).

The issue is, there are often edits in which the context is a bit hard to tell, and that thus might not be relevant. For instance, this class from step 2:

```java=
public final class b {
   public static final b a = new b();

   private final void a(Context var1) {
      if (!this.a(var1, "/data/local/tmp/frida-server")) {
         this.a(var1, "/data/local/tmp/re.frida.server");
      }

   }

   private final boolean a(@NotNull Context var1, String var2) {
      boolean var3 = (new File(var2)).exists();
      boolean var4 = var3;
      if (!var3) {
         label17: {
            try {
               new FileInputStream(var2);
            } catch (Exception var5) {
               var4 = var3;
               break label17;
            }

            var4 = true;
         }
      }

      if (var4) {
         var1.getSharedPreferences("flag", 0).edit().putString("o", "i").apply();
      }

      return false;
   }

   private final void b(@NotNull Context var1) {
      ThreadsKt.thread$default(false, false, (ClassLoader)null, (String)null, 0, new a(var1), 31, (Object)null);
   }

   public final void c(@NotNull Context var1) {
      this.a(var1);
      this.b(var1);
      var1.getSharedPreferences("flag", 0).edit().remove("w").apply();
   }
}
```

A safe method to find the good key was therefore to list all the $n$ potential (key, value) pairs of `flag`, and bruteforce the $2^n$ possible keys.

Last thing I'll show you is the most important keys in `flag`, that are set in `step2/a/a/a/c$a.class` and `step1/a/a/a/c$b.class` (Smali only):

```smali=
L2 {
    aload4
    ldc "Congrats, almost there" (java.lang.String)
    iconst_0
    invokestatic android/widget/Toast.makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
    invokevirtual android/widget/Toast.show()V
    aload0 // reference to self
    getfield a/a/a/c$a.b:android.app.Activity
    ldc "flag" (java.lang.String)
    iconst_0
    invokevirtual android/app/Activity.getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    invokeinterface android/content/SharedPreferences.edit()Landroid/content/SharedPreferences$Editor;
    ldc "q" (java.lang.String)
    aload1
    invokeinterface android/content/SharedPreferences$Editor.putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    invokeinterface android/content/SharedPreferences$Editor.apply()V
    ldc "FLAG 2" (java.lang.String)
    aload1
    invokestatic android/util/Log.i(Ljava/lang/String;Ljava/lang/String;)I
    pop
    aload0 // reference to self
    getfield a/a/a/c$a.a:android.app.Activity
    astore6
 }
```

We can guess putString in called with key "q", but the value argument is pushed by `aload1`. If we take a look a bit higher up in the code, we can see where it is stored:

```smali
invokestatic a/a/a/c.a(La/a/a/c;)Ljavax/crypto/Cipher;
ldc "5sxJURBMWadPV+Qfj2g/WFVWcaLbXoUxyXeiIvpa4pu1SjSj0nqneJeN0tNkKbJx" (java.lang.String)
iconst_0
invokestatic android/util/Base64.decode(Ljava/lang/String;I)[B
invokevirtual javax/crypto/Cipher.doFinal([B)[B
astore5
new java/lang/String
astore1
```

The decrypted value of this string was the second flag `ECW_AIU/yMZg3c7(NqGyqu8Iv3j8Oszx+1<>i'7&o(9g`: maybe this is actually the value for "q".

Same thing in `step1/a/a/a/c$b.class` with the key "j" that is set to the first flag, which was `ECW_oe8%jXffkWul&#!V@tqB(:V%WP?JUKm@I(2KqIfv`.

Finally, we already know the `a` key was set to the string `LuKXSGlN5(%:Vk=alEbl9khIEPBo=mXu;hR7Ez7E`.

Now it turns out concatening these three values is enough to work, and that the "letter" values in `flag` were only bait!

```python=
C = "fEd6buSL5HmuH0pTdCJG4ZVCCn/bMC8bun44MKlw6mz2UrtH9Zhz3gMax4X8eGq5"
C = b64decode(C)

pin = '314685405262'

all = [
  'LuKXSGlN5(%:Vk=alEbl9khIEPBo=mXu;hR7Ez7E',
  'ECW_oe8%jXffkWul&#!V@tqB(:V%WP?JUKm@I(2KqIfv',
  'ECW_AIU/yMZg3c7(NqGyqu8Iv3j8Oszx+1<>i\'7&o(9g',
]

print(decrypt(C, (''.join(all) + pin).encode()))
```

Result:

```
b'ECW_50l8!3*ojKrfFHYCiLON+iDd5-0(4!iG04Y6U32L\x04\x04\x04\x04'
```

### Conclusion

I do have to admit static analysis was a pain in the ass at some times, but it still allowed me to go pretty fast: it took me an hour to solve the first part and 20 minutes for the second part. If I had realized sooner that I was missing some crucial code in my decompilation export, I would have solved the last part in roughly an hour too.

It's a tradeoff between how much time it'll take you to setup a working debug environment (I tried but I failed, I couldn't get past the first "trick", I even tried to patch the apk but then I got a blank screen...) and how confident you feel about going full blind, as it takes a lot of rigor and intuition.

All in all, a solid challenge with a fun Machine Learning twist at the end!
