# RSA Public-Key Encryption and Signature Lab

This week's suggested lab was RSA (Rivest-Shamir-Adleman) Public-Key Encryption and Signature Lab, from SEED labs, with the intent of providing us with a better understanding of how this algorithm works and how it is implemented.

# Introduction

In this lab, we seek to gain hands-on experience with the RSA algorithm. Besides that, this lab covers the following topics:

- Public-key cryptography.
- The RSA algorithm and key generation.
- Big number calculation.
- Encryption and Decryption using RSA.
- Digital signature.
- X.509 certificate.

## Background

Typically, the RSA algorithm involves computations on large numbers. And these computations involve more than 32-bit or 64-bit numbers. Most of the time, these numbers are more than 512 bits long. To perform arithmetic operations in these numbers we'll use the Big Number library provided by *OpenSSL* that has an API that enables us to do those computations. We were presented a simple script where three `BIGNUM` variables, a, b, and n are initialized, and we compute `a * b` and `a^b mod n`. The script is as follows:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *res = BN_new();

    // Initialize a, b, n
    BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
    BN_dec2bn(&b, "273489463796838501848592769467194369268");
    BN_rand(n, NBITS, 0, 0);
    
    // res = a*b
    BN_mul(res, a, b, ctx);
    printBN("a * b = ", res);
    
    // res = aˆb mod n
    BN_mod_exp(res, a, b, n, ctx);
    printBN("a^c mod n = ", res);
    
    return 0;
}
```

When compiling and running the script, we get the following result:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc bn_sample.c -o bn_sample -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./bn_sample     
a * b =  A5A38F6F914CFDDEDF9998C401C6AC24230A6D011DA777D53832FE24CDBCAF8C1B9DB466B3D69BC82E6B88B88F30C2BC
a^c mod n =  3BEEB779B28C81F2B160DB875CB980896C07E18C7E8BF51E05D26D0D2107AFA7
```

Indeed, the results of the computations are much larger than 32-bit or 64-bit numbers!

# Tasks

# Task 1

In the first task we are asked to derive the private key of RSA given the `p`, `q`, and `e` prime numbers, such that `n = p * q` and `(e, n)` is the public key. `n` is the so-called modulus, `e` is the public key exponent, and the private key (exponent) is `d`. The RSA key generation process works as follows:
- Choose two large random prime numbers, `p` and `q`.
- Compute `n = p * q`. This number is the modulus for the public key and private key. To be secure, `n` needs to be large. In our task, we already have `p` and `q`, so we can calculate `n`.
- Select an integer `e`, such that `1 < e < ¢(n)`, and `e` is relatively prime to `¢(n)`, meaning the greatest common divisor (gcd) of `e` and `¢(n)` is one. This number is called the public key exponent, and it is made public. This number does not need to be large; in practice, many public keys choose `e = 65537`, which is a prime number. In practice, we find `e` first, and then generate `p` and `q`. If `¢(p * q)` and `e` are not relatively prime, we will pick another `p` and/or `q`, until the condition is met. Also, it's important to note that this `¢(n)` is Euler's totient function and counts the positive integers up to a given integer `n` that are relatively prime to `n`.
- Lastly, we find `d`, such that `e * d mod ¢(n) = 1`. We can use the Extended Euclidean algorithm to get `d`. This number is called the private key exponent, and it is kept a secret.

Knowing the three prime numbers we were given, we can find the value of `d`. Even given `e` and `n` it is possible to get `p` and `q`, but factoring a large number is a difficult problem, and there's no efficient way to do that yet. Factoring a 2048-bit number is considered infeasible using today's computer power. It is based on this that the RSA algorithm security stands.

Note the way `¢(n)` is calculated is as follows:

`¢(n) = ¢(p) * ¢(q) = (p - 1) * (q - 1)`

Also, for the equation `e * d mod ¢(n) = 1` used in RSA, it comes from the calculation of the greatest common divisor:

`a * x + b * y = gcd(a, b)`

Substituting the right arguments (`a` for `e`, `x` for `d` and `b` for `¢(n)`):

`e * d + ¢(n) * y = gcd(e, ¢(n)) = 1`

Applying `mod ¢(n)` on both sides, we get:

`e * d mod ¢(n) = 1`

To solve this task we used the following C script that does the described operations:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *p_minus_one = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *res = BN_new();

    // Initialize p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // Compute p - 1 and q - 1
    BN_sub(p_minus_one, p, BN_value_one()); 
    BN_sub(q_minus_one, q, BN_value_one()); 
    
    // n = p * q
    BN_mul(n, p, q, ctx);

    // Compute ¢(n)
    BN_mul(phi, p_minus_one, q_minus_one, ctx);

    // Check if e and ¢(n) are relatively prime (i.e. gcd(e, ¢(n)) = 1)
    BN_gcd(res, phi, e, ctx);
    if (!BN_is_one(res)) {
        exit(0);
    } 

    // Compute the private key exponent d solving this equation: e * d mod ¢(n) = 1
    BN_mod_inverse(d, e, phi, ctx);

    printBN("d = ", d);

    return 0;
}
```

Compiling and running it, we get `d` as the private key:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task1.c -o task1 -lcrypto
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task1                      
d =  3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB
```

## Task 2

For this task, given the public key `(e, n)`, the decryption key `d` for verification purposes, and a message "A top secret!" we need to encrypt this message using the RSA algorithm.

First, we convert our message to hexadecimal format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("A top secret!".encode("utf-8").hex())'
4120746f702073656372657421
```

The output is `4120746f702073656372657421`, as can be seen.

With this in mind, we developed a script that takes the aforementioned values and encrypts our message using the equation `c = m^e mod n` and also decrypts it for verification purposes using the equation `m = c^d mod n`. The script is as follows:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *new_m = BN_new();

    // Initialize n, m, e, d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m, "4120746f702073656372657421");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Encryption: Calculate m^e mod n
    BN_mod_exp(c, m, e, n, ctx);
    printBN("Encryption: ", c);

    // Decryption: Calculate c^d mod n (Verification)
    BN_mod_exp(new_m, c, d, n, ctx);
    printBN("Decryption: ", new_m);

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task2.c -o task2 -lcrypto
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task2
Encryption:  6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC
Decryption:  4120746F702073656372657421
```

We can indeed see the encrypted message being `6FB078DA550B2650832661E14F4F8D2CFAEF475A0DF3A75CACDC5DE5CFC5FADC` in hexadecimal format and the decrypted message being `4120746F702073656372657421` which is exactly what we obtained using that short python line at the beginning of this task.

## Task 3

In this task, contrary to what we were asked in the previous task we have to decrypt a message. Using the parameters `n`, `e` and `d` given, and knowing the ciphertext `c` is `8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F`, we just need to use the formula `c^d mod n` and we get the decrypted text according to the RSA algorithm. For this, we developed a C script that takes the given arguments and calculates the decrypted text in hexadecimal format. The script is as follows:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();

    // Initialize n, c, e, d
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Decryption: Calculate c^d mod n
    BN_mod_exp(m, c, d, n, ctx);
    printBN("Decryption: ", m);

    return 0;
}
```

Compiling and running:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task3.c -o task3 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task3                      
Decryption:  50617373776F72642069732064656573
```

As it can be seen the decrypted text in hexadecimal format is `50617373776F72642069732064656573`. Converting this to ASCII format can be done using the following python code:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print(bytearray.fromhex("50617373776F72642069732064656573").decode())'
Password is dees
```

The deciphered text is "Password is dees".

## Task 4

In this task, we are asked to sign a message. Note that this signature should be directly applied to the message and not to its hash value, as it's commonly done due to the long dimension that some messages might have. For a message `m` that needs to be signed, we need to follow the equation `s = m^d mod n` using our private key `d`, and `s` will serve as our signature on the message.

For the message "I owe you $2000." we first need to convert it to hexadecimal format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("I owe you $2000.".encode("utf-8").hex())'
49206f776520796f752024323030302e
```

Then, we developed the following C script to achieve sign the message. Note that the parameters in use are the same as in task 2.

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();

    // Initialize n, d, e, m
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "49206f776520796f752024323030302e");

    // Signature: Calculate m^d mod n
    BN_mod_exp(s, m, d, n, ctx);
    printBN("Signature: ", s);

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task4.c -o task4 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task4                                                    
Signature:  55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB
```
The signature obtained is `55A4E7F17F04CCFE2766E1EB32ADDBA890BBE92A6FBE2D785ED6E73CCB35E4CB`.

If we instead change the message `m` to "I owe you $3000." the result would be as follows. First, we convert the message to hexadecimal format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("I owe you $3000.".encode("utf-8").hex())'
49206f776520796f752024333030302e
```

Changing the previous script in the line of the initialization of the `m` variable to:

```c
BN_hex2bn(&m, "49206f776520796f752024333030302e");
```

And compiling and running the script again:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task4.c -o task4 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task4
Signature:  BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822
```

We get this new signature: `BCC20FB7568E5D48E434C387C06A6025E90D29D848AF9C3EBAC0135D99305822` which is completely different from the previous one, as expected. A slight change in the message produces a different signature. This confers some collision resistance to the algorithm since there's no apparent correlation between the original message and the generated signature.

## Task 5

In this task, we are asked to verify a signature given an original message "Launch a missile.". Knowing the parameters `e` and `n`, part of the RSA public key and the signature value obtained using an unknown private key we can verify that the signature `643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F` comes from the message "Launch a missile." using the public key. 

First, we calculate the hexadecimal format of the given message:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ python -c 'print("Launch a missile.".encode("utf-8").hex())'
4c61756e63682061206d697373696c652e
```

After that, we developed a C script that calculates `s^e mod n`. The result is the content of the original message before being signed. If this result matches the output of the "Launch a missile." in hexadecimal format, then we can firmly state that the signature matches! To prove that, we developed another C script:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *new_m = BN_new();

    // Initialize n, s, e, m
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");

    // Verify Signature: Calculate s^e mod n
    BN_mod_exp(new_m, s, e, n, ctx);
    printBN("Signature Verification : ", new_m);

    if(BN_cmp(m, new_m) == 0)
        printf("Signature matches!");
    else 
        printf("Signature doesn't match!");

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task5.c -o task5 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task5                      
Signature Verification :  4C61756E63682061206D697373696C652E
Signature matches!
```

We can see that the signature matches!

If we modified the signature one small bit such that the last byte was `3F` instead of `2F` then our obtained message wouldn't match the original message, as the signature would become invalid. To verify this we only change the initialization of the variable `s` in the previous script to:

```c
BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
```

And then we compile and run the program again:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task5.c -o task5 -lcrypto
                                                                                                                   
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task5                      
Signature Verification :  91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294
Signature doesn't match!
```

The obtained message `91471927C80DF1E42C154FB4638CE8BC726D3D66C83A4EB6B7BE0203B41AC294` is very different from the original one `643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F`, thus we can state that after aplying the RSA public key on the signature, we get a block of data that is significantly different from the original one.

## Task 6

In this task, we will manually verify an X.509 certificate. An X.509 certificate contains data about a public key and an issuer's signature on the data. We will fetch an X.509 certificate from a web server, get its issuer's public key and use it to verify the signature on the certificate.

First, we download a certificate from a web server, for instance `www.linkedin.com`. We can do that with the following command:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl s_client -connect www.linkedin.com:443 -showcerts
CONNECTED(00000003)
depth=2 C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
verify return:1
depth=1 C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
verify return:1
depth=0 C = US, ST = California, L = Sunnyvale, O = LinkedIn Corporation, CN = www.linkedin.com
verify return:1
---
Certificate chain
 0 s:C = US, ST = California, L = Sunnyvale, O = LinkedIn Corporation, CN = www.linkedin.com
   i:C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
-----BEGIN CERTIFICATE-----
MIII1TCCB72gAwIBAgIQB3tL2YAMJq+v2SVWIn3H5zANBgkqhkiG9w0BAQsFADBN
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMjIwMzI4MDAwMDAwWhcN
MjIwOTI4MjM1OTU5WjBwMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTESMBAGA1UEBxMJU3Vubnl2YWxlMR0wGwYDVQQKExRMaW5rZWRJbiBDb3Jwb3Jh
dGlvbjEZMBcGA1UEAxMQd3d3LmxpbmtlZGluLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMDhGFnTZhW6oMZr1WwyHDF/g6VqR0BIr0tHN9Z50JB5
tkG6JuUwWbnojyH2yFrRLRIGnYTjsluzHR4LRxrG2Aqqk9qK6zE3j3R0xM7JxaMX
ah4k6DkG8aWnEfuI3VzYfv4DTzsJBC5TaR0BvYfcc5kvEqG6I4fQtURc0Go+VRmS
FCHB65ACC1Bu0IBQ7V8bymedYSLlILEKjwl1XdpWQRUdAz34qZFS/3i6s2s8qpTI
bcoElfwqOxPrgwpt3t3DyO5rQWxqFFNziyEB9pLlZ/Ai9z1J6GTMEDWpa6c2doWC
P5b4GRQS75OcOmJtAnyXu+lxEcXbnUyqYQBAI2vBgVkCAwEAAaOCBYwwggWIMB8G
A1UdIwQYMBaAFA+AYRyCMWHVLyjnjUY4tCzhxtniMB0GA1UdDgQWBBTromzzM755
DHWlHpivyN/aHkYX+DCCAjgGA1UdEQSCAi8wggIrghB3d3cubGlua2VkaW4uY29t
ggxsaW5rZWRpbi5jb22CFnJ1bTUucGVyZi5saW5rZWRpbi5jb22CFWV4cDQud3d3
LmxpbmtlZGluLmNvbYIVZXhwMy53d3cubGlua2VkaW4uY29tghVleHAyLnd3dy5s
aW5rZWRpbi5jb22CFWV4cDEud3d3LmxpbmtlZGluLmNvbYIWcnVtMi5wZXJmLmxp
bmtlZGluLmNvbYIWcnVtNC5wZXJmLmxpbmtlZGluLmNvbYIWcnVtNi5wZXJmLmxp
bmtlZGluLmNvbYIXcnVtMTcucGVyZi5saW5rZWRpbi5jb22CFnJ1bTgucGVyZi5s
aW5rZWRpbi5jb22CFnJ1bTkucGVyZi5saW5rZWRpbi5jb22CFWFmZC5wZXJmLmxp
bmtlZGluLmNvbYIXcnVtMTQucGVyZi5saW5rZWRpbi5jb22CF3J1bTE4LnBlcmYu
bGlua2VkaW4uY29tghdydW0xOS5wZXJmLmxpbmtlZGluLmNvbYIVZXhwNS53d3cu
bGlua2VkaW4uY29tghlyZWFsdGltZS53d3cubGlua2VkaW4uY29tghNweC5hZHMu
bGlua2VkaW4uY29tghRweDQuYWRzLmxpbmtlZGluLmNvbYITZGMuYWRzLmxpbmtl
ZGluLmNvbYIHbG5rZC5pboIUcHguam9icy5saW5rZWRpbi5jb22CEW1pZDQubGlu
a2VkaW4uY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwgY0GA1UdHwSBhTCBgjA/oD2gO4Y5aHR0cDovL2NybDMuZGlnaWNl
cnQuY29tL0RpZ2ljZXJ0U0hBMlNlY3VyZVNlcnZlckNBLTEuY3JsMD+gPaA7hjlo
dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaWNlcnRTSEEyU2VjdXJlU2VydmVy
Q0EtMS5jcmwwPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0
cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMH4GCCsGAQUFBwEBBHIwcDAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEgGCCsGAQUFBzAChjxodHRw
Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyU2VjdXJlU2VydmVy
Q0EtMi5jcnQwCQYDVR0TBAIwADCCAX4GCisGAQQB1nkCBAIEggFuBIIBagFoAHcA
KXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF/0SKiNQAABAMASDBG
AiEAnWEH3HuBs0RoP/uaTf7EfYPx1fjHZiOBW6j8sPLkgTsCIQC9Lmp/bXw6ch5L
efQKh+0lE1sueS4Wqj9OcpkCxR0xtwB1AFGjsPX9AXmcVm24N3iPDKR6zBsny/ee
iEKaDf7UiwXlAAABf9EiomQAAAQDAEYwRAIgL+HjQX3xucNHwAGbJwru5SDZGxLA
qBJMraL81HRTIjMCIF4waMVeOuaWAFwGHjzVyIzgIe/A0o0fIwQA6abx/zNkAHYA
QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYAAAF/0SKh+AAABAMARzBF
AiEA7n7WeRmyAy7gGEy3aUTFbC8Ms0HzdrmumGoV9kcUISMCIERv4IXz0QHdSU7f
AnT0V38rPOOe/jsYsMtVPZ4KzzHcMA0GCSqGSIb3DQEBCwUAA4IBAQDUYmaEhKOj
KGdYT/BFfsT0npxwABiRMm/ixodu8qrIgmsk4OE7z+qgvH7Y9Kac+ug/y8oQYcMX
cW9mamBnrtd1f0CWhkvclSJKUIw3rdBivACKBh8Rutmif1xGh+0gbogn5F+HBn9L
mNaHxZDt5wMano2iWd9JChwpQtDwWiKazH2uIFf6v5UacRBIMMVPYZJ1F2hkqK45
XRbcylvc9SXAX6J2davOpOs0zktMfFMtBWpHFzj9pKrAwd14GBcBbBOfJXVAJQH2
htCLu+swf1hI0ybyOnKwLZYvTPO736U888Fr0p09KtC7SKz6zCG8I1GKGgVREbzQ
mg6DvQO9X7G0
-----END CERTIFICATE-----
 1 s:C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
   i:C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
-----BEGIN CERTIFICATE-----
MIIE6DCCA9CgAwIBAgIQAnQuqhfKjiHHF7sf/P0MoDANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
QTAeFw0yMDA5MjMwMDAwMDBaFw0zMDA5MjIyMzU5NTlaME0xCzAJBgNVBAYTAlVT
MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAa4wggGqMB0GA1UdDgQWBBQPgGEcgjFh
1S8o541GOLQs4cbZ4jAfBgNVHSMEGDAWgBQD3lA1VtFMu2bwo+IbG8OXsj3RVTAO
BgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIG
A1UdEwEB/wQIMAYBAf8CAQAwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhho
dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNl
cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcnQwewYDVR0f
BHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xv
YmFsUm9vdENBLmNybDA3oDWgM4YxaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0Rp
Z2lDZXJ0R2xvYmFsUm9vdENBLmNybDAwBgNVHSAEKTAnMAcGBWeBDAEBMAgGBmeB
DAECATAIBgZngQwBAgIwCAYGZ4EMAQIDMA0GCSqGSIb3DQEBCwUAA4IBAQB3MR8I
l9cSm2PSEWUIpvZlubj6kgPLoX7hyA2MPrQbkb4CCF6fWXF7Ef3gwOOPWdegUqHQ
S1TSSJZI73fpKQbLQxCgLzwWji3+HlU87MOY7hgNI+gH9bMtxKtXc1r2G1O6+x/6
vYzTUVEgR17vf5irF0LKhVyfIjc0RXbyQ14AniKDrN+v0ebHExfppGlkTIBn6rak
f4994VH6npdn6mkus5CkHBXIrMtPKex6XF2firjUDLuU7tC8y7WlHgjPxEEDDb0G
w6D0yDdVSvG/5XlCNatBmO/8EznDu1vr72N8gJzISUZwa6CCUD7QBLbKJcXBBVVf
8nwvV9GvlW+sbXlr
-----END CERTIFICATE-----
---
Server certificate
subject=C = US, ST = California, L = Sunnyvale, O = LinkedIn Corporation, CN = www.linkedin.com

issuer=C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA

---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: ECDH, P-384, 384 bits
---
SSL handshake has read 4343 bytes and written 476 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 44F9D86FD926D15571972B4A2983EDFA23A7E62AA28D758E4F68798F113F4863
    Session-ID-ctx: 
    Master-Key: 2C2865DA333FEF1506E5B9F178A3F393D626E155A4E41667B03868E42BB7DB6162DD7DDD282596EBB8119C40EA3C0390
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 36000 (seconds)
    TLS session ticket:
    0000 - 00 00 00 00 03 63 57 34-06 5d 3f 4a b9 ec 61 e4   .....cW4.]?J..a.
    0010 - 0f 86 15 28 90 f1 e2 93-a7 7e 8b cd 4b 3e 9d 02   ...(.....~..K>..
    0020 - 94 d7 e5 99 76 d0 9f 12-be 91 3b 8a 39 ad 76 4e   ....v.....;.9.vN
    0030 - 1b 12 8f fd 1e f4 56 25-30 dc 16 9e b4 83 3d 3c   ......V%0.....=<
    0040 - b0 a3 4a 57 f4 f1 82 76-9a d2 7e 61 81 f9 5e 96   ..JW...v..~a..^.
    0050 - b6 b9 2f b5 51 80 73 81-43 c2 d5 60 5e ee fd df   ../.Q.s.C..`^...
    0060 - 37 1b eb 66 66 55 0a ae-36 d6 3b f0 d3 81 0a aa   7..ffU..6.;.....
    0070 - cf 0a 47 28 57 bf 0d cf-c0 27 8a a3 4d 74 3c 4a   ..G(W....'..Mt<J
    0080 - 0c bb 44 bb 55 50 5a 8c-bd 15 07 0a d0 7d c6 1e   ..D.UPZ......}..
    0090 - 03 4e 49 ed 0d 33 35 1a-04 93 a1 9b 78 1d ed 05   .NI..35.....x...
    00a0 - 9d 96 b9 bc 6c 5a f6 93-f9 15 78 96 0c 06 2b c1   ....lZ....x...+.
    00b0 - 80 51 b8 12 cb bf 82 f1-38 4e f3 2c 97 c3 58 0b   .Q......8N.,..X.
    00c0 - 1a 32 da 8a b1 28 29 2b-f1 26 34 d5 9b c3 a3 7c   .2...()+.&4....|
    00d0 - d0 f1 1c be b9 db e4 a2-f9 8a 62 05 1d 6c 8e 71   ..........b..l.q
    00e0 - 06 57 c9 3e 97 9c 20 28-e2 14 e8 29 78 04 c6 30   .W.>.. (...)x..0
    00f0 - ff fe b9 2d d1 62 7c 0e-73 07 c2 ce dc 4a 9b fe   ...-.b|.s....J..
    0100 - 69 01 81 b9 b9 36 b8 68-95 98 06 9b 08 41 b3 eb   i....6.h.....A..
    0110 - 8c c6 1d d9                                       ....

    Start Time: 1651309383
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: yes
---
```

The result of the command contains two certificates. In the entry starting with `s:` we can see who's the certificate for, i.e., `linkedin.com`. The issuer field entry starting with `i:` provides the issuer's information. Note that the subject field of the second certificate matches the issuer field of the first certificate. Basically, the second certificate belongs to an intermediate CA that is signed by a root CA, in our case DigiCert Global Root CA. We then copy each of the certificates to a file named `c0.pem` and `c1.pem` respectively.

Next, we extract the public key `(e, n)` from the issuer's certificate and here OpenSSL provides commands that can help us extract attributes from X.509 certificates. First, we extract the modulus (`n`) from the issuer's certificate:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl x509 -in c1.pem -noout -modulus                 
Modulus=DCAE58904DC1C4301590355B6E3C8215F52C5CBDE3DBFF7143FA642580D4EE18A24DF066D00A736E1198361764AF379DFDFA4184AFC7AF8CFE1A734DCF339790A2968753832BB9A675482D1D56377BDA31321AD7ACAB06F4AA5D4BB74746DD2A93C3902E798080EF13046A143BB59B92BEC207654EFCDAFCFF7AAEDC5C7E55310CE83907A4D7BE2FD30B6AD2B1DF5FFE5774533B3580DDAE8E4498B39F0ED3DAE0D7F46B29AB44A74B58846D924B81C3DA738B129748900445751ADD37319792E8CD540D3BE4C13F395E2EB8F35C7E108E8641008D456647B0A165CEA0AA29094EF397EBE82EAB0F72A7300EFAC7F4FD1477C3A45B2857C2B3F982FDB745589B
```

Then we print out all the fields in the certificate and find the exponent (`e`):

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl x509 -in c1.pem -text -noout   
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            02:74:2e:aa:17:ca:8e:21:c7:17:bb:1f:fc:fd:0c:a0
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Global Root CA
        Validity
            Not Before: Sep 23 00:00:00 2020 GMT
            Not After : Sep 22 23:59:59 2030 GMT
        Subject: C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:dc:ae:58:90:4d:c1:c4:30:15:90:35:5b:6e:3c:
                    82:15:f5:2c:5c:bd:e3:db:ff:71:43:fa:64:25:80:
                    d4:ee:18:a2:4d:f0:66:d0:0a:73:6e:11:98:36:17:
                    64:af:37:9d:fd:fa:41:84:af:c7:af:8c:fe:1a:73:
                    4d:cf:33:97:90:a2:96:87:53:83:2b:b9:a6:75:48:
                    2d:1d:56:37:7b:da:31:32:1a:d7:ac:ab:06:f4:aa:
                    5d:4b:b7:47:46:dd:2a:93:c3:90:2e:79:80:80:ef:
                    13:04:6a:14:3b:b5:9b:92:be:c2:07:65:4e:fc:da:
                    fc:ff:7a:ae:dc:5c:7e:55:31:0c:e8:39:07:a4:d7:
                    be:2f:d3:0b:6a:d2:b1:df:5f:fe:57:74:53:3b:35:
                    80:dd:ae:8e:44:98:b3:9f:0e:d3:da:e0:d7:f4:6b:
                    29:ab:44:a7:4b:58:84:6d:92:4b:81:c3:da:73:8b:
                    12:97:48:90:04:45:75:1a:dd:37:31:97:92:e8:cd:
                    54:0d:3b:e4:c1:3f:39:5e:2e:b8:f3:5c:7e:10:8e:
                    86:41:00:8d:45:66:47:b0:a1:65:ce:a0:aa:29:09:
                    4e:f3:97:eb:e8:2e:ab:0f:72:a7:30:0e:fa:c7:f4:
                    fd:14:77:c3:a4:5b:28:57:c2:b3:f9:82:fd:b7:45:
                    58:9b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                0F:80:61:1C:82:31:61:D5:2F:28:E7:8D:46:38:B4:2C:E1:C6:D9:E2
            X509v3 Authority Key Identifier: 
                keyid:03:DE:50:35:56:D1:4C:BB:66:F0:A3:E2:1B:1B:C3:97:B2:3D:D1:55

            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            Authority Information Access: 
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertGlobalRootCA.crt

            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://crl3.digicert.com/DigiCertGlobalRootCA.crl

                Full Name:
                  URI:http://crl4.digicert.com/DigiCertGlobalRootCA.crl

            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.1
                Policy: 2.23.140.1.2.1
                Policy: 2.23.140.1.2.2
                Policy: 2.23.140.1.2.3

    Signature Algorithm: sha256WithRSAEncryption
         77:31:1f:08:97:d7:12:9b:63:d2:11:65:08:a6:f6:65:b9:b8:
         fa:92:03:cb:a1:7e:e1:c8:0d:8c:3e:b4:1b:91:be:02:08:5e:
         9f:59:71:7b:11:fd:e0:c0:e3:8f:59:d7:a0:52:a1:d0:4b:54:
         d2:48:96:48:ef:77:e9:29:06:cb:43:10:a0:2f:3c:16:8e:2d:
         fe:1e:55:3c:ec:c3:98:ee:18:0d:23:e8:07:f5:b3:2d:c4:ab:
         57:73:5a:f6:1b:53:ba:fb:1f:fa:bd:8c:d3:51:51:20:47:5e:
         ef:7f:98:ab:17:42:ca:85:5c:9f:22:37:34:45:76:f2:43:5e:
         00:9e:22:83:ac:df:af:d1:e6:c7:13:17:e9:a4:69:64:4c:80:
         67:ea:b6:a4:7f:8f:7d:e1:51:fa:9e:97:67:ea:69:2e:b3:90:
         a4:1c:15:c8:ac:cb:4f:29:ec:7a:5c:5d:9f:8a:b8:d4:0c:bb:
         94:ee:d0:bc:cb:b5:a5:1e:08:cf:c4:41:03:0d:bd:06:c3:a0:
         f4:c8:37:55:4a:f1:bf:e5:79:42:35:ab:41:98:ef:fc:13:39:
         c3:bb:5b:eb:ef:63:7c:80:9c:c8:49:46:70:6b:a0:82:50:3e:
         d0:04:b6:ca:25:c5:c1:05:55:5f:f2:7c:2f:57:d1:af:95:6f:
         ac:6d:79:6b
```

We can find the exponent in the following line:

```
Exponent: 65537 (0x10001)
```

Afterward, we extract the signature from the server's certificate. Observing the certificate's parameters:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl x509 -in c0.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            07:7b:4b:d9:80:0c:26:af:af:d9:25:56:22:7d:c7:e7
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = DigiCert Inc, CN = DigiCert SHA2 Secure Server CA
        Validity
            Not Before: Mar 28 00:00:00 2022 GMT
            Not After : Sep 28 23:59:59 2022 GMT
        Subject: C = US, ST = California, L = Sunnyvale, O = LinkedIn Corporation, CN = www.linkedin.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:c0:e1:18:59:d3:66:15:ba:a0:c6:6b:d5:6c:32:
                    1c:31:7f:83:a5:6a:47:40:48:af:4b:47:37:d6:79:
                    d0:90:79:b6:41:ba:26:e5:30:59:b9:e8:8f:21:f6:
                    c8:5a:d1:2d:12:06:9d:84:e3:b2:5b:b3:1d:1e:0b:
                    47:1a:c6:d8:0a:aa:93:da:8a:eb:31:37:8f:74:74:
                    c4:ce:c9:c5:a3:17:6a:1e:24:e8:39:06:f1:a5:a7:
                    11:fb:88:dd:5c:d8:7e:fe:03:4f:3b:09:04:2e:53:
                    69:1d:01:bd:87:dc:73:99:2f:12:a1:ba:23:87:d0:
                    b5:44:5c:d0:6a:3e:55:19:92:14:21:c1:eb:90:02:
                    0b:50:6e:d0:80:50:ed:5f:1b:ca:67:9d:61:22:e5:
                    20:b1:0a:8f:09:75:5d:da:56:41:15:1d:03:3d:f8:
                    a9:91:52:ff:78:ba:b3:6b:3c:aa:94:c8:6d:ca:04:
                    95:fc:2a:3b:13:eb:83:0a:6d:de:dd:c3:c8:ee:6b:
                    41:6c:6a:14:53:73:8b:21:01:f6:92:e5:67:f0:22:
                    f7:3d:49:e8:64:cc:10:35:a9:6b:a7:36:76:85:82:
                    3f:96:f8:19:14:12:ef:93:9c:3a:62:6d:02:7c:97:
                    bb:e9:71:11:c5:db:9d:4c:aa:61:00:40:23:6b:c1:
                    81:59
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:0F:80:61:1C:82:31:61:D5:2F:28:E7:8D:46:38:B4:2C:E1:C6:D9:E2

            X509v3 Subject Key Identifier: 
                EB:A2:6C:F3:33:BE:79:0C:75:A5:1E:98:AF:C8:DF:DA:1E:46:17:F8
            X509v3 Subject Alternative Name: 
                DNS:www.linkedin.com, DNS:linkedin.com, DNS:rum5.perf.linkedin.com, DNS:exp4.www.linkedin.com, DNS:exp3.www.linkedin.com, DNS:exp2.www.linkedin.com, DNS:exp1.www.linkedin.com, DNS:rum2.perf.linkedin.com, DNS:rum4.perf.linkedin.com, DNS:rum6.perf.linkedin.com, DNS:rum17.perf.linkedin.com, DNS:rum8.perf.linkedin.com, DNS:rum9.perf.linkedin.com, DNS:afd.perf.linkedin.com, DNS:rum14.perf.linkedin.com, DNS:rum18.perf.linkedin.com, DNS:rum19.perf.linkedin.com, DNS:exp5.www.linkedin.com, DNS:realtime.www.linkedin.com, DNS:px.ads.linkedin.com, DNS:px4.ads.linkedin.com, DNS:dc.ads.linkedin.com, DNS:lnkd.in, DNS:px.jobs.linkedin.com, DNS:mid4.linkedin.com
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 CRL Distribution Points: 

                Full Name:
                  URI:http://crl3.digicert.com/DigicertSHA2SecureServerCA-1.crl

                Full Name:
                  URI:http://crl4.digicert.com/DigicertSHA2SecureServerCA-1.crl

            X509v3 Certificate Policies: 
                Policy: 2.23.140.1.2.2
                  CPS: http://www.digicert.com/CPS

            Authority Information Access: 
                OCSP - URI:http://ocsp.digicert.com
                CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2SecureServerCA-2.crt

            X509v3 Basic Constraints: 
                CA:FALSE
            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 29:79:BE:F0:9E:39:39:21:F0:56:73:9F:63:A5:77:E5:
                                BE:57:7D:9C:60:0A:F8:F9:4D:5D:26:5C:25:5D:C7:84
                    Timestamp : Mar 28 15:26:22.261 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:46:02:21:00:9D:61:07:DC:7B:81:B3:44:68:3F:FB:
                                9A:4D:FE:C4:7D:83:F1:D5:F8:C7:66:23:81:5B:A8:FC:
                                B0:F2:E4:81:3B:02:21:00:BD:2E:6A:7F:6D:7C:3A:72:
                                1E:4B:79:F4:0A:87:ED:25:13:5B:2E:79:2E:16:AA:3F:
                                4E:72:99:02:C5:1D:31:B7
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 51:A3:B0:F5:FD:01:79:9C:56:6D:B8:37:78:8F:0C:A4:
                                7A:CC:1B:27:CB:F7:9E:88:42:9A:0D:FE:D4:8B:05:E5
                    Timestamp : Mar 28 15:26:22.308 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:44:02:20:2F:E1:E3:41:7D:F1:B9:C3:47:C0:01:9B:
                                27:0A:EE:E5:20:D9:1B:12:C0:A8:12:4C:AD:A2:FC:D4:
                                74:53:22:33:02:20:5E:30:68:C5:5E:3A:E6:96:00:5C:
                                06:1E:3C:D5:C8:8C:E0:21:EF:C0:D2:8D:1F:23:04:00:
                                E9:A6:F1:FF:33:64
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : 41:C8:CA:B1:DF:22:46:4A:10:C6:A1:3A:09:42:87:5E:
                                4E:31:8B:1B:03:EB:EB:4B:C7:68:F0:90:62:96:06:F6
                    Timestamp : Mar 28 15:26:22.200 2022 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:21:00:EE:7E:D6:79:19:B2:03:2E:E0:18:4C:
                                B7:69:44:C5:6C:2F:0C:B3:41:F3:76:B9:AE:98:6A:15:
                                F6:47:14:21:23:02:20:44:6F:E0:85:F3:D1:01:DD:49:
                                4E:DF:02:74:F4:57:7F:2B:3C:E3:9E:FE:3B:18:B0:CB:
                                55:3D:9E:0A:CF:31:DC
    Signature Algorithm: sha256WithRSAEncryption
         d4:62:66:84:84:a3:a3:28:67:58:4f:f0:45:7e:c4:f4:9e:9c:
         70:00:18:91:32:6f:e2:c6:87:6e:f2:aa:c8:82:6b:24:e0:e1:
         3b:cf:ea:a0:bc:7e:d8:f4:a6:9c:fa:e8:3f:cb:ca:10:61:c3:
         17:71:6f:66:6a:60:67:ae:d7:75:7f:40:96:86:4b:dc:95:22:
         4a:50:8c:37:ad:d0:62:bc:00:8a:06:1f:11:ba:d9:a2:7f:5c:
         46:87:ed:20:6e:88:27:e4:5f:87:06:7f:4b:98:d6:87:c5:90:
         ed:e7:03:1a:9e:8d:a2:59:df:49:0a:1c:29:42:d0:f0:5a:22:
         9a:cc:7d:ae:20:57:fa:bf:95:1a:71:10:48:30:c5:4f:61:92:
         75:17:68:64:a8:ae:39:5d:16:dc:ca:5b:dc:f5:25:c0:5f:a2:
         76:75:ab:ce:a4:eb:34:ce:4b:4c:7c:53:2d:05:6a:47:17:38:
         fd:a4:aa:c0:c1:dd:78:18:17:01:6c:13:9f:25:75:40:25:01:
         f6:86:d0:8b:bb:eb:30:7f:58:48:d3:26:f2:3a:72:b0:2d:96:
         2f:4c:f3:bb:df:a5:3c:f3:c1:6b:d2:9d:3d:2a:d0:bb:48:ac:
         fa:cc:21:bc:23:51:8a:1a:05:51:11:bc:d0:9a:0e:83:bd:03:
         bd:5f:b1:b4
```

The final part name "Signature Algorithm: sha256WithRSAEncryption" holds the value we want. To delete the "space" and ":" from the data, we can first save the signature to a file named `signature`, and then use the `tr` command.

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ cat signature | tr -d '[:space:]:'
d462668484a3a32867584ff0457ec4f49e9c70001891326fe2c6876ef2aac8826b24e0e13bcfeaa0bc7ed8f4a69cfae83fcbca1061c317716f666a6067aed7757f4096864bdc95224a508c37add062bc008a061f11bad9a27f5c4687ed206e8827e45f87067f4b98d687c590ede7031a9e8da259df490a1c2942d0f05a229acc7dae2057fabf951a71104830c54f619275176864a8ae395d16dcca5bdcf525c05fa27675abcea4eb34ce4b4c7c532d056a471738fda4aac0c1dd781817016c139f2575402501f686d08bbbeb307f5848d326f23a72b02d962f4cf3bbdfa53cf3c16bd29d3d2ad0bb48acfacc21bc23518a1a055111bcd09a0e83bd03bd5fb1b4
```

Then we need to extract the body of the server's certificate. This is because a CA generates a signature for a server certificate by first computing the hash of the certificate, and then signing the hash. To verify the signature, we also need to generate the hash from a certificate. Since this hash is generated before the signature is computed, we need to exclude the signature block of a certificate when computing the hash. Finding out what part of the certificate is used to generate the hash is quite challenging, so we need a good understanding of the certificate's format. X.509 certificates are encoded using the ASN.1 (Abstract Syntax Notation.One) standard, so if we can parse the ASN.1 structure, we can easily extract any field from the certificate. We can do that with the following command:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl asn1parse -i -in c0.pem
    0:d=0  hl=4 l=2261 cons: SEQUENCE          
    4:d=1  hl=4 l=1981 cons:  SEQUENCE          
    8:d=2  hl=2 l=   3 cons:   cont [ 0 ]        
   10:d=3  hl=2 l=   1 prim:    INTEGER           :02
   13:d=2  hl=2 l=  16 prim:   INTEGER           :077B4BD9800C26AFAFD92556227DC7E7
   31:d=2  hl=2 l=  13 cons:   SEQUENCE          
   33:d=3  hl=2 l=   9 prim:    OBJECT            :sha256WithRSAEncryption
   44:d=3  hl=2 l=   0 prim:    NULL              
   46:d=2  hl=2 l=  77 cons:   SEQUENCE          
   48:d=3  hl=2 l=  11 cons:    SET               
   50:d=4  hl=2 l=   9 cons:     SEQUENCE          
   52:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
   57:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
   61:d=3  hl=2 l=  21 cons:    SET               
   63:d=4  hl=2 l=  19 cons:     SEQUENCE          
   65:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
   70:d=5  hl=2 l=  12 prim:      PRINTABLESTRING   :DigiCert Inc
   84:d=3  hl=2 l=  39 cons:    SET               
   86:d=4  hl=2 l=  37 cons:     SEQUENCE          
   88:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
   93:d=5  hl=2 l=  30 prim:      PRINTABLESTRING   :DigiCert SHA2 Secure Server CA
  125:d=2  hl=2 l=  30 cons:   SEQUENCE          
  127:d=3  hl=2 l=  13 prim:    UTCTIME           :220328000000Z
  142:d=3  hl=2 l=  13 prim:    UTCTIME           :220928235959Z
  157:d=2  hl=2 l= 112 cons:   SEQUENCE          
  159:d=3  hl=2 l=  11 cons:    SET               
  161:d=4  hl=2 l=   9 cons:     SEQUENCE          
  163:d=5  hl=2 l=   3 prim:      OBJECT            :countryName
  168:d=5  hl=2 l=   2 prim:      PRINTABLESTRING   :US
  172:d=3  hl=2 l=  19 cons:    SET               
  174:d=4  hl=2 l=  17 cons:     SEQUENCE          
  176:d=5  hl=2 l=   3 prim:      OBJECT            :stateOrProvinceName
  181:d=5  hl=2 l=  10 prim:      PRINTABLESTRING   :California
  193:d=3  hl=2 l=  18 cons:    SET               
  195:d=4  hl=2 l=  16 cons:     SEQUENCE          
  197:d=5  hl=2 l=   3 prim:      OBJECT            :localityName
  202:d=5  hl=2 l=   9 prim:      PRINTABLESTRING   :Sunnyvale
  213:d=3  hl=2 l=  29 cons:    SET               
  215:d=4  hl=2 l=  27 cons:     SEQUENCE          
  217:d=5  hl=2 l=   3 prim:      OBJECT            :organizationName
  222:d=5  hl=2 l=  20 prim:      PRINTABLESTRING   :LinkedIn Corporation
  244:d=3  hl=2 l=  25 cons:    SET               
  246:d=4  hl=2 l=  23 cons:     SEQUENCE          
  248:d=5  hl=2 l=   3 prim:      OBJECT            :commonName
  253:d=5  hl=2 l=  16 prim:      PRINTABLESTRING   :www.linkedin.com
  271:d=2  hl=4 l= 290 cons:   SEQUENCE          
  275:d=3  hl=2 l=  13 cons:    SEQUENCE          
  277:d=4  hl=2 l=   9 prim:     OBJECT            :rsaEncryption
  288:d=4  hl=2 l=   0 prim:     NULL              
  290:d=3  hl=4 l= 271 prim:    BIT STRING        
  565:d=2  hl=4 l=1420 cons:   cont [ 3 ]        
  569:d=3  hl=4 l=1416 cons:    SEQUENCE          
  573:d=4  hl=2 l=  31 cons:     SEQUENCE          
  575:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Authority Key Identifier
  580:d=5  hl=2 l=  24 prim:      OCTET STRING      [HEX DUMP]:301680140F80611C823161D52F28E78D4638B42CE1C6D9E2
  606:d=4  hl=2 l=  29 cons:     SEQUENCE          
  608:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Subject Key Identifier
  613:d=5  hl=2 l=  22 prim:      OCTET STRING      [HEX DUMP]:0414EBA26CF333BE790C75A51E98AFC8DFDA1E4617F8
  637:d=4  hl=4 l= 568 cons:     SEQUENCE          
  641:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Subject Alternative Name
  646:d=5  hl=4 l= 559 prim:      OCTET STRING      [HEX DUMP]:3082022B82107777772E6C696E6B6564696E2E636F6D820C6C696E6B6564696E2E636F6D821672756D352E706572662E6C696E6B6564696E2E636F6D8215657870342E7777772E6C696E6B6564696E2E636F6D8215657870332E7777772E6C696E6B6564696E2E636F6D8215657870322E7777772E6C696E6B6564696E2E636F6D8215657870312E7777772E6C696E6B6564696E2E636F6D821672756D322E706572662E6C696E6B6564696E2E636F6D821672756D342E706572662E6C696E6B6564696E2E636F6D821672756D362E706572662E6C696E6B6564696E2E636F6D821772756D31372E706572662E6C696E6B6564696E2E636F6D821672756D382E706572662E6C696E6B6564696E2E636F6D821672756D392E706572662E6C696E6B6564696E2E636F6D82156166642E706572662E6C696E6B6564696E2E636F6D821772756D31342E706572662E6C696E6B6564696E2E636F6D821772756D31382E706572662E6C696E6B6564696E2E636F6D821772756D31392E706572662E6C696E6B6564696E2E636F6D8215657870352E7777772E6C696E6B6564696E2E636F6D82197265616C74696D652E7777772E6C696E6B6564696E2E636F6D821370782E6164732E6C696E6B6564696E2E636F6D82147078342E6164732E6C696E6B6564696E2E636F6D821364632E6164732E6C696E6B6564696E2E636F6D82076C6E6B642E696E821470782E6A6F62732E6C696E6B6564696E2E636F6D82116D6964342E6C696E6B6564696E2E636F6D
 1209:d=4  hl=2 l=  14 cons:     SEQUENCE          
 1211:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Key Usage
 1216:d=5  hl=2 l=   1 prim:      BOOLEAN           :255
 1219:d=5  hl=2 l=   4 prim:      OCTET STRING      [HEX DUMP]:030205A0
 1225:d=4  hl=2 l=  29 cons:     SEQUENCE          
 1227:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Extended Key Usage
 1232:d=5  hl=2 l=  22 prim:      OCTET STRING      [HEX DUMP]:301406082B0601050507030106082B06010505070302
 1256:d=4  hl=3 l= 141 cons:     SEQUENCE          
 1259:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 CRL Distribution Points
 1264:d=5  hl=3 l= 133 prim:      OCTET STRING      [HEX DUMP]:308182303FA03DA03B8639687474703A2F2F63726C332E64696769636572742E636F6D2F44696769636572745348413253656375726553657276657243412D312E63726C303FA03DA03B8639687474703A2F2F63726C342E64696769636572742E636F6D2F44696769636572745348413253656375726553657276657243412D312E63726C
 1400:d=4  hl=2 l=  62 cons:     SEQUENCE          
 1402:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Certificate Policies
 1407:d=5  hl=2 l=  55 prim:      OCTET STRING      [HEX DUMP]:30353033060667810C0102023029302706082B06010505070201161B687474703A2F2F7777772E64696769636572742E636F6D2F435053
 1464:d=4  hl=2 l= 126 cons:     SEQUENCE          
 1466:d=5  hl=2 l=   8 prim:      OBJECT            :Authority Information Access
 1476:d=5  hl=2 l= 114 prim:      OCTET STRING      [HEX DUMP]:3070302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D304806082B06010505073002863C687474703A2F2F636163657274732E64696769636572742E636F6D2F44696769436572745348413253656375726553657276657243412D322E637274
 1592:d=4  hl=2 l=   9 cons:     SEQUENCE          
 1594:d=5  hl=2 l=   3 prim:      OBJECT            :X509v3 Basic Constraints
 1599:d=5  hl=2 l=   2 prim:      OCTET STRING      [HEX DUMP]:3000
 1603:d=4  hl=4 l= 382 cons:     SEQUENCE          
 1607:d=5  hl=2 l=  10 prim:      OBJECT            :CT Precertificate SCTs
 1619:d=5  hl=4 l= 366 prim:      OCTET STRING      [HEX DUMP]:0482016A01680077002979BEF09E393921F056739F63A577E5BE577D9C600AF8F94D5D265C255DC7840000017FD122A23500000403004830460221009D6107DC7B81B344683FFB9A4DFEC47D83F1D5F8C76623815BA8FCB0F2E4813B022100BD2E6A7F6D7C3A721E4B79F40A87ED25135B2E792E16AA3F4E729902C51D31B700750051A3B0F5FD01799C566DB837788F0CA47ACC1B27CBF79E88429A0DFED48B05E50000017FD122A264000004030046304402202FE1E3417DF1B9C347C0019B270AEEE520D91B12C0A8124CADA2FCD47453223302205E3068C55E3AE696005C061E3CD5C88CE021EFC0D28D1F230400E9A6F1FF336400760041C8CAB1DF22464A10C6A13A0942875E4E318B1B03EBEB4BC768F090629606F60000017FD122A1F80000040300473045022100EE7ED67919B2032EE0184CB76944C56C2F0CB341F376B9AE986A15F6471421230220446FE085F3D101DD494EDF0274F4577F2B3CE39EFE3B18B0CB553D9E0ACF31DC
 1989:d=1  hl=2 l=  13 cons:  SEQUENCE          
 1991:d=2  hl=2 l=   9 prim:   OBJECT            :sha256WithRSAEncryption
 2002:d=2  hl=2 l=   0 prim:   NULL              
 2004:d=1  hl=4 l= 257 prim:  BIT STRING
```

The field starting from the line `4:d=1  hl=4 l=1981 cons:  SEQUENCE` denotes the body of the certificate that is used to generate the hash. The field starting from the line `1989:d=1  hl=2 l=  13 cons:  SEQUENCE` is the signature block. So, the certificate body is from offset 4 to 1988, while the signature block is from 1989 to the end of the file. Getting the body of the certificate, excluding the signature block can be done in the following way:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin --noout
```

The output is stored in the `c0_body.bin` file. 

Next, we calculate its hash using the command:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ sha256sum c0_body.bin 
76f1d7a395bedd4008ce2398487b98e2dad6513cf28205b16c9ddbb781462c72  c0_body.bin
```

Currently we have fetched three different values:
- **CA's public key**:
  - Modulus (`n`):  `DCAE58904DC1C4301590355B6E3C8215F52C5CBDE3DBFF7143FA642580D4EE18A24DF066D00A736E1198361764AF379DFDFA4184AFC7AF8CFE1A734DCF339790A2968753832BB9A675482D1D56377BDA31321AD7ACAB06F4AA5D4BB74746DD2A93C3902E798080EF13046A143BB59B92BEC207654EFCDAFCFF7AAEDC5C7E55310CE83907A4D7BE2FD30B6AD2B1DF5FFE5774533B3580DDAE8E4498B39F0ED3DAE0D7F46B29AB44A74B58846D924B81C3DA738B129748900445751ADD37319792E8CD540D3BE4C13F395E2EB8F35C7E108E8641008D456647B0A165CEA0AA29094EF397EBE82EAB0F72A7300EFAC7F4FD1477C3A45B2857C2B3F982FDB745589B`
  - Public exponent (`e`):
    `0x10001`
- **CA's signature**:
  `d462668484a3a32867584ff0457ec4f49e9c70001891326fe2c6876ef2aac8826b24e0e13bcfeaa0bc7ed8f4a69cfae83fcbca1061c317716f666a6067aed7757f4096864bdc95224a508c37add062bc008a061f11bad9a27f5c4687ed206e8827e45f87067f4b98d687c590ede7031a9e8da259df490a1c2942d0f05a229acc7dae2057fabf951a71104830c54f619275176864a8ae395d16dcca5bdcf525c05fa27675abcea4eb34ce4b4c7c532d056a471738fda4aac0c1dd781817016c139f2575402501f686d08bbbeb307f5848d326f23a72b02d962f4cf3bbdfa53cf3c16bd29d3d2ad0bb48acfacc21bc23518a1a055111bcd09a0e83bd03bd5fb1b4`
- **Hashed body of the server's certificate**:
  `76f1d7a395bedd4008ce2398487b98e2dad6513cf28205b16c9ddbb781462c72`

To verify if the signature present in the server's certificate is valid, we have to get the content that was originally signed by the CA. If the result of this operation matches the `sha256` hash of the body of the server's certificate, then the signature is valid! Otherwise, it isn't! To achieve this, we developed the following C script:

```c
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main ()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *new_m = BN_new();

    // Initialize n, s, e, m
    BN_hex2bn(&n, "DCAE58904DC1C4301590355B6E3C8215F52C5CBDE3DBFF7143FA642580D4EE18A24DF066D00A736E1198361764AF379DFDFA4184AFC7AF8CFE1A734DCF339790A2968753832BB9A675482D1D56377BDA31321AD7ACAB06F4AA5D4BB74746DD2A93C3902E798080EF13046A143BB59B92BEC207654EFCDAFCFF7AAEDC5C7E55310CE83907A4D7BE2FD30B6AD2B1DF5FFE5774533B3580DDAE8E4498B39F0ED3DAE0D7F46B29AB44A74B58846D924B81C3DA738B129748900445751ADD37319792E8CD540D3BE4C13F395E2EB8F35C7E108E8641008D456647B0A165CEA0AA29094EF397EBE82EAB0F72A7300EFAC7F4FD1477C3A45B2857C2B3F982FDB745589B");
    BN_hex2bn(&s, "d462668484a3a32867584ff0457ec4f49e9c70001891326fe2c6876ef2aac8826b24e0e13bcfeaa0bc7ed8f4a69cfae83fcbca1061c317716f666a6067aed7757f4096864bdc95224a508c37add062bc008a061f11bad9a27f5c4687ed206e8827e45f87067f4b98d687c590ede7031a9e8da259df490a1c2942d0f05a229acc7dae2057fabf951a71104830c54f619275176864a8ae395d16dcca5bdcf525c05fa27675abcea4eb34ce4b4c7c532d056a471738fda4aac0c1dd781817016c139f2575402501f686d08bbbeb307f5848d326f23a72b02d962f4cf3bbdfa53cf3c16bd29d3d2ad0bb48acfacc21bc23518a1a055111bcd09a0e83bd03bd5fb1b4");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "76f1d7a395bedd4008ce2398487b98e2dad6513cf28205b16c9ddbb781462c72");

    // Verify Signature: Calculate s^e mod n
    BN_mod_exp(new_m, s, e, n, ctx);
    printBN("Signature Verification:", new_m);

    // Truncate hash value to 256 bits
    BN_mask_bits(new_m, 256);
    printBN("Hash Value:", new_m);

    if(BN_cmp(m, new_m) == 0)
        printf("Signature matches!");
    else 
        printf("Signature doesn't match!");

    return 0;
}
```

Compiling and running it:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ gcc task6.c -o task6 -lcrypto
                                                                                                                    
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ ./task6
Signature Verification: 01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D06096086480165030402010500042076F1D7A395BEDD4008CE2398487B98E2DAD6513CF28205B16C9DDBB781462C72
Hash Value: 76F1D7A395BEDD4008CE2398487B98E2DAD6513CF28205B16C9DDBB781462C72
Signature matches!
```

We can observe that the first output ("Signature Verification") gives us the message that was signed but is padded, as we will further detail. To fetch the 256 bits of the `sha256sum` we used the `BN_mask_bits` function that will truncate the hash value. We can then see that the signature is valid, as the hash of the server's certificate is indeed the same as obtained.

As a side note, we can confirm this output is correct by following some steps:
- Obtain the intermediate CA public key. We can do this by typing:

```
openssl x509 -pubkey -noout -in c1.pem > CA_pub.pem
```

- Change the signature in the server's certificate to binary format:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ cat signature | tr -d '[:space:]:' | xxd -r -p > new_signature.bin
```

- Verify the hash of the body of the server's certificate using the following command:

```
┌──(kali㉿kali)-[~/Documents/seed-labs/category-crypto/Crypto_RSA]
└─$ openssl rsautl -verify -inkey CA_pub.pem -in new_signature.bin -pubin -raw | xxd
00000000: 0001 ffff ffff ffff ffff ffff ffff ffff  ................
00000010: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000020: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000030: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000040: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000050: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000060: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000070: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000080: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000090: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000a0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000b0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000c0: ffff ffff ffff ffff ffff ffff 0030 3130  .............010
000000d0: 0d06 0960 8648 0165 0304 0201 0500 0420  ...`.H.e....... 
000000e0: 76f1 d7a3 95be dd40 08ce 2398 487b 98e2  v......@..#.H{..
000000f0: dad6 513c f282 05b1 6c9d dbb7 8146 2c72  ..Q<....l....F,r
```

We can indeed see that this output matches the output's first line of the execution of the C script of this task, meaning the last 256 bits are the hash we are looking for. With this, we prove that our code is correct and that the server's certificate was indeed signed by the intermediate CA.

Also, note that the reason why this padding is a bit weird is that it follows the PKCS#1 1.5 format. So, when signing a message, you take the hash of the message you want to sign, as already explained, and then you encode it using the following format:

```
X'00' || BT || PS || X'00' || D
```

Here, `BT` is the block type, X'00', X'01', or X'02'. `PS` is the padding of as many bytes as required to make the block the same length as the modulus of the RSA key. Padding of X'00' is used for block type 0, X'FF' for block type 1 (our case), and random and non-X'00' for block type 2. The length of `PS` must be a minimum of eight bytes. Lastly, `D` is the key, or the concatenation of the BER-encoded hash identifier and the hash value. This BER-encoded hash identifier is a very complex binary encoding of the hash type and length. In our case, we indeed have the BER-encoded hash identifier plus the hash value.

After the padding, we sign the encoding using the RSA algorithm. 