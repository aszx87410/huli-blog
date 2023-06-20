---
title: Is it meaningful to encrypt passwords when calling APIs on the website frontend?
catalog: true
date: 2023-01-10 09:10:44
tags: [Security]
categories: [Security]
photos: /img/security-of-encrypt-or-hash-password-in-client-side/cover.png
---

Recently, someone posted a [post](https://www.facebook.com/groups/f2e.tw/posts/5689037364466915) in the Facebook frontend exchange community, which he saw a problem: [Is there a problem with passing account and password json plaintext when logging in to the API?](https://ithelp.ithome.com.tw/questions/10211642), and wanted to know everyone's opinion on this issue.

Most of the answers below think that "using HTTPS is enough, there is no need to implement an additional layer of encryption, and there is not much meaning."

To be honest, I used to think so too, and there have been similar discussions in the community in the past. At that time, I thought that since HTTPS already exists, and the purpose of HTTPS itself is to ensure the security of transmission, why do we need to do encryption ourselves?

But after being exposed to information security for the past year or two, my thinking has changed. I think it is meaningful for the frontend to encrypt passwords before transmission, and I will explain my reasons in detail below.

<!-- more -->

## Define the problem

Before getting into the topic, I want to define the problem more clearly, so as not to compare two completely different situations. Under the original post, there are many comments discussing different issues. It is important to define the problem clearly.

First, the objects we want to compare are:

1. Pass the plaintext password directly when calling the login API without doing anything under the premise of using HTTPS
2. Encrypt the password before calling the login API under the premise of using HTTPS, and then send it to the server

It should be noted here that "both situations are HTTPS", so if you want to talk about "no need to invent new technologies" or "inventing new encryption methods yourself is not safer" and so on, they are not applicable under this premise.

Because the transmission layer still relies on HTTPS for transmission, there is no new way invented at this stage. I just add an extra layer of encryption to the transmitted data at the application layer.

Next, regardless of the cost, let's look at the advantages and disadvantages from a technical perspective (the cost-related issues will be discussed later).

Finally, the scenario I want to deal with here is "encrypting passwords" rather than hash. This is because I think the situation of hash is more complicated. I want to use encryption as an example first, and this encryption is "asymmetric encryption".

That is, we can imagine that there is already a public key stored on the client side (of course, everyone can get it), and before sending the request, JavaScript will encrypt the password with the public key and then send it out, and the server will use the private key to decrypt it. After getting the password, hash it and store it in the database.

In summary, the problem I want to deal with in this article is: "After using HTTPS, what is the difference between encrypting the password before calling the login API or doing nothing?"

And we can divide the answer into two parts:

1. Assuming that HTTPS is cracked, what is the difference?
2. Assuming that HTTPS is secure, what is the difference?

## What is the difference if HTTPS is not secure?

First, let's think about what kind of situation will cause HTTPS to be insecure, and which parts of the system does the attacker control?

It can be briefly divided into four situations for discussion:

1. The attacker controls the entire computer and trusts malicious certificates
2. The attacker successfully executed a man-in-the-middle attack
3. The attacker can listen to requests at the network layer and use vulnerabilities to obtain plaintext
4. The attacker directly attacks the HTTPS server

### The attacker controls the entire computer and trusts malicious certificates

If it is this type of situation, it doesn't matter whether there is encryption or not, because the attacker has other better means to obtain your password.

### The attacker successfully executed a man-in-the-middle attack

What if it is "the attacker successfully executed a man-in-the-middle attack (Man-In-The-Middle)"? Your computer is fine, but the packet is intercepted by the man-in-the-middle during the transmission process.

Under this premise, the plaintext password can be directly obtained without encryption, and if there is encryption, the attacker can only obtain the encrypted ciphertext instead of the plaintext. However, it should be noted that since it is called a man-in-the-middle attack, the attacker can also send forged responses to you in addition to listening to your request, and replace the part of the frontend used to encrypt the password.

Therefore, regardless of whether the password is encrypted or not, the attacker can obtain the plaintext, but if there is encryption, the cost for the attacker to obtain the password is higher (need to find where the encryption is, and then change that part).

### The attacker can listen to requests at the network layer and use vulnerabilities to obtain plaintext

The difference between this situation and the previous one is that this one can only read, not write. If there is a way to decrypt the request packet, you can see the plaintext.

So if the password is encrypted first, the attacker cannot obtain the plaintext of the password.

It should be noted here that although the plaintext cannot be obtained, the attacker can still log in to your account by resending the request (assuming there is no other mechanism), so your account is still stolen, but the attacker does not know the plaintext of your password.

Does this make a difference? Yes!

Assuming that someone knows your password in plaintext, they can use your account and password to try various services. If you use the same account and password for other websites, they will also be compromised (commonly known as a credential stuffing attack).

Therefore, encrypting passwords in this situation is obviously more secure.

You may ask, "Under what circumstances can an attacker obtain plaintext HTTPS?" Here is a presentation by the US Department of Health and Human Services (HHS): [SSL/TLS Vulnerabilities](https://www.hhs.gov/sites/default/files/securing-ssl-tls-in-healthcare-tlpwhite.pdf), which records some vulnerabilities that SSL/TLS has had in the past, so it is indeed possible to obtain plaintext HTTPS.

However, knowing that "it is possible" is not enough. The question should be "Is the probability high?" When discussing risks, the severity and seriousness of the risk are usually used to determine how to deal with the risk.

The answer is "the probability is very low." The vulnerabilities in the presentation are from 2017 and are related to some old and problematic encryption algorithms. In addition, many other conditions must be met to execute the attack, so I think the probability is indeed very low.

For example, DROWN (Decrypting RSA with Obsolete and Weakened eNcryption), published in 2016, requires the server to support SSLv2, and the attacker must be able to capture the encrypted TLS connection. After meeting these conditions, a lot of calculations can be performed to decrypt one of the 900 connections, and the computational cost at that time was $440, about NT$13,000.

In summary, for this situation, we can say:

> Assuming that the attacker can obtain plaintext HTTPS, it is indeed safer to encrypt at the application layer, but the cost of meeting this assumption is very high, and the probability is very low.

### Attacker directly attacks HTTPS server

I am referring to the Heartbleed vulnerability that occurred in 2014. Attackers can read the server's memory through the OpenSSL vulnerability.

This situation is similar to the previous one. If the client encrypts the password first, what the attacker reads on the server is the encrypted password, and they do not know what the plaintext password is.

Therefore, the conclusion is the same as before, encrypting the password is safer.

## Summary

We just discussed several situations where "HTTPS becomes insecure." From past cases, we know that "HTTPS becomes insecure" is possible. If the attacker can read plaintext transmitted through HTTPS, encrypting the password at the application layer can prevent the attacker from obtaining the plaintext password, making it safer than not encrypting it.

If we want to be more detailed, we can approach it from two dimensions: severity and possibility.

In terms of severity, whether the password is encrypted or not, as long as the attacker can obtain the content of the request, your account has already been compromised. The only difference is whether the attacker can obtain the plaintext password. If they can, they can execute a credential stuffing attack and try the password on more websites.

The possibility is the possibility of "plaintext HTTPS being obtained." From past experiences and research, although it is possible, the probability is very low in 2023.

Therefore, our conclusion at this stage should be:

If the attacker can bypass HTTPS and obtain plaintext requests, it is indeed safer to encrypt the password at the application layer, but it should be noted that it is very difficult to meet this premise, and the probability is extremely low.

## Assuming HTTPS is secure

Next, we will discuss the second situation, assuming that HTTPS is secure, and no one can see the plaintext content in the middle. This should also be the premise that most people assume in the comment area.

What are the risks in this situation?

There is a risk that occurs in real life and has indeed occurred, which is logging.

As a front-end engineer, it is reasonable to add some error tracking services to the front-end. If we directly implement a mechanism of "record the request whenever the server returns 5xx," if the login API encounters this situation, you can see the user's plaintext password in the log.

Moreover, not only the front-end but also the back-end may have similar mechanisms. When encountering some problems, the entire request is written to the log file for future viewing and debugging. If you are not careful, the password may be written in it.

In this situation, it is obviously beneficial to encrypt the password on the client-side. In these error handling logs, the recorded password will be ciphertext, and unless you have the key, you will not know the user's password.

I found an article on the Internet that has the same argument as mine: [The case for client-side hashing: logging passwords by mistake](https://www.sjoerdlangkemper.nl/2020/02/12/the-case-for-client-side-hashing-logging-passwords-by-mistake/), which includes many reference links to cases where major companies accidentally recorded plaintext passwords.

Then there is a small point to mention. The article above is about "hashing on the client side", which is slightly different from the "asymmetric encryption on the client side" that I set at the beginning of this article. Hashing is a bit more secure and ensures that no one on the server really knows what your password plaintext is.

Anyway, encrypting or hashing the password on the client side can prevent the user's password plaintext from accidentally appearing in the log, which is obviously an additional advantage.

## Encryption or Hashing?

At the beginning of the article, I mentioned that the situation with hashing is a bit complicated, so I first set the scenario to "asymmetric encryption of passwords" before transmission on the client side, because for the examples I mentioned above, the difference between these two scenarios is not significant.

For example, if HTTPS is intercepted in plaintext, no matter whether you perform asymmetric encryption or hashing on the password, you cannot obtain the plaintext password without obtaining the server-side key.

So why is the situation with hashing a bit complicated?

Suppose we first hash the password on the front end and then transmit it to the back end. Should the back end store it directly in the database? If it is stored directly in the database, when the contents of the database are exposed one day, the attacker will obtain these hashed passwords.

Usually, under the premise of salting and strong hashing algorithms, the security of hashed passwords can still be guaranteed, but in this case, it becomes very insecure.

Because the content transmitted from the front end to the back end has been hashed, the attacker can directly use the hashed password to log in without knowing what the plaintext is. Although the plaintext is protected, the security of the original hash is lost.

Therefore, if you want to do client-side hashing, the server-side must also do it again after receiving it. In this way, even if the database is stolen, the attacker cannot use the hash in the database to log in directly.

Some people may be curious like me: "Isn't doing two hashes less secure?" We can see how Google says in [Modern password security for system designers](https://cloud.google.com/static/solutions/modern-password-security-for-system-designers.pdf):

> Have the client computer hash the password using a cryptographically secure algorithm and a unique salt provided by the server. When the password is received by the server, hash it again with a different salt that is unknown to the client. Be sure to store both salts securely. If you are using a modern and secure hashing algorithm, repeated hashing does not reduce entropy.

It looks okay, there is no problem.

In short, the safest but more complicated solution seems to be to hash once on the client side, and then hash again when throwing it to the server and store it in the database. In this way, it can be ensured that:

1. When HTTPS fails for various reasons, the attacker cannot obtain the plaintext password
2. On the server side, no one knows the plaintext password of the user
3. The plaintext password will not be recorded in the log due to human error

So if it is really more convenient, why isn't anyone using it?

## Who is hashing or encrypting on the front end in real life?

When I first encountered this problem and said "why no one is using it", it was actually just "I haven't encountered anyone using it myself", but I don't actually know how the login mechanisms of those well-known websites are implemented.

Therefore, I went directly to see the login mechanism of several well-known websites. Let's take a look at the results together. For convenience of viewing, I removed all content unrelated to account passwords.

When I was testing, I basically used test or test@test.com with a simple password like 1234 for testing, and then observed the content of the request.

Let's start with FAANG!

### FAANG

#### Facebook

API URL: https://zh-tw.facebook.com/login

Request content:

```
email=test@test.com
encpass=#PWD_BROWSER:5:1673256089:AbJQAJUvZZNvh2dZbeDqdu9dp7HWwyHOl3+0sCGjiHMMjvYdxJokpdHE/O+E5LIbnakRmDWQfV40ZaB31MaNXFYo1b+RI+LHh6MAdDPa4PJ+BesDp4u8B4F4diVQ+q7idbEhT5wTNaU=
```

Unexpectedly, Facebook is a website that implements front-end encryption! The Base64 at the end is not directly Base64 the password, but Base64 the encrypted password. The decoded result is like this: `\x01²P\x00\x95/e\x93o\x87gYmàêvï]§±ÖÃ!Î\x97\x7F´°!£\x88s\f\x8Eö\x1DÄ\x9A$¥ÑÄüï\x84ä²\x1B\x9D©\x11\x985\x90}^4e wÔÆ\x8D\\V(Õ¿\x91#âÇ\x87£\x00t3Úàò~\x05ë\x03§\x8B¼\x07\x81xv%Pú®âu±!O\x9C\x135¥`

#### Amazon

API URL: https://www.amazon.com/ap/signin
Request Content: `email=test@test.com&password=1234`

#### Apple

API URL: https://idmsa.apple.com/appleauth/auth/signin
Request Content: `{"accountName":"test@test.com","password":"1234"}`

#### Netflix

API URL: https://www.netflix.com/tw/login
Request Content: `userLoginId=test@test.com&password=1234`

#### Google

API URL: https://accounts.google.com/v3/signin/_/AccountsSignInUi/data/batchexecute

Request Content:
```
f.req=[[["14hajb","[1,1,null,[1,null,null,null,[\"1234\",null,true]]]]
```

It seems that only Facebook has implemented it among the FAANG companies.

Then I suddenly became curious about whether other commonly used services have implemented it, and I posted the results below.

#### GitHub

API URL: https://github.com/session
Request Content: `login=test@test.com&password=1234`

#### Microsoft

API URL: https://login.live.com/ppsecure/post.srf
Request Content: `login=test@test.com&passwd=1234`

#### IBM Cloud

API URL: https://cloud.ibm.com/login/doLogin
Request Content: `{"username":"test@test.com","password":"1234"}`

It seems that only a few have implemented it. What about cybersecurity companies? Do they have their own implementations?

### Cybersecurity Companies

#### Kaspersky

API URL: https://eu.uis.kaspersky.com/v3/logon/proceed
Request Content: `{"login":"test@test.com","password":"12345678"}`

#### Trend Micro

API URL: https://sso1.trendmicro.com/api/usersigninauth 
Request Content: `{"email":"test@test.com","password":"12345678"}`

#### Tenable

API URL: https://cloud.tenable.com/session
Request Content: `{"username":"test","password":"1234"}`

#### Proton 

This may not be a cybersecurity company, but I suddenly became curious about how privacy-focused Proton does it, and I found that it seems quite complicated.

When logging in, the username is sent first, and some things that look like keys are obtained.

API URL: https://account.proton.me/api/auth/info

```
{"Username":"test@test.com"}
```

```
{
  "Code":1000,
  "Modulus":"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nu9K5yr97L9VV2ijOSI62tJcewUiRhQa8qJa24baNpGyw0lf3JLiF4fxUHqTErwF9UdoxE0z4Kb147naphylBFddyKsjhzHNcxk2rBw9haiPxD69BrVYm0n+LVlPqmjXFF7btr1H7oqHGX4b4Dy9omL/KaZz/Dco2NEhw0UBhEZbTAs6Ch01ur9XLbSOI7yb6MRsqCehfy82gDTdbPtXvqQsQjg5XoC2Ib2qTYFaU/24mq/gOaMbVuAGX0hBYzr5NpN9ol2XCdHOLg28Xe90+kisg39VV04axy7Ndvh489dC1CxjcWSSpXd6cPJyOn/HH9aPeTZeucBllRGbPgwR6/w==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD1GwEAoC91QCSfXPEuWM13NZvy\nvL9NQIABuSrVOvgJwMhUTnUBAPb4zbIdTYFOQNrPLvonJt2mmRNy4lGcW7uN\n5yHzJ18J\n=Oykn\n-----END PGP SIGNATURE-----\n",
  "ServerEphemeral":"DY6eRYM1bqYZZ5jzZFdWv88tKYP2PnS0y4A+f7/eqMXj8wB2VefV2kfIDrZ5AorWfDzBq4wMtNG2k5dzbT2qWppzpvltrSl2Nm4i8eWIRVxXWHl/46dGuPXFHUcXBNMP3XEQvft0YEbHOPO9Es0RZRaObV5XPFyx6kzOJxXc1tIt4PfbhODMfsAoy/yxt6eLN3HUiORCBOvzsH2sfG99Gx1YSAe3GL6g/K+bdg59eglueXRESoB0/VFRsvQevi9nVXx/JZNTG0U4BBUOlMjpYYMgEP6eQgZZ/09ZPYD3a2tW65mSnNt6lSDfwiKj02UuDqymTvj7mYm44T0SuAocwg==",
  "Version":4,
  "Salt":"dI7OcD+K4rGPBA==",
  "SRPSession":"3fa6224285409b6af07c811971e05341"
}
```

Then, when entering the password to log in, a request like the following is sent, which also looks quite complicated:

```
{
  "ClientProof":"I9Nfd0Nd3OzODf2nt9zLxFHWogEwfRje8zjoeZnblyLfyzz23uXTjJ4qgRFomjIEEtZrlM1jTQa4wRIMGIIV7E6pMqq8c6wcc2tegP4Xt76S0EbnVtE1F9i0Wj46aCPUM0Mha3Zmgi9LKerrGlaftr2FBedjPFT9rPrbLqRQcFNMD33tn69gD/p28q4RAr3/7d/tz7TYhytD5oxCAUwrkqiZOi0kg//2mUJ9YNT2nWcgqUERoaU51NbNMcaPnMteEe1PlIJdiQbvNa5K07u8rk7itpBrGW2FP26bREp0UMTzNYM5HcDDkmp4dp9GoBjFJL9n0THUdt/oRRJ/Enj5WQ==",
  "ClientEphemeral":"D013N7FXYHylqMeWa6ctJIv3J4uF1hqodyYfw6O+Sj7MZOIB+wksfgk/nkXCmRxQhuSYwqwMJIpyFD3MEolOZAHMU2n6HQlxe9A4KbrE4gk3UiGwfgcZDmFejTmMMxfWhf4zO2Z1fBbohreqwwN0mz3AqqsfE5dsDh3LEfkiJB449YGZfHeUHyIzS1jTmnx/8l6uVSKwJDCJelVFYKMXrxVt0ltcGRoYD92MUj82kR0am+BN4+djHyYYXuwuIYArnTW4kDP3T2yCIAMVgZnFaUCc2gfynt40mQP4q87jmMELOl8TDIDo5iKyH4gJc/470qIuIyj4ffVLiZ7t8S+kcw==",
  "SRPSession":"3fa6224285409b6af07c811971e05341",
  "Username":"test@test.com",
  "Payload":{
    "qcA_CRYU6gSyHWdn":"c6UZSKPo4Sfm/3+DvQN72TTxyj+/TplKT9edDiUI5wMfGUsoJs9FGerOtkoW8T49r7KOvqHkzS2+M2v8ra7J9l5kSf5jgC9ZvgZ8Ja5Xgg02nxgAABydOirGLoL4htFsYVtwLrNg8NeSEanLwYLCVaSqkjANRJks0eaKpUOd8xRhCFtUH/GCbyg27oZfzDsqKXemKprOUsOh42NTqzEmruAkxs2x8mUsLy/vXptVAdaiJLrsSRqD0YBGjvOp4W2/0g6V2zfedJpJEzVwtSi1vXTC5bwxmEJlYdV9AiQECogAAJFxLQi7JjtmgFe4tNcv97JD0B8giZ6XS35swjz0vz0mOjVBUwmiDa8n54Y5kBaAoZe5pijdp2S4SOcRAknDIcD1nf0v7oSMOE9WtH/sa+XI1D2s5lFKo/iInf7r5R9src2hHFoy0b2XT0oCfLPwFX87yjaKbf7bbkjByx/3dOgzEliAkS6nHK+fmeDDVM4EoZqVSKZHLg3QTcg4DKaICyDsotALr2UqI/ARzkX4yhAXz5xHFaxl6hWAKLJPJcgk6il6oX0s0PCBNSY0Fi3vbQvXD4WalUx+LBNto6CUqeAIzVuAh8sCubzufoSORypE5WqfnuJzAlZ9sMEjaQycuRi497aV3jmjgx53UwO0OiZGxDTEMFBcov4P0g1blZ4vxmULhZU0RfdP31udLr6GTCAB90CM6Vk9w9CsYM+hmo3+JpEAtIVgLVVqcPikTbV+yaOJ1RknxBf3g06kTl0LQ+zBV6pG2rFVi8G4XT9L4FsIgxTNsl/ryzs8vJU7K+HvyE1Lp2pAXrfcju7TAIqK/FOXvp1c8Ay9O6d4fmd/PZalnRDv5mQ6Gmd6JSNzNh6i6AibBuF13w3OBaulY3FGNU/cH/AXLBIqjSzf/OySwkKkC9HBurSs3D0zqcH9BwUpmPEL8jbc8yPE+hPAim+tDo1BXCQNClxgGLaI6FXkuCiQ4AHiKsq0xs5b3WAFzcvBv1rc003RWxRegH/2teIooKU9w1kDPQRaK8/rIYe8u+BlBeZq4OwCXxx56JHfmTxtJwBi95KqsWzLGtY3ILcb+/XkzSRmE2TWbkW1IXzRsl8F6NSJj7JnHA3UrQf4hxuwbaYxpKJrcHuHc8e1wxqXrUSKooCOUxwSBgxvLLT37eaByNTxpfWomxIsH671wuydnmMedWyNIqyaMtxBORuiWUiG4jbMC2BjrVptXJ7VWigf3Vy5OQlMOyTx8tLWi1qZODYyywMBAvHYQlFfSqmIrm4y4dmK/srJE/+daEnNS+kWF48Jm/rQORO5AUwqWL+Lefg9pchcL1BnHOANcviO8pAkxLo8TiK7VLKI5/xUsZQoQSlhRt27zMF+sIv+exY375HApiY+a1VQ6OqE4Nvba7O8ETLoLFg4a8Aj+W8erXFHW5F0vVIRphAve9orM4QYnAmOigFAiLb0Pxx124wUjFR9s5oP98hAtNL/t+uGAXrb0oxiCfyHb9wa2Qb0x6o9FpuBIc5ZXId+cEXEvOdqhnUQ7ZuOi/fX81hlqgUaiD/A6P+zjAcREXdktd+hrhSXwCIKSBkp/mNymnalQKJkLaNVT+W2sOWqXxTSTIytCQx36xABcj1BXRApntob6Qvche8QJLTjzr9bDpn+Mo59N9PSU51DPIj5Avre6ChTHEQvjz9s1IM2XroBX/KFBnPj33aYQZyov4uxrVXxic+fiY+fLMF8x1ut/eNWeQU6fn+rU5PEGQ9bbAsjVBZYA5H93ROhO5lnSxoEk5PHkgQ9WpxueckPjJIUGAs+O8QMRFicccfKjhNIc32rXTqbVqLyoz62riDn8Y18MUBoeI8ORyqZOKEEBFsi5dwqoq8t82NFdx5LFjsLdk4RmMXZ2uygNLk8gH2Yyfu3iOQS2bKtNCW42Xmo66Xu5kt8NwAneYQK0mTn6HUv94K10J4hY+Q="
  }
}
```

Supplement: After being reminded by someone in the discussion thread, I found out that this is a protocol called SRP (Secure Remote Password), and Proton provides a [ProtonMail Security Features and Infrastructure](https://proton.me/static/9f5e7256429a2f674c943c5825257b82/protonmail_authentication_excerpt.pdf), which records their security measures and mentions this mechanism.

It looks quite complicated and will take some time to study. For those interested, you can refer to: [SRP — A More Robust Login and Data Transmission Protection Protocol](https://blog.amis.com/srp-1f28676aa525)

Although it is more secure, the cost should be higher.

### Exchanges and Banks

After reading the above cases, I found that only a few have implemented it, so I was curious whether encryption-focused cryptocurrency exchanges and traditional banks have implemented it.

#### Binance

API URL: https://accounts.binance.com/bapi/accounts/v2/public/authcenter/login

Request Content:

``` js

{
  "email":"test@test.com",
  "password":"fe2e6b4138fcd7f27a32bc9af557d69a",
  "safePassword":"d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
}
```

#### Coinbase

API URL: https://login.coinbase.com/api/v1/authenticate-credentials

Request Body:

``` js
{"email":"test@test.com", "password":"1234"}
```

#### Kraken

API URL: https://www.kraken.com/api/internal/account/settings/tfa

Request Body:

``` js
{"username":"test", "password":"1234"}
```

#### Esun Bank

API URL: https://ebank.esunbank.com.tw/fco/fco08001/FCO08001_Home.faces

Request Body:

```
loginform:custid=A0000...
loginform:name=mxagZmaqygDx0XX6784Svw==__NgZQcFfAx+lQmPza2eNpOA==
loginform:pxsswd=8,lIRnuUxw/yStOt9QIYG2U3Gn2XkG03x4Ey/UU6JGtsbUxfRXoAv9CjE3EWerDN3tfx3dD/B3ChLAPMSG2BA3jMXUCZC06y8UbQ5isKc9fCWZSSZAWWcOmJ7LdXw1ZhjV55hpw1upvAr9WEmZ0XF6x7if+dBxJ4KZ00d83qA9eA+3VaSk+JLhN8/CFBfTKTfJEs3PDNsm12XzRUBb4YE1aPQosVX10mdvh3zY5lmkrKuq8gnuImEf3oLOk4EF3eVpr6jJiFzMKlHybvGdtKYS25+pgTS68wn3v023barbSmgivcv5atm0XsyXWDY2dKEtdQz+7A6R+AB0bExbQlRjqQ==
```


#### Cathay United Bank

API URL: https://www.cathaybk.com.tw/MyBank/Quicklinks/Home/NormalSignin

Request Body:

```
CustID=A000...
UserId=DC0C6E52BE2A2354C53401207F220F1B
Password=8cf5e1977f149ed0362629007a7f91d0efc7b12cb1895ba701c528a12b38d12f8148ca03ee671fe25d2a3a807be980f7728566e359a675734ce046899b147658388bb60f9b900e2ccc9adac280b54b5f2e28cb7eee1b634d0e1ed1c0c0c598c350f61eb003405559331a7f047add7289466bf42cfd5b9e774a1fa116af4fd7050adb8f174d42a8e2098a014a788bd2ffae3bf4ff7a8d8d7e2e8068402fda395da41be6e5d32f2d32cbee2afc26e82c58b60357b5cb186a3b9cf69df2deb9da8c9fde45337935180cb4e177109413d7a758d38bfc8334a4509d8d8fb6a37080f0e0086b4a5ef68f7809ca2ef97183b7f66d996873bb7dbfcee61d2da424b8b968
```

#### CTBC Bank

API URL: https://www.ctbcbank.com/IB/api/adapters/IB_Adapter/resource/preLogin

Request Body:

```
{
  "rqData": {
    "custId": "A00....",
    "pin": "878dbee38bbb4d77a30ee128f55f7bfe2169e45380d62a75453d3ca175e8ce8b|43d0499147b62adeec4eef3c77d33171b4569d0bdf7bbbe2b8b9bde3d30a26aba69aadfb28dfbaa9a997a0ccf668aaab0b6da582275175272172569a58a60bbfc5ac3a8c6862ce31f86247d7c1adf307e363c0f251fb88c4d39afa6ed0ca0a49e053f4f90000fa77b4e78beaead72ebdf52a13ecb4f20ae9a532947fad8156d5ec69d6763243364e71659079e469d1e01d0c384b0c71f4e9e524890227d82a51a340ef0b48638e05e347d75cb93d4a825a2bce6a90ef47f512351ee2d0d1ea17fb8afd521e427578603ea775191711f81d8dcb18e46b72daf3a49a60e50d12d3887e3bafab3758730f7fb0276373ebe1da01a03162ec8e73a202091a51b7f88d",
    "userId": "bfcdb9b2d6896a3bfb4a6542e8fb2689486d000b11bdc0c7bc336a6534aec74c|1b1a758bb26702bc0ac7cd660da2a72866f2cfdcf3668f2d39a5f8b006854f52a08f418b0a460b36374f95b7a310d73ea9994788698041f524ecd1f153448ab5d51f901a9a08ac2a9ee04c5c273ecb9d4ec1b6a62e9696c6126271e2f8c334fe17ce8b8538139363b90be75c1130cb251ec240bd26c920b52f5be9fc59094ce7d935d826242d69dc1ff7047a5abbf11d3c7de639a14bb10230912903cd948c05b3b3cb0cdb100f979640e291774e623a7109bde7b55bb8a6a373c0ca12820b072132ea61c845e60e26d09c7ee0fe23f7de286cbccb067a86fd1985c5b455f9ae46ce24dc8f52bcb05c205d6a462345162ae82c35e045bf3fd43a297c3edcfe17"
  }
}
```

#### Bank of America

API URL: https://m.globalcard.bankofamerica.com/pkmslogin.form

Request Body:

```
username=fcc63767-1a43-4cc6-8c3e-1346350b5274
password=12345678
```

#### DBS Bank (Singapore)

API URL: https://internet-banking.dbs.com.sg/IB/Welcome

Request Body:

```
USER_LOGON_NAME=test123
ENCRYPTED_PIN_BLOCK=A8C48B7572A1A53C5A66E9B43365027C7FBF14BF461F480A46781E49648A8F70271A29C374F86FCD55A76ED17B2284B47C799B74475F29749D68631FF7E322177A21EEE8C41D8950638A2828C34A2653D7C9F69F5DA568E42D64CE89FCE8F024217B235835E6F8BC3C536F56361EDF459AFCE9A512BDBACAB2D25423209996C2E84A18EA8446685DAF9FAD4B1D6D8DF0F378EC27D9A81AD4D1A2B91BA3CFD838140A9BD48AD8D38D33B0093110BD1CA2C76F3DE4CBD969A9B0260DB890E9B1A99DC1193BFE9A1EDB3E56F71CB1CD8630558B242B040F733A4A40B2E17DE6DA03A58DEC8BB12DA87BB25971E2DBE5AF7AE6112266A3F9027B449BDF46D8DC0A1A
```

## Conclusion

Out of the 20 randomly selected websites, 7 of them implemented encryption or hashing on the client-side (I'm too lazy to check which ones, but they did something). The list includes:

1. Facebook
2. Proton
3. Binance
4. Esun Bank
5. Cathay United Bank
6. CTBC Bank
7. DBS Bank (Singapore)

Although 35% seems high, it's mainly because banks make up the majority of the list. Most general websites do not implement this mechanism.

In conclusion, the first conclusion is: "Encrypting or hashing passwords on the client-side before sending them can indeed increase security."

This is because it can achieve the following:

1. When HTTPS fails for various reasons, attackers cannot obtain plaintext passwords.
2. On the server-side, no one knows the user's plaintext password.
3. Plaintext passwords will not be recorded in logs due to human error.

All of the above cannot be achieved without encrypting or hashing on the client-side.

The second conclusion is: "Some large companies do implement this mechanism, but it is not the majority, although it seems to be mainstream in the banking industry."

The complete data is posted above. General websites rarely implement this mechanism, but some still do.

The third conclusion is: "Although it can indeed increase security from a technical perspective, other factors still need to be considered when implementing it."

These factors are the "possibility" mentioned earlier and the "cost" mentioned at the beginning. If it is really more secure, why don't general websites implement this mechanism?

Perhaps because the possibility of HTTPS being compromised is too low to be considered (I believe this is the reason why most commenters think it is unnecessary, and I agree), or perhaps because the cost is too high and would increase code complexity. If an encryption scheme is used, it will also consume more computing resources for encryption and decryption, which is also a cost.

This is where I think it should be made clear.

Hashing or encrypting in the front-end does have advantages, it is not redundant, it is not meaningless, and it does not make the system more dangerous.

But this does not mean that every system should implement this mechanism, because the benefits it brings may not outweigh the costs, which depends on the considerations of each company. For most companies, instead of investing in the low possibility of HTTPS failure, it is better to spend time strengthening the security of other login links (such as 2FA or login warnings on different devices), which will bring greater benefits.

Some services will also choose to encrypt the entire request package, not just the password, which is even more secure but also more expensive and difficult to debug. Although it is true that since encryption is done on the client-side, attackers will definitely be able to reverse engineer this mechanism and figure out how it works, but this does not mean that these mechanisms are not helpful.

For example, suppose I have a ticket-snatching app that doesn't want others to know how to call the API, so I implemented a super complex encryption mechanism. Although experts can still reverse engineer and write a ticket-snatching robot, this mechanism increases their time and technical requirements.

Technically speaking, even if it will definitely be cracked in theory, these mechanisms are still meaningful because they increase the difficulty of cracking. Obfuscation and encryption are the same, and these mechanisms should not be avoided just because "client-side things will definitely be seen through."

The key is whether the value of the business logic you want to protect is high enough for you to pay these costs to implement additional security mechanisms.

Finally, if you need a simple summary in bullet points, it would be:

1. In any case, HTTPS must be used first.
2. Encrypt or hash the password in the front-end before sending it, which can increase security, but also comes with a lot of costs.
3. If you are a bank or need equivalent security, then consider whether to do this. Otherwise, in most cases, you don't need this mechanism to be secure enough, and investing resources in other areas will bring greater benefits.

If you have different opinions on this conclusion, or if you find any logical or technical errors in the article, please feel free to leave a comment for correction and discussion. Thank you.

To supplement, this article mostly looks at it from a technical perspective. In addition to this, it can also be viewed from the perspective of legal compliance or practical experience in information security, but I have zero experience in these areas. I hope someone with relevant experience can come out and give some guidance, which may have different opinions.
