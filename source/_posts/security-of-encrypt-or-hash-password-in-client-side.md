---
title: 網站前端打 API 時把密碼加密，有意義嗎？
catalog: true
date: 2023-01-10 09:10:44
tags: [Security]
categories: [Security]
photos: /img/security-of-encrypt-or-hash-password-in-client-side/cover.png
---

最近有人在臉書前端交流社群發了一則[貼文](https://www.facebook.com/groups/f2e.tw/posts/5689037364466915)，內容是他看到了一個問題：[請問登入api傳賬號、密碼json明碼會有問題嗎?](https://ithelp.ithome.com.tw/questions/10211642)，想知道大家對這個問題的看法。

而底下的回答大部份都是覺得「有用 HTTPS 就好了，沒必要額外再實作一層加密，沒有什麼太大的意義」

老實說我以前也是這樣認為的，而且過去在社群中就有出現過類似的討論。我那時候想說都已經有 HTTPS 了，而 HTTPS 本身的目的就是為了保障傳輸的安全，為什麼要自己再做加密？

但這一兩年接觸資安以後，我的想法有了改變，我認為前端在傳輸前把密碼加密，是有其意義的，而接下來我會詳細說明我的理由。

<!-- more -->

## 定義問題

在進入正題之前，我想把問題定義得更明確一點，免得出現一堆張飛打岳飛，拿兩個完全不同的情境來比較的狀況。在原文底下，就有不少留言在討論的是不同的問題，把問題先定義清楚滿重要的。

首先，我們要比較的對象是：

1. 在使用 HTTPS 的前提下，打登入 API 時不做任何事直接傳送密碼的明文
2. 在使用 HTTPS 的前提下，打登入 API 時先把密碼加密，再傳送到 server

這邊需要注意的是「兩個狀況都是 HTTPS」，所以如果你想講的是「沒必要自己發明新技術」或是「自己發明新的加密方式不會比較安全」等等，在這個前提下全都不適用。

因為傳輸層還是靠 HTTPS 在傳輸，所以在這個階段並沒有自己發明新的方式，我只是在應用層自己把傳輸的資料額外加密一層而已。

再來，先不考慮成本這件事，純粹只從技術的角度去看可能有哪些優缺點（成本相關的最後再來討論）。

然後這篇也不討論「保護帳號安全」這件事情，純粹在討論「保護密碼」。舉例來說，有人會講說：「密碼加密有什麼用？多此一舉而已，先做 2FA 比較實在」，這種就是超出範圍的討論。2FA 或 MFA 屬於「保護帳號安全」，就算密碼被偷走，攻擊者也會被其他驗證所擋住，因此沒有辦法登入進去帳號。

這與「保護密碼」是完全不同的兩件事情，因為實作 MFA 對於保護密碼沒什麼幫助。很簡單就可以假設出一種狀況是雖然攻擊者無法登入帳號，但密碼明文還是被偷走了。

使用者可能會在多個服務使用同一組密碼，當使用者在你網站的密碼被偷走，影響到的不只是他在這邊的帳號，還有可能影響到其他服務，這就是為什麼我們在討論「保護密碼」。

最後呢，我這邊的情境是「加密密碼」而非 hash，這是因為我覺得 hash 的狀況比較複雜，我自己想先用加密來舉例，而且這個加密是「非對稱式加密」。

也就是我們可以想像已經有一把 public key 存在於 client 端（當然，每個人都可以拿得到），在送出 request 以前，會先使用 JavaScript 把密碼用 public key 加密以後再送出，而 server 使用 private key 解密，拿到密碼以後 hash 過再存入資料庫中。

綜合以上，這篇想處理的問題是：「已經使用了 HTTPS，在打登入 API 以前先把密碼加密過或是不做任何處理，這兩者的差別在哪？」

而我們可以把回答分成兩個部分：

1. 假設 HTTPS 被破解了，是不安全的，差在哪？
2. 假設 HTTPS 是安全的，差在哪？

## 假設 HTTPS 不安全，差在哪？

首先，可以先想一下怎樣的狀況會造成 HTTPS 不安全，攻擊者掌握了系統的哪些部分？

底下簡單分為四種狀況討論：

1. 攻擊者掌控整台電腦，信任惡意憑證
2. 攻擊者成功執行了中間人攻擊
3. 攻擊者可以在網路層監聽 request 並使用漏洞取得明文
4. 攻擊者直接針對 HTTPS server 進行攻擊

### 攻擊者掌控整台電腦，信任惡意憑證

若是這種類型的狀況，那當然是有沒有加密都沒差，因為攻擊者都有其他更好的手段去取得你的密碼。

### 攻擊者成功執行了中間人攻擊

那如果是「攻擊者成功執行了中間人攻擊（Man-In-The-Middle）」呢？你的電腦沒事，只是封包在傳輸的過程中被中間人攻擊。

在這樣的前提底下，沒加密的情形就能直接被獲取密碼，而有加密的情形攻擊者只能獲取到加密過的密文而非明文。但需要注意的是既然是叫中間人攻擊，那攻擊者除了監聽你的 request 以外，也能傳送偽造的 response 給你，把前端用來加密密碼的部分換掉。

因此無論密碼是否加密，攻擊者都可以拿到明文，只是如果有加密的話，攻擊者取得密碼的成本較高（需要先找到在哪邊加密的，然後把那段改掉）。

### 攻擊者可以在網路層監聽 request 並使用漏洞取得明文

這個狀況跟上一個的不同之處在於這個只能讀，不能寫。若是有辦法解密 request 的封包，就能夠看到明文。

所以如果有把密碼先加密，攻擊者就無法取得密碼的明文。

這邊需要注意的是儘管無法取得明文，攻擊者依然可以透過重送請求來登入你的帳號（先假設沒有其他機制），所以你帳號還是被盜了，只是攻擊者不知道你的密碼明文。

這有差嗎？有！

假設他知道了你的密碼明文，就可以拿你的這組帳號密碼去各個服務都試試看，若是你其他網站也用同一組帳號密碼，就會跟著淪陷（俗稱的撞庫攻擊）。

因此在這個狀況底下，加密密碼的安全性顯然是更高的。

此時你可能會想問的問題是：「那在什麼狀況下攻擊者能夠取得 HTTPS 的明文？真的有可能嗎？」

這邊有一份美國衛生及公共服務部 HHS 所做的簡報：[SSL/TLS Vulnerabilities](https://www.hhs.gov/sites/default/files/securing-ssl-tls-in-healthcare-tlpwhite.pdf)，裡面有記錄一些 SSL/TLS 曾經有過的漏洞，所以取得 HTTPS 的明文確實是有可能的。

不過光是知道「有可能」是不夠的，應該問的是「機率高嗎？」，在討論風險的時候，通常也會根據風險的高低以及嚴重程度來決定該怎麼處理這個風險。

答案是「機率很低」，簡報裡的漏洞最近的已經是 2017 年的事情了，而且是使用一些舊的、有問題的加密演算法，除此之外還需要符合不少其他條件，才能執行攻擊，所以我認為機率確實是很低的。

以 2016 年發表的 [DROWN(Decrypting RSA with Obsolete and Weakened eNcryption)](https://drownattack.com/) 來說，Server 要支援 SSLv2，而攻擊者要能抓到加密過的 TLS connection，符合這些條件以後，進行一大堆運算後就可以解開 900 個 connection 中的 1 個，而運算成本在當時是 440 美金，約 13k 台幣。

總之呢，針對這個狀況，我們可以說：

> 假設攻擊者可以取得 HTTPS 的明文，那確實自己在應用層加密會更安全，但要符合這個假設的成本很高，發生機率很低

### 攻擊者直接針對 HTTPS server 進行攻擊

這個分類我指的是在 2014 年發生過的 [Heartbleed](https://devco.re/blog/2014/04/11/openssl-heartbleed-how-to-hack-how-to-protect/) 漏洞，攻擊者可以藉由 OpenSSL 的漏洞讀取到 server 的記憶體。

這個狀況跟上一個滿像的，如果有在 client 端先加密過密碼，那攻擊者在 server 上讀到的就是加密過後的，不知道密碼明文是什麼。

所以結論跟上個一樣，就是加密密碼會更安全。

## 中場總結

剛剛我們討論了幾種「HTTPS 變得不安全」的狀況，從以往發生過的案例可以得知「HTTPS 變得不安全」是有可能的。若是攻擊者能夠讀到 HTTPS 傳輸的明文，那在應用層將密碼加密，就能防止攻擊者取得密碼的明文，因此會比沒有加密來得更安全。

如果要講得更詳細，可以從兩個維度去切入，一個是嚴重性（severity），另一個是可能性（possibility）。

以嚴重性來說，不管有沒有加密密碼，只要攻擊者有辦法拿到 request 的內容，你的帳號就已經淪陷了，而有沒有加密唯一的差別只有攻擊者是否能取得明文密碼，有的話就可以執行撞庫攻擊，拿密碼去試更多其他的網站。

而可能性就是「HTTPS 的明文被拿到」這件事的可能性，從過往的經歷以及研究來看，雖然是有可能的，但在 2023 年的今天，機率是很低的。

因此我們現階段的結論應該是：

攻擊者若是可以繞過 HTTPS 拿到明文的 request，那在應用層將密碼加密，確實會比較安全，但要注意的是要達成這個前提非常困難，發生的機率極低。

## 假設 HTTPS 是安全的

接下來我們討論第二種狀況，那就是假設 HTTPS 是安全的，沒有任何人可以從中間看到明文的內容，這應該也是留言區中大多數人假設的前提。

在這種狀況下，會有哪些風險呢？

有一個現實生活中會發生，而且也確實發生過的風險，那就是 logging。

身為前端工程師，在前端加裝一些 error tracking 的服務是很合理的事情，若是我們直接實作一個「只要伺服器回傳 5xx，就把 request 記錄起來」的機制，如果好巧不巧哪天登入的 API 出現這個狀況，你就可以在 log 裡面看到使用者的明文密碼。

而且不只前端，後端也可能有類似的機制，碰到一些問題就把 request 整個寫到 log 檔去，方便以後查看以及 debug，一不小心密碼就可能被寫進去。

在這種狀況下，在 client 端先把密碼加密顯然是有好處的，那就是在這些錯誤處理的 log 中，被記錄下來的密碼會是密文，除非你有密鑰，否則你是不會知道使用者的密碼的。

我在網路上找到一篇跟我論點一樣的文章：[The case for client-side hashing: logging passwords by mistake](https://www.sjoerdlangkemper.nl/2020/02/12/the-case-for-client-side-hashing-logging-passwords-by-mistake/)，裡面有附上很多參考連結，都是以前各大公司不小心把密碼的明文記錄下來的案例。

然後有個小地方稍微講一下，上面這篇做的是「在 client 端 hash」，跟我這篇一開始設定的「在 client 端做非對稱式加密」有點不同，hash 會更安全一點，確保在 server 真的沒人知道你的密碼明文是什麼。

總之呢，在 client 端先把密碼加密或是 hash，可以避免在日誌中不小心出現使用者的密碼明文，這個顯然是個額外的優點。

## 加密還是 hash？

文章開頭我有提到 hash 的狀況有些複雜，所以我先把情境設定在「對密碼做非對稱式加密」再傳輸，因為對上面我舉的那些例子而言，這兩種情境的差異不大。

舉例來說，HTTPS 被拿到明文內容，無論你對密碼做了非對稱式加密還是雜湊，在攻擊者無法取得伺服器端密鑰的前提之下，都是拿不到明文密碼的。

那為什麼 hash 的狀況有些複雜呢？

假設我們在前端先把密碼 hash 過後再傳到後端，那後端是要直接存進去資料庫嗎？如果直接存進去資料庫，哪天資料庫的內容曝光，攻擊者就拿到這些 hash 過的密碼了。

通常在有加鹽以及雜湊演算法夠強的前提之下，被拿到 hash 的密碼還是能保證一定的安全性，可是在這種情況下，反而變得很不安全。

因為前端傳給後端的內容已經是 hash 過的了，所以攻擊者可以直接拿 hash 過的密碼進行登入，根本不用知道明文是什麼。雖然保護了明文，但失去了原本雜湊的安全性。

因此如果要做 client side hashing，server side 收到後也要再做一次。如此一來，就算資料庫被偷走，攻擊者也沒辦法利用資料庫中的 hash 直接登入。

有些人可能跟我一樣好奇：「做兩次 hash 不會更不安全嗎？」，我們可以看一下 Google 在 [Modern password security for system designers](https://cloud.google.com/static/solutions/modern-password-security-for-system-designers.pdf) 裡面怎麼說：

> Have the client computer hash the password using a cryptographically secure algorithm and a unique salt provided by the server. When the password is received by the server, hash it again with a different salt that is unknown to the client. Be sure to store both salts securely. If you are using a modern and secure hashing algorithm, repeated hashing does not reduce entropy.

看起來是還好，問題不大。

總之呢，看起來最安全的但也更複雜的解法就是 client side 先 hash 一次，然後丟到 server 的時候再 hash 一次存進資料庫，如此一來就可以保證：

1. HTTPS 因為各種原因失效時，攻擊者無法取得明文密碼
2. 在 Server 端，沒有任何人知道使用者的明文密碼
3. 明文密碼不會因為人為失誤被記錄到 log 中

那如果真的比較好用，為什麼沒人在用？

## 現實生活中，到底有誰在前端做 hash 或是加密？

當我一開始碰到這個問題，講出「怎麼沒人在用」的時候，其實只是「我自己沒碰過有人這樣用」，但實際上我並不知道那些知名網站的登入是怎麼做的。

因此呢，我就直接去看了幾個知名網站的登入機制，我們一起來看一下結果，為了方便觀看，我把跟帳號密碼無關的內容都拿掉了。

我在測試的時候，基本上都是用 test 或是 test@test.com 搭配簡單的密碼如 1234 在測試，然後觀察 request 的內容。

先來看一下 FAANG 吧！

### FAANG

#### Facebook

API 網址：https://zh-tw.facebook.com/login

請求內容：

```
email=test@test.com
encpass=#PWD_BROWSER:5:1673256089:AbJQAJUvZZNvh2dZbeDqdu9dp7HWwyHOl3+0sCGjiHMMjvYdxJokpdHE/O+E5LIbnakRmDWQfV40ZaB31MaNXFYo1b+RI+LHh6MAdDPa4PJ+BesDp4u8B4F4diVQ+q7idbEhT5wTNaU=
```

沒想到 Facebook 就是有實作前端加密的網站！後面那段 Base64 並不是直接把密碼 Base64，而是把加密過的密碼做 Base64，解出來是這樣：`\x01²P\x00\x95/e\x93o\x87gYmàêvï]§±ÖÃ!Î\x97\x7F´°!£\x88s\f\x8Eö\x1DÄ\x9A$¥ÑÄüï\x84ä²\x1B\x9D©\x11\x985\x90}^4e wÔÆ\x8D\\V(Õ¿\x91#âÇ\x87£\x00t3Úàò~\x05ë\x03§\x8B¼\x07\x81xv%Pú®âu±!O\x9C\x135¥`

#### Amazon

API 網址：https://www.amazon.com/ap/signin
請求內容：`email=test@test.com&password=1234`

#### Apple

API 網址：https://idmsa.apple.com/appleauth/auth/signin
請求內容：`{"accountName":"test@test.com","password":"1234"}`

#### Netflix

API 網址：https://www.netflix.com/tw/login
請求內容：`userLoginId=test@test.com&password=1234`


#### Google

API 網址：https://accounts.google.com/v3/signin/_/AccountsSignInUi/data/batchexecute

請求內容：
```
f.req=[[["14hajb","[1,1,null,[1,null,null,null,[\"1234\",null,true]]]]
```

看來 FAANG 裡面，只有 Facebook 是有實作的。

接著我突然好奇起其他常用服務的登入有沒有做，底下貼結果。

#### GitHub

API 網址：https://github.com/session
請求內容：`login=test@test.com&password=1234`

#### Microsoft

API 網址：https://login.live.com/ppsecure/post.srf
請求內容：`login=test@test.com&passwd=1234`

#### IBM cloud

API 網址：https://cloud.ibm.com/login/doLogin
請求內容：`{"username":"test@test.com","password":"1234"}`

看來有實作的是少數，那資安廠商呢？資安廠商自己有做嗎？

### 資安廠商

#### Kaspersky

API 網址：https://eu.uis.kaspersky.com/v3/logon/proceed
請求內容：`{"login":"test@test.com","password":"12345678"}`

#### 趨勢

API 網址：https://sso1.trendmicro.com/api/usersigninauth 
請求內容：`{"email":"test@test.com","password":"12345678"}`

#### Tenable

API 網址：https://cloud.tenable.com/session
請求內容：`{"username":"test","password":"1234"}`

#### Proton 

這個應該不算資安廠商，但突然很好奇強調隱私的 Proton 是怎麼做的，一看發現好像很複雜。

在登入的時候會先把 username 送過去，拿到一些看起來是 key 的東西。

API 網址：https://account.proton.me/api/auth/info

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

接著輸入密碼登入時，會送出如下的 request，看起來也很複雜：

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

補充：經討論串有人提醒後發現這是一個叫做 SRP（Secure Remote Password）的協議，Proton 有提供一個 [ProtonMail Security Features and Infrastructure](https://proton.me/static/9f5e7256429a2f674c943c5825257b82/protonmail_authentication_excerpt.pdf)，裡面有記錄他們的安全措施，就有講到這個機制。

看起來滿複雜要花不少時間研究，先放著，有興趣的可以參考：[SRP — 更健全的登入及資料傳輸保護協議](https://blog.amis.com/srp-1f28676aa525)

雖然更安全，但成本應該又更高了。

### 交易所與銀行

看完上面案例發現有做的是少數，因此我好奇更注重安全的加密貨幣交易所與傳統銀行有沒有做。

#### Binance

API 網址：https://accounts.binance.com/bapi/accounts/v2/public/authcenter/login

請求內容：

``` js

{
  "email":"test@test.com",
  "password":"fe2e6b4138fcd7f27a32bc9af557d69a",
  "safePassword":"d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
}
```

#### Coinbase

API 網址：https://login.coinbase.com/api/v1/authenticate-credentials

請求內容：

``` js
{"email":"test@test.com", "password":"1234"}
```

#### kraken

API 網址：https://www.kraken.com/api/internal/account/settings/tfa

請求內容：

``` js
{"username":"test", "password":"1234"}
```

#### 玉山銀行

API 網址：https://ebank.esunbank.com.tw/fco/fco08001/FCO08001_Home.faces

請求內容：

```
loginform:custid=A0000...
loginform:name=mxagZmaqygDx0XX6784Svw==__NgZQcFfAx+lQmPza2eNpOA==
loginform:pxsswd=8,lIRnuUxw/yStOt9QIYG2U3Gn2XkG03x4Ey/UU6JGtsbUxfRXoAv9CjE3EWerDN3tfx3dD/B3ChLAPMSG2BA3jMXUCZC06y8UbQ5isKc9fCWZSSZAWWcOmJ7LdXw1ZhjV55hpw1upvAr9WEmZ0XF6x7if+dBxJ4KZ00d83qA9eA+3VaSk+JLhN8/CFBfTKTfJEs3PDNsm12XzRUBb4YE1aPQosVX10mdvh3zY5lmkrKuq8gnuImEf3oLOk4EF3eVpr6jJiFzMKlHybvGdtKYS25+pgTS68wn3v023barbSmgivcv5atm0XsyXWDY2dKEtdQz+7A6R+AB0bExbQlRjqQ==
```


#### 國泰世華

API 網址：https://www.cathaybk.com.tw/MyBank/Quicklinks/Home/NormalSignin

請求內容：

```
CustID=A000...
UserId=DC0C6E52BE2A2354C53401207F220F1B
Password=8cf5e1977f149ed0362629007a7f91d0efc7b12cb1895ba701c528a12b38d12f8148ca03ee671fe25d2a3a807be980f7728566e359a675734ce046899b147658388bb60f9b900e2ccc9adac280b54b5f2e28cb7eee1b634d0e1ed1c0c0c598c350f61eb003405559331a7f047add7289466bf42cfd5b9e774a1fa116af4fd7050adb8f174d42a8e2098a014a788bd2ffae3bf4ff7a8d8d7e2e8068402fda395da41be6e5d32f2d32cbee2afc26e82c58b60357b5cb186a3b9cf69df2deb9da8c9fde45337935180cb4e177109413d7a758d38bfc8334a4509d8d8fb6a37080f0e0086b4a5ef68f7809ca2ef97183b7f66d996873bb7dbfcee61d2da424b8b968
```

#### 中國信託

API 網址：https://www.ctbcbank.com/IB/api/adapters/IB_Adapter/resource/preLogin

請求內容：

```
{
  "rqData": {
    "custId": "A00....",
    "pin": "878dbee38bbb4d77a30ee128f55f7bfe2169e45380d62a75453d3ca175e8ce8b|43d0499147b62adeec4eef3c77d33171b4569d0bdf7bbbe2b8b9bde3d30a26aba69aadfb28dfbaa9a997a0ccf668aaab0b6da582275175272172569a58a60bbfc5ac3a8c6862ce31f86247d7c1adf307e363c0f251fb88c4d39afa6ed0ca0a49e053f4f90000fa77b4e78beaead72ebdf52a13ecb4f20ae9a532947fad8156d5ec69d6763243364e71659079e469d1e01d0c384b0c71f4e9e524890227d82a51a340ef0b48638e05e347d75cb93d4a825a2bce6a90ef47f512351ee2d0d1ea17fb8afd521e427578603ea775191711f81d8dcb18e46b72daf3a49a60e50d12d3887e3bafab3758730f7fb0276373ebe1da01a03162ec8e73a202091a51b7f88d",
    "userId": "bfcdb9b2d6896a3bfb4a6542e8fb2689486d000b11bdc0c7bc336a6534aec74c|1b1a758bb26702bc0ac7cd660da2a72866f2cfdcf3668f2d39a5f8b006854f52a08f418b0a460b36374f95b7a310d73ea9994788698041f524ecd1f153448ab5d51f901a9a08ac2a9ee04c5c273ecb9d4ec1b6a62e9696c6126271e2f8c334fe17ce8b8538139363b90be75c1130cb251ec240bd26c920b52f5be9fc59094ce7d935d826242d69dc1ff7047a5abbf11d3c7de639a14bb10230912903cd948c05b3b3cb0cdb100f979640e291774e623a7109bde7b55bb8a6a373c0ca12820b072132ea61c845e60e26d09c7ee0fe23f7de286cbccb067a86fd1985c5b455f9ae46ce24dc8f52bcb05c205d6a462345162ae82c35e045bf3fd43a297c3edcfe17"
  }
}
```

#### 美國銀行

API 網址：https://m.globalcard.bankofamerica.com/pkmslogin.form

請求內容：

```
username=fcc63767-1a43-4cc6-8c3e-1346350b5274
password=12345678
```

#### 新加坡星展銀行

API 網址：https://internet-banking.dbs.com.sg/IB/Welcome

請求內容：

```
USER_LOGON_NAME=test123
ENCRYPTED_PIN_BLOCK=A8C48B7572A1A53C5A66E9B43365027C7FBF14BF461F480A46781E49648A8F70271A29C374F86FCD55A76ED17B2284B47C799B74475F29749D68631FF7E322177A21EEE8C41D8950638A2828C34A2653D7C9F69F5DA568E42D64CE89FCE8F024217B235835E6F8BC3C536F56361EDF459AFCE9A512BDBACAB2D25423209996C2E84A18EA8446685DAF9FAD4B1D6D8DF0F378EC27D9A81AD4D1A2B91BA3CFD838140A9BD48AD8D38D33B0093110BD1CA2C76F3DE4CBD969A9B0260DB890E9B1A99DC1193BFE9A1EDB3E56F71CB1CD8630558B242B040F733A4A40B2E17DE6DA03A58DEC8BB12DA87BB25971E2DBE5AF7AE6112266A3F9027B449BDF46D8DC0A1A
```

## 結論

在隨機想到的 20 個網站中，有 7 個有在前端做加密或是 hash（我懶得看是哪個了，總之有做事就對了），名單是：

1. Facebook
2. Proton
3. Binance
4. 玉山銀行
5. 國泰世華
6. 中國信託
7. 新加坡星展銀行

雖然說 35% 看起來很高，但那是因為銀行佔了大多數，一般網站則是很少實作這個機制。

寫到這邊，可以來下結論了。

第一個結論是：「在 client 端傳送密碼前先把密碼加密或是 hash，確實能夠增加安全性」

理由是做了以後，能夠達成以下事項：

1. HTTPS 因為各種原因失效時，攻擊者無法取得明文密碼
2. 在 Server 端，沒有任何人知道使用者的明文密碼
3. 明文密碼不會因為人為失誤被記錄到 log 中

以上都是沒有在 client 加密或是 hash 時做不到的。

而第二個結論是：「確實有些大公司有做這個機制，但是非大多數，不過在銀行業似乎是主流」

這個結論上面有貼完整的資料了，一般的網站很少做這個機制，但還是有人做。

第三個結論是：「雖然從技術上來看能夠增加安全性，但實際上是否實作，仍然要考慮其他因素」

這因素就是我前面提過的「可能性」還有開頭我講先不談的「成本」。

若是真的比較安全，為什麼一般網站不會實作這個機制？

或許是因為覺得 HTTPS 被攻破的可能性太低，低到可以忽略不計（我相信這是大多數留言的人覺得不需要做的理由，我也同意這點），也或許是成本太高，會增加程式碼複雜度；若是採用加密的方案，也會消耗更多運算的資源在加解密上面，這也是成本。

這就是我覺得應該講清楚的地方。

在前端先做 hash 或是加密，它確實是有優點的，不是多此一舉，也不是沒有意義，更不是讓系統變得更危險。

但這不代表每個系統都該實作這個機制，因為它帶來的效益或許沒有成本高，這個端看各個公司的考量。對大部分的公司來說，與其為了 HTTPS 失效這個極低的可能性去投入成本，不如把時間花在加強其他登入環節的安全性（例如說 2FA 啦，或是不同裝置登錄警告等等），帶來的效益會更高。

有些服務還會選擇把整包 request 都加密，而非只有密碼，這個又更安全但是成本又更高，而且 debug 很不方便。雖然說既然加密做在 client 端，攻擊者一定有辦法逆向這個機制，看出是怎麼做的，但這不代表這些機制沒幫助。

舉例來說，假設我有個搶票 App 不想讓別人知道 API 怎麼呼叫，於是就實作了一個超複雜的加解密機制，儘管高手還是可以做逆向工程，寫出一個搶票機器人，但這個機制增加了他的時間成本以及對技術的要求。

以技術上來說，就算理論上一定會被破解，這些機制還是有意義的，它的意義在於增加破解難度，加殼、混淆都是一樣的，不會因為「在 client 端的東西一定會被看穿」而不去做這些機制。

重點在於你想保護的商業邏輯的價值，有沒有高到你需要付出這些成本去做額外的安全機制。

很多人在討論這個問題的時候，沒有辦法把「單一問題」跟「最佳實踐」切開來看，總是在討論著「以成本來說，怎樣怎樣才是最好的」或是「為什麼不乾脆怎樣怎樣」，但技術選型從來都不是一刀切的事情，最好的方案通常成本也較高，如果真的沒有這麼多的資源怎麼辦？是不是就需要選擇次好且成本較低的方案？

不是只有最佳實踐才叫做實踐，技術是需要進行妥協的。

舉個例子，把登入驗證機制都換成 [Passkeys](https://developers.google.com/identity/passkeys?hl=zh-tw)，成本可能是 50，增加的安全性是 90。

把原本明文傳輸的密碼先 hash，成本可能是 20，增加的安全性是 5。

儘管 Passkeys 的效益整體來說更高，但問題是有些公司可能現在就只有 20 個單位的資源。

我自己認為一位優秀的工程師不能只給得出最佳實踐，而是必須針對有限資源的狀況之下，給出各種不同的解法，因此這篇討論的問題不是毫無意義的。把這個問題整理過一輪之後，自然而然就會出現許多成本不同，效益也不同的解法。

有多少資源，就做多少事。

最後，如果你需要一個條列式的簡單結論，會是：

1. 無論如何，一定要先用 HTTPS
2. 可以的話，能用 Passkeys 當然是最好，少掉傳統密碼的一些問題
3. 如果你想要用很安全的方式驗證密碼，請參考 SRP（Secure Remote Password）協定
4. 若是上述都沒有資源做的話，那在前端先把密碼做加密或是 hash 後再傳送，確實能夠增加一點安全性，但同時還是會帶來額外成本
5. 如果你是銀行或需要較高的安全性，再來考慮要不要做這個，否則極大多數的狀況下，你不需要這個機制就夠安全了，資源投入在其他地方的效益會更大

若是對這個結論有不同意見，或是有在文章中發現哪些邏輯錯誤或技術錯誤，歡迎留言指正與討論，感恩。

補充一下，這篇大多數從技術面來看，除此之外還可以從法遵面或是資安的實務經驗來看，但這些面向我就零經驗了。許願一下有相關經驗的人出來指點迷津，或許會有不同觀點。
