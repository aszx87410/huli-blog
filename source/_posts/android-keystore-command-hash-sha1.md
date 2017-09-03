---
title: '[Android] keystore 相關指令'
date: 2016-03-08 16:20
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
昨天看到[Android簽名相關知識整理](http://droidyue.com/blog/2016/03/06/summary-of-android-signing/)這篇，才讓我想到我應該也把自己搜集的一些指令記下來

首先是建立一個 `keystore` 檔案，有一行指令可以完成
這邊是我寫的一個 shell script 的部分 code
```
keytool -genkeypair -keyalg RSA \
-dname "cn=NAME, ou=NAME, o=NAME, c=TW" \
-alias ${name} -keypass ${password} \
-keystore ${name}.keystore -storepass ${password} -validity 9999
```
把`${}`換成自己想要的東西就好了

再來是用 `keystore` 對 apk 簽名
簽名完記得 zipalign 一下，不能不能上傳到 google play
```
jarsigner -verbose -digestalg SHA1 -keystore ~/documents/keystore/A.keystore TEST.apk ALIAS
zipalign -v 4 TEST.apk TEST_final.apk
```

最後是從現有的 apk 導出一些訊息
如果有串`Facebook`或是`Google`登入，那應該很實用

[Is there any way to get key hash from signed APK?](http://stackoverflow.com/questions/17423870/is-there-any-way-to-get-key-hash-from-signed-apk)

文章裡附的是 linux 版，改一下之後就可以在 mac 上面跑
上面會輸出 facebook 要的 keyhash
下面會輸出 Google 要的 sha-1 fingerprint
```
keytool -list -printcert -jarfile pet_thai_lz_v1.0.2.apk | grep "SHA1: " | cut -d " " -f 3

keytool -list -printcert -jarfile ~/Downloads/YOURAPKFILE.apk | grep "SHA1: " | cut -d " " -f 3 | xxd -r -p | openssl base64
```
