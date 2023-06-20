---
title: 'Quickly Obtain APK Related Information'
date: 2016-09-29 00:26
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
categories:
  - Android
---
(Original article published at: http://blog.techbridge.cc/2016/05/20/fast-way-to-get-apk-information/)

## Introduction
In a [previous article](http://blog.techbridge.cc/2016/03/24/android-decompile-introduction/), we introduced how to decompile an Android APK. By decompiling, we can obtain a lot of information related to the APK, such as `AndroidManifest.xml`. With this file, we can see some basic information about the APK, and also see the entire code of the APK and the resources used (pictures, videos, sounds, etc.).

But if today we only want to know the basic information, and we don't care about how the APK is written or what resources it uses, what should we do? Decompiling takes some time, and the larger the APK, the longer it takes. Is there a better way?

<!-- more -->

## What information do we need?
First of all, let's define what "basic information" refers to. For me, the basic information I want to obtain includes the following six points:

1. Package name
2. Version code
3. Version name
4. Launch activity
5. Google SHA1 Fingerprint
6. Facebook Keyhash

The purpose of the first four is that if you are developing an internal APK deployment system for your company, with the first four pieces of information, you can do verification similar to Google Play, such as verifying whether the package name is the same as the last upload, whether the version number is higher than the last time, etc.

As for the last two, readers who have integrated Google and Facebook login will know that these two are necessary for login. You need to add these two sets of keys in the settings to use the login function, otherwise, verification errors will appear.

Now that we know what we need, let's get started!

## Useful keytool
`keytool` is a built-in command related to certification.  
We can use `keytool -list -printcert -jarfile NAME.apk` to extract some information:

```
Signer #1:

Signature:

Owner: CN=Android Debug, O=Android, C=US
Issuer: CN=Android Debug, O=Android, C=US
Serial number: 4b52355e
Valid from: Sun Jan 17 05:53:34 CST 2010 until: Mon Jan 17 05:53:34 CST 2011
Certificate fingerprints:
   MD5:  14:99:01:12:7A:69:CD:75:4F:31:75:8C:59:F6:71:63
   SHA1: 24:69:FD:17:6B:C3:43:FC:3A:85:EC:4B:C5:D7:9F:09:4A:71:60:80
   SHA256: 57:EB:73:81:D7:08:E6:45:FE:26:99:FB:3C:1F:37:1E:EE:38:39:20:E0:2D:C6:76:0E:84:2B:DD:1C:5C:C9:70
   Signature algorithm name: SHA1withRSA
   Version: 3
```

For this APK, it lists information such as owner, issuer, validity period, and certificate fingerprints, and the `SHA1` is the information used for Google login.

What about Facebook Keyhash? From the [official documentation](https://developers.facebook.com/docs/android/getting-started#release-key-hash), we can know that it is just to convert sha1 to binary and then do base64. With sha1, and some commands, we can easily generate Facebook Keyhash.

## Almighty aapt
The full name of aapt is: Android Asset Packaging Tool, which is super useful!  
Let's take a look at what aapt can do first. Since we need to extract information, let's directly look at the dump part:

```
 aapt d[ump] [--values] WHAT file.{apk} [asset [asset ...]]
   badging          Print the label and icon for the app declared in APK.
   permissions      Print the permissions from the APK.
   resources        Print the resource table from the APK.
   configurations   Print the configurations in the APK.
   xmltree          Print the compiled xmls in the given assets.
   xmlstrings       Print the strings of the given compiled xml assets.
```

Interested readers can try each of them to see what results they get. For our needs, badging is the most suitable.

`aapt dump badging NAME.apk`

```
package: name='com.gmail.aszx87410.movie_to_nine' versionCode='1' versionName='1.0'
sdkVersion:'8'
targetSdkVersion:'16'
uses-permission:'android.permission.INTERNET'
uses-gl-es:'0x20000'
uses-feature-not-required:'android.hardware.telephony'
uses-feature:'android.hardware.screen.portrait'
uses-feature-not-required:'android.hardware.screen.landscape'
application-label:'Tonight 9 PM Movie 2.0'
application-label-he:'Tonight 9 PM Movie 2.0'
application-label-es:'Tonight 9 PM Movie 2.0'
application-label-iw:'Tonight 9 PM Movie 2.0'
application-icon-120:'res/drawable-ldpi/icon.png'
application-icon-160:'res/drawable-mdpi/icon.png'
application-icon-240:'res/drawable-hdpi/icon.png'
application-icon-320:'res/drawable-xhdpi/icon.png'
application-icon-480:'res/drawable-xxhdpi/icon.png'
application: label='Tonight 9 PM Movie 2.0' icon='res/drawable-mdpi/icon.png'
launchable-activity: name='com.ansca.corona.CoronaActivity'  label='Tonight 9 PM Movie 2.0' icon=''
uses-feature:'android.hardware.touchscreen'
uses-implied-feature:'android.hardware.touchscreen','assumed you require a touch screen unless explicitly made optional'
main
other-activities
other-receivers
other-services
supports-screens: 'small' 'normal' 'large' 'xlarge'
supports-any-density: 'true'
locales: '--_--' 'he' 'es' 'iw'
densities: '120' '160' '240' '320' '480'
native-code: '' 'armeabi-v7a'
```

Ta-da! All the information we need is here, along with permission lists, app logo, app name, and other information. 
Up to this point, everything we need is available, and the rest is just string cutting and integration.

## Summary
This article briefly introduces the use of `keytool` and `aapt`. The main purpose is to extract the information we need using other tools without relying on `apktool`, which saves time and effort.

If you are interested in knowing what the final product looks like, [apkinfo.sh](https://github.com/aszx87410/apkinfo.sh) is a small project I put on GitHub, which does exactly what this article teaches, which is to extract relevant information from an APK.
