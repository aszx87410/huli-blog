---
title: "Android App Reverse Engineering Part 4: Dynamic Analysis with Frida"
catalog: true
date: 2023-04-27 15:10:44
tags: [Security]
categories: [Security]
photos: /img/android-apk-decompile-intro-4/cover-en.png
---

In the previous articles, we talked about static analysis, which means we didn't actually run the app. Instead, we studied the logic of the app's operation through decompiled code and modified the code before repackaging and executing it.

Dynamic analysis, on the other hand, means that we will run the app and use various methods to hook various methods to monitor the input and output of certain methods, and even tamper with them.

In this article, let's learn how to use Frida for dynamic analysis.

<!-- more -->

Series links:

1. [Android App Reverse Engineering Part 1: Decompiling and Rebuilding APKs](/2023/04/27/en/android-apk-decompile-intro-1/)
2. [Android App Reverse Engineering Part 2: Modifying Smali Code](/2023/04/27/en/android-apk-decompile-intro-2/)
3. [Android App Reverse Engineering Part 3: Monitoring App Packets](/2023/04/27/en/android-apk-decompile-intro-3/)
4. [Android App Reverse Engineering Part 4: Dynamic Analysis with Frida](/2023/04/27/en/android-apk-decompile-intro-4/)

## Tool Introduction: Frida

The dynamic analysis tool we will be using this time is [Frida](https://frida.re/). The official website describes it as a "Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers." It can be used for dynamic analysis on not only Android but also other platforms.

There is a tool called Objection that is based on Frida, and it is recommended to install it directly because it will also install Frida. Installation instructions can be found here: https://github.com/sensepost/objection/wiki/Installation

To use Frida, it must be installed on both the phone and the computer. Installation instructions can be found on the official website: https://frida.re/docs/installation/

Also, if you have Frida installed on your phone but are switching to a different computer, make sure to install the same version. The steps are:

1. Check the version of Frida on your phone: `frida-server --version`, assuming it is 15.1.14.
2. Find the version number of frida-tools here: https://github.com/frida/frida/releases/tag/15.1.14
3. Install these two on your computer:

```
pip install frida==15.1.14
pip install frida-tools==10.4.1
```

Make sure the version numbers match, or you will encounter errors.

Although Frida may seem like it requires root access, there are actually two ways to run it: one that requires root access and one that does not.

To use the version that requires root access, install frida-server on your phone. Details can be found on the official website: https://frida.re/docs/android/

Basically, you just need to run an executable on your phone with root privileges. If it is not the default root when you run the file, you can use `adb shell` to change it:

``` shell
adb shell

# kill old process
ps -e | grep frida-server
kill -9 {your_process_id}

# run as root
su
/data/local/tmp/frida-server &
```

After running it, you can use `frida-ps -U` to confirm that it is running.

The second method, which does not require root access, involves modifying the APK. You add a Frida so file to the APK and add a line of `System.loadLibrary()` at the entry point to use Frida. Details can be found in the wiki: https://github.com/sensepost/objection/wiki/Patching-Android-Applications

You don't need to execute the above process yourself; there are ready-made commands to help you. If you can't package it, you can use this command:

``` shell
objection patchapk --source test.apk --skip-resources --ignore-nativelibs
```

If it still doesn't work, you can use the knowledge we learned earlier to modify it yourself. First, use `apktool d` to unpack the packaged APK, then modify the contents yourself. For example, sometimes there may be an alignment issue with the so file, so you can change `android:extractNativeLibs` in `AndroidManifest.xml` to true and then repack it.

## Basic Usage of Frida

First, let's talk about what Frida does. The most common use case is to write some code to hook functions. Hooking means that you can override the implementation of any function, observe input and output, and change the return value of the function.

These codes are written in JavaScript and injected into the app when it is launched. In my experience, after seeing more examples, it is quite easy to get started.

Instead of talking so much, let's try it out. The sample app used this time is the same as the first article, which is an app that checks whether the device is rooted after pressing a button: https://github.com/aszx87410/demo/raw/master/android/demoapp.apk

After opening this app, the default activity will be `com.cymetrics.demo/MainActivity`. Let's hook the onCreate method of this class.

First, create a file named `script.js` with the following content:

``` js
function run() {
  Java.perform(() => {
    var MainActivity = Java.use('com.cymetrics.demo.MainActivity')
    MainActivity.onCreate.implementation = function() {
      console.log('MainActivity onCreate')
    }
  })
}

setImmediate(run)
```

Then run the command:

``` shell
frida -U --no-pause -l script.js -f "com.cymetrics.demo"
```

If you don't have root, the startup method will be different. First, patch the app as mentioned above, then install it on your phone, and then enter the following command in the terminal:

``` shell
frida -U Gadget -l script.js
```

Then you should see a new log line on your terminal, which is `MainActivity onCreate`, and the app on your phone crashes. This is normal.

Let's briefly talk about the basic structure of Frida scripts. The starting point is:

``` js
function run() {
  Java.perform(() => {
    // code
  })
}

setImmediate(run)
```

Then it depends on what method you want to hook. In our previous code, we first use `Java.use` to get the class we want to hook, and then use `MainActivity.onCreate.implementation` to replace the original implementation with our own function.

Why did the app crash after hooking? Because the function we implemented ourselves did nothing except log, which means that everything the original onCreate should have done was removed, so the crash is reasonable. To find out the root cause of the crash, you can use `adb logcat | grep AndroidRuntime`:

``` shell
android.util.SuperNotCalledException: Activity {com.cymetrics.demo/com.cymetrics.demo.MainActivity} did not call through to super.onCreate()
```

So what should we do? Just remember to call the original implementation at the end, like this:

``` js
function run() {
  Java.perform(() => {
    var MainActivity = Java.use('com.cymetrics.demo.MainActivity')
    MainActivity.onCreate.implementation = function() {
      console.log('MainActivity onCreate')
      this.onCreate.call(this)
    }
  })
}

setImmediate(run)
```

`this` will be the original MainActivity, and `this.onCreate.call` can call the original implementation, with the first parameter of the call method being `this`, followed by the parameters.

After executing the above script, another error will appear:

``` shell
Error: onCreate(): argument types do not match any of:
  .overload('android.os.Bundle')
```

This is because onCreate should actually have parameters, but we did not receive any parameters when we overrode it, so an error occurred. To avoid this problem, I would recommend adding `.overload()` at the beginning when overriding the implementation, like this:

``` js
MainActivity.onCreate.overload().implementation = function() {

}
```

Frida will then show an error message again to tell you what the correct parameters should be, so you can follow it. Finally, it will look like this:

``` js
function run() {
  Java.perform(() => {
    var MainActivity = Java.use('com.cymetrics.demo.MainActivity')
    MainActivity.onCreate.overload('android.os.Bundle').implementation = function(a) {
      console.log('MainActivity onCreate')
      this.onCreate.call(this, a)
    }
  })
}

setImmediate(run)
```

In this way, you can know what the parameters are, and you can also pass in parameters when calling the original implementation, so there will be no errors.

Since we can insert code, we can do a lot of things, such as displaying a new message directly on the UI:

``` js
function run() {
  Java.perform(() => {
    var MainActivity = Java.use('com.cymetrics.demo.MainActivity')
    MainActivity.onCreate.overload('android.os.Bundle').implementation = function(a) {
      console.log('MainActivity onCreate')
      // Toast should be run on the main thread(UI thread)
      Java.scheduleOnMainThread(function() {
        var Toast = Java.use("android.widget.Toast");
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        // We need context for displaying the Toast
        var context = currentApplication.getApplicationContext();
        Toast.makeText(
          context,
          // The type should be correct
          Java.use("java.lang.String").$new("Hello!"),
          Toast.LENGTH_SHORT.value
        ).show();
      });
      this.onCreate.call(this, a)
    }
  })
}

setImmediate(run)
```

Code from: [makeToast.js](https://gist.github.com/myzhan/ab13068463cd7f77b7f06ae561ea853a).

## Bypassing Root Detection with Frida

In our previous article, we bypassed root detection by directly modifying the smali code and patching the function that performs the detection. With Frida, we don't need to modify the smali code anymore. We can directly hook the function that performs the detection and replace its implementation, like this:

``` js
function run() {
  Java.perform(() => {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer')    
    RootBeer.isRooted.overload().implementation = function(){
        console.log('bypass rootbeer')
        return false
    };
  })
}

setImmediate(run)
```

Yes, it's that easy.

You may ask, how do we know to hook this function? This part still requires static analysis. From static analysis, we know that this function is doing a check, so we use Frida to hook this function.

For myself, I usually use two methods in combination. First, I disassemble and statically analyze the code, take a quick look at the code, and then use Frida to hook it to see if I can achieve what I want. If I can, I will go to the corresponding place in smali and then repack the app. This way, I can execute the process I want even on a phone without Frida.

In fact, the basic use of Frida is like this. The rest depends on understanding of the code and Android development to determine which function to hook.

## Other Frida Tips

Below are some Frida tips that I found on the internet and have used in practice for your reference.

### Print stack trace

Suppose an app has a check mechanism that detects whether it has root, and the source code is obfuscated, making it difficult to trace. However, when checking, it will output check-related information using Log.d. At this time, we can hook Log.d and use `Log.getStackTraceString` to output the stack trace to know where this function is called:

``` js
var Log = Java.use("android.util.Log");
var Exception = Java.use("java.lang.Exception");
Log.d.overload("java.lang.String", "java.lang.String").implementation = function (a, b) {
   if (b.indexOf('root') >= 0) {
    // print stack trace
    console.log(Log.getStackTraceString( Exception.$new()));
   }
   return this.d.overload("java.lang.String", "java.lang.String").call(this, a, b)
};
```

### Hook Reflect-related methods

In Java, in addition to calling methods directly, you can also call them through reflection (Reflect). Some obfuscated programs use this technique extensively to enhance the difficulty of static analysis. We can print out every dynamically called method to see if there are any clues:

``` js
// hook Class.forName
var JavaClass = Java.use('java.lang.Class');
JavaClass.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader').implementation = function(name, b, c) {
  console.log('Class.forName', name)
  // we can log all methods in certain class
  if (name.indexOf('cymetrics') === 0) {
    var TargetClass = Java.use(name);
    var methodsList = TargetClass.class.getDeclaredMethods();
    for (var k=0; k<methodsList.length; k++){
        console.log(methodsList[k].getName());
    }  
  }
  return this.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader').call(this, name, b, c)
}

// hook Method.invoke
var Method = Java.use('java.lang.reflect.Method')
Method.invoke.overload('java.lang.Object', '[Ljava.lang.Object;').implementation = function(a,b){
  console.log('reflect', a, b)
  return this.invoke.call(this,a,b)
}
```

### Hook string operations

Some obfuscated programs will scramble all the fixed strings in the program through various steps to make them difficult to search, such as turning strings into numbers and then restoring them. Usually, when restoring, string operations will be performed. At this time, we can directly hook the string operations and use the stack trace mentioned earlier to trace:

``` js
['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
  Java.use(clazz)['toString'].implementation = function() {
    var ret = this.toString();
    console.log('ret:', ret)
    return ret;
  }   
}); 
```

### Hook encryption and decryption-related operations

Usually, in an Android app, if you want to perform encryption and decryption, you will use the built-in API, like this (source: [AES encryption in Android--Part 1](https://cloud.tencent.com/developer/article/1647740)):

``` java
public static final String CODE_TYPE = "UTF-8";
public static final String AES_TYPE = "AES/ECB/PKCS5Padding";
private static final String AES_KEY="1111222233334444";

public static String encrypt(String cleartext) {
    try {
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(AES_TYPE);
        cipher.init(Cipher.ENCRYPT_MODE, key); 
        byte[] encryptedData = cipher.doFinal(cleartext.getBytes(CODE_TYPE));
        return Base64.encodeToString(encryptedData,Base64.DEFAULT);
    } catch (Exception e) {
        e.printStackTrace();
        return "";
    }
}
```

Therefore, as long as you can hook methods like `SecretKeySpec` or `doFinal`, you can intercept the key and plaintext before encryption.

This article is worth reading: [How Secure is your Android Keystore Authentication?](https://labs.f-secure.com/blog/how-secure-is-your-android-keystore-authentication/), which includes a bunch of Frida scripts related to encryption and decryption. Here: https://github.com/FSecureLABS/android-keystore-audit/blob/master/frida-scripts/tracer-cipher.js

By the way, the script does not directly convert byte arrays to strings. Here is a more convenient way (source: [frida小技巧之string与byte转化](https://lingwu111.github.io/frida%E5%B0%8F%E6%8A%80%E5%B7%A7%E4%B9%8Bstring%E4%B8%8Ebyte%E8%BD%AC%E5%8C%96.html)):

``` js
function bytesToString(bytes) {
    var javaString = Java.use('java.lang.String');
    return javaString.$new(bytes);
}

var Base64 = Java.use('android.util.Base64')
Base64.decode.overload('[B', 'int').implementation = function(a, b) {
  console.log(bytesToString(a))
  return this.decode.call(this, a, b)
}
```

## SSL Pinning

I saw a great script in [Defeating Android Certificate Pinning with Frida](https://httptoolkit.tech/blog/frida-certificate-pinning/) that automatically hooks various functions that do SSL pinning, allowing you to bypass this mechanism. I saved a copy here: https://gist.github.com/aszx87410/f7ae60826d436d8e5bd17deb3e40c249

After saving, run it like this:

```
frida -U --no-pause -l ssl.js -f "com.example"
```

## Detecting Frida

Since Frida is so powerful, some app security mechanisms naturally want to block it. Once Frida is detected, the app will either exit directly or cause a crash. You can refer to the following two articles:

1. [Android Reverse Engineering: Multiple Feature Detection of Frida](https://www.jianshu.com/p/f679cb404524)
2. [Multiple Feature Detection of Frida](https://blog.csdn.net/zhangmiaoping23/article/details/109697329)

There are many ways to anti-detection, one of which is to hook the various methods mentioned in the above articles. After all, we have root privileges and Frida hook in front, so as long as we know how it is judged, we can definitely remove the check. If you can't find the check, you can use various hooks mentioned above to find it out step by step.

## Conclusion

In this article, we introduced the basic usage of Frida and learned how to use Frida to hook various methods to obtain various information we want.

In the first four articles, we covered some basic things, including:

1. Basic Android App composition
2. How to use Apktool to unpack and repack apk
3. How to use jadx to restore smali to java files
4. Familiar with a little bit of smali syntax, know how to modify code and add code
5. How to intercept packets through a proxy on a computer
6. How to modify the apk to allow the proxy to intercept smoothly
7. How to use Frida to hook function
8. Various tricks of Frida

If you go further, you will enter the field of native.

In addition to using Java to write Android Apps, you can also use [Android NDK](https://developer.android.com/ndk) to write code in C/C++, which can be provided to Android apps.

When do you need it? The first is the more performance-consuming places, such as image recognition, using C++ to write will be faster than Java, so native is usually used. The second is some more secretive operations, such as encryption and decryption. If placed in the Java layer, it is easy to decompile and see what is being done. If written in native, more binary-related knowledge is required to crack it.

In addition, the apps in the real world are not as simple as the apps we demonstrated earlier. They may be encapsulated or more strongly obfuscated. Even if the apk can be unpacked, if the shell cannot be removed, the real logic cannot be seen. Some shells also have mechanisms for anti-tampering and anti-dynamic analysis, which can block attackers with insufficient skills. Relevant introductions can refer to the agenda of [2019 Taiwan Cyber Security Week](http://confapi.ithome.com.tw/session/4186): [Building a Secure and Convenient App Security Protection Product](https://s.itho.me/cybersec/2019/slides/321/I_%E4%B8%96%E8%B2%BF%E4%B8%89/0321I51610%E7%8E%8B%E7%BE%BF%E5%BB%B7.pdf)

The reason why this series is called "Introduction" is because it completely does not mention the practical things that will be encountered, and only focuses on the basics and tools of the introduction. However, for apps without special obfuscation or encapsulation, this should be enough.

References:

1. [Frida Handbook](https://github.com/hookmaster/frida-all-in-one)
2. [Translation-N Ways to Unpack Android Malware](https://www.giantbranch.cn/2019/10/25/%E7%BF%BB%E8%AF%91%E2%80%94%E2%80%94N%E7%A7%8D%E8%84%B1%E5%A3%B3%E5%AE%89%E5%8D%93%E6%81%B6%E6%84%8F%E8%BD%AF%E4%BB%B6%E7%9A%84%E6%96%B9%E5%BC%8F/)
4. [This is probably the most detailed notes for learning Frida](https://juejin.cn/post/6847902219757420552#heading-39)
5. [frida-snippets](https://github.com/iddoeldor/frida-snippets#class-description)
6. [Frida Tutorial](https://book.hacktricks.xyz/mobile-apps-pentesting/android-app-pentesting/frida-tutorial)
7. [Practical FRIDA Advanced: Memory Roaming, Hook Anywhere, Packet Capture](https://www.anquanke.com/post/id/197657)
