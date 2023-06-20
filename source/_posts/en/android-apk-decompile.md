---
title: '[Android] APK Decompilation for Everyone'
date: 2016-03-20 15:11
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
categories:
  - Android
---

## Introduction

For Android engineers, understanding how to decompile can enhance their understanding of the Android system and also consider how to protect their APK from being decompiled.

For the general public, many ready-made tools can help us easily decompile APKs and see Java source code, satisfying our curiosity.

This article only introduces the use of some tools, suitable for beginners to watch. If you want to understand more underlying knowledge, you can refer to the extended reading attached at the end of the article.

<!-- more -->

## Preparations
First, we need an APK to be cracked. Simply build one with any tool you are familiar with.

The structure is very simple, just a `MainActivity` and two `TextViews`.

``` java MainActivity.java
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TextView text = (TextView)findViewById(R.id.text);
        text.setText("Taiwan No1");
    }
}
```

``` xml activity_main.xml
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:orientation="vertical"
    android:layout_height="match_parent">

    <TextView
        android:text="@string/hello_world"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />

    <TextView
        android:id="@+id/text"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content" />

</LinearLayout>
```

After installing it on the phone, you will see this screen:

![device-2016-03-20-152510.png](/img/old-articles/android-p1.png)

## Hands-on
Okay, this is the APK we want to test.

Then you need some very useful tools:

1. [apktool](http://ibotpeaches.github.io/Apktool/)
2. [jd-gui](http://jd.benow.ca/)
3. [dex2jar](https://sourceforge.net/projects/dex2jar/)

I won't go into how to install them. You can read the documentation or search the internet for a bunch of answers.

`apktool` is used to unpack the APK, which can decompile the APK and see the `smali` files and `resource`.

`dex2jar` can convert the APK to a jar, and then use `jd-gui` to view the Java code.

Then we open the terminal, go to the directory of the demo APK just now, and execute `apktool d APKNAME.apk`

![螢幕快照 2016-03-20 下午3.32.47.png](/img/old-articles/android-p2.png)

After execution, a `APKNAME` folder will be automatically generated, which contains the decompiled things.

```
.
├── AndroidManifest.xml
├── apktool.yml
├── original
├── res
└── smali
```

One of the more noteworthy folders is the `smali` folder, which is actually your source code, just in a different format. You can find your `MainActivity.java` in the `smali` folder, with the following contents: (It may look strange, but if you look closely, you'll find that it's not that difficult to understand.)

``` java MainActivity.java
.class public Lapktest/huli/com/apkdecompile/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

# direct methods
.method public constructor <init>()V
    .locals 0

    .prologue
    .line 8
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    return-void
.end method

# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    .line 12
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 13
    const v1, 0x7f040019

    invoke-virtual {p0, v1}, Lapktest/huli/com/apkdecompile/MainActivity;->setContentView(I)V

    .line 14
    const v1, 0x7f0c0050

    invoke-virtual {p0, v1}, Lapktest/huli/com/apkdecompile/MainActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    .line 15
    .local v0, "text":Landroid/widget/TextView;
    const-string v1, "Taiwan No1"

    invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 16
    return-void
.end method
```

You can compare this with the Java code you wrote earlier and see that it's just a different format.

``` java
setContentView(R.layout.activity_main);
```

Is actually equivalent to:

``` java
.line 13
const v1, 0x7f040019
invoke-virtual {p0, v1}, Lapktest/huli/com/apkdecompile/MainActivity;->setContentView(I)V
```

You may wonder where `0x7f040019` comes from. In fact, you can find the answer in the `res/values/public.xml` file:

``` xml
<public type="layout" name="activity_main" id="0x7f040019" />
```

At this point, you should have a rough idea of the Android compilation process:

1. Compress and process all resource files and package them together to generate an `id-to-memory-location mapping` table.
2. Replace all `R.xx.xxx` in the code with actual memory locations using the table generated earlier.
3. Convert Java code to smali code (similar to converting C code to assembly code).

## Modification

In the `smali` code above, there is the following section:

``` java
.line 15
.local v0, "text":Landroid/widget/TextView;
const-string v1, "Taiwan No1"

invoke-virtual {v0, v1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
```

Let's replace `Taiwan No1` with `T@iw@n n0!`.
Do you remember the other `TextView` that used `R.string.hello_world`?
In `res/values/strings.xml`, you can find the definition of this string:
``` xml
<string name="hello_world">Hello world!</string>
```
Change it to:
``` xml
<string name="hello_world">HELLO WORLD</string>
```

After making sure everything has been changed, you can "assemble" the code again.
Do you remember the decompilation command we used earlier? `apktool d APK_NAME.apk`
Here, `d` means `decompile`, so if you want to reverse assemble it, it's `b`, `build`.

`apktool b APK_NAME`

After executing it, you can find an apk in `APK_NAME/dist`.
Note that this apk has not been signed, so it cannot be installed.
You can generate a keystore or find an existing one to sign it.
`jarsigner -verbose -digestalg SHA1 -keystore ~/KEY.keystore APK_NAME.apk KEY_ALIAS`

After installation, you will see this screen:

![device-2016-03-20-160501.png](/img/old-articles/android-p3.png)

Yes! It's that simple. An apk has been modified like this.

But `smali` code is hard to understand. Can we directly see the java code?

This is where the recommended tools `dex2jar` and `jd-gui` come in handy.

The former can turn an apk into a jar, and the latter can open a jar and display the java code.

The combination of the two allows you to see the original code directly.

After downloading `dex2jar`, there will be a bunch of shell scripts. `dex2jar` is the one we want.

`./d2j-dex2jar.sh app.apk`

After execution, there will be a jar. Open it with jd-gui, and you will see your code at a glance.

![螢幕快照 2016-03-20 下午4.10.15.png](/img/old-articles/android-p4.png)

## Summary
People who have not touched decompilation may be surprised: What! It's so easy to modify an apk!

Yes, it's that simple, and this is just a very basic example.

In fact, you can also add new code and resources (images, sounds, etc.).

That is to say, you can not only modify but also extend the original apk.

But there are also methods to prevent unscrupulous people from decompiling apk.

For example, shell, obfuscation, dynamic loading, etc.

I will introduce them later if there is a chance.

## Further reading

1. [Android Decompilation and Anti-Decompilation](https://magiclen.org/android-decompiler/)
2. [[Android] Code Obfuscation (ProGuard) and Decompilation](http://aiur3908.blogspot.tw/2015/07/android-proguard.html)
3. [[Android] Decompilation Cracking Android's apk installation file](http://blog.davidou.org/archives/553)
4. [Common tools and usage methods for decompilation](http://www.wangchenlong.org/2016/03/19/reverse-analyze-apk/)
5. [Smali--Dalvik virtual machine instruction language-->[android_smali syntax learning one]](http://blog.csdn.net/wdaming1986/article/details/8299996)
6. [android decompilation-smali syntax](http://blog.isming.me/2015/01/14/android-decompile-smali/)
