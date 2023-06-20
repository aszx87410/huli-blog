---
title: "Android App Reverse Engineering Part 2: Modifying Smali Code"
catalog: true
date: 2023-04-27 14:12:44
tags: [Security]
categories: [Security]
photos: /img/android-apk-decompile-intro-2/cover-en.png
---

In the first part, we learned the basics of using Apktool to decompile an APK, modify its resources, reassemble it, and install the aligned and signed APK on a device.

In this part, we will learn how to modify the code.

Our goal is to bypass the root detection check on a rooted device and make the app display that it is not rooted. If you are testing on a non-rooted device, you can do the opposite and modify the app to detect that you have root access.

<!-- more -->

Series links:

1. [Android App Reverse Engineering Part 1: Decompiling and Recompiling APKs](/2023/04/27/en/android-apk-decompile-intro-1/)
2. [Android App Reverse Engineering Part 2: Modifying Smali Code](/2023/04/27/en/android-apk-decompile-intro-2/)
3. [Android App Reverse Engineering Part 3: Intercepting App Traffic](/2023/04/27/en/android-apk-decompile-intro-3/)
4. [Android App Reverse Engineering Part 4: Dynamic Analysis with Frida](/2023/04/27/en/android-apk-decompile-intro-4/)

## What is Smali

In the content we decompiled using `apktool d`, there is a folder called `smali`, which contains the code that was decompiled from `classes.dex`. However, this code may not look like what you expect. For example, let's take a look at `smali/com/cymetrics/demo/MainActivity.smali`:

``` java
.class public Lcom/cymetrics/demo/MainActivity;
.super Landroidx/appcompat/app/AppCompatActivity;
.source "MainActivity.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 16
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V

    return-void
.end method


# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 1

    .line 20
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onCreate(Landroid/os/Bundle;)V

    const p1, 0x7f0b001c

    .line 21
    invoke-virtual {p0, p1}, Lcom/cymetrics/demo/MainActivity;->setContentView(I)V

    const p1, 0x7f080122

    .line 22
    invoke-virtual {p0, p1}, Lcom/cymetrics/demo/MainActivity;->findViewById(I)Landroid/view/View;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/widget/Toolbar;

    .line 23
    invoke-virtual {p0, p1}, Lcom/cymetrics/demo/MainActivity;->setSupportActionBar(Landroidx/appcompat/widget/Toolbar;)V

    const p1, 0x7f08007a

    .line 25
    invoke-virtual {p0, p1}, Lcom/cymetrics/demo/MainActivity;->findViewById(I)Landroid/view/View;

    move-result-object p1

    check-cast p1, Lcom/google/android/material/floatingactionbutton/FloatingActionButton;

    .line 26
    new-instance v0, Lcom/cymetrics/demo/MainActivity$1;

    invoke-direct {v0, p0}, Lcom/cymetrics/demo/MainActivity$1;-><init>(Lcom/cymetrics/demo/MainActivity;)V

    invoke-virtual {p1, v0}, Lcom/google/android/material/floatingactionbutton/FloatingActionButton;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    return-void
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2

    .line 38
    invoke-virtual {p0}, Lcom/cymetrics/demo/MainActivity;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const/high16 v1, 0x7f0c0000

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    const/4 p1, 0x1

    return p1
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 2

    .line 47
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    const v1, 0x7f08003f

    if-ne v0, v1, :cond_0

    const/4 p1, 0x1

    return p1

    .line 54
    :cond_0
    invoke-super {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method

```

If you find it hard to read, that's normal.

Smali is the byte code that runs on the Android Dalvik VM and has its own syntax rules. To see the Java code we are familiar with, we need to decompile the Smali code back into Java.

## Decompiling Smali Code into Java Code with jadx

Next, we will use another tool: [jadx](https://github.com/skylot/jadx), which describes itself on GitHub as a "Dex to Java decompiler."

I will skip the installation process, and we will use jadx to decompile the APK:

``` shell
# -r means don't decompile resources
# -d is for destination
jadx -r demoapp.apk -d jadx-demoapp
```

After running the command, we will see a new folder called `jadx-demoapp`. We can navigate to `sources/com/cymetrics/demo/MainActivity.java` and see the following content:

``` java
package com.cymetrics.demo;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;
/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        setSupportActionBar((Toolbar) findViewById(R.id.toolbar));
        ((FloatingActionButton) findViewById(R.id.fab)).setOnClickListener(new View.OnClickListener() { // from class: com.cymetrics.demo.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", 0).setAction("Action", (View.OnClickListener) null).show();
            }
        });
    }

    @Override // android.app.Activity
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override // android.app.Activity
    public boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(menuItem);
    }
}

```

This is the content we want to see! Since this APK has not been obfuscated, we can see almost the entire Java file, which is not much different from the original source code.

To briefly explain obfuscation, it is the process of scrambling the code to make it difficult for people to see what the original code was. For example, changing variable names to meaningless names like aa, bb, cc, dd is the most basic form of obfuscation. In Android development, ProGuard is usually used to obfuscate code.

The code above is obviously not obfuscated, making it easy for us to see the original logic.

The code we want to modify is in `com/cymetrics/demo/FirstFragment.java`:

``` java
package com.cymetrics.demo;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import com.scottyab.rootbeer.RootBeer;
/* loaded from: classes.dex */
public class FirstFragment extends Fragment {
    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        return layoutInflater.inflate(R.layout.fragment_first, viewGroup, false);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        super.onViewCreated(view, bundle);
        view.findViewById(R.id.button_first).setOnClickListener(new View.OnClickListener() { // from class: com.cymetrics.demo.FirstFragment.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view2) {
                TextView textView = (TextView) view2.getRootView().findViewById(R.id.textview_first);
                if (new RootBeer(view2.getContext()).isRooted()) {
                    textView.setText("Rooted!");
                } else {
                    textView.setText("Safe, not rooted");
                }
            }
        });
    }
}
```

The main logic is in this section:

``` java
public void onClick(View view2) {
    TextView textView = (TextView) view2.getRootView().findViewById(R.id.textview_first);
    if (new RootBeer(view2.getContext()).isRooted()) {
        textView.setText("Rooted!");
    } else {
        textView.setText("Safe, not rooted");
    }
}
```

This section calls a third-party library to check for root access. If root access is detected, it displays "Rooted!" Otherwise, it displays "Safe, not rooted."

When studying the code logic, we can look at the Java code. However, if we want to modify the code, it is not as simple as modifying the Java code. We must modify the Smali code directly to repackage the app.

## Modifying Smali Code

Do you remember the folder we extracted using Apktool? The Smali code is in there, and the path is `smali/com/cymetrics/demo/FirstFragment$1.smali`. If we carefully examine the content, we can find the `onClick` code:

``` java
# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 2

    .line 32
    invoke-virtual {p1}, Landroid/view/View;->getRootView()Landroid/view/View;

    move-result-object v0

    const v1, 0x7f08011c

    invoke-virtual {v0, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/TextView;

    .line 34
    new-instance v1, Lcom/scottyab/rootbeer/RootBeer;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    invoke-direct {v1, p1}, Lcom/scottyab/rootbeer/RootBeer;-><init>(Landroid/content/Context;)V

    .line 35
    invoke-virtual {v1}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z

    move-result p1

    if-eqz p1, :cond_0

    const-string p1, "Rooted!"

    .line 36
    invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    goto :goto_0

    :cond_0
    const-string p1, "Safe, not rooted"

    .line 38
    invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :goto_0
    return-void
.end method
```

This is a brief explanation of some basic smali syntax. `.method public onClick(Landroid/view/View;)V` means that there is a public method called onClick, which takes a parameter of type `android/view/View`, and the V at the end of the parentheses means void, indicating that there is no return value.

`.locals 2` means that this function will use two registers, v0 and v1. If you use v2, it will cause an error. Therefore, if you need more registers, remember to change this part.

The parameter is represented by p. Usually, p0 represents this, and p1 is the first parameter. Therefore, `invoke-virtual {p1}, Landroid/view/View;->getRootView()Landroid/view/View;` calls the `getRootView()` method with the first parameter.

The core code in this section is:

``` java
.line 35
invoke-virtual {v1}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z

move-result p1

if-eqz p1, :cond_0

const-string p1, "Rooted!"

.line 36
invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

goto :goto_0

:cond_0
const-string p1, "Safe, not rooted"
```

`if-eqz p1, :cond_0` means that if p1 is 0, it will jump to `:cond_0`, and p1 is the return value of `RootBeer->isRooted()`. That is to say, p1 represents the result of the root check, and as long as p1 is changed, different results can be forged.

There are many ways to change it. For example, changing the original `if-eqz` to `if-nez` can reverse the logic, or we can directly change p1 to 0 and add a log to confirm that we have executed here:

``` java
.line 35
invoke-virtual {v1}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z

move-result p1

# add log, print "we are here"
const-string v1, "we are here"
invoke-static {v1, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

# set p1 to 0
const/4 p1, 0x0

if-eqz p1, :cond_0

const-string p1, "Rooted!"

.line 36
invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

goto :goto_0

:cond_0
const-string p1, "Safe, not rooted"
```

After adding those three lines, save it, then repack it as mentioned in the previous article, install it on the phone, and check the log.

To view Android's log, you need to use the `adb logcat` command. However, if you enter this command directly, a lot of logs will be displayed. Here are two useful commands.

The first is `adb logcat -c`, which clears the previous log. The second is:

``` shell
adb logcat --pid=`adb shell pidof -s com.cymetrics.demo`
```

This can display logs of the specified package name and exclude other noise, which is really useful.

After preparation, click the `CHECK ROOT` button in the app, and you will see a new log:

``` shell
01-25 09:32:06.528 27651 27651 E we are here: we are here
```

And the words `Safe, not rooted` on the screen, which means we have succeeded.

## Modifying code in other places

We just modified the code in the fragment, which is the logic of the program, and replaced the return value of `isRooted()` to always be false, bypassing the check.

But if there are other places in the program that will do similar checks, it will be troublesome because we must find every place that does the check and do similar things to change each one.

Therefore, a more efficient method is to directly modify the code of this third-party library to make `isRooted` always return false. This way, even if the app checks in multiple places, they will all be bypassed.

The code when calling the function is `Lcom/scottyab/rootbeer/RootBeer;->isRooted()`, so we can find this file by searching for `com/scottyab/rootbeer/RootBeer.smali` and searching for `isRooted` to find the code:

``` java
.method public isRooted()Z
    .locals 1

    .line 44
    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->detectRootManagementApps()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->detectPotentiallyDangerousApps()Z

    move-result v0

    if-nez v0, :cond_1

    const-string v0, "su"

    invoke-virtual {p0, v0}, Lcom/scottyab/rootbeer/RootBeer;->checkForBinary(Ljava/lang/String;)Z

    move-result v0

    if-nez v0, :cond_1

    .line 45
    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->checkForDangerousProps()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->checkForRWPaths()Z

    move-result v0

    if-nez v0, :cond_1

    .line 46
    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->detectTestKeys()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->checkSuExists()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->checkForRootNative()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0}, Lcom/scottyab/rootbeer/RootBeer;->checkForMagiskBinary()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    return v0
.end method
```

Patching this function is very simple. We just make it always return false:

``` java
.method public isRooted()Z
    .locals 1
    
    # always returns false
    const/4 v0, 0x0
    return v0
    
    # 以下省略...
.end method
```

After that, repack it and install it on the phone as before, and you will see the bypassed result.

## Summary

In this article, we learned how to read basic smali code and modify it, and how to use `adb logcat` to view Android app logs. We also modified smali practically, reversed the original logic, and bypassed the root check of the app.

Adding logs is a method that I think seems stupid and inefficient, but it is very useful. It is like adding a lot of `console.log` when writing code with errors to confirm that the execution flow of the program matches our expectations, which is helpful for restoring logic.

Finally, I only briefly mentioned smali in this article. If you want to learn more about smali syntax, you can refer to the following articles:

1. [Android Reverse Basics: Smali Syntax](https://www.jianshu.com/p/9931a1e77066)
2. [APK Decompilation 1: Basic Knowledge-Smali File Reading](https://blog.csdn.net/chenrunhua/article/details/41250613)

In the next article, I will introduce how to monitor the requests and responses sent by the app to help us understand the communication between the app and the API server.

Series links:

1. [Android App Reverse Engineering Part 1: Decompiling and Rebuilding APKs](/2023/04/27/en/android-apk-decompile-intro-1/)
2. [Android App Reverse Engineering Part 2: Modifying Smali Code](/2023/04/27/en/android-apk-decompile-intro-2/) - You are here
3. [Android App Reverse Engineering Part 3: Monitoring App Packets](/2023/04/27/en/android-apk-decompile-intro-3/)
4. [Android App Reverse Engineering Part 4: Dynamic Analysis with Frida](/2023/04/27/en/android-apk-decompile-intro-4/)
