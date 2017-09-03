---
title: '[Android] failed to complete gradle execution, cause is ""'
date: 2015-07-28 11:07
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
今天碰到了這個問題
[Android Studio: failed to complete gradle execution, cause is empty](http://stackoverflow.com/questions/27407855/android-studio-failed-to-complete-gradle-execution-cause-is-empty)

找了一下解法原本以為是因為這個
[Building Apps with Over 65K Methods](http://developer.android.com/intl/ru/tools/building/multidex.html#mdex-gradle)

加了以後發現不是，找到[這篇](http://stackoverflow.com/questions/30630427/failed-to-complete-gradle-execution-cause-is-empty-65k-methods-limit)

用`gradlew assembleDebug --stacktrace`自己下去build，就可以看到錯誤在哪了
