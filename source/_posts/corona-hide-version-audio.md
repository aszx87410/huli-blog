---
title: '[Corona] 隱藏版Audio '
date: 2014-04-23 18:18
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [corona]
---
[The secret/undocumented audio APIs in Corona SDK](http://coronalabs.com/blog/2011/07/27/the-secretundocumented-audio-apis-in-corona-sdk/)

某些不太穩定的audio API，提供了更多的功能
例如說可以調pitch，而使用的方式很簡單

``` lua
local music = audio.loadSound("sounds/a.mp3",system.ResourcesDirectory)
local channel, music_play = audio.play(music)
al.Source(music_play, al.PITCH, 2.0);
```