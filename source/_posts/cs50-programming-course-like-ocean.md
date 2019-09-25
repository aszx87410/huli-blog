---
title: '如海洋般的程式課程：CS50'
date: 2016-03-28 21:56
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [CS50]
categories:
  - Others
---
CS50 的全名是 **Introduction to Computer Science**，是一堂哈佛大學的通識課程
在 [edx](https://www.edx.org/course/introduction-computer-science-harvardx-cs50x) 上面有開課，任何人都可以去修，甚至還有助教幫你改作業（只有程式作業，不包含其他像是紙本作業的那種題目）

我第一次聽到 CS50 這堂課，是經由這篇報導：[CS50：一堂超過 800 個哈佛學生選修的「硬課」，魅力何在？](http://www.inside.com.tw/2014/12/17/harvard-cs50)
一直到最近把這門課修完之後，才了解這門課厲害在哪裡。

先來回答標題的意思：如海洋般的程式課程。為什麼是海洋，因為這門課：**又深又廣**
有多深多廣呢？我記下每一週的課程大綱跟作業，請你身邊有資工背景的朋友看看，就會知道我在說什麼了

<!-- more -->

## 第零週
二進位、ASCII、RGB、二分搜尋法
介紹基本程式語言：條件判斷、變數、迴圈、陣列、函式
作業：用 [scratch](https://scratch.mit.edu/) 寫一個程式

## 第一週
開始介紹 C 語言，以及講解 compile 的觀念
介紹各種形態，像是 double, float, int, bool, char, long long...
介紹浮點數誤差與 overflow
教你 command line 基本操作，像是 `mv`, `ls`, `cd`, `make` 等等
作業：寫一個簡單的 C 程式（迴圈印出星星）

## 第二週
介紹 function, string, array
以及如何利用 `argc`, `argv` 傳入參數
還有講到加密，像是 RSA
教了 command line 的 Redirecting（`>`）還有 Pipe（`|`）
作業：字串處理，簡單加解密實作

## 第三週
搜尋、排序（氣泡、插入、選擇、快排、合併）、big O
遞迴、bit 操作
GDB 的使用
作業：實作O(n^2)的排序跟二分搜

## 第四週
再次講解遞迴
字串、指標、`struct`、bitmap 格式
檔案處理（`fprint`/`fopen`...）
`malloc`，記憶體分配
教你用 `xxd` 看檔案的 hex
作業：給你 bitmap header 的文件，處理 bitmap 圖片，例如說放大兩倍

## 第五週
深入講解記憶體與指標
資料結構：`linked list`, `queue`, `stack`, `tree`, `BST`, `tries`, `hashmap`
教你用 `wget` 抓檔案，以及如何寫 `Makefile`
作業：實作字典樹或是 hashmap

## 第六週
這週開始講跟網路有關的，包括：`IP`, `IPv6`
`domain`, `nslookup`, `traceroute`, 封包
`ports`, `dns`, `vpn`, `http`, `request`, `response`
教你用`chmod`改檔案權限，以及`curl`抓網頁
作業：用 C 寫一個 http server（的部份功能）

## 第七週
chrome dev tool 的使用，像是看 `html`, `request`
基本 `html` 與 `css` 教學
`php` 簡介
get/post 參數介紹
`sql`基本教學
教你用`apt-get`安裝套件
作業：完成簡單的 `php` 網頁以及與資料庫溝通

## 第八週
示範重構程式碼，講解`MVC`的觀念
教基本 `SQL` 語法
有介紹到`SQL Injection`
作業：串`Google Map API`，使用`jQuery`跟`ajax`做出互動性較高的網頁

## 第九週
javascript 語法簡介
json 格式講解
DOM 模型
event handler，事件機制
（從這週以後沒有作業）

## 第十週
探討資訊安全與隱私權
像是密碼安全性（加密演算法、salting）
智慧型電視
釣魚信件
Two-factor authentication
cookies, session, https
也稍微講了一下語音辨識，像`siri`背後的原理

## 第十一週
遊戲AI相關的介紹與無人車的介紹
有提到：
dfs, bfs
minimax
evaluation function
alpha-beta 剪枝
各種不同遊戲的ai特性
還講了一點機器學習，像是`netflix`怎麼推薦影片給使用者

## 第十二週
整個課程的回顧加上大家玩一點小遊戲
這週沒什麼課程

我修這門課的時候，簡直驚呆了
哇塞！居然教你怎麼寫`Makefile`，還教你用`xxd`看檔案，甚至給你`bitmap`的文件，要你按照這些格式把圖片讀取出來，然後放大之後寫回去！
寫到我最崩潰的作業是 http server 那個，因為要用`C`做字串處理...

從上面洋洋灑灑十二週的課程介紹，就知道這門課真的**又深又廣**
稍微整理一下，你修完之後可以學到：
1. 寫程式的基本功：變數、陣列、判斷、迴圈、函式
2. 你學會了指標！
3. 直接操作記憶體，了解電腦底層在做什麼
4. 熟悉基本排序演算法法與資料結構
5. 各種 command line 指令的使用（我覺得這一點超級實用）
6. 網路的基本知識（ip, dns, server, port, request, response...）
7. 後端程式語言 php
8. 前端 html/css/javascript
9. 資料庫 mysql 的使用與指令
10. 資訊安全（加解密、sql injection, buffer overflow）
11. 機器學習、人工智慧、語音辨識初步了解

我一直以來都是自學程式的，儘管上大學之後有修過幾門程式相關的課
但都只是當做複習而已，沒有學到太多東西
可是這次碰到這門課，真的讓我打從心底讚嘆不已
他課程裡所介紹到的每一個東西都很實用，有些甚至連我也都是近期才會用的
以前自學的時候甚至連 command line 都沒用過勒！因為根本也沒有機會用到

除此之外，儘管這門課講的內容有深度，但老師在上課的時候幽默風趣，可以把生澀的概念講的很生動
例如說講到二分搜尋法，老師拿電話簿當做例子，接著直接從中間撕一半！
又或是上到二進位，台上就有幾個燈泡，亮的就是1，暗的就是0，藉由這樣實體的互動加深印象

在課程教學上面，也有幾點是我很欣賞的
第一，從 `scratch` 入門
在修完 cs50 以後，我決定以後要教人程式設計，都要從`scratch`開始
因為它視覺化，你可以很明顯看到程式的結構長怎樣；而且它速度快、內建資源完整
你想做遊戲就拖拉幾個角色、定義一下事件就好
我認為`scratch是程式入門的最佳選擇

第二，把很難講解的概念先包裝起來
像是字串，在`C`裡面其實就是`char*`，或者說是`char`形成的陣列
可是在一開始，你要怎麼跟學生講解呢？
於是他們就寫了一個`string`的type出來，把這些資訊隱藏起來，等之後上到陣列時，再跟學生講

還有`scanf`，會牽涉到`pointer`跟`call by value`之類的概念，這也不適合在一開始就講
可是程式還有要有輸入阿，怎麼辦呢？
於是他們就包成一個`GetInt()`的函式，把這些細節封裝起來

第三，雲端IDE
要搭建開發環境不是件容易的事
CS50 與 [c9](https://c9.io/) 合作，提供線上的 IDE
你可以寫code，可以看檔案、可以用 command line 操作，一切作業都在上面完成
超級方便！

最後
這一堂課真的是門硬課，但同時也是很扎實、很有用的課
推薦給任何想要學寫程式的人

若是你正在修，卻找不到人討論的話，可以到這個臉書社團：
[cs50 中文討論區](https://www.facebook.com/groups/556507217856457/)
