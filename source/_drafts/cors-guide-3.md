---
title: CORS 完全手冊（三）：CORS 詳解
catalog: true
date: 2020-07-24 23:07:47
tags: [Ajax,JavaScript,Front-end,CORS]
categories:
  - Front-end
---

## 前言

在上一篇裡面我們提到了常見的 CORS 錯誤解法，以及大多數狀況的唯一正解：請後端加上 response header。

但其實「跨網域請求」這個東西又可以再細分成兩種，簡單請求跟非簡單請求，簡單請求的話可以透過上一篇的解法來解，但非簡單請求的話就比較複雜一些了。

除此之外，跨網域請求預設是不會把 cookie 帶上去的，需要在使用 xhr 或是 fetch 的時候多加一個設定，而後端也需要加一個額外的 header 才行。

這篇就讓我們仔細來看看這些與 CORS 有關的細節，再更瞭解 CORS 一點吧！

## Preflight request

如果你試著送出一個跨網域的請求
錯誤原因

## 帶上 Cookie

有時候需要驗

1. 
