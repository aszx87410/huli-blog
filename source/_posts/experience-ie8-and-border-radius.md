---
title: '[心得] IE8 與 border-radius'
date: 2016-01-15 16:07
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [frontend]
---
眾所皆知，IE8不支援一大堆東西，包括 `border-radius`
有個神奇的網站叫做： http://css3pie.com/，會有一個 `PIE.htc`的檔案
加上：`behavior: url(/css/PIE.htc);`
可是加進去之後發現背景看不到了，還是壞的
經過千辛萬苦地查詢之後，發現解答就在：http://css3pie.com/documentation/known-issues/

>The only way I know of to work around this is to either:
1. make the target element position:relative, or
2. make the ancestor element position:relative and give it a z-index.

加上 `position: relative;` 就行了，大功告成！

