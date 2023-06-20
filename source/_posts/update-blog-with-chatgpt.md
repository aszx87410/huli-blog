---
title: 利用 chatGPT 翻新部落格
catalog: true
date: 2023-06-20 14:10:44
tags: [Others]
categories: [Others]
photos: /img/update-blog-with-chatgpt/cover.png
---

我的部落格架構其實很久沒有大幅改動過了，hexo 現在已經出到 v6，v7 正在 beta，而我的部落格還停留在 hexo3。

最近想說剛好比較有空，就趁機找時間翻新部落格，順便運用了 chatGPT 來當小助手。

這次做的改動有：

1. Hexo 升級版本
2. 修改 syntax highlight
3. 深色模式
4. 自動翻譯（重點）

<!-- more -->

## Hexo 升級版本

這次升級比我想像中順利很多，照著網路上找到的教學安裝 `npm-upgrade`，跑一下之後就升級了，而且升級之後沒什麼東西需要調整。

真是順利！

## 修改 syntax highlight

原本用的是 highlight.js，但想換很久了，原因是這套不支援 JSX。

升級版本之後發現 Hexo 內建就有支援另一套 Prism.js，就順便換過去了，只要改一下設定檔跟手動新增 style 就弄好了，其實滿簡單的。

比較麻煩的是有些 class 跟其他 library 有衝突，就需要再手動調整一下。

## 深色模式

![dark mode](/img/update-blog-with-chatgpt/p1.png)

我的佈景主題用了 [Bulma](https://bulma.io/) 這一套 CSS library，而它並不支援深色模式，因此要自己做一個。

我改的方式也很簡單，就是先找到頁面上每一個字跟背景的顏色，把它換成 CSS variable，最後加上一點簡單的 JavaScript 就完成了。

CSS 部分像是這樣：

``` css
:root {
  --main-text-color: #4a4a4a;
  --main-bg-color: white;
  --main-border-color: #dbdbdb;
  --title-text-color: #363636;
  --link-text-color: #3273dc;
  --link-hover-text-color: #363636;
  --code-bg-color: whitesmoke;
  --code-text-color: #ff3860;
  --tag-bg-color: whitesmoke;
  --tag-text-color: #363636;
  --quote-bg-color: whitesmoke;
  --nav-link-text-color: darkgray;
  --notice-bg-color: #ffe4c4;
  --archive-time-color: #888;
  --archive-hover-border-color: black;
}

body.dark-mode {
  --main-text-color: #f8f8f8;
  --main-bg-color: #061320;
  --main-border-color: #dbdbdb;
  --title-text-color: #fafafa;
  --link-text-color: #27ebda;
  --link-hover-text-color: #98fff6;
  --code-bg-color: #324b7e;
  --code-text-color: #f7f7f7;
  --tag-bg-color: whitesmoke;
  --tag-text-color: #363636;
  --quote-bg-color: #49495e;
  --nav-link-text-color: #b4b5b4;
  --notice-bg-color: #257800;
  --archive-time-color: #ddd;
  --archive-hover-border-color: #51ce97;
}
```

JavaScript 則是這樣：

``` js
if (localStorage.getItem('dark-mode')) {
    if (localStorage.getItem('dark-mode') === 'true') {
        document.body.classList.add('dark-mode')
    }
} else {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.body.classList.add('dark-mode')
    }
}
```

大概花了半天左右的時間邊改邊測，就可以全部弄完。

另外順便解決了一下 CSS 大小的問題，用這個服務可以幫你把沒有用到的 CSS 清掉：https://purifycss.online/

雖然說還是會有些殘留或是誤刪，所以記得用完之後要自己再檢查一遍。

## 自動翻譯

重頭戲來了，這個功能大幅依靠 chatGPT 幫我完成。

![translation](/img/update-blog-with-chatgpt/p3.png)

首先是最重要的翻譯的部分，靠的是 [markdown-gpt-translator](https://github.com/smikitky/markdown-gpt-translator) 這個套件，會幫你自動分段然後 call API，再把結果組裝回來。

還有一點很棒的是 code block 不會上傳，所以省了很多 token，但要注意的是 code block 裡面的 comment 要自己翻譯。

當初驗證過這一個翻譯的 lib 可以用之後，我就著手進行修改，順便跟我原本想要的自動翻譯功能整合。

然後，因為 TypeScript 的環境設置有點麻煩，我用了這個工具幫我直接轉成 JavaScript：https://transform.tools/typescript-to-javascript

自動翻譯要先把以前舊的文章全部翻一遍，流程是：

1. 列出所有文章的檔案
2. 查看翻譯後的版本是否存在
3. 不存在，呼叫翻譯並寫入檔案

這些功能的框架都直接丟給 chatGPT 幫我寫，我自己再調整一下，補充一下細節即可。

![chatgpt](/img/update-blog-with-chatgpt/p2.png)

以我自己的文章來說，翻譯一篇需要一分鐘左右，價錢的話大約是 0.02 ~ 0.04 美元。部落格總共 100 多篇文章，翻譯完之後花了不到 3 塊美金，我覺得滿便宜的。

不過當然還是會有一些需要手動調整的地方，而且還不少，所以還是需要人來做這件事情，我把程式碼跟需要注意的地方都放在這邊了：https://github.com/aszx87410/huli-blog/tree/master/apps/translator

其實原本翻譯完以後，我想說我一篇一篇看過，但發現有點太花時間了，所以就先放著了，等之後有時間再來 review。

## 翻新 Open Graph Image

之前寫了一個產生瀏覽圖的小功能，但是以前很多文章都還沒用到這個功能，這次也靠 chatGPT 幫我寫了一個小程式能夠快速轉換。

稍微翻修了一下以前的程式碼，順便把以前文章全部掃過一遍，沒產生的就自動產生，然後加上正確的路徑。


## 還沒做好的功能

最後記一下還沒做好的功能，以後要找比較方便：

1. 更新 sitemap
2. 檢查英文文章連結
3. 檢查英文文章內容
4. 修改留言系統
5. 修改多語系 RSS
6. 自動壓縮圖片
