---
title: 一些不太好記卻很好用的 CSS 屬性
catalog: true
date: 2021-04-17 22:27:27
tags: [Front-end]
categories:
  - Front-end
---

## 前言

CSS 寫一陣子之後，大家對於常見的屬性應該都很熟了，例如說最基本的 display、position、padding、margin、border、background 等等，在寫 CSS 的時候不需要特別查什麼東西，很順的就可以寫出來。

這些屬性之所以常見，是因為許多地方都用得到所以常見，而有些 CSS 屬性只能使用在某些特定地方，或者是只有某個特定的情境之下才會出現。我很常會忘記這些沒那麼常用到的屬性，但在某些時候這些屬性其實特別重要。

因此這篇想來介紹一些我覺得不太好記但是卻很好用的 CSS 屬性，也是順便幫自己留個筆記。

<!-- more -->

## input 的外框跟「那一根」的顏色

比起 border，outline 是一個比較少出現的屬性，但這邊要特別提的是在 input 上的應用。瀏覽器預設的行為中，當你 focus 到 input 時外層會出現藍色的一圈：

![](https://static.coderbridge.com/img/aszx87410/20397c22ae6d44a28b9444b12bea3723.gif)

那個藍色的就是 outline，可以透過 Chrome devtool 證實這件事：

![](https://static.coderbridge.com/img/aszx87410/83fd44bc13d54182a1deb221ba0d4792.png)

所以如果不想要 outline 或是想改顏色，就用 outline 這個屬性去改就行了。

然後 focus 之後會出現的那個一直閃的那一根 | 叫做 caret，如果想改變顏色的話可以用 caret-color 這屬性去改：

![](https://static.coderbridge.com/img/aszx87410/7d0fa9146b51406ab481f82cf6b0d113.png)

## 點擊時的藍色框框

我記得在手機上點擊一些東西的時候會出現一個藍色的外框還什麼之類的，但我剛剛怎麼試都沒有試出來，總之對應的屬性叫做 `-webkit-tap-highlight-color`，用這關鍵字查應該可以查到一些其他文章跟範例。

## 滑動時超出範圍（？）的移動

不知道怎麼明確形容這個，直接上圖：

![](https://static.coderbridge.com/img/aszx87410/e5f88faa32e84b929f19dd07f4b5f39a.gif)

在手機上的時候有時候可以滑出超過頁面，就會看到背景的白色，或者是有些瀏覽器會有下拉重整的功能，當你在頁面最頂端還往下拉的時候就會變成重新整理。

如果想阻止這個行為，可以用 `overscroll-behavior` 這個屬性。

更詳細的介紹可以參考：[Take control of your scroll: customizing pull-to-refresh and overflow effects](https://developers.google.com/web/updates/2017/11/overscroll-behavior)

## 平滑捲動

有許多網站都有一個功能，最常見的是部落格，在右側可能會出現文章的每一個段落標題，點下去之後就可以快速捲動到那個段落去。

如果什麼都沒有設定的話，就是點下去直接跳到那邊。但有一種東西叫做平滑捲動（smooth scroll），中間會有一些過場，會讓使用者知道是捲到那邊去的。

很久以前這功能可能需要 JS，但現在可以用 CSS 的 `scroll-behavior: smooth;` 來搞定（底下範例取自 [MDN](https://developer.mozilla.org/zh-CN/docs/Web/CSS/scroll-behavior)）：

![](https://static.coderbridge.com/img/aszx87410/3cd94361cae14ac69eeef2a9a20d1406.gif)

## 載入新內容時的 scroll 位置

許多網站都有捲到最底下的時候自動載入更多的功能，在載入更多的時候，你會預期使用者還是停留在同一個位置，不會因為載入更多就自動把捲軸往下捲之類的。

但有時候瀏覽器預設的處理方式不如預期，有可能你載入更多元素的時候，畫面並沒有停留在你想像中的位置。

這時候可以用 `overflow-anchor` 這個 CSS 屬性來調整這個行為，細節可以參考：[CSS overflow-anchor属性与滚动锚定](https://www.zhangxinxu.com/wordpress/2020/08/css-overflow-anchor/)

## 滑一次就滑一個元素

有時候我們會需要一個效果是使用者輕輕滑一下，就直接滑到下一個元素，而不是滑到任意地方，這可以透過 `scroll-snap` 相關的屬性來達成，像是這樣：

![](https://static.coderbridge.com/img/aszx87410/dbe5f93d8df548d7ac0355638c974060.gif)

這感覺要做 carousel 的時候應該滿好用的，想看更多用法可以參考：[Practical CSS Scroll Snapping](https://css-tricks.com/practical-css-scroll-snapping/)，上面的範例也是來自於這篇文章。

## 手機上的 300ms 點擊延遲

這應該不少人知道，在手機上面的點擊事件會有個大約 300ms 的 delay，也就是說你點下去之後要等 300ms 才會觸發 click 事件。會有這個 delay 是因為在手機上你可以雙擊來放大畫面 zoom in，所以在你點第一次的時候，瀏覽器不知道你是要點兩次還是只點一次，因此需要等一段時間。

這個 delay 在之前好像就已經被拔掉了，但如果你發現還有的話，可以用 `touch-action: manipulation` 這個 CSS 屬性來解決，這屬性可以設置停用一些手勢。

更多詳情可以參考 [MDN](https://developer.mozilla.org/zh-CN/docs/Web/CSS/touch-action)，或者是這篇文章：[300ms tap delay, gone away](https://developers.google.com/web/updates/2013/12/300ms-tap-delay-gone-away)。

順帶一提，我是在 Facebook 的網站看到這個 CSS 屬性的。

## font-smooth

我是在 Create React App 預設的 [css](https://github.com/facebook/create-react-app/blob/master/packages/cra-template/template/src/index.css#L6) 裡面看到這個屬性的：

```
body {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
```

實際上在許多網站也可以發現這兩個屬性，查了一下發現是跟字體的渲染有關，例如說 antialiased 其實就是大家應該都聽過的「反鋸齒」。可以自己決定要用什麼方式來渲染字體。

更多細節可以參考：

1. [了解CSS属性font-kerning,font-smoothing,font-variant](https://www.zhangxinxu.com/wordpress/2017/02/font-kerning-font-smoothing-font-variant/)
2. [What is font smoothing in CSS?](https://www.educative.io/edpresso/what-is-font-smoothing-in-css)

## 結語

這篇簡單筆記一些我覺得比較難記的 CSS 屬性，因為不會很頻繁地去使用，所以等到真的要用的時候很容易忘記屬性名稱，如果關鍵字下得不對的話，很難找到這個屬性叫什麼。

會想寫這篇的原因之一也是因為有個朋友來問我某個行為怎麼解，原本以為無解或是一定要用 JS，後來發現用 CSS 其實就可以解了。因為知道那個屬性所以才解得出來，所以平時多看一些 CSS 屬性是很有幫助的，至少碰到問題的時候你會知道可以用 CSS 來解。

如果你也知道一些這類型的 CSS 屬性，歡迎分享給我。