---
title: 淺談 Atomic CSS 的發展背景與 Tailwind CSS
catalog: true
date: 2022-05-23 19:07:10
tags: [Front-end]
categories: [Front-end]
---

<img src="/img/atomic-css-and-tailwind-css/cover.png" style="display:none">

這陣子在 [Front-End Developers Taiwan](https://www.facebook.com/groups/f2e.tw) 臉書社團上有一系列關於 Tailwind CSS 的討論，起因是另一篇已經刪除的貼文，那篇貼文我有看過，因為怕原文內容跟記憶內容有落差，因此這邊就不講我記憶中的原文大概是在寫什麼了，畢竟這也不是這篇所關注的重點。

總之呢，那篇貼文引起了臉書上前端社團的熱烈討論，在短短兩三天內迅速多出許多討論相關技術的文章。

而有許多人在討論的議題，其實比起 Tailwind CSS 這個工具，更多的是在討論 Atomic CSS 這個概念本身。

<!-- more -->

Atomic CSS 這個詞由 Thierry Koblentz 所提出，最早出自於這篇 2013 年發表的必讀的經典：[Challenging CSS Best Practices](https://www.smashingmagazine.com/2013/10/challenging-css-best-practices-atomic-approach/)。

那什麼是 Atomic CSS？這邊直接取用 [Let’s Define Exactly What Atomic CSS is](https://css-tricks.com/lets-define-exactly-atomic-css/) 這篇文章給的定義：

> Atomic CSS is the approach to CSS architecture that favors small, single-purpose classes with names based on visual function.

例如說像這樣子的東西就是 Atomic CSS：

``` css
.bg-blue {background-color: #357edd; } 
.margin-0 { margin: 0; }
```

而 Tailwind CSS 就是實作了 Atomic CSS 這個概念的一個 CSS 框架。

在 2019 年的時候我也寫過一篇在講 Atomic CSS 的文章，但那時用的是另外一個同義詞叫做 Functional CSS：[邪魔歪道還是苦口良藥？Functional CSS 經驗分享](https://blog.huli.tw/2019/01/27/functional-css/)，在那篇裡面已經有提到一些這篇想講的東西，但我覺得還不夠完整，因此才又寫了一篇。

在這篇文章中，我希望跟大家一起讀一下這些經典文章，因為你會發現有些爭論的點可能早在八九年前就已經被提出、討論或甚至是解決了。接著就可以來看看最早的 Atomic CSS 跟現在的 Tailwind CSS 的差別在哪，優缺點又是什麼？

大綱如下：

1. Atomic CSS 的誕生背景
2. Atomic CSS 到底想解決什麼問題？
3. 針對 Atomic CSS 的問題與反駁
4. 我對 Atomic CSS 的看法
5. Tailwind CSS 改良了哪些部分？
6. 結語

## Atomic CSS 的誕生背景

如開頭所述，Atomic CSS 一詞出自於 Yahoo! 的工程師 Thierry Koblentz（以下簡稱 TK）在 2013 年所發表的 [Challenging CSS Best Practices](https://www.smashingmagazine.com/2013/10/challenging-css-best-practices-atomic-approach/)。

在看這篇文章之前，我們可以先看一下 2022 年 2 月的這篇專訪：[The Making of Atomic CSS: An Interview With Thierry Koblentz](https://css-tricks.com/thierry-koblentz-atomic-css/)，在這篇裡面提及了更多 Atomic CSS 出現的背景以及早期在 Yahoo! 內部的應用。

根據文章中的說法，有天他的主管來問他有沒有一種可以不改到 stylesheet 但還是可以動到畫面的方法，因為他想避免把東西改壞。

於是 TK 就做了一個「utility-sheet」，讓工程師可以在不改到 stylesheet 的狀況下依然能改到前端的樣式。聽起來這個 utility-sheet 應該就是一個靜態的 CSS 檔案，然後裡面有著各種 utility class。

接著過了幾年，一個工程主管問他是否能「全部都用 utility class」來改寫 Yahoo! 的首頁，在當時可以說是先驅中的先驅了。

最後他們寫了一個純靜態（static）的 CSS 並取名為 Stencil 來完成這件事（這邊會講到純靜態是為了跟等一下會出現的東西來做對比），並且從中發現了很多這樣子使用的好處。

這套純靜態的 CSS 的特色之一是可以強迫遵從一些 design style，例如說只寫了 `margin-left-1`、`margin-left-2`、`margin-left-3` 之類的 class，然後每一個對應到的是 x4，因此你的 margin 就只有 4px、8px 跟 12px 這些 4 的倍數可以用，利用這個來強迫設計遵循既有的規則。

不過後來他們發現這套系統行不通。因為在現實世界中，每個 design team 都有自己不同的要求，他們想要的 padding、margin、字體、顏色全部都不同，所以靜態是不行的，需要客製化，需要動態產生。

於是 [Atomizer](https://acss.io/guides/atomizer.html) 就誕生了，一個幫你產生相對應 CSS 檔案的工具。

例如說你有個頁面寫了：

``` html
<div class="D(b) Va(t) Fz(20px)">Hello World!</div>
```

Atomizer 就會自動幫你產生底下的 CSS 出來：

``` css
.D(b) {
    display: block;
}
.Va(t) {
    vertical-align: top;
}
.Fz(20px) {
    font-size: 20px;
}
```

如此一來，工程師們就可以有更大的彈性去符合設計的需求。

上面看到的這些語法叫做 ACSS，其實功能基本上跟現在的 Tailwind CSS 已經滿類似的了，只是使用的語法不太一樣而已。這套 ACSS 系統的[命名規則](https://acss.io/guides/acss-classes.html)的靈感是來自於 Emmet，一個可以利用語法幫你快速建置 HTML 的套件，而 class name 中的 `()` 的靈感則是來自於函式呼叫。

接著 TK 談到了在像是 Yahoo! 這種大型企業寫 CSS 跟其他地方有什麼不同，你會面臨到的狀況超級複雜，包括跨國跨時區的溝通、分佈各地的團隊成員、幾百個共用的 component、l10n 跟 i18n、一堆 legacy code，以及一堆的辦公室政治。

在需要維護一個超級複雜的專案的狀況之下，他開始反思一些常見做法（common pratice）是否真的能帶來益處，最後卻發現有些概念除了沒有帶來益處以外，甚至是有害的。

在複雜的專案之中，有很多你可能沒想過的狀況會發生，所以維護變得很艱難，必須要小心翼翼去避開一些陷阱。

另外，在內部推廣 ACSS 的旅程剛開始並不順利，看起來有許多 team 都對那樣的語法卻步（我猜就如同我在之前的文章寫的一樣，一開始看到都會覺得這是什麼邪魔歪道），但是 ACSS 帶來的好處反映在數據上面，採用了 ACSS 的專案少了大約 36% 的 CSS 與 HTML 的大小，因此至今依然有許多專案還用著 ACSS。

如果你把 A 網頁的 HTML 複製，貼上到 B 網頁去，你會發現 UI 完全沒變，使用了 ACSS 之後不會因為你在別的頁面就有不同的樣式，這就是 ACSS 所帶來的好處，原文是這樣寫的：

> This is because ACSS makes these components page agnostic.

「page agnostic」是我覺得很重要的一個性質，這個之後會再提到。

原文的專訪還有提到更多故事背景跟挑戰，不過在這邊我就不繼續再提了，有興趣的讀者們可以去看原文。而之前 TechBridge 的好夥伴 Arvin 以前在 Yahoo! 待過，在公司內有寫過 ACSS，他在 2017 年的時候有寫過一篇文章，也很值得一看：[淺談 CSS 方法論與 Atomic CSS](https://blog.techbridge.cc/2017/04/29/css-methodology-atomiccss/)。

這篇專訪中其實對於 Atomic CSS 想解決的問題並沒有到這麼多的著墨，不過從中可以看見 TK 在工作上需要維護大型的專案，因此自然也會碰到許多痛點，不難想像出 Atomic CSS 誕生的背景也與此有關。

想知道 Atomic CSS 要解決什麼問題，就要來看經典之作了。

## Atomic CSS 到底想解決什麼問題？

底下我會引用許多來自於 [Challenging CSS Best Practices](https://www.smashingmagazine.com/2013/10/challenging-css-best-practices-atomic-approach/) 的內容，因為原文寫得很清楚。如果英文閱讀能力 ok 的話，也強烈推薦讀者們自己看過一遍。

在文章開頭的 quick summary，就有這樣一段：

> When it comes to CSS, I believe that the sacred principle of “separation of concerns” (SoC) has lead us to accept bloat, obsolescence, redundancy, poor caching and more. Now, I’m convinced that the only way to improve how we author style sheets is by moving away from this principle.

大家都知道在寫網頁的時候要注重關注點分離（separation of concerns），讓 HTML 做好它的事情，只關注內容，而 CSS 只關注樣式，兩者透過 class name 連結在一起。可是作者發現這樣子的概念，其實會帶來許多負面影響，因此這篇文章就是來說服大家不要再把這種做法奉為信條，如果有更好的路，那幹嘛執著在這呢？

接著文中舉了一個簡單的例子，稱之為 media object，HTML 長這樣：

``` html
<div class="media">
  <a href="https://twitter.com/thierrykoblentz" class="img">
        <img src="thierry.jpg" alt="me" width="40" />
  </a>
  <div class="bd">
    @thierrykoblentz 14 minutes ago
  </div>
</div>
```

CSS 長這樣：

``` css
media {
    margin: 10px;
}
.media,
.bd {
    overflow: hidden;
    _overflow: visible;
    zoom: 1;
}
.media .img {
    float: left;
    margin-right: 10px;
}
.media .img img {
    display: block;
}
```

最後呈現出來的結果如下：

![media object](/img/atomic-css-and-tailwind-css/p1.png)

接著第一個需求來了，有些地方需要把圖片顯示在右邊而不是左邊，於是我們可以在 HTML 的元素上增加新的 class `imgExt`，並且新增底下的 CSS：

``` css
.media .imgExt {
    float: right;
    margin-left: 10px;
}
```

然後第二個需求來了，當這一塊內容出現在某個右側區塊（原文為 right rail）時，文字要變小。於是我們可以包一個 div 在外面，像這樣：

``` html
<div id="rightRail">
    <div class="media">
        <a href="https://twitter.com/thierrykoblentz" class="img">
            <img src="thierry.jpg" alt="me" width="40" />
        </a>
        <div class="bd">
            @thierrykoblentz 14 minutes ago
        </div>
    </div>
</div>
```

然後針對這個 `#rightRail` 去調整樣式，調整完的全部樣式如下：

``` css
media {
    margin: 10px;
}
.media,
.bd {
    overflow: hidden;
    _overflow: visible;
    zoom: 1;
}
.media .img {
    float: left;
    margin-right: 10px;
}
.media .img img {
    display: block;
}

.media .imgExt {
    float: right;
    margin-left: 10px;
}

#rightRail .bd {
    font-size: smaller;
}
```

這些調整樣式的方法應該都滿直覺的，但作者點出其實有幾個問題：

1. 每次 UI 要支援不同的樣子，就要新增一個 CSS rule
2. `.media` 跟 `.bg` 共用同樣的樣式，如果還有別的要共用，CSS selector 就會越來越多，越來越大
3. 在最後的六個 CSS selector 中，有四個是基於 context 的，不好維護也不好重用
4. RTL（Right To Left）跟 LTR（Left To Right）會變得很複雜

第一點其實乍看之下滿正常，你要在不同狀況支援不同的樣子，不就一定要寫新的 CSS 規則嗎？但作者卻說有更好的方法來處理，不一定要新增。

第二點其實看起來也滿正常，要共用 style 的話，寫成 `.media, .bg` 不是很常見嗎？檔案大的話也是必然的吧？

第三點的話這個 context 是個很重要的概念，例如說我們最後這個規則：`#rightRail .bd`，讓在 `#rightRail` 底下的 `.bd` 改變字體大小，有不同的樣式。

所以我們的 media object 會根據 context（是否在 `#rightRail`） 底下有不同的樣式，就寫了不同的 CSS 規則去處理。

一旦讓你的 CSS 規則跟 context 有關，在大型專案中維護就會變得困難。

舉例來說，如果有人手賤去改了 `rightRail` 這個 id，想說改成 `blockRightRail` 會更好，那你的樣式就壞了。你可能會質疑說：「不對啊，這是他的錯啊，他要改的話應該就要確認其他地方不會壞」，有改過的人都知道，要確認其他地方有沒有壞，是多麽困難的一件事情，更何況是在大型專案之中。很可能你改 A 的時候，根本不會預期 B 會壞掉，因為你根本不知道他們有關。

或如果別的 team 想把你這個 media object 拿去用，於是就連同 CSS 一起複製貼上到他們專案，可是卻發現他們的 id 並沒有 `rigthRails`，那就要去改動 style。

第四點的話也是只有在 Yahoo! 這種大型公司才比較會做到的事情（至少我是沒做過），就是在做 l10n 的時候會有很多細節要考慮，例如說有些國家的閱讀方向是左到右，有些是右到左。

上面的 case 如果要改變方向，就要加上這兩個規則：

``` css
.rtl .media .img {
    margin-right: auto; /* reset */
    float: right;
    margin-left: 10px;
}
.rtl .media .imgExt {
    margin-left: auto; /* reset */
    float: left;
    margin-right: 10px;
}
```

接著，作者就提出了 Atomic CSS 的概念，然後以 Atomic CSS 來改寫，並告訴你這樣改的好處在哪，HTML 跟 CSS 如下：

``` html
<div class="Bfc M-10">
    <a href="https://twitter.com/thierrykoblentz" class="Fl-start Mend-10">
        <img src="thierry.jpg" alt="me" width="40" />
    </a>
    <div class="Bfc Fz-s">
        @thierrykoblentz 14 minutes ago
    </div>
</div>
```

``` css
.Bfc {
    overflow: hidden;
    zoom: 1;
}
.M-10 {
    margin: 10px;
}
.Fl-start {
    float: left;
}
.Mend-10 {
    margin-right: 10px;
}
.Fz-s {
    font-size: smaller;
}
```

針對第一點的問題，還記得一開始的新需求嗎？現在我們不需要新增一個 CSS 規則，只需要在 HTML 加上 `class="Fl-sart Mend-10"`，就可以改變 UI 的樣式，但是沒有新增任何規則。

第二點，現在所有需要 `overflow:hidden` 跟 `zoom:1` 的元素，我都只要用一個 class name 叫做 `.Bfc` 就可以搞定了，無論有多少個元素要用，我都只有一個 CSS selector。

第三點，現在的 class name 已經跟 context 無關了，我上面講的問題完全不會發生。今天我樣式要變，我可以很安心地把 class name 刪掉，因為我知道其他地方絕對不會壞掉。這就是開頭第一段所講的「page agnostic」，沒有 context 的 class name 才能做到容易刪改，而且可以搬來搬去還能保證相同樣式。

換句話說，它解決的是 scope 的問題，就如同原文所說：

> I believe that this approach is a game-changer because it narrows the scope dramatically. We are styling not in the global scope (the style sheet), but at the module and block level. We can change the style of a module without worrying about breaking something else on the page.

最後關於剛剛第四點的方向問題，已經透過 class name 抽象化了，如果要改方向的話，只需要把 CSS 改成這樣即可：

``` css
.Fl-start {
    float: right;
}
.Mend-10 {
    margin-left: 10px;
}
```

透過改寫成 Atomic CSS，我們成功解掉了傳統 CSS 寫法上會碰到的幾個問題，而且具有以下優點：

1. CSS 大小是線性成長的，重複的規則都會用到同一個 class name，因此檔案大小大幅降低
2. 很容易可以支援 RTL 跟 LTR
3. class name 變得與 context 無關，scope 也變小，因此更好維護也更好改動

其中我認為最重要的是第三點，這也是我支持 Atomic CSS 的原因。

在改樣式的時候，你可以直接把 class name 刪掉而不用怕影響到其他的元素，這是多麽美好的一件事情，你再也不用擔心改 A 壞 B，因為 class name 都跟 context 無關了。

Tailwind CSS 的作者以前有寫過一篇文章，對於 Atomic CSS 如何解決傳統 CSS 的問題有更多著墨跟範例，如果上面的理由無法說服你，可以看看這篇文章：[CSS Utility Classes and "Separation of Concerns"](https://adamwathan.me/css-utility-classes-and-separation-of-concerns/)。

總之呢，在原文中 TK 也預期到了僅管這個做法能解決問題，但讀者一定會有一堆疑惑，所以準備來一一擊破。

## 針對 Atomic CSS 的問題與反駁

關於底下的問題跟反駁，除了文章以外，我可能還會引用到這三處的資料：

1. [ACSS FAQ](https://acss.io/frequently-asked-questions.html)
2. [HTML5DevConf: Renato Iwashima, "Atomic Cascading Style Sheets"](https://www.youtube.com/watch?v=ojj_-6Xiud4&ab_channel=HTML5DevConf%26IoTaconf)
3. [Thierry Koblentz 在 FED London 2015 的簡報](https://www.haikudeck.com/atomic-css-uncategorized-presentation-dJ0xlFjhBQ)

### 1. 你的 class name 沒有語義，這樣不行啊，規格不是這樣寫的

關於 semantic 的問題，在 2012 時也有一篇文章討論過這件事情：[About HTML semantics and front-end architecture](https://nicolasgallagher.com/about-html-semantics-front-end-architecture/)，在 [HTML spec](https://html.spec.whatwg.org/multipage/dom.html#classes) 裡面確實有這個段落：

> There are no additional restrictions on the tokens authors can use in the class attribute, but authors are encouraged to use values that describe the nature of the content, rather than values that describe the desired presentation of the content.

如果這個元素是個 image，那你的 class name 應該取叫 `image`，而不是取叫它的樣式例如說：`display-block width-[150px] margin-3` 之類的。

而上面引的那篇文章提到說其實在維護大型專案時，這樣的命名策略反而會變成一種阻礙，我們根本沒理由一定要照著這個做，因為：

1. 跟 content 有關的語義你看 HTML 就看得出來了
2. 除了一個叫做 Microformats 的標準以外，class name 對機器跟一般訪客來說沒什麼太大的意義
3. 我們會用 class name，只是因為要跟 JS 或是 CSS 結合在一起。你想想，如果一個網站不需要 style 也不需要 JS，是不是就不會取 class name 了？那這樣你的網站有比較不 semantic 嗎？
4. 對開發者而言，class name 應該包含一些更有用的資訊

接著他舉了一個例子：

``` html
<div class="news">
  <h2>News</h2>
  [news content]
</div>
```

你看內容就知道這個區塊是來呈現 news 的，根本不需要 class name 也行。

這讓我想到當初 JSX 的發展，也是直接破壞掉了以往 JavaScript 跟 HTML 應該要分開的 best practice。

如果大家都執著於前人訂下的規範，當作信條一樣遵從，而不去反思這個信條存在的理由，就不會有這麼多革新的東西出現。

就如同 Challenging CSS Best Practices 一文中在最後提到的：

> Tools, not rules. We all need to be open to new learnings, new approaches, new best practices and we need to be able to share them.

### 2. 你的 class name 太難懂了，看不懂，可讀性很差

直接截一張 FED London 2015 裡的簡報圖，他們說 ACSS 的語法參考自 Emmet，可讀性其實不會差：

![emmet](/img/atomic-css-and-tailwind-css/p2.jpg)

不過這個解釋我不是很買單就是了，因為對於一個沒用過 Emmet 的人來說，看起來真的不太好懂，要花一段時間去熟悉那些縮寫。

### 3. 你這跟 inline style 有什麼不同？

其實本質上是一樣的，都是把 style 限制在很小的 scope 裡面，但 Atomic CSS 解決了 inline style 的幾個壞處：

1. CSS 的優先順序很高，很難蓋過去
3. 很冗長
4. 不支援 pseudo-class 或是 pseudo-element

底下截一張官網的圖：

![inline style](/img/atomic-css-and-tailwind-css/p3.png)

Atomic CSS 保留了 inline style 的好處，也就是 scope 很小，同時也解決了上面提到的那些壞處。

### 4. 你說可以降低 CSS 大小，但 HTML 大小不是也會上升嗎？那只是把成本轉到別的地方而已

在原本 ACSS 的寫法下，其實 class name 的長度不會比本來大多少。

舉例來說，原本叫做 `profile__image-background`，改寫之後可能是 `D-ib Bgc(#ff0010)` 之類的。根據他們自己做的統計，Yahoo! 自己的網站平均的 class name 長度是 22，而其他沒有用 ACSS 寫法的 Twitter 平均是 28，USA today 是 38，衛報網站是 36，只有特別對 class name 做了 uglify 的 Facebook 是 18，些微勝出而已。

而且，除了 class name 並沒有明顯變長以外，ACSS 還有一個好處是重複字元很多，所以 gzip 的壓縮率會比較高。官網有給了一個數據是說他們自己經過測試後，semantic classes 可以降 35% 大小，而 ACSS 可以降 48%。

### 5. 那共用元件像是 button 該怎麼辦？難道我要每個地方都改樣式？

在 Challenging CSS Best Practices 一文中有一個段落是在講這個：

> The technique I’m discussing here is not about banning “semantic” class names or rules that group many declarations. The idea is to reevaluate the benefits of the common approach, rather than adopting it as the de facto technique for styling Web pages. In other words, we are restricting the “component” approach to the few cases in which it makes the most sense.

Atomic CSS 的出現並沒有要完全取代傳統 semantic 的做法，正確的做法應該是哪個適合就用哪個。

而官網 FAQ 也有特別提到類似的事情：

> If changing some styling requires you to edit multiple files, then you should use the classic CSS approach

舉例來說，你的程式裡面有個按鈕會一直重複出現，這時候如果每次都複製貼上 HTML，要改 class 的時候就要每個檔案都改，顯然是不合理。

在這種狀況下，用傳統的做法當然會是更好的。

## 我對 Atomic CSS 的看法

前面看完了這麼多經典教材，來講一下我自己的想法。

首先，我認為 Atomic CSS 帶來了兩個獨特的好處：

1. 降低 CSS 檔案大小
2. 最大程度縮減 scope，讓維護變得容易

第一點是顯而易見的，這個應該就不用再多提了，CSS 檔案大小會小很多，這一點是其他 CSS 的解決方案沒辦法做到的。

第二點就如同我之前所講的，你改一個元素的 class name，保證只會改到這個元素本身，而不會動到其他地方，這是我認為 Atomic CSS 帶來的最大的好處，讓 style 變成 local scope。

有些人可能會疑惑說：「但你講的這個，CSS-in-JS 或是 CSS modules 也都做得到啊」，沒錯，這兩個解決方案也可以解決 scope 的問題。但 Atomic CSS 剛誕生的時候似乎這些解決方案都還不存在（或是還在非常早期），所以這裡比較的對象是傳統 CSS 的解決方案（像是 OOCSS、BEM、SMACSS 這些管理 CSS 的方法）。

除了優點以外，我也認為 Atomic CSS 有一些缺點以及不適合使用的地方：

1. class name 很長，直接看 HTML 的話不好閱讀
2. 如果沒辦法做到 component 化，那就不適合使用 Atomic CSS
3. 需要花一段時間上手 Atomic CSS 的語法以及熟悉各種縮寫

三大框架的流行導致了現在的前端工程師普遍都會以 component 的思考方式去開發，而非傳統的 HTML 就管理內容、JavaScript 就管理程式、CSS 就管理樣式。以元件的方式去思考後，三者會合在一起，變成一個獨立封裝的元件。

而元件化之後，前兩項問題也就迎刃而解了。

第一點的話開發時我們都是去看 component 的檔案，不會直接去看到 HTML，而看到 component 時根據它的命名我們也會知道它在幹嘛，不需要 class name 做為輔助。

第二點的話因為都變成 component，所以可以保證要改動的時候只要改一個地方就好。

而第三點是我認為要導入 Atomic CSS 相關工具需要付出的成本，那就是熟悉新的語法跟各種縮寫，這個是避免不掉的。但是對我來說，這樣的成本不高，學習曲線也不高，頂多就是剛開始入門時要一直查表。比起它帶來的效益，成本其實已經很小了。

最後提一下 CSS-in-JS 跟 CSS modules 這兩個方案，一樣都解決了 scope 的問題，但跟 Atomic CSS 比起來有兩樣是做不到的。

第一點是 CSS-in-JS 跟 CSS modules 這兩個方案據我所知，應該都需要搭配一些前端的 library 或是框架來使用，例如說 React 或 Vue，但 Atomic CSS 不需要。舉例來說，假設今天一個專案它的 component 是在後端用 template engine 達成的，而非在前端，那就沒辦法用這兩套解決方案。

第二點是 CSS 大小，沒辦法跟 Atomic CSS 一樣這麼小。

不過關於這點，可以參考 Facebook 提出的 [Atomic CSS-in-JS](https://sebastienlorber.com/atomic-css-in-js) 方案，讓你寫起來像 CSS-in-JS，可以用傳統 CSS 語法，但實際上產生時卻幫你用 Atomic CSS 的方式來產生，巧妙地融合了兩者的優點，是滿值得關注的一項技術。

## Tailwind CSS 改良了哪些部分？

上面談到了這麼多 Atomic CSS 的東西，最後我們簡單來看一下 Tailwind CSS，比起一開始 Yahoo! 創造的 [Atomizer](https://acss.io/guides/atomizer.html)，它有哪些優勢？

其實在功能面上我覺得沒有相差太多，最大的優勢是我認為它的 DX（Developer Experience）更為突出，例如說它使用了更好看懂的 class name，文件也更加完整，很快就可以查到什麼語法應該怎樣寫：

![tailwind](/img/atomic-css-and-tailwind-css/p4.png)

不過事實上，我認為這些基於 Atomic CSS 的框架最佳化的方向都是類似的，都是針對 DX 的方向去做改善。

例如說 [Windi CSS](https://windicss.org/) 就帶來很多語法上的改善以及新的用法，而 [UnoCSS](https://github.com/unocss/unocss) 以及 [master CSS](https://styles.master.co/) 也都有各自不同的做法，來增加開發者的體驗或是加快編譯的效率。

至於這些最佳化的細節我就不熟了，詳情可以參考[重新构想原子化 CSS](https://antfu.me/posts/reimagine-atomic-css-zh) 這篇文章。

我對 Tailwind CSS 也沒有到很熟，這邊補充一個需要注意的地方，那就是 Tailwind CSS 是去掃你的 source code 字串有哪些符合特定格式，所以如果你的 class name 是用動態產生的，就會抓不到，像這樣：

``` html
// 這樣寫抓不到
<div class="text-{{ error ? 'red' : 'green' }}-600"></div>

// 這樣寫才抓得到
<div class="{{ error ? 'text-red-600' : 'text-green-600' }}"></div>
```

不確定其他的 library 有沒有把這問題解掉，但我自己是覺得沒有太大的關係，因為這種動態產生的方式能避免就盡量避免會比較好。

為什麼我會這樣說呢？

分享一個小故事，以前我在維護一個用 Redux 的專案時有一系列操作長很像，例如說 post、user 跟 restaurant 的 CRUD 之類的，程式碼有很大一部分都重複，因此我就寫了一個 utils 來處理共同邏輯，只要寫 `generateActions('user')`，就自動幫你動態產生出 `readUser` 與 `createUser` 之類的 actions。

那時我想說這樣很讚，但同事提醒我說如果你這樣做，那全域搜尋 `readUser` 的時候就搜不到東西，因為那是程式動態產生的，在原始碼裡面找不到。

雖然我那時不覺得有什麼，但過了兩個月後我知道我錯了。當你面對一個不熟悉的專案時，要去修一個 bug，最常做的就是拿你手上的資訊去搜尋原始碼，看看出現在哪邊。如果你搜不到東西，那是滿挫折的一件事情，會需要花更多時間去找問題到底在哪個範圍。因此，可以被搜尋到是很重要的。

或是再舉一個例子，假設今天設計師突然改變心意，說所有之前用 `text-red-600` 的地方應該要改成 `text-red-500`，但新的地方還是會用到 `text-red-600`，所以我們不能直接改設定檔的色碼，一定要去改 source code，把 `text-red-600` 都換成 `text-red-500`。此時你會怎麼做？全域搜尋然後取代，搞定。

此時，像上面那種動態產生 class name 的 case 除非你特別記得，否則就不會被改到。因為搜尋不到，所以你也不知道那邊其實會出現 `text-red-600`。如果真的要用動態產生，那至少加個註解標注一下會用到的東西的全名，讓它能被搜尋到。

## 結語

「每樣工具都有它適合的地方」這句話大家都知道，但重點是「那它到底適合什麼地方？不適合什麼地方？它解決了什麼問題？又額外創造了哪些問題？」，基於這些問題去討論一項技術，才能更深入地去了解它。

Atomic CSS 是在維護大型專案的時空背景之下誕生的，如果你沒有碰到那種「牽一髮而動全身，改一個地方要檢查好多地方會不會壞掉」的狀況，那你用了 Atomic CSS，可能確實感覺不到它的好處，因為它想解決的問題你根本沒有碰到。

對於那些「它想解決的問題，你的專案沒碰到」的狀況下，導不導入的差異本來就不大，有些甚至還會增加不必要的複雜度。

若是在一個「相同的元件卻四處分散，當你改 HTML 時需要同時改很多地方」的專案用上了 Atomic CSS，那確實是不適合，官方文件也不推薦這樣做。如果硬要用，那碰到維護性的問題時並不是 Atomic CSS 的錯，而是當時選擇技術的人的錯（就跟你說不適合了還要用）。

又或是你寫了一個 UI library，而這個 library 又需要支援一些 UI 的客製化，如果你用 Atomic CSS 來做樣式，那你要怎麼完成這件事？難道要把每一個 HTML 元素都開放傳 class name 進去嗎？在這個狀況下，像是 [antd](https://ant.design/docs/react/customize-theme-cn) 那樣使用傳統的 CSS 解決方案說不定比較適合，因為可以直接改原本的 Less 檔案，就能輕鬆客製化。

（[daisyUI](https://daisyui.com/) 是靠著把 HTML 一起開放出來，藉此達成客製化，我上面指的案例比較像是寫一個 React component，把實作細節包在裡面的那種）

每個專案都有不同適合的技術與工具，在做選擇時應該先了解每個專案的需求，以及每一項技術的優缺點，才能挑到相對合適的技術。

最後，從 Atomic CSS 的歷史中，我覺得最值得學習的其實是「Tools, not rules」那一段。以前的最佳實踐不一定適用於現在的狀況，以前的 class name 不是這樣用的，不代表現在就不行。我們不該墨守成規，不該執著在那些規則上面；如果別的做法有顯而易見的好處，那為何不呢？

參考資料：

1. [Challenging CSS Best Practices](https://www.smashingmagazine.com/2013/10/challenging-css-best-practices-atomic-approach/)
2. [Let’s Define Exactly What Atomic CSS is](https://css-tricks.com/lets-define-exactly-atomic-css/)
3. [The Making of Atomic CSS: An Interview With Thierry Koblentz](https://css-tricks.com/thierry-koblentz-atomic-css/)
4. [Atomizer](https://acss.io/guides/atomizer.html)
5. [ACSS FAQ](https://acss.io/frequently-asked-questions.html)
6. [HTML5DevConf: Renato Iwashima, "Atomic Cascading Style Sheets"](https://www.youtube.com/watch?v=ojj_-6Xiud4&ab_channel=HTML5DevConf%26IoTaconf)
7. [Thierry Koblentz 在 FED London 2015 的簡報](https://www.haikudeck.com/atomic-css-uncategorized-presentation-dJ0xlFjhBQ)
8. [About HTML semantics and front-end architecture](https://nicolasgallagher.com/about-html-semantics-front-end-architecture/)
9. [Atomic CSS-in-JS](https://sebastienlorber.com/atomic-css-in-js)
10. [淺談 CSS 方法論與 Atomic CSS](https://blog.techbridge.cc/2017/04/29/css-methodology-atomiccss/)
11. [邪魔歪道還是苦口良藥？Functional CSS 經驗分享](https://blog.huli.tw/2019/01/27/functional-css/)
12. [客觀評價 TailwindCSS](https://medium.com/@nightspirit622/%E5%AE%A2%E8%A7%80%E8%A9%95%E5%83%B9-tailwindcss-af27581f6d9)
13. [Uno CSS - 一統天下的明日之星？](https://blog.errorbaker.tw/posts/benben/06-uno-css/)
14. [重新构想原子化 CSS](https://antfu.me/posts/reimagine-atomic-css-zh)
15. [在 VUE SFC (vue-cli) 規劃 Tailwind CSS 架構](https://muki.tw/tech/javascript/tailwind-css-in-vue/)
