---
title: 一個有趣的 styled components bug
date: 2020-07-11 16:06:54
catalog: true
tags: [Front-end]
categories:
  - Front-end
---

## 前言

之前在公司裡面做一些效能上的調整時，無意間發現了一個奇怪的現象，繼續往下追查之後才發現是個好像沒有被什麼人發現過的 bug，而且成因我覺得挺有趣的，就想說可以寫一篇跟大家分享一下。

這篇技術含量不高，可以抱持著看故事的心態來看這篇，會比較有趣一點。

## 故事的開端

故事的起源呢，是之前在公司裡面要做一些網站上的調整，試著增進一下載入的速度。當我們談到性能最佳化這一塊，其實有很多可以做的，例如說跟 Server 那邊比較有關的是：

1. 使用 HTTP/2
2. 使用 gzip 或是 brotli 進行壓縮
3. 使用 Cache（可以加快 revisit 的速度）
4. 使用 CDN
5. 降低 TTFB 時間

不過以上都需要後端或是 SRE 的協助，跟前端其實關係不大。跟前端關係比較大的，也可以分成很多面向來看，例如說以「減少資源」的角度來看，可以做的事情有：

1. Image 格式調整（壓縮 + webp 或其他格式）
2. JS 大小（ugligy、code spliting、dynamic import）
3. CSS 大小（minify、移除不需要的 CSS）

如果以「加速載入重要資源」的角度，可以加上 preload 或是 preconnect 這些 hint，來提示瀏覽器哪些東西應該先被載入。

還可以從「減少 JS 執行時間」的角度來看，例如說如果是寫 React，可以用 shouldComponentUpdate、PureComponent 或是 memo 來減少不必要的 re-render。

這一篇既然標題都寫 styled components 了，主題當然就是圍繞在 CSS 這一塊。

<!-- more -->

在 CSS 這一塊，為了減少第一次載入的時間，有一個招數是把 critical CSS inline 在 HTML 裡面，這樣就不用再去發一個 request 拿 CSS 回來，少了一個 round-trip。不過連帶會影響到的就是 HTML 的 size 會變大就是了，但其實也不會大到多少。

總之呢，我們的網站有用了這個招數，把 CSS inline 在 HTML 裡面，看起來就會像是這樣：

![css1](/img/sc/css1.png)

一大堆密密麻麻的 CSS。

而這之中最吸引我注意的，就是那些 vendor prefix：

![css1](/img/sc/css2.png)

因為各種歷史因素，有些 CSS 屬性要加上 vendor prefix 才能夠運作，例如說你想在比較舊版本的 IE 上面用 flexbox 時，你需要寫：`display: -ms-flexbox;`。而我稍微看了一下我們網站上有的 prefix，大概是：

1. display: -ms-flexbox
2. display: -webkit-flex
3. -ms-flex-wrap: wrap
4. -webkit-flex-wrap: wrap
5. -ms-transform: rotate(45deg)
6. -webkit-transform: rotate(45deg)
7. -ms-letter-spacing: 0.03em
8. -webkit-letter-spacing: 0.03em
9. ....more

這些 prefix 都是 styled components 幫我們加上的，這邊簡單介紹一下 styled components 好了，簡單來說就是可以用這種寫法幫 component 加上 CSS：

``` jsx
import styled from 'styled-components';

const Box = styled.div`
  background: red;
`

// 使用時，這樣用你就可以有一個背景紅色的 div
<Box />
```

背後原理則是 styled components 會把你寫的 style 轉成一個 className，然後幫你放到這個元件上面去。而 vendor prefix 也是它會幫你處理的一環。

這一切看似都沒有問題，可是其實有著改進的空間。

以我們的專案為例，其實已經定好瀏覽器的支援程度了，而且不需要支援 IE。既然不需要支援 IE 的話，那很多 `-ms` 開頭的 prefix 其實不用加也可以，而且拿掉會比較省空間，所以拿掉比較好。

可是，要怎麼拿呢？

## 去除額外的 prefix

以這種要幫 CSS 加上正確的 prefix 的需求來說，有一個工具非常知名，叫做：[Autoprefixer](https://github.com/postcss/autoprefixer)：

![autoprefixer](/img/sc/autoprefixer.png)


這套工具很簡單，你只要把你的 CSS 整個丟給它，它就會幫你轉成正確的形式，所謂正確，指的是：

1. 加上必要的 prefix
2. 去除不必要的 prefix

那它怎麼知道什麼是必要的呢？

這就是最棒的點了，它支援一個東西叫做 [Browserslist](https://github.com/browserslist/browserslist)，簡單來說你可以寫一個檔案，裡面寫明你的專案要支援哪些瀏覽器，像是：

```
# Browsers that we support

defaults
not IE 11
not IE_Mob 11
> 1%
```

你還可以用 `> 1%` 這種語法，讓他幫你去抓出哪些瀏覽器的使用率 > 1%，並且加進去清單裡面。所以有了這個清單再搭配 Autoprefixer，就可以產生出精簡的 CSS，去除不必要的 vendor prefix。

那這套要怎麼跟 styled components 合在一起用呢？

styled components 裡面有一個東西叫做 StyleSheetManager，在 v5 裡面新增了兩個參數：

1. disableVendorPrefixes
2. stylisPlugins

第一個參數可以把所有 vendor prefix 移除，它就不會幫你自動加：

``` js
// 範例來自官方網站
import styled, { StyleSheetManager } from 'styled-components'

const Box = styled.div`
  color: ${props => props.theme.color};
  display: flex;
`

render(
  <StyleSheetManager disableVendorPrefixes>
    <Box>If you inspect me, there are no vendor prefixes for the flexbox style.</Box>
  </StyleSheetManager>
)
```

而第二個參數 `stylisPlugins` 其實才是我們的重點，官方範例是這樣的：

``` js
import styled, { StyleSheetManager } from 'styled-components'
import stylisRTLPlugin from 'stylis-plugin-rtl';

const Box = styled.div`
  background: mediumseagreen;
  border-left: 10px solid red;
`

render(
  <StyleSheetManager stylisPlugins={[stylisRTLPlugin]}>
    <Box>My border is now on the right!</Box>
  </StyleSheetManager>
)
```

簡單來說呢，其實 styled components 底層是用了一個叫做 stylis 的套件，而這個套件可以傳自定的 plugin 進去，就可以做一些轉換。聽起來是條很有希望的路，但是官方文件其實著墨的不多，於是我就去翻了 styled components 的程式碼，查一下該怎麼寫這個 plugin，查到了[這段](https://github.com/styled-components/styled-components/blob/master/packages/styled-components/src/utils/stylis.js#L69)：

``` js
  /**
   * When writing a style like
   *
   * & + & {
   *   color: red;
   * }
   *
   * The second ampersand should be a reference to the static component class. stylis
   * has no knowledge of static class so we have to intelligently replace the base selector.
   *
   * https://github.com/thysultan/stylis.js#plugins <- more info about the context phase values
   * "2" means this plugin is taking effect at the very end after all other processing is complete
   */
  const selfReferenceReplacementPlugin = (context, _, selectors) => {
    if (context === 2 && selectors.length && selectors[0].lastIndexOf(_selector) > 0) {
      // eslint-disable-next-line no-param-reassign
      selectors[0] = selectors[0].replace(_selectorRegexp, selfReferenceReplacer);
    }
```

可是裡面附的連結點下去以後，卻發現完全找不到跟 plugin 有關的資訊...於是我只好轉個方向，去研究剛剛範例中出現的套件：[stylis-plugin-rtl](https://github.com/styled-components/stylis-plugin-rtl/blob/master/src/stylis-rtl.js)，這次的原始碼詳細多了：

``` js
// @flow

import cssjanus from "cssjanus";

// https://github.com/thysultan/stylis.js#plugins
const STYLIS_CONTEXTS = {
  POST_PROCESS: -2,
  PREPARATION: -1,
  NEWLINE: 0,
  PROPERTY: 1,
  SELECTOR_BLOCK: 2,
  AT_RULE: 3
};

export type StylisContextType = $Values<typeof STYLIS_CONTEXTS>;

// We need to apply cssjanus as early as possible to capture the noflip directives if used
// (they are not present at the PROPERTY, SELECTOR_BLOCK, or POST_PROCESS steps)
export const STYLIS_PROPERTY_CONTEXT = STYLIS_CONTEXTS.PREPARATION;

function stylisRTLPlugin(context: StylisContextType, content: string): ?string {
  if (context === STYLIS_PROPERTY_CONTEXT) {
    return cssjanus.transform(content);
  }
}

// stable identifier that will not be dropped by minification unless the whole module
// is unused
/*#__PURE__*/
Object.defineProperty(stylisRTLPlugin, "name", { value: "stylisRTLPlugin" });

export default stylisRTLPlugin;
```

之前看過類似的 plugin 寫法，所以滿快就能進入狀況的。stylis 會提供給你幾個不同的 context 跟 content，你可以根據 context 去決定要做什麼處理，並且把處理完成的 style 傳回去。

因此，我們的 plugin 可以這樣寫：

``` js
import autoprefixer from 'autoprefixer';
import postcss from 'postcss';

const POST_PROCESS_CONTEXT = -2;
function plugin (context, content) {
    if (context !== POST_PROCESS_CONTEXT) {
      return content;
    }

    return postcss([autoprefixer]).process(content).css;
}
```

在 post process 這個階段去呼叫 postcss，並把內容用 autoprefixer 去轉換，最後就可以得到乾淨的 CSS。

## 成果報告

這邊講一下成效如何，在沒有用之前，我統計了 CSS 裡面出現的 prefix 的數量（直接 global search 統計）：

* -webkit: ~300
* -ms: ~200
* -moz: ~60
* -o: 1

一共 560 個左右

用了 autoprefixer 之後，變成：

* -webkit: ~300 => 26
* -ms: ~200 => 6
* -moz: ~60 => 13
* -o: 1 => 0

從 560 個變到 45 個，減少了大約 90% 的不必要的 vendor prefix！

而原本整份 HTML + inline CSS 的大小經過 gzip 壓縮後為 43KB，大家可以猜一下做了這個改動之後變成多少。

.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  
.  

答案是：42KB！

對，你沒看錯，就是只減少了 1KB。

在我看到這個結果時，我學到了兩件事：

1. gzip 很強悍
2. 果然優化是需要衡量的，有時候你以為改進了很多，但其實沒有

我猜測之所以只減少 1KB，是因為經過 gzip 之後其實根本沒什麼差。雖然說 prefix 數量大幅減少，但不會真的省到這麼多空間。gzip 記的資訊可能從：「300 個 webkit」變成「26 個 webkit」，只是前面的數量減少而已，因此在檔案大小上根本沒什麼改進。

雖然檔案大小的確減少不多，不過往好處想，還是有一些改進，任務順利達成了。

## 說好的 bug 呢？

好，看到這邊你可能會想說：學到一招了...等等，不對啊，這篇不是要講 bug 嗎？那 bug 在哪裡？怎麼沒看到像是 bug 的東西？

bug 其實就藏在前面我整理出來的一個清單：

1. display: -ms-flexbox
2. display: -webkit-flex
3. -ms-flex-wrap: wrap
4. -webkit-flex-wrap: wrap
5. -ms-transform: rotate(45deg)
6. -webkit-transform: rotate(45deg)
7. -ms-letter-spacing: 0.03em
8. -webkit-letter-spacing: 0.03em
9. ....more

仔細看其實你會發現有個屬性很奇妙，叫做 `letter-spacing`，我當初看到以為是我學藝不精，怎麼寫 CSS 這麼多年，還不知道 `letter-spacing` 要加上 prefix 才能運作，於是就去 caniuse 查了一波，發現跟我記憶中一樣，是不需要加的。

那為什麼這邊有呢？

在好奇心的驅使之下，我去找了 stylis 的原始碼來看。這邊順帶一提，前面有講到 styled components 原始碼裡面附的連結點過去沒有 plugin 相關介紹，是因為版本問題。stylis 在今年（2020 年）4 月份更新成了 v4，而 styled components 用的是 v3.5.4。

或是如果要講的更詳細一點，其實 styled components 依賴的是 `@emotion/stylis v0.8.4`（對，就是另一個 library emotion），而這個 emotion 的 stylis 依賴的是真正的 stylis 3.5.4 版本。

所以這個 letter-spacing 的問題不止 styled components，其實連 emotion 也有。這邊是一個 codesandbox 的 demo：https://codesandbox.io/s/stylis-bug-6yu6g?file=/src/App.js

開啟之後對上面元素按右鍵檢查，就看得到了：

![code](/img/sc/code.png)


既然知道之前是版本找錯以後，就可以找正確版本的原始碼來看，是一份很大的檔案：https://github.com/thysultan/stylis.js/blob/v3.5.4/stylis.js

我擷取一段最精華的，加上 vendor prefix 的部分（有省略部分程式碼）：

``` js
function property (input, first, second, third) {
  var index = 0
  var out = input + ';'
  var hash = (first*2) + (second*3) + (third*4)
  var cache

  // animation: a, n, i characters
  if (hash === 944) {
    return animation(out)
  } else if (prefix === 0 || (prefix === 2 && !vendor(out, 1))) {
    return out
  }

  // vendor prefix
  switch (hash) {
    // text-decoration/text-size-adjust/text-shadow/text-align/text-transform: t, e, x
    case 1015: {
      // text-shadow/text-align/text-transform, a
      return out.charCodeAt(10) === 97 ? webkit + out + out : out
    }
    // filter/fill f, i, l
    case 951: {
      // filter, t
      return out.charCodeAt(3) === 116 ? webkit + out + out : out
    }
    // color/column, c, o, l
    case 963: {
      // column, n
      return out.charCodeAt(5) === 110 ? webkit + out + out : out
    }
    // box-decoration-break, b, o, x
    case 1009: {
      if (out.charCodeAt(4) !== 100) {
        break
      }
    }
    // mask, m, a, s
    // clip-path, c, l, i
    case 969:
    case 942: {
      return webkit + out + out
    }
    // appearance: a, p, p
    case 978: {
      return webkit + out + moz + out + out
    }
  }
}
```

看起來對於每個 prefix 都會加上註解，於是我就搜尋了一下 `letter-spacing`，發現一無所獲，事情就變得有趣了起來，看來 `letter-spacing` 有 vendor prefix 這個行為好像不是預期的。

再來我們看一下它加上 prefix 的方式，是先把屬性經過一個自定義的 hash：`var hash = (first*2) + (second*3) + (third*4)` 之後，判斷 hash 出來的結果，再根據結果來加上 prefix。

那我們試著把 `letter-spacing` 來做 hash 好了：

``` js
function hash(str) {
  return str.charCodeAt(0) * 2 +
    str.charCodeAt(1) * 3 +
    str.charCodeAt(2) * 4
} 

console.log(hash('letter-spacing')) // 983
```

接著在 source code 裡面搜尋 983：

![hash](/img/sc/hash.png)


謎底揭曉！

原來是一個因為 hash collision 所引起的 bug！之前聽過很多建議說 hash function 最好不要自己定義，沒想到真的讓我看到一個現實世界中，用自定義 hash function 結果碰撞的案例。

`user-select` 這個字串經過 hash 以後也是 983，跟 `letter-spacing` 一樣。因此在轉換 `letter-spacing`  的時候就會跑到這個 case 裡面，幫 `letter-spacing` 也加上 vendor prefix。

所以在這邊也修正一下標題，其實不是 styled components 的 bug，而是 stylis 的 bug，但是 styled components 跟 emotion 都用到了 stylis，所以也都有這個 bug。

## 後續處理

我在 styled, emotion 跟 styled components 的 repo 都搜過一輪，發現好像沒有人注意到這個 issue，不過有發現到的是 emotion 有一個把 stylis 更新到 v4 的 PR：[Stylis v4 #1817](https://github.com/emotion-js/emotion/pull/1817)，而且在近期已經 merge 進去了，所以下一版的 emotion（應該是大版本號的更新，因為是 breaking change）就沒有這問題了。

而 stylis 那邊我也發了一個 issue 告知他們這件事：[Redundant css vendor prefix for letter-spacing in v3 #223](https://github.com/thysultan/stylis.js/issues/223)，不過看起來他們那邊也沒什麼能做的，而且這是存在於舊版的 bug，在新版已經沒有了，所以也不會在舊版修掉。

最後是 styled components 那邊，我一樣發了一個 issue 講這件事：[Redundant css vendor prefix for letter-spacing #3157](https://github.com/styled-components/styled-components/issues/3157)，但目前還沒人理我就是了。

同時也發了一個改文件網址的 PR：[Update stylis plugin docs url #3156](https://github.com/styled-components/styled-components/pull/3156)，避免有其他人跟我一樣找不到 plugin 的文件。

## 總結

其實從這件事情上面學到滿多的。

第一點是發現了一個有趣的 bug，一個因為 hash collision 所引起的 bug。

第二點是我原本以為移除掉那 500 多個 prefix 以後，可以降低一點檔案大小，沒想到實際衡量過後，才減少 1KB 而已。很多時候我都忘記把 gzip 這個因素考慮進去，在這次之後就不會忘掉它了。

第三點是我發現我好像對於 bug 有一種「一定要修好」的心態，但在現實世界中並不會這麼理想，畢竟做事情有優先順序。

雖然說 letter-spacing 加上 prefix 的確是一件冗余的事，但是影響範圍是什麼？就是增加了一點微不足道的檔案大小，還有看起來比較奇怪而已。說實在的，並不是什麼嚴重的 bug，就算不修好像也沒有太大的影響，網頁也不會因此而跑版，所以其實是一個很無害的 bug。

所以也藉由這個事件，重新整理了一次自己面對 bug 時應該要有的心態。

這篇到這邊就差不多啦，如果你家的網站也有在用 emotion 或是 styled components，不如去看一下是不是也有這個 letter-spacing 的問題吧！


