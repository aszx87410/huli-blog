---
title: '[心得] 什麼是 postcss?'
date: 2015-04-30 15:05
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [frontend,css,postcss]
---
今天早上在facebook的前端開發社團看到了[這則twitter](https://twitter.com/mdo/status/591364406816079873)

>Oh, btw—Bootstrap 4 will be in SCSS. And if you care, v5 will likely be in PostCSS because holy crap that sounds cool

`postcss`？那是什麼東西？
好奇心的驅使下，開始拜google大神，開始研讀一些我找到的滿有用的資料
以下是一些我的心得跟理解，如果有錯誤的話還麻煩各位大大幫我指出<(_ _)>

#先來談談 preprocessor 吧
在以前寫純css的時候，常常會碰到許多問題，像是變數
假如我寫了一份css是
``` css
h1{
	color:red;
}
.title{
	color:red;
}
.special{
	color:red;
}
```
若是有一天，我想要把顏色改成用藍色怎麼辦？
尋找->red->取代->blue
那如果我`title`這個class想要維持原有的顏色怎麼辦？手動改回來
於是你的時間就在這樣尋找、取代等等的事情上消耗掉了

這就像是你在寫程式或寫網頁的時候
你不會把每個頁面的footer都寫死在裡面，而是會用類似`include footer.php`的方式
這樣才能確保你想改footer的時候，只要改一個地方就好
但偏偏css就沒有這種功能，那怎麼辦呢？

於是scss/sass/less就出現了
他們都是css的預處理器(pre-processor)
先直接來看範例

``` scss
$font-stack:    Helvetica, sans-serif;
$primary-color: #333;

body {
  font: 100% $font-stack;
  color: $primary-color;
}
```
這就是變數的功能，以後想要修改資料直接改變數內容就好，不用在每一個地方都改了
所以像`scss`這些預處理器，你要學一些新的語法，學一些新的表示方式
你就可以用這些新的語法寫好一些看起來很像css但不是css的東西，然後把它compiler成css

#再來看看 postprocessor
了解什麼是`pre-processor`以後，來看看什麼是`post-processor`
看範例最快了
直接來看這個 [CSS Prefixer](http://cssprefixer.appspot.com/)
在寫css的時候，會針對瀏覽器加上一些prefix，但是每次都這樣寫實在是很麻煩
官方範例，原本的css長這樣
``` css
.my-class, #my-id {
    border-radius: 1em;
    transition: all 1s ease;
    box-shadow: #123456 0 0 10px;
}
```
處理過後的css長這樣
``` css
.my-class, #my-id {
    -moz-border-radius: 1em;
    -webkit-border-radius: 1em;
    border-radius: 1em;
    -moz-transition: all 1s ease;
    -o-transition: all 1s ease;
    -webkit-transition: all 1s ease;
    transition: all 1s ease;
    -moz-box-shadow: #123456 0 0 10px;
    -webkit-box-shadow: #123456 0 0 10px;
    box-shadow: #123456 0 0 10px
    }
```
將將將將～全部都幫你加好了
這就是後處理器（post-processor）

簡單來說，預處理器是你把一些長得很像css但不是css的東西丟給它，處理過後會給你編譯過後的css
而css再經過後處理器，透過一些規則幫它加上一些東西，最後產生出完成品！

$a = red;
h1{ color:$a } -> preprocessor -> h1{color:red;} -> postprocessor -> h1{webkit-color:red;}
這邊的`webkit-color`純粹是亂舉例，但差不多就是這樣的意思

##但是你舉的例子，preprocessor也可以做到啊
``` scss
@mixin border-radius($radius) {
  -webkit-border-radius: $radius;
     -moz-border-radius: $radius;
      -ms-border-radius: $radius;
          border-radius: $radius;
}

.box { @include border-radius(10px); }
```
沒錯，在scss裡面，用`mixin`也可以達成加上前綴這樣的目的

##那為什麼要用postprocessor?

後處理器有幾個優點：
1.你可以寫自己的plugin
如果你選了SCSS，你就必須接受SCSS的一切，接受他的語法，要用就要用一整套SCSS，你不能只選擇你要的某些功能
但是如果你用了postcss，你可以選擇你自己想要的功能
舉例來說，加上prefix就是一個功能，或是讓你可以用變數也是一個功能，你可以自己選擇你想要的功能加入，而不是一用就要用一整套完整的方案，當然，你也可以用javascript寫自己的plugin，解析css語法並且加入一些自己想要的東西

2.用標準的css語法
前面有提過預處理器跟後處理器的差別，一個是寫好SCSS(或其他的)丟進去，一個是把CSS加上一些東西之類丟出來
有些人相信將來的某一天，所有瀏覽器都會支援標準的css，例如說你不必再加上`webkit-`之類的prefix
到了那一天，如果你是用postcss，你可以不做任何動作，直接拿原有的css就好，但如果你用的是scss就沒有辦法這樣
像是 http://www.myth.io/ 這套，就提倡用「未來的css標準」寫css，在現代先用後處理器的方式去產生可以跑的css，但是在未來的某一天，把那些plugin拔掉以後，你的css還是可以正常地跑出結果。

最後，回到原來的主題：什麼是postcss?
>PostCSS is a tool for transforming CSS with JS plugins. These plugins can support variables and mixins, transpile future CSS syntax, inline images, and more.

就是一套很方便的工具，你可以自己寫plugin整合進去，或是挑選你要的plugin
然後把原來的css處理過後，讓它變成你想要的樣子。
總之就是後處理器的集大成者就是了

還有一點要特別說明的是，預處理器跟後處理器這兩種概念不是互斥的，他們是可以互相融合的
你可以先用scss寫一段code，編譯成css，再用postcss加上一些你想要的東西，最後產生出完成品
有興趣深入研究的可以參考下面的連結

最後有一點想特別提，最早提出這個概念的人似乎是 TJ Holowaychuk
他實在是太猛了...


參考資料：
[What Will Save Us from the Dark Side of CSS Pre-Processors?](http://alistapart.com/column/what-will-save-us-from-the-dark-side-of-pre-processors)
[myth.io](http://www.myth.io/)
[PostCSS: the Future after Sass and Less](http://ai.github.io/about-postcss/en/)
[Modular CSS preprocessing with rework](http://tjholowaychuk.tumblr.com/post/44267035203/modular-css-preprocessing-with-rework)
[Compare PostCSS with other Frontend tool ](https://github.com/postcss/postcss/issues/237)
[Postprocessors CSS An efficient workflow CSS](https://translate.google.fr/translate?sl=fr&tl=en&js=y&prev=_t&hl=fr&ie=UTF-8&u=http%3A%2F%2Fslides.iamvdo.me%2Fblend14%2F%23%2F&edit-text=&act=url)
[pleeease.io](http://pleeease.io/)
[postcss--预处理器与后处理器](http://motype.org/post/design/css-postprocessor)
[I'm Excited About PostCSS But I'm Scared to Leave Sass](http://davidtheclark.com/excited-about-postcss/)
[Breaking up with Sass: it’s not you, it’s me](http://benfrain.com/breaking-up-with-sass-postcss/)