---
title: '[javascript] Dust.js 入門'
date: 2015-04-22 17:04
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript,dustjs]
---

[Dust.js](http://www.dustjs.com/)是一套javascript的模板引擎(templating engine)，就像ejs、jade那樣
都是為了減少開發成本，讓我們在render頁面時更加方便，不會有一堆雜亂又看不懂的程式碼，或是程式碼邏輯跟html頁面完全混雜在一起（想想沒有用任何framework的php...）

原本的Dust.js已經很久沒維護了，但大名鼎鼎的Linkedin看到了這套模板的潛力，所以就接手拿來維護

先附上一些有用的參考資料
[Dust.js语法简介](http://blog.sprabbit.com/blog/2013/08/16/introduction-dustjs-1/)
這篇講的滿詳細的，而且中文教學超少的，這篇不錯

[官方教學 - getting started](http://www.dustjs.com/guides/getting-started/)
官方的教學也寫得很好，而且還附有練習！
讓你去改原本的code，改成對的樣子，邊做邊學習

看完這篇可以看[Context Helpers](http://www.dustjs.com/guides/context-helpers)跟[Partials](http://www.dustjs.com/guides/partials)，都是會比較常用到的東西

[測試Dust.js](http://linkedin.github.io/dustjs/test/test.html)
你可以把寫好的dust template跟要傳進去的資料丟進去，就會輸出結果給你看

{% raw %}

先來個超級無敵簡單的範例

``` js
hello, {name}
```

然後資料長這樣

``` js
{
  name:"world"
}
```

就會輸出`hello, world`

接著我們語法不變，但是把資料換成陣列

``` javascript
{
  name:['a','b','c','d']
}
```

會輸出`hello, a,b,c,d`

但通常我們不會對陣列這樣子直接輸出，而是會取各項資料

``` html
<ul>
  {#name}
    <li>{.}</li>
  {/name}
</ul>
```

會輸出

``` html
<ul>
  <li>a</li>
  <li>b</li>
  <li>c</li>
  <li>d</li>
</ul>
```

`.`就代表現在指到的那個元素
而`{#name}`跟`{/name}`這種成對的組合還有其他用法
例如說

``` html
<ul>
  {#list}
    <li>{name}</li>
  {/list}
</ul>
```

資料：

``` html
{
  list:{
    name:"nick"
  }
}
```

就會輸出：

``` html
<ul><li>nick</li></ul>
```

這樣的用法稱作section，在`{#list}`這個section裡面，Dust就會去找在`list`底下的object

最後來看看簡單的邏輯判斷，這邊偷懶直接拿官方範例來用

``` html
<input type="checkbox"{?isSelected} selected{/isSelected}>
```

資料：

``` js
{
  isSelected: true
}
```

輸出 `<input type="checkbox" selected>`

前面加個`?`代表`isSelected`是`true`的時候才會執行下去
如果前面加的是`^`則是相反，`false`時才會輸出
或你也可以加`{:else}`去處理

``` html
<input type="checkbox" {?isSelected} selected {:else}not_selected {/isSelected}>
```

最基本的用法大概就是這些，至於更多比較複雜的做法，就參考官方的docs吧
{% endraw %}
