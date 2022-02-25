---
title: 來數數 JavaScript 的所有資料型別
catalog: true
date: 2022-02-25 23:02:51
tags: [JavaScript]
categories: [JavaScript]
---

JavaScript 裡面一共有幾個資料型別？又分別是哪些？

要談型別之前，我們應該要先知道 JavaScript 中一共有幾種型別，並且對每一種型別都有最基本的理解。在文章開始之前，你也可以自己先數數看，再來跟我對答案，看是不是正確的。

由於 JavaScript 是會進化的，這篇的型別會以本文寫作時最新的 ECMAScript 2021 為準，底下如果有提到「spec」，指的都是 [ECMAScript 2021 language specification](https://www.ecma-international.org/publications-and-standards/standards/ecma-262/)。

<!-- more -->

## JavaScript 中一共有幾種型別？

在 spec 當中，於第六章：「ECMAScript Data Types and Values」談到了型別，而且將其分為兩種型別：

> Types are further subclassified into ECMAScript language types and specification types. (p.71)

那什麼是 ECMAScript language types，什麼又是 specification types 呢？我們先來看後者：

> A specification type corresponds to meta-values that are used within algorithms to describe the semantics of ECMAScript language constructs and ECMAScript language types. The specification types include Reference, List, Completion, Property Descriptor, Environment Record, Abstract Closure, and Data Block. (p.100)

Specification types 人如其名，是在規格中會用到的型別，可以拿來描述一些規格中的語法或是演算法，例如說你會在規格中看到「Reference」、「List」、「Environment Record」這些型別。

而另外一種 ECMAScript language types，規格上是這麼說的：

> An ECMAScript language type corresponds to values that are directly manipulated by an ECMAScript programmer using the ECMAScript language. (p.71)

因此，這才是我們一般在談的 JavaScript 中的型別，也是我們這篇要討論的主題。

那一共有幾種型別呢？根據規格所說：

> The ECMAScript language types are Undefined, Null, Boolean, String, Symbol, Number, BigInt, and Object. (p.71)

所以一共有 8 種型別，分別是：

1. Undefined
2. Null
3. Boolean
4. String
5. Symbol
6. Number
7. BigInt
8. Object

有些人可能會算成 7 種，少了最新的 BigInt，有些會算成 6 種，再少了 ES6 新增的 Symbol，但總之呢，答案是 8 種。

接著，我們就來簡單看一下規格上是怎麼描述這八種型別的，以及基本的使用方式。

### 1. Undefined

規格上是這樣描述的：

> The Undefined type has exactly one value, called undefined. Any variable that has not been assigned a value has the value undefined. (p.72)

所以，Undefined 是一個型別，而 `undefined` 是一個 Undefined 型別的值，這就像是「 Number 是一個型別，而 9 就是 Number 型別的值」，是一樣的意思。

Undefined 這個型別就只有 `undefined` 這個值，當一個變數沒有被賦予任何值的時候，它的值就是 `undefined`。

這點很容易可以驗證：

``` js
var a
console.log(a) // undefined
```

用 `typeof` 也可以得到 `'undefined'` 這個結果：

``` js
var a
if (typeof a === 'undefined') { // 注意，typeof 的回傳值是字串
 console.log('hello') // hello
}
```

### 2. Null

規格上的描述更簡單了：

> The Null type has exactly one value, called null. (p.72)

有些人會搞不太清楚 `null` 與 `undefined` 的差別，因為這兩個確實是有點類似，這時候就要來看一張經典梗圖（出處：[推特 @ddprrt](https://twitter.com/ddprrt/status/1074955395528040448?lang=zh-Hant)）：

![null vs undefined](/img/js-type/p1.jpeg)

`undefined` 基本上就是不存在的意思，而 `null` 是「存在但沒有東西」，有種刻意用 `null` 來標記「沒東西」的感覺。

另外，還有一個地方要注意，就是如果用 `typeof` 的話，你會得到 `'object'` 這個錯誤的結果：

``` js
console.log(typeof null) // 'object'
```

這是 JavaScript 最著名的 bug 之一，在這一篇：[The history of “typeof null”](https://2ality.com/2013/10/typeof-null.html) 文章中，作者有解釋了為什麼會有這個 bug，並且實際拿出了早期 JavaScript 引擎的程式碼來佐證，而 JavaScript 之父 Brendan Eich 也有在底下留言，修正一些細節。

### 3. Boolean

規格上的描述是：

> The Boolean type represents a logical entity having two values, called true and false. (p.72)

所以 Boolean 這個型別的值不是 `true` 就是 `false`，這大家也應該都滿熟悉的，就不多提了。

### 4. String

String 在規格上的描述比較長，我們擷取其中一段來看：

> The String type is the set of all ordered sequences of zero or more 16-bit unsigned integer values (“elements”) up to a
maximum length of 2^53 - 1 elements. The String type is generally used to represent textual data in a running ECMAScript program, in which case each element in the String is treated as a UTF-16 code unit value (p.72)

上面寫說字串就是一連串的 16-bit 的數字，而這些數字就是 UTF-16 的 code unit，字串的長度最多則是 2^53 - 1。

相信很多人看了之後可能還是搞不太懂這是什麼意思，有關於 UTF-16 跟字串編碼的東西，可以講的東西很多，之後會額外再寫一篇，目前我們只要大概看過字串的定義就好了。

### 5. Symbol

接著我們來看看 Symbol：

> The Symbol type is the set of all non-String values that may be used as the key of an Object property.
> 
> Each possible Symbol value is unique and immutable.
> 
> Each Symbol value immutably holds an associated value called [[Description]] that is either undefined or a String value. (p.73)

Symbol 是 ES6 才新增的資料型別，如同上面所述，是除了字串以外唯一可以當作 object 的 key 的東西，而每一個 Symbol 的值都是獨一無二的。

我們一樣直接來看個範例比較快：

``` js
var s1 = Symbol()
var s2 = Symbol('test') // 可以幫 Symbol 加上敘述以供辨識
var s3 = Symbol('test')
console.log(s2 === s3) // false，Symbol 是獨一無二的
console.log(s2.description) // test 用這個可以取得敘述

var obj = {}
obj[s2] = 'hello' // 可以當成 key 使用
console.log(obj[s2]) // hello
```

簡單來說，Symbol 基本上是拿來當物件的 key 用的，因為它獨一無二的特性，所以不會跟其他 key 相衝突。

話雖如此，如果你想要的話還是可以用 `Symbol.for()` 來取得同樣的 Symbol，像是這樣：

``` js
var s1 = Symbol.for('a')
var s2 = Symbol.for('a')
console.log(s1 === s2) // true
```

為什麼可以做到這樣呢？因為當你在用 `Symbol.for` 這個 function 的時候，他會先去一個全域的 Symbol registry 尋找有沒有這個 Symbol，如果有的話就回傳，沒有的話就新建一個，然後把建立好的寫入到 Symbol registry 中。因此其實也不是產生同樣的 Symbol，只是幫你找出之前已經建立好的 Symbol 而已。

除此之外，還有一個重要的特性是隱藏資訊，當你在用 `for in` 的時候，如果 key 是 Symbol 型別，並不會被列出來：

``` js
var obj = {
  a: 1,
  [Symbol.for('hello')]: 2
}
for(let key in obj) {
  console.log(key) // a
}
```

知道了 Symbol 的這些特性以後，你可能會跟我一樣好奇，那實際上 Symbol 到底可以用在哪邊，又該如何使用呢？

想知道這問題的答案，我們可以來看一個經典的實際案例：React。

如果你有寫過 React 的話，對這樣的寫法應該不陌生：

``` jsx
function App() {
  return (
    <div>hello</div>
  )
}
```

這樣子把 JavaScript 跟 HTML 混在一起寫的語法叫做 JSX，而這背後其實是利用 Babel 的 plugin，把上面的程式碼轉換成底下這樣：

``` js
function App() {
  return (
    React.createElement(
      'div', // 標籤
      null, // props
      'hello' // children
    )
  )
}
```

而 `React.createElement` 會回傳一個像是這樣的 object，就是我們平常在講的 Virtual DOM：

``` js
{
  type: 'div',
  props: {
    children: 'hello'
  },
  key: null,
  ref: null,
  _isReactElement: true
}
```

所以其實最後都是 JavaScript，沒什麼特別的，而 React 對於 XSS 都有做基本的防護，所以除非使用 `dangerouslySetInnerHTML` 這個屬性（名稱是故意設計成這麼長的），否則你是沒辦法插入 HTML 的，例如說這樣：

``` jsx
function App({ text }) {
  return (
    <div>{text}</div>
  )
}

const text = "<h1>hello</h1>"
ReactDOM.render(
  <App text={text} />,
  document.body
)
```

你所傳進去的 text 在放到 DOM 時會用 `textContent` 的方式放上去，所以最後只會出現純文字的 `<h1>hello</h1>`，而不是以 HTML 標籤的形式出現。

好，這些看起來都沒有問題，但如果上面範例的 `text` 不是文字，而是一個物件的話，會發生什麼事情呢？例如說這樣：

``` jsx
function App({ text }) {
  return (
    <div>{text}</div>
  )
}

const text = {
  type: 'div',
  props: {
    dangerouslySetInnerHTML: {
      __html: '<svg onload="alert(1)">'
    }
  },
  key: null,
  ref: null,
  _isReactElement: true
}

ReactDOM.render(
  <App text={text} />,
  document.body
)
```

由於 `React.createElement` 最後是回傳一個物件，因此我們可以直接把 `text` 變成 `React.createElement` 會回傳的格式，它就會被看成是一個 React component，然後我們就可以控制它的屬性，透過前面提到的 `dangerouslySetInnerHTML`，來塞入任意的值，進而達成 XSS！

這就是 React 在 v0.14 以前的漏洞，只要攻擊者可以傳入物件當作參數，並且能夠控制這些屬性，就能達成 XSS。

你可以設想一個狀況，假設某個網站有個設定暱稱的功能，在顯示暱稱的部分，這個網站會去打 API，根據 API 回傳的 `response.data.nickname` 去 render React component，而 Server 有個 bug 是在設定暱稱時，雖然說照理來講只能填字串，但因為沒有做型態檢查，導致你可以把暱稱設定成物件。

因此，假設你把暱稱設定成物件，就可以像上面那樣設置成一個 React component，在 render 的時候就會觸發 XSS。

那修復方式是什麼呢？很簡單，就是把原本的 `_isReactElement` 換成 Symbol：

``` js
const text = {
  type: 'div',
  props: {
    children: 'hello'
  },
  key: null,
  ref: null,
  $$typeof: Symbol.for('react.element')
}
```

為什麼這樣就可以了呢？因為根據我們上面設想的狀況，我在把暱稱修改成 object 的時候，`$$typeof` 傳什麼都不對，都沒辦法是 `Symbol.for('react.element')`，因為 Symbol 的特性就是這樣，我不可能從 Server 端產生出這個值。

除非我可以從 JavaScript 去控制這個 object，但如果我都可以從 JavaScript 去控制它了，那通常就代表我可以執行任意程式碼了（例如說我已經找到 XSS 漏洞）

如此一來，React 就能防範我們上面講的攻擊方式，攻擊者並不能透過一個從 Server 或其他地方來的 object 去偽裝成 React component，因為他偽造不出 Symbol，這就是 Symbol 在實際用途中很重要的一個部分。

Dan 哥的部落格有一篇就是在講這個，上面的內容也是參考自這篇部落格：[Why Do React Elements Have a $$typeof Property?](https://overreacted.io/why-do-react-elements-have-typeof-property/)

### 6. Number

Number 的 spec 也很長，我們簡單看一下：

> The Number type has exactly 18,437,736,874,454,810,627 (that is, 2^64 - 2^53 + 3) values, representing the double-precision 64-bit format IEEE 754-2019 values as specified in the IEEE Standard for Binary Floating-Point Arithmetic, except that the 9,007,199,254,740,990 (that is, 2^53 - 2) distinct “Not-a-Number” values of the IEEE Standard are represented in ECMAScript as a single special NaN value. (p.76)

裡面有提到了 Number 這個型別有可能的值，是有一個明確數字的，也就是說這個型別並不能完整地儲存所有的數字，一旦超過某個範圍就會有誤差。

再者，規格也寫說它儲存的形式是「double-precision 64-bit format IEEE 754-2019」，有清楚地說明是按照哪一個規格在存，從中也可以看出 JS 中的數字都是 64 bit。

上面講到的範圍是很重要的一個部分，看底下範例比較清楚：

``` js
var a = 123456789123456789
var b = a + 1
console.log(a === b) // true
console.log(a) // 123456789123456780
```

什麼！為什麼這個數字加一之後居然還是一樣？而且為什麼印出來的並不是我們當初設定的值？仔細想想，其實會發現以 Number 的儲存機制來說，是非常合理的，上面有講到 JS 中的 Number 是個 64 bit 的數字，而 64 bit 是個有限的空間，所以能存的數字當然也是有限的。

這就像鴿籠原理一樣，你有 N 個籠子跟 N+1 隻鴿子，把所有鴿子放到籠子裡面，勢必會有兩隻鴿子在同一個籠子裡。Number 也一樣，儲存空間是有限的，數字是無限的，所以你一定沒辦法精準地儲存所有數字，一定會有誤差產生。

有關於其他細節，我之後會再寫一篇特別講數字的文章來探討一下。

### 7. BigInt

BigInt 是 ES2020 才新增的型別，描述如下：

> The BigInt type represents an integer value. The value may be any size and is not limited to a particular bit-width. (p.85)

可以看到跟剛剛的 Number 有個很明顯的差別，那就是理論上 BigInt 可以儲存的數字似乎是沒有上限的，從這點也能大概猜出什麼時候該用 BigInt，什麼時候又該用 Number。

剛剛 Number 的例子如果用 BigInt 來改寫，就不會有問題：

``` js
var a = 123456789123456789n // n 代表 BigInt
var b = a + 1n
console.log(a === b) // false
console.log(a) // 123456789123456789n
```

這就是為什麼我們需要 BigInt，更多的細節之後會再寫一篇文章來講。

### 8. Object

最後來看看我們的 Object，底下我跳著節錄幾個重點：

> An Object is logically a collection of properties.
> 
> Properties are identified using key values. A property key value is either an ECMAScript String value or a Symbol value. All String and Symbol values, including the empty String, are valid as property keys. A property name is a property key that is a String value.
> 
> Property keys are used to access properties and their values(p.89)

物件是由很多屬性（property）組成，而第二段所說的「key value」其實就是我們常在講的 key，用來取得某個屬性的值。從規格上也可以看出一些很有趣的東西，例如說物件的 key 一定要是字串或是 Symbol，也就是說如果你用數字當作 key，其實背後還是字串：

``` js
var obj = {
 1: 'abc',
}
console.log(obj[1]) // abc
console.log(obj['1']) // abc
```

而且空字串也可以拿來當作 key，是合法的：

``` js
var obj = {
 '': 123
}
console.log(obj['']) // 123
```

物件在 JavaScript 中是個很重要的概念，所以之後會陸續有幾篇文章都在講物件相關的東西。

相信大家都有聽過一個說法，那就是在 JavaScript 裡型別有分兩種，原始型別（Primitive data type）跟物件，基本上除了物件以外的型別都是原始型別。

不過在 ECMAScript spec 中，其實並沒有出現「primitive data type」這個詞，只有出現「primitive values」，例如說：

>  A primitive value is a member of one of the following built-in types: Undefined, Null, Boolean, Number, BigInt, String, and Symbol; an object is a member of the built-in type Object; (p.49)

而「primitive type」這個詞有出現，但只出現了唯一一次：

> If an object is capable of converting to more than one primitive type, it may use the optional hint preferredType to favour that type (p.112)

網路上能查到最多出現 primitive data type 這個詞的是 Java，雖然 JavaScript spec 中沒有出現，也沒有正式定義「primitive data type」或是「primitive type」（只有 primitive value 有正式定義），但把表示 primitive value 的資料型別稱之為 primitive data type，似乎也滿合理的就是了。

總之這只是一些名詞而已，我只是補充一下在 spec 上的文字，日常使用的時候我覺得講 primitive data type 也無妨。

## 總結

以上就是目前 ECMAScript 2021 spec 中提到的 8 種不同的資料型別，分別是：

1. Undefined
2. Null
3. Boolean
4. String
5. Symbol
6. Number
7. BigInt
8. Object

我稍微介紹了一下每個型別，以及一些從 spec 上看到的小知識，也針對 Symbol 這個型別做了更完整的介紹。

看完這些之後我自己很好奇一個問題，那就是什麼時候會有第九種？如果有的話，最有可能會是什麼？

我查了一下 [TC39](https://github.com/tc39/proposals) 的 proposal，目前似乎只有一個處於 stage 1 的提案有可能新增一個原始型別，叫做 [BigDecimal](https://github.com/tc39/proposal-decimal)，拿來處理小數用的，就跟 Java 的命名一模一樣。

雖然這個提案還在滿早期的階段，但我認為確實滿有可能在未來被採用，畢竟 JavaScript 目前要精確處理小數還是得靠各種第三方函式庫，就跟以前要處理大數一樣，如果多了原生 API 的支持那也是挺不錯的，不過應該還有滿長的一段路要走。