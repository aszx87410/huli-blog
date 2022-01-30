---
title: 你知道的 JavaScript 知識都有可能是錯的
catalog: true
date: 2022-01-30 17:32:14
tags: [JavaScript]
categories: [JavaScript]
---

談完了 JavaScript 的歷史以及包袱以後，我們來談談 JavaScript 本身。

不知道大家有沒有想過一個問題，當你看到一本 JavaScript 書籍或是教學文章的時候，你要怎麼知道作者沒有寫錯？要怎麼知道書裡講的知識是正確的？就如同標題所說，會不會你以前知道的 JavaScript 知識其實是錯的？

因為作者常寫技術文章，所以就相信他嗎？還是說看到 MDN 上面也是這樣寫，因此就信了？又或是大家都這樣講，所以鐵定沒錯？

有些問題是沒有標準答案的，例如說電車難題，不同的流派都會有各自認可的答案，並沒有說哪個就一定是對的。

但幸好程式語言的世界比較單純，當我們提到 JavaScript 的知識時，有兩個地方可以讓你驗證這個知識是否正確，第一個叫做 ECMAScript 規格，第二個大家可以先想想，我們待會再提。

<!-- more -->

## ECMAScript

1995 年的時候 JavaScript 正式推出，那時候只是個可以在 Netscape 上跑的程式語言，如果想要保證跨瀏覽器的支援度的話，需要的是一個標準化的規範，讓各家瀏覽器都遵循著標準。

在 1996 年時網景聯繫了 Ecma International（European Computer Manufacturers Association，歐洲電腦製造商協會），成立了新的技術委員會（Technical Committee），因為是用數字來依序編號，那時候正好編到 39，就是我們現在熟悉的 TC39。

1997 年時，正式發佈了 ECMA-262 第一版，也就是我們俗稱的 ECMAScript 第一版。

為什麼是叫做 ECMAScript，而不是 JavaScript 呢？因為 JavaScript 在那時已經被 Sun 註冊為商標，而且不開放給 Ecma 協會使用，所以沒辦法叫做 JavaScript，因此後來這個標準就稱之為 ECMAScript 了。

至於 JavaScript 的話，你可以視為是去實作 ECMAScript 這個規範的程式語言。當你想知道某個 JavaScript 的功能的規範是什麼，去看 ECMAScript 準沒錯，詳細的行為都會記載在裡面。

而標準是會持續進化的，幾乎每一年都會有新的標準出現，納入新的提案。例如說截止撰寫當下，最新的是 2021 年推出的 ECMAScript 第 12 版，通常又被稱之為 ES12 或是 ES2021，大家常聽到的 ES6 也被稱為 ES2015，代表是在 2015 年推出的 ECMAScript 第 6 版。

如果你對 ECMAScript 的歷史以及這些名詞有興趣，可以參考底下文章：

1. [JavaScript 二十年：創立標準](https://cn.history.js.org/part-2.html#%E5%91%BD%E5%90%8D%E6%A0%87%E5%87%86)
2. [Day2 [JavaScript 基礎] 淺談 ECMAScript 與 JavaScript](https://ithelp.ithome.com.tw/articles/10213310)
3. [JavaScript 之旅 (1)：介紹 ECMA、ECMAScript、JavaScript 和 TC39](https://ithelp.ithome.com.tw/articles/10237660)

接著，我們就來簡單看看 ECMAScript 的規格到底長什麼樣子。

## 初探 ECMAScript

ECMAScript 的所有版本都可以在這個頁面中找到：https://www.ecma-international.org/publications-and-standards/standards/ecma-262/

可以直接下載 PDF 檔，也可以用線上的 HTML 版本觀看，我會建議大家直接下載 PDF，因為 HTML 似乎是全部內容一起載入，所以要載很久，而且有分頁當掉的風險。

我們打開 ES2021 的規格，會發現這是一個有著 879 頁的超級龐大文件。規格就像是字典一樣，是讓你拿來查的，不是讓你一頁一頁當故事書看的。

但只要能善用搜尋功能，還是很快就可以找到我們想要的段落。底下我們來看看三個不同種類的功能的規格。

### String.prototype.repeat

搜尋「String.prototype.repeat」，可以找到目錄的地方，點了目錄就可以直接跳到相對應的段落：`22.1.3.16 String.prototype.repeat`，內容如下：

![](/img/how-to-validate-javascript-knowledge/ecma-repeat.png)

大家可以自己先試著讀一遍看看。

規格這種東西其實跟程式有點像，就像是虛擬碼（pseudo code）那樣，所以有很多程式的概念在裡面，例如說上面你就會看到有很多 function call，需要去查看其他 function 的定義才能了解確切到底做了什麼。不過，許多函式從命名就可以推測出做的事情，可見函式命名真的很重要。

上面的規格中基本上告訴了我們兩件以前可能不知道的事情：

1. 呼叫 repeat 時如果 count 是負數或是無限大，就會出錯
2. repeat 似乎不是只有字串可以用

第二點其實在 JavaScript 中是滿重要的一件事情，在 ECMAScript 你也會很常看到類似的案例，寫著：「The xxx function is intentionally generic」，這是什麼意思呢？

不知道你有沒有注意到前兩個步驟，分別是：

1. Let O be ? RequireObjectCoercible(this value).
2. Let S be ? ToString(O).

我們不是已經是字串了嗎？為什麼還要再 ToString？又為什麼跟 this 有關？

當我們在呼叫 `"abc".repeat(3)` 的時候，其實是在呼叫 `String.prototype.repeat` 這個函式，然後 this 是 `"abc"`，因此可以視為是 `String.prototype.repeat.call("abc", 3)`。

既然可以轉換成這樣的呼叫方式，就代表你也可以傳一個不是字串的東西進去，例如說：`String.prototype.repeat.call(123, 3)`，而且不會壞掉，會回傳 `"123123123"`，而這一切都要歸功於規格定義時的延展性。

剛剛我們有在規格中看到它有特別寫說這個函式是故意寫成 generic 的，為的就是不只有字串可以呼叫，只要「可以變成字串」，其實都可以使用這個函式，這也是為什麼規格中的前兩步就是把 this 轉成字串，這樣才能確保非字串也可以使用。

再舉一個更奇耙的例子：

``` js
function a(){console.log('hello')}
const result = String.prototype.repeat.call(a, 2)
console.log(result)
// function a(){console.log('hello')}function a(){console.log('hello')}
```

因為函式可以轉成字串，所以當然也可以丟進去 repeat 裡面，而函式的 toString 方法會回傳函式的整個程式碼，因此才有了最後看到的輸出。

有關於 prototype 跟上面這些東西，我們之後提到 prototype 時應該會再講一次。

總之呢，從規格中我們看出 ECMAScript 的一個特性，就是故意把這些內建的方法做得更廣泛，適用於各種型態，只要能轉成字串都可以丟進去。

### typeof

一樣在 PDF 中搜尋 typeof，會找到 `13.5.3 The typeof Operator`，內容如下：

![](/img/how-to-validate-javascript-knowledge/ecma-typeof.png)

可以看到 typeof 會先對傳入的值進行一些內部的操作，像是 `IsUnresolvableReference` 或是 `GetValue` 之類的，但通常我們關心的只有下面那張表格，就是每個型態會回傳的東西。

表格中可以看到兩件有趣的事情，第一件事情就是著名的 bug，`typeof null` 會回傳 object，這個 bug 到今天已經變成了規格的一部分。

第二件事情是對於規格來說，object 跟 function 其實內部都是 `Object`，只差在有沒有實作 `[[Call]]` 這個方法。

事實上，如果看其他段落的話，你也可以看到在規格中多次使用了 `function object` 這個說法，就可以知道在規格中 function 就只是「可以被呼叫（callable）的物件」

### Comments

接著我們來看一下註解的語法，搜尋 comments，可以找到 `12.4 Comments`，底下是部分截圖：

![](/img/how-to-validate-javascript-knowledge/ecma-comment.png)

可以看到 ECMAScript 是怎麼表示語法的，由上讀到下，Comment 分成兩種，MultiLineComment 跟 SingleLineComment，而底下有各自的定義，MultiLineComment 就是 `/* MultiLineCommentChars */`，那個黃色小字 opt 指的是 optional，意思就是沒有 MultiLineCommentChars 也可以，例如說 `/**/`，而底下又繼續往下定義，我就不再一一解釋了。

單行註解的地方則是這樣：

![](/img/how-to-validate-javascript-knowledge/ecma-comment2.png)

其實意思跟多行註解差不多，而最後一行則是把我們引導至了 B.1.3，我們來看一下那邊的內容：

![](/img/how-to-validate-javascript-knowledge/ecma-comment3.png)

這邊額外定義了 HTML-like Comments，看起來除了一些特殊狀況之外，都是合法的用法。

我們可以看到這裡將註解的定義再額外增加了三種：

1. SingleLineHTMLOpenComment
2. SingleLineHTMLCloseComment
3. SingleLineDelimitedComment

從規格中我們可以得到新的冷知識，那就是單行註解其實不只有 `//`，連 HTML 的也可以使用：

``` js
<!-- 我是註解
console.log(1)

// 我也是
console.log(2)

--> 我也是
console.log(3)
```

這就是只能從規格中才能看到的 JavaScript 冷知識。

當有人告訴你 JavaScript 的註解只有 `//` 跟 `/* */` 時，你只要有看過 ECMAScript 規格，就可以知道他講的是錯的，其實不只。

以上就是我們從 ECMAScript 中找出的三個小段落，主要是想讓大家稍微看一下規格長什麼樣子。

如果你對閱讀規格有興趣的話，我會建議大家先去看 ES3 的規格，因為 ES3 比起前兩版完整度高了許多，而頁數又少，只有 188 頁而已，是可以當作一般書籍來看，可以一頁一頁翻的那種。

雖然說從 ES6 以後規格的用詞跟底層的機制有一些變動，但我認為從 ES3 開始看規格還是挺不錯的，至少可以用最少的力氣去熟悉規格。

若是看一看開始對規格產生興趣，想要仔細研究的話，可以參考底下兩篇文章：

1. [翻譯 如何閱讀 ECMAScript Specification 中文版](https://dwatow.github.io/2021/05-08-how-to-read-ecma-262-zh-tw/)
2. [V8 blog - Understanding ECMAScript](https://v8.dev/blog/tags/understanding-ecmascript)

前面我們有提到過有兩個地方可以讓你驗證 JavaScript 的知識是否正確，第一個是 ECMAScript 規格，而第二個則是請大家先自己想一想。

現在要來公布答案了，第二個就是：「JavaScript 引擎原始碼」。

## 淺談 JavaScript 引擎原始碼

ECMAScript 規格定義了一個程式語言「應該如何」，但實際上到底是怎麼樣，就屬於「實作」的部分了，就像是 PM 定義了一個產品規格，但工程師有可能漏看導致實作錯誤，也有可能因為各種原因沒辦法完全遵守規格，會產生一些差異。

所以假如你在 Chrome 上面發現了一個奇怪的現象，去查了 ECMAScript 規格後也發現行為不同，很有可能就是 Chrome 裡 JavaScript 引擎的實作其實跟規格不一樣，才導致這種差異。

規格只是規格，最後我們使用時還是要看引擎的實作為何。

以 Chrome 來說，背後使用一個叫做 V8 的 JavaScript 引擎，如果你對 JS 引擎一無所知，可以先看一下這個影片：[Franziska Hinkelmann: JavaScript engines - how do they even? | JSConf EU](https://www.youtube.com/watch?v=p-iiEDtpy6I)。

而如果想要看 V8 的程式碼，可以看官方版：[https://chromium.googlesource.com/v8/v8.git](https://chromium.googlesource.com/v8/v8.git)，也可以看這個在 GitHub 上的版本：[https://github.com/v8/v8](https://github.com/v8/v8)

在看 ECMAScript 規格時，我們看了三個不同的功能，底下就讓我們來看看這些功能在 V8 中是怎麼被實作的。

### String.prototype.repeat

在 V8 中有一個程式語言叫做 Torque，是為了更方便去實作 ECMAScript 中的邏輯而誕生的，語法跟 TypeScript 有點類似，詳情可參考：[V8 Torque user manual](https://v8.dev/docs/torque)

有關於 `String.prototype.repeat` 的相關程式碼在這：[src/builtins/string-repeat.tq](https://chromium.googlesource.com/v8/v8.git/+/refs/tags/10.0.51/src/builtins/string-repeat.tq)

``` typescript
// https://tc39.github.io/ecma262/#sec-string.prototype.repeat
transitioning javascript builtin StringPrototypeRepeat(
    js-implicit context: NativeContext, receiver: JSAny)(count: JSAny): String {
  // 1. Let O be ? RequireObjectCoercible(this value).
  // 2. Let S be ? ToString(O).
  const s: String = ToThisString(receiver, kBuiltinName);
  try {
    // 3. Let n be ? ToInteger(count).
    typeswitch (ToInteger_Inline(count)) {
      case (n: Smi): {
        // 4. If n < 0, throw a RangeError exception.
        if (n < 0) goto InvalidCount;
        // 6. If n is 0, return the empty String.
        if (n == 0 || s.length_uint32 == 0) goto EmptyString;
        if (n > kStringMaxLength) goto InvalidStringLength;
        // 7. Return the String value that is made from n copies of S appended
        // together.
        return StringRepeat(s, n);
      }
      case (heapNum: HeapNumber): deferred {
        dcheck(IsNumberNormalized(heapNum));
        const n = LoadHeapNumberValue(heapNum);
        // 4. If n < 0, throw a RangeError exception.
        // 5. If n is +∞, throw a RangeError exception.
        if (n == V8_INFINITY || n < 0.0) goto InvalidCount;
        // 6. If n is 0, return the empty String.
        if (s.length_uint32 == 0) goto EmptyString;
        goto InvalidStringLength;
      }
    }
  } label EmptyString {
    return kEmptyString;
  } label InvalidCount deferred {
    ThrowRangeError(MessageTemplate::kInvalidCountValue, count);
  } label InvalidStringLength deferred {
    ThrowInvalidStringLength(context);
  }
}
```

可以看到註解其實就是規格的內容，而程式碼就是直接把規格翻譯過去，真正在實作 repeat 的程式碼則是這一段：

``` typescript
builtin StringRepeat(implicit context: Context)(
    string: String, count: Smi): String {
  dcheck(count >= 0);
  dcheck(string != kEmptyString);
  let result: String = kEmptyString;
  let powerOfTwoRepeats: String = string;
  let n: intptr = Convert<intptr>(count);
  while (true) {
    if ((n & 1) == 1) result = result + powerOfTwoRepeats;
    n = n >> 1;
    if (n == 0) break;
    powerOfTwoRepeats = powerOfTwoRepeats + powerOfTwoRepeats;
  }
  return result;
}
```

從這邊可以看到一個有趣的小細節，那就是在 repeat 的時候，並不是直接跑一個 1 到 n 的迴圈，然後複製 n 遍，這樣太慢了，而是利用了[平方求冪](https://zh.wikipedia.org/wiki/%E5%B9%B3%E6%96%B9%E6%B1%82%E5%B9%82)的演算法。

舉例來說，假設我們要產生 `'a'.repeat(8)`，一般的做法需要 7 次加法，但其實我們可以先加一次產生 aa，然後再互加產生 aaaa，最後再互加一次，就可以用三次加法做出 8 次重複（`2^3 = 8`），省下了不少字串相加的操作。

從中可以看出，像是 JavaScript 引擎這種接近底層的實作，必須要把效能也考慮在內。

### typeof

V8 裡面對於 typeof 的定義在這裡，註解裡面一樣有寫到相關的 spec 段落：[src/objects/objects.h#466](https://chromium.googlesource.com/v8/v8.git/+/refs/tags/10.0.51/src/objects/objects.h#466)

``` c
// ES6 section 12.5.6 The typeof Operator
static Handle<String> TypeOf(Isolate* isolate, Handle<Object> object);
```

實作則是在這邊：[src/objects/objects.cc#870](https://chromium.googlesource.com/v8/v8.git/+/refs/tags/10.0.51/src/objects/objects.cc#870)

``` c
// static
Handle<String> Object::TypeOf(Isolate* isolate, Handle<Object> object) {
  if (object->IsNumber()) return isolate->factory()->number_string();
  if (object->IsOddball())
    return handle(Oddball::cast(*object).type_of(), isolate);
  if (object->IsUndetectable()) {
    return isolate->factory()->undefined_string();
  }
  if (object->IsString()) return isolate->factory()->string_string();
  if (object->IsSymbol()) return isolate->factory()->symbol_string();
  if (object->IsBigInt()) return isolate->factory()->bigint_string();
  if (object->IsCallable()) return isolate->factory()->function_string();
  return isolate->factory()->object_string();
}
```

可以看到裡面針對各種型態都進行了檢查。

有些人可能會很好奇上面的 Oddball 是什麼，`null`、`undefined`、`true` 跟 `false` 都是用這個型態來存的，詳細原因我也不太清楚，想深入研究可參考：

1. [Learning Google V8](https://github.com/danbev/learning-v8#oddball)
2. [Playing with Node/V8 postmortem debugging](https://www.davepacheco.net/blog/post/2012-01-13-playing-with-nodev8-postmortem-debugging/)
3. [V8源码边缘试探-黑魔法指针偏移](https://zhuanlan.zhihu.com/p/39951011)

不過如果 Oddball 裡面已經包含了 `undefined`，為什麼底下還有一個檢查，也會回傳 undefined 呢？這個 undetectable 是什麼呢？

``` c
if (object->IsUndetectable()) {
  return isolate->factory()->undefined_string();
}
```

這一切的一切都是因為一個歷史包袱。

在那個 IE 盛行的年代，有一個 IE 專屬的 API，叫做：`document.all`，可以用 `document.all('a')` 來拿到指定的元素。而那時候也因為這個 IE 專屬的功能，流行著一種偵測瀏覽器是否為 IE 的做法：

``` js
var isIE = !!document.all
if (isIE) {
 // 呼叫 IE 才有的 API
}
```

後來 Opera 也跟上，實作了 `document.all`，可是碰到了一個問題，那就是既然實作了，如果網站有用到上面判斷 IE 的方法的話，就會被判定為是 IE，可是 Opera 並沒有那些 IE 專屬的 API，於是網頁就會爆炸，執行錯誤。

Firefox 在實作這個功能時從 Opera 的故事中學到了教訓，雖然實作了 `document.all` 的功能，可是卻動了一些手腳，讓它沒辦法被偵測到：

``` js
typeof document.all // undefined
!!document.all // false
```

也就是說，`typeof document.all` 必須強制回傳 `undefined`，而且 toBoolean 的時候也必須回傳 `false`，真是 workaround 大師。

而到後來其他瀏覽器也跟上這個實作，這個實作到最後甚至變成了標準的一環，出現在 `B.3.7 The [[IsHTMLDDA]] Internal Slot` 之中：

![](/img/how-to-validate-javascript-knowledge/ecma-document-all.png)

我們在 V8 看到的 IsUndetectable，就是為了實作這個機制而產生，可以在註解裡面看得很清楚，程式碼在 [src/objects/map.h#391](https://chromium.googlesource.com/v8/v8.git/+/refs/tags/10.0.51/src/objects/map.h#391)：

``` js
// Tells whether the instance is undetectable.
// An undetectable object is a special class of JSObject: 'typeof' operator
// returns undefined, ToBoolean returns false. Otherwise it behaves like
// a normal JS object.  It is useful for implementing undetectable
// document.all in Firefox & Safari.
// See https://bugzilla.mozilla.org/show_bug.cgi?id=248549.
DECL_BOOLEAN_ACCESSORS(is_undetectable)
```

看到這邊，大家不妨去打開 Chrome devtool，把玩一下 `document.all`，親自體驗這個歷史包袱。

Chrome 也因為這個歷史包袱，曾經出現過一個 bug，相關的故事可以參考：[What is the bug of V8's typeof null returning "undefined"](https://programmerall.com/article/5623928123/)，上述段落也是參考這篇文章寫的。

### Comments

前面有提到過 JavaScript 其實還有幾種鮮為人知的註解方式，像是 `<!--` 跟 `-->`，在 V8 中有關於語法的部分，可以看這個檔案：[/src/parsing/scanner-inl.h](https://github.com/v8/v8/blob/master/src/parsing/scanner-inl.h)，我們擷取幾個段落：

``` c
case Token::LT:
  // < <= << <<= <!--
  Advance();
  if (c0_ == '=') return Select(Token::LTE);
  if (c0_ == '<') return Select('=', Token::ASSIGN_SHL, Token::SHL);
  if (c0_ == '!') {
    token = ScanHtmlComment();
    continue;
  }
  return Token::LT;

case Token::SUB:
  // - -- --> -=
  Advance();
  if (c0_ == '-') {
    Advance();
    if (c0_ == '>' && next().after_line_terminator) {
      // For compatibility with SpiderMonkey, we skip lines that
      // start with an HTML comment end '-->'.
      token = SkipSingleHTMLComment();
      continue;
    }
    return Token::DEC;
  }
  if (c0_ == '=') return Select(Token::ASSIGN_SUB);
  return Token::SUB;

case Token::DIV:
  // /  // /* /=
  Advance();
  if (c0_ == '/') {
    base::uc32 c = Peek();
    if (c == '#' || c == '@') {
      Advance();
      Advance();
      token = SkipSourceURLComment();
      continue;
    }
    token = SkipSingleLineComment();
    continue;
  }
  if (c0_ == '*') {
    token = SkipMultiLineComment();
    continue;
  }
  if (c0_ == '=') return Select(Token::ASSIGN_DIV);
  return Token::DIV;
```

如果碰到 `<!`，就呼叫 `ScanHtmlComment`。

如果碰到 `-->` 而且是在開頭，就呼叫 `SkipSingleHTMLComment`，這段也告訴了我們一件事，就是 `-->` 一定要在開頭，不是開頭就會出錯（這邊指的開頭是前面沒有其他有意義的敘述，但空格跟註解是可以的）。

如果碰到 `//`，檢查後面是不是 `#` 或是 `@`，是的話就呼叫 `SkipSourceURLComment`，這其實就是 source map 的語法，詳情可以參考：[sourceMappingURL and sourceURL syntax changed](https://developers.google.com/web/updates/2013/06/sourceMappingURL-and-sourceURL-syntax-changed) 跟 [Source map 運作原理](https://blog.techbridge.cc/2021/03/28/how-source-map-works/)。

不是的話就呼叫 `SkipSingleLineComment`。

如果是 `/*` 的話則呼叫 `SkipMultiLineComment`。

上面呼叫的相對應的函式都在 [src/parsing/scanner.cc](https://github.com/v8/v8/blob/master/src/parsing/scanner.cc) 中，我們看一個比較有趣的，碰到 `<!` 會呼叫的 `ScanHtmlComment `：

``` c
Token::Value Scanner::ScanHtmlComment() {
  // Check for <!-- comments.
  DCHECK_EQ(c0_, '!');
  Advance();
  if (c0_ != '-' || Peek() != '-') {
    PushBack('!');  // undo Advance()
    return Token::LT;
  }
  Advance();

  found_html_comment_ = true;
  return SkipSingleHTMLComment();
}
```

這邊會繼續往下看，看後面是不是 `--`，如果不是的話會復原操作，然後回傳 `Token::LT`，也就是 `<`；是的話則呼叫 `SkipSingleHTMLComment`。

而 `SkipSingleHTMLComment` 的程式碼也很簡單：

``` c
Token::Value Scanner::SkipSingleHTMLComment() {
  if (flags_.is_module()) {
    ReportScannerError(source_pos(), MessageTemplate::kHtmlCommentInModule);
    return Token::ILLEGAL;
  }
  return SkipSingleLineComment();
}
```

按照規格中說的，檢查 `flags_.is_module()` 是不是 true，是的話就拋出錯誤。如果想重現這個狀況，可以新建一個 `test.mjs` 的檔案，裡面用 `<!--` 當作註解，用 Node.js 執行後就會噴錯：

```
<!-- 我是註解
   ^

SyntaxError: HTML comments are not allowed in modules
```

而 `<!--` 可以當作註解，也會造成一個很好玩的現象。大多數時候運算子之間有沒有空格，通常不會影響結果，例如說 `a+b>3` 跟 `a + b > 3` 結果是一樣的，但因為 `<!--` 是一整組的語法，所以：

``` js
var a = 1
var b = 0 < !--a 
console.log(a) // 0
console.log(b) // true
```

執行的過程是先 `--a`，把 a 變成 0，接著 `!` 過後變成 1，然後 `0 < 1` 是 true，所以 b 就是 true。

但如果把 `< !--` 改成 `<!--`：

``` js
var a = 1
var b = 0 <!--a 
console.log(a) // 1
console.log(b) // 0
```

那就變成沒有任何運算操作，因為 `<!--` 後面都是註解，所以就是單純的 `var a = 1` 跟 `var b = 0` 而已。

話說在找尋實作的程式碼時，要從茫茫 code 海中找到自己關注的地方不是件容易的事情，分享一個我自己會用的方法，就是 google。直接搜尋關鍵字，或是利用 filter 去幫你搜尋程式碼，像這樣：`typeof inurl:https://chromium.googlesource.com/v8/v8.git`。

如果程式碼在 GitHub 的話，也可以用這個很好用的網站，叫做 [grep.app](https://grep.app/search?q=typeof&filter[repo][0]=v8/v8)，可以指定 GitHub repo 去搜尋內容。

## 結語

當你從任何地方（也包括這篇文章）得到關於 JavaScript 的知識時，都不一定是正確的。

如果想確認的話，有兩個層面可以驗證這個知識是否正確，第一個層面是「是否符合 ECMAScript 的規範」，這點可以透過去尋找 ECMAScript 中相對應的段落來達成。我的文章中如果有參考到 ECMAScript，都會盡量附上參考的段落，方便大家自己去驗證。

第二個層面則是「是否符合 JavaScript 引擎的實作」，因為有時候實作不一定會跟規格一致，而且會有時間的問題，例如說已經被納入規範，但還沒實作，或甚至是反過來。

而 JavaScript 引擎其實也不只一個，像是 Firefox 在使用的 [SpiderMonkey](https://spidermonkey.dev/) 就是另一個不同於 V8 的引擎。

如果你看完這篇文章以後想試試看閱讀規格，卻又不知道該從何下手的話，那我來出一個問題，請你從規格中找出答案：「假設 `s` 是任意字串，請問 `s.toUpperCase().toLowerCase()` 跟 `s.toLowerCase()` 是否永遠相等？如果否，請舉一個反例」