---
title: 淺談 JavaScript 中的時間與時區處理
date: 2020-12-26 20:54:01
tags: [JavaScript,Front-end]
categories:
  - JavaScript
---

## 前言

部落格需要顯示發佈時間，餐廳網站要顯示訂位時間，拍賣網站則是要顯示訂單的各種時間，無論你做什麼，都會碰到「顯示時間」這個很常見的需求。

這問題看似簡單，不就是顯示個時間嗎？但如果牽扯上「時區」的話，問題就會變得再更複雜一些。以時區來說，通常會有這幾個需求：

1. 網站上的時間需要在某個固定時區顯示，我在美國跟在台灣要在網站上看到同樣的時間
2. 網站上的時間會根據使用者的瀏覽器設置不同，我在美國跟在台灣看到的時間會不一樣
3. PM 根本沒想過這問題，只考慮到當地的使用者，所以暫時不用擔心這個

而這還只是顯示的部分而已，還有另外一個部分是與後端的溝通，這個我們可以待會再提，但總之呢，要正確處理時間跟時區並不是一件簡單的事。

在最近這一兩份工作剛好都有碰過相關的問題，因此對這一塊有點小小心得，就寫了這一篇來跟大家分享一下。

<!-- more -->

## 先從 timestamp 開始談起

要談時間，我比較喜歡從 timestamp 開始談起，或講得更精確一點是 Unix timestamp。

什麼是 timestamp 呢？你打開 devtool 的 console 然後輸入：`console.log(new Date().getTime())`，出來的東西就是我們所謂的 timestamp。

而這個 timestamp 指的是：「從 UTC+0 時區的 1970 年 1 月 1 號 0 時 0 分 0 秒開始，總共過了多少毫秒」，而我寫這篇文章的時候得出來的值是 1608905630674。

ECMAScript 的 spec 是這樣寫的：

>  20.4.1.1 Time Values and Time Range
> 
> Time measurement in ECMAScript is analogous to time measurement in POSIX, in particular sharing definition in terms of the proleptic Gregorian calendar, an epoch of midnight at the beginning of 01 January, 1970 UTC, and an accounting of every day as comprising exactly 86,400 seconds (each of which is 1000 milliseconds long).

在 Unix 系統中的時間就是這樣表示的，而許多程式語言得到的 timestamp 也都是類似的表示方法，但有些可能只能精確到「秒」，有些可以精確到「毫秒」，如果你發現程式碼中有些地方需要除以 1000 或是乘以 1000，就很有可能是在做秒跟毫秒的轉換。

上面我們有提到「UTC +0」這東西，這其實就是 +0 時區的意思。

舉例來說，臺灣的時區是 +8，或如果要講得更標準一點，就是 GMT +8 或是 UTC +8，這兩者的區別可以參考：[到底是 GMT+8 還是 UTC+8 ?](https://pansci.asia/archives/84978)，現在的標準基本上都是 UTC 了，所以這篇文章接下來都只會用 UTC。

## 儲存時間的標準格式

有了一些基本概念之後，可以來談該如何儲存時間。其中一種儲存方式就是存上面所說的 timestamp，但缺點是無法用肉眼直接看出時間是什麼，一定要經過轉換。

而另外一種儲存時間的標準叫做 [ISO 8601](https://www.iso.org/iso-8601-date-and-time-format.html)，在許多地方你都可以發現它的蹤影。

例如說 [OpenAPI](https://swagger.io/docs/specification/data-models/data-types/) 裡面有定義了一個格式叫做 `date-time`，它的敘述是這樣寫的：

> the date-time notation as defined by RFC 3339, section 5.6, for example, 2017-07-21T17:32:28Z

如果你直接去看 [RFC 3339](https://tools.ietf.org/html/rfc3339) 的話，開頭的摘要就已經寫明了：

> This document defines a date and time format for use in Internet protocols that is a profile of the ISO 8601 standard for representation of dates and times using the Gregorian calendar.

那這到底是個什麼樣的格式呢？其實就是像 `2020-12-26T12:38:00Z` 這種格式，用字串表現一個帶有時區的時間。

更詳細的規則可以看 [RFC](https://tools.ietf.org/html/rfc3339#section-5.6)：

![](/img/date-time/rfc3339.png)

RFC 的規則會定義的比較完整，但總而言之就是我上面說的那種形式，然後最後面如果是 Z 就代表 UTC +0，如果要其他時區可以這樣寫：`2020-12-26T12:38:00+08:00`，代表 +8 時區的 12 月 26 號 12 點 38 分 0 秒。

在 JavaScript 裡面則是基於一個 ISO 8601 的延伸格式，在 ECMAScript spec 中的 20.4.1.15 Date Time String Format 有提到 ：

![](/img/date-time/es.png)

其中比較有趣的是年份的部分，除了大家所熟知的四位數 0000~9999 之外，居然還可以有一個六位數的，而且可以有負數，可以表示西元前的年份：

![](/img/date-time/ad.png)

理解了表示時間的標準格式以後，有個重要的觀念要先銘記在心，那就是時間的相對性。

舉例來說，1593163158 這個 timestamp 代表的是：
「UTC +0 時區的 2020-06-26 09:19:00」，同時也代表著  
「UTC +8 時區的 2020-06-26 17:19:00」，這兩個時間是一樣的，都是同一個時間。

所以當你拿到一個 timestamp 以後，你無法從 timestamp 本身知道你應該要顯示成什麼時區的時間。

談完了這些概念之後，我們來聊聊 JS 中怎麼處理這些時間。

## JavaScript 中的時間處理

在 JS 裡面你可以用 `Date` 來處理時間相關的需求，例如說 `new Date()` 可以產生出現在的時間，然後 `new Date().toISOString()` 就可以產生 ISO 8601 格式的字串，像是：`2020-12-26T04:52:26.255Z`。

在 `new Date()` 裡面放上參數的話則是會幫你 parse 時間，例如說 `new Date(1593163158000)` 或是 `new Date('2020-12-26T04:52:26.255Z')`。

除此之外還有許多 function 可以幫你拿到時間的各個部分，以上面那個字串 `2020-12-26T04:52:26.255Z` 為例，我們用 `new Date('2020-12-26T04:52:26.255Z')` 搭配底下的各個 function：

1. getYear => 120
2. getMonth => 11
3. getDate => 26
4. getHours => 12
5. getMinutes => 52
6. getSeconds => 26
7. getMilliseconds => 255

有幾個部分看起來完全沒問題，但有些部分看起來很怪，我們挑那些怪異的部分來講解。

### getYear

你可能預期會拿到 2020 但卻拿到了 120，因為 getYear 會是年份 - 1900 之後的結果，如果你想拿到 2020 要用 `getFullYear`。

### getMonth

你會預期拿到 12，但卻拿到了 11，這是因為這邊拿到的數字會從 0 開始，所以如果是 1 月會拿到 0，因此 12 月拿到了 11。

### getHours

傳進去的時間是 4，所以你預期會拿到 4，但卻拿到了 12。這是因為 JS 在進行這些操作之前，都有一個步驟是把時間轉成「Local Time」：

![](/img/date-time/gethours.png)

因此 UTC +0 的 4 點，轉成 UTC +8 就變成 12 點了，因此拿到的就會是 12。

先不論最後那個轉成 local time 的特性，一定有很多人疑惑說為什麼月份要 - 1，然後 getYear 不好好回傳年份就好了。這些設計其實並不是 JS 獨創的，而是直接從 Java 1.0 抄過來的。

雖然說 JavaScript 跟 Java 現在確實沒什麼關係，但在 JavaScript 剛誕生的時候它跟 Java 的淵源其實很深（不然怎麼會取叫這個名字），本來就希望能夠在語法上看起來像是 Java，吸引 Java 的開發者，所以會直接從 Java 1.0 把 java.util.Date 整個抄過來好像也是件能理解的事情。

不過這些設計其實在 JDK 1.1 之後就被 deprecated 了，只是 JavaScript 礙於向下相容的關係只能繼續使用。現在依然可以在 Java 的文件中找到 [getMonth](https://docs.oracle.com/javase/10/docs/api/java/util/Date.html#getMonth%28%29) 以及 [getYear](https://docs.oracle.com/javase/10/docs/api/java/util/Date.html#getYear%28%29) 的說明。

而 getYear 會回傳 -1900 之後的結果在當時應該也是一件正常的事，因為那時候在儲存年份時好像習慣儲存兩位數，例如說 1987 就存 87 而已。這也導致了後來的千禧蟲危機，Year 2000 Problem（簡稱 Y2K），在 2000 年的時候年份會變成 00。

上面這些歷史在 [JavaScript: the first 20 years](https://dl.acm.org/doi/abs/10.1145/3386327) 裡面都有提到，Java date 那一段在第 19 頁。

## 日期時間需注意的地方

用 `new Date(string)` 就等於 `Date.parse(string)`，可以讓 JS 來幫你解析一個字串並轉換成時間。如果你給的字串符合標準格式的話那沒有問題，但如果不符合標準的話，就會根據實作的不同而有不同的結果：

![](/img/date-time/parsedate.png)

這就是需要小心的地方了，比如說這兩個字串：

```
new Date('2020-02-10')
new Date('2020/02/10')
```

不都是 2020 年 2 月 10 號嗎？

但如果你在 Chrome devtool 上面執行，會發現些微的不同：

![](/img/date-time/utc.png)

根據 spec 的說法：

> When the UTC offset representation is absent, date-only forms are interpreted as a UTC time and date-time forms are interpreted as a local time.

前者是符合 ISO 8601 格式的，所以被解析成為 UTC +0 的 2 月 10 號 0 點 0 分，所以我們看到的結果才會是 +8 時區的 8 點。

而後者並不符合 ISO 8601 格式，所以會根據實作不同而產生不同的結果，而看起來第二種格式 V8 會當作是 local time，V8 的 date parser 在這裡：[src/date/dateparser-inl.h](https://github.com/v8/v8/blob/dc712da548c7fb433caed56af9a021d964952728/src/date/dateparser-inl.h)（不過我也還沒找到是哪一段造成這個結果就是了）。

還有另外一個常見的非標準格式是這樣：`2020-02-02 13:00:00`

這個格式少了一個 T，在 Safari 上面會直接回給你一個 Invalid Date，而在 Chrome 上面則可以正常解析。這我其實覺得滿合理的，你丟一個非標準格式的東西，本來就是 invalid。瀏覽器可以正常解析是額外幫你多做事，但不能正常解析你也不能怪它。

補充：感謝 othree 的留言補充以及討論，這邊其實有一個小細節在

前面有提到 ISO 8601 跟 RFC3339，這兩個其實有一點細微的差異。

在 ISO 8601 裡面寫著：

> The character [T] shall be used as time designator to indicate the start of the representation of the time of day component in these expressions.

> NOTE By mutual agreement of the partners in information interchange, the character [T] may be omitted in applications where there is no risk of confusing a date and time of day representation with others defined in this International Standard.

也就是說在 ISO 8601 的標準裡面，T 這個字元在溝通的雙方都同意之下是可以省略的，會變成像是：2020-02-0213:00:00 這樣，但並沒有寫說可以用空白來取代。

而在 RFC3339 裡面則是寫著：

> NOTE: ISO 8601 defines date and time separated by "T". Applications using this syntax may choose, for the sake of readability, to specify a full-date and full-time separated by (say) a space character.

所以 RFC3339 為了可讀性，是可以用空白取代 T 的。因此用空白來分隔的字串，遵守 RFC3339 但不遵守 ISO 8601。

那 ECMAScript 是哪一種呢？根據 spec 上的說明，看起來 T 也是必須要有的，所以在 ECMAScript 裡面一個正確的 date time 需要用 T 來分隔，不能用空白取代。

但有趣的事情來了，那就是在 ES5 之前，其實 ECMAScript 的規格裡對於 date time 的格式是沒有說明的，也就是說並沒有講什麼才是標準的格式，所以少了一個 T 也可以解析可以當作是為了支援以前的實作而保留的行為。

（參考資料：[In an ISO 8601 date, is the T character mandatory?](https://stackoverflow.com/questions/9531524/in-an-iso-8601-date-is-the-t-character-mandatory)、[Allow space to seperate date and time as per RFC3339](https://github.com/toml-lang/toml/issues/424)）

總之呢，加上 T 之後就沒問題了，加上去之後會變成少了時區的 date time：`2020-02-02T13:00:00`。

丟到 Chrome 之後是：`Sun Feb 02 2020 13:00:00 GMT+0800`   
丟到 Safari 之後是：`Sun Feb 02 2020 21:00:00 GMT+0800`

根據我們上面貼的 spec 節錄，如果缺少了時區而且是 date time format 的話，應該要當作是 local time 才對，所以 Chrome 的做法是正確的，但 Safari 卻把這個時間當成是 UTC +0 的時間，所以差了八個小時。

我認為這是一個 bug 啦，但是去 webkit 的 bugtracker 沒找到有人回報，或許會這樣做也是有什麼特殊的理由。

以上這些問題也可以參考[前端工程研究：關於 JavaScript 中 Date 型別的常見地雷與建議作法](https://blog.miniasp.com/post/2016/09/25/JavaScript-Date-usage-in-details)，裡面提到了更多瀏覽器上的測試。

但總之只要把握一個原則就對了，就是用標準的格式來溝通，就不會有這些問題了。

### 2023-11-25 更新

感謝底下留言區的讀者 Glenn8119 留言，Safari 已經修正了上述的行為，我去查了一下發現其實還修了更多東西。

上面有提到 Safari 跟 Chrome 不同的兩點：

1. `2020-02-02 13:00:00` 會回傳 invalid date
2. `2020-02-02T13:00:00` 會當成 +0 時間

這兩個現在都已經修復囉！

第一個 invalid date 的問題是在 2022 年修好的：[Bug 235468: [JSC] Relax Date.parse requirement](https://bugs.webkit.org/show_bug.cgi?id=235468)，修改了 parse 的邏輯，新增了對於空格以及小寫 t 的支援：

``` diff
diff --git a/Source/WTF/wtf/DateMath.cpp b/Source/WTF/wtf/DateMath.cpp
index ebd69a4c76cd7acb0a233be552071158ca2171ca..01976e039682c467765ef77d54925dd84a4b7da1 100644
--- a/Source/WTF/wtf/DateMath.cpp
+++ b/Source/WTF/wtf/DateMath.cpp
@@ -645,7 +645,7 @@ double parseES5DateFromNullTerminatedCharacters(const char* dateString, bool& is
         return std::numeric_limits<double>::quiet_NaN();
     // Look for a time portion.
     // Note: As of ES2016, when a UTC offset is missing, date-time forms are local time while date-only forms are UTC.
-    if (*currentPosition == 'T') {
+    if (*currentPosition == 'T' || *currentPosition == 't' || *currentPosition == ' ') {
         // Parse the time HH:mm[:ss[.sss]][Z|(+|-)(00:00|0000|00)]
         currentPosition = parseES5TimePortion(currentPosition + 1, hours, minutes, seconds, milliseconds, isLocalTime, timeZoneSeconds);
         if (!currentPosition)
```

而第二個時區的問題更早，在 2020 年就被修復了（不過修復是一回事，deploy 是一回事，我不確定什麼時候 deploy 的）：[Bug 89071: JavaScript: Invalid date parse for ISO 8601 strings when no timezone given](https://bugs.webkit.org/show_bug.cgi?id=89071)，對修改有興趣的話可以看這個 commit：https://github.com/WebKit/WebKit/commit/2148a43f377e67c60b167f5730c7b5c5c21b202d


## 最後來談時區的顯示

前面講了這麼多，終於可以來談開頭講的時區的問題了。在處理時間這一塊，比較多人應該都是挑一個順眼的 library 來用，例如說 moment、date-fns、dayjs 或是 luxon 之類的，這些 library 如果沒有正確使用的話，會跟你想像的結果不同。

例如說，請問底下的輸出結果會是什麼？

``` js
luxon.DateTime
  .fromISO('2020-02-02T13:00:00+03:00')
  .toFormat('HH:mm:ss')
```

..  
..  
..  
防雷
..  
.. 
..  
.. 

有許多人都會誤以為如果你的 date time 有帶 timezone 的話，format 出來的結果就會依照那個 timezone。但不是這樣的，最後 format 還是會以 local time 為主。

所以上面的例子中，由於我的電腦是臺灣 +8 時區，所以結果會是 18:00:00 而不是 13:00:00。

這點大家一定要記住，無論是 dayjs 或是 moment 也都一樣，如果沒有在 format 之前特別指定時區，format 出來的結果都會依照使用者當前的時區。所以同一段程式碼，在不同使用者的電腦可能會有不同的輸出。

因此 Server 端給你什麼都不重要，給你 `2020-02-02T13:00:00+03:00` 或是 `2020-02-02T10:00:00Z` 或 `2020-02-02T18:00:00+08:00`，對前端來說都是一樣的，都代表著同一個時間，用 format 也都會產生出一樣的結果。

如果你想要用 date time 裡的時區為主的話，可以這樣使用：

``` js
luxon.DateTime
  .fromISO('2020-02-02T13:00:00+03:00', { 
    setZone: true
  })
  .toFormat('HH:mm:ss')
```

但是大部分情形下會建議的做法都是由前端自行決定要顯示成哪個時區的時間，而不是由後端給的 date time 來決定。

那要怎麼決定顯示成哪個時區呢？以 luxon 來說會是這樣：

``` js
luxon.DateTime
  .fromISO('2020-02-02T13:00:00+03:00')
  .setZone('Asia/Tokyo')
  .toFormat('HH:mm:ss')
```

moment 則是這樣：

```  js
moment('2020-02-02T13:00:00+03:00')
  .tz('Asia/Tokyo')
  .format('HH:mm:ss')
```

dayjs 也類似：

``` js
dayjs('2020-02-02T13:00:00+03:00')
  .tz('Asia/Tokyo')
  .format('HH:mm:ss')
```

透過這樣的方式，我們就可以保證輸出的時間一定是固定在同一個時區。什麼時候會需要這樣做呢？例如說我之前待過的一間公司是餐廳訂位的網站，後端會傳給我們餐廳可以訂位的時段，像是下午一點，下午兩點之類的，這邊後端會用標準格式給我們，例如說：`2020-02-02T13:00:00+08:00`，代表 2020 年 2 月 2 號的下午 1 點可以訂位。

在前端顯示的時候，如果只是用 `moment('2020-02-02T13:00:00+08:00').format('HH:mm')` 的話，在我的電腦上看會是正確的，結果會是 `13:00`，這往往也是 bug 的開端，因為自己看是正確的就覺得是正確的。

若是換了一個時區，假設換到日本好了，那同一段程式碼所產生出的結果就是 `12:00`，就是預期外的結果了。因為要訂的是臺灣的餐廳，所以訂位時間應該都要顯示台灣時間才對，而不是使用者電腦時區的時間。

這時候就要按照上面所說的，用：

``` js
moment('2020-02-02T13:00:00+03:00')
  .tz('Asia/Taipei')
  .format('HH:mm:ss')
```

就能夠保證在日本或在其他地方的使用者，看到的都是用臺灣時區顯示的結果。

## 送時間到後端去

前面講的是後端給你一個時間然後你要正確顯示出來，解法就是上面所說的，加上正確的 method，才能確保是以固定的時區顯示時間。

還有另外一種需要注意的則是相反過來，那就是前端要產生一個 date time 送到後端去。

舉例來說，延續之前餐廳訂位網站的例子好了，假設今天有一個聯絡客服的頁面要填去餐廳的日期，格式是：`2020-12-26` 這樣子，但你送到後端去的資料會是 date time，所以你要把它變成 ISO 8601 的標準格式。

這時候你會怎麼做呢？

有些人會想說，這不就很簡單嗎？原生的方法就是 `new Date('2020-12-26').toISOString()`，如果用其他 library 可能就是：`moment('2020-12-26').format()`。

但其實這是不對的。

假設去的餐廳是在台灣的餐廳，那這個 2020-12-26 就應該是台灣時間，正確的輸出應該要是：`2020-12-26T00:00:00+08:00` 或是 `2020-12-25T16:00:00Z` 之類的，簡單來說就是台灣時間的 12 月 26 號 0 點 0 分。

而上面的程式碼，你有可能產生的是「UTC +0 時區的 0 點 0 分」或者是「使用者電腦時區的 0 點 0 分」，這時候產生出來的 date time 就會是錯誤的，就有了時差。

正確的使用方式跟剛剛差不多，你需要去呼叫 timezone 相關的 method，像是這樣：

``` js
// moment
moment.tz('2020-12-26', 'Asia/Taipei').format()

// dayjs
dayjs.tz('2020-12-26', 'Asia/Taipei').format()
```

才能正確告訴 library 說：「我的這個日期是在台北的日期，而不是在 UTC 也不是在使用者時區」。

## 總結

在處理時間的時候，最常碰到的就是多一天或是少一天的問題，明明就應該顯示 12/26，怎麼使用者看到的是 12/25？而會有這些問題，往往都跟時區有關，沒有正確處理好時區的話就會產生這些問題。

在處理時區上面只要能謹記幾個原則，就可以避免掉這些基本的問題：

1. 前後端都用標準格式的字串溝通
2. 由前端來決定用什麼時區顯示
3. 前端產生 date time 時記得想一下要不要指定時區

不過除了這些之外，我也有想到有些問題滿有趣的，例如說生日，生日感覺就應該直接存成一個字串而不是 date time string。

假設現在有一個大型的跨國網站，然後有個會員系統，註冊的時候要填生日，假設我生日是 2020-12-26 好了，那如果要存成 date time，就會是：`2020-12-26T00:00:00+08:00`。

好，這邊看起來沒什麼問題。

但顯示的話呢？要用什麼時區來顯示？看起來固定用台灣時區來顯示才不會出錯，可是這樣的話，系統也得知道我是台灣人，才能知道要用什麼時區來顯示。但是系統不一定會有這個資訊。

那看起來解法就是兩個，一個是系統直接存 `2020-12-26`，不存 date time 了，前端顯示也直接顯示字串，不要當作時間來解析。另一個則是「儲存跟顯示都用 UTC +0 時區來做」，這樣應該也不會有問題。

處理時間真的不容易，而且在時間上我們常會有許多錯誤的假設，可以參考 [Your Calendrical Fallacy Is...](https://yourcalendricalfallacyis.com/) 跟 [Falsehoods programmers believe about time zones](https://www.zainrizvi.io/blog/falsehoods-programmers-believe-about-time-zones/)，裡面都提到了許多錯誤的認知。

從文章中也可以看出原生的 date 其實已經沒有辦法負荷日常使用了，因此只要是處理時間，基本上大家一定都會找一個 library 來用。目前有一個值得關注的提案叫做 [Temporal](https://github.com/tc39/proposal-temporal)，目前處於 stage2，希望能成為未來 JS 處理日期時間相關的標準。更詳細的介紹可以參考這一篇：[Temporal - Date & Time in JavaScript today!](https://dev.to/romulocintra/temporal-date-time-in-javascript-today-23cb) 或是這個簡報：[Temporal walkthrough](https://docs.google.com/presentation/d/1xP3_UaXlS4-SilVpFu6UFOL8QQw0Dr_VsaR8mSSEATI/edit#slide=id.p)

最後，如果你有用 jest 寫測試，可以在 config 裡面加上 `process.env.TZ = 'Asia/Taipei';` 來指定測試要跑的時區，也可以直接用環境變數帶進去。

我自己習慣的做法是在兩個不同的時區都跑跑看，測試都有過才代表你是真的有寫對，而不只是誤打誤撞才寫對。