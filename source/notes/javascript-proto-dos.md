---
layout: note
title: "JS特性變成漏洞"
date: 2025-07-20 13:04:36
---
在寫 code 的時候，大家應該都很討厭奇怪的功能或是特性，比如說 new Date.getMonth 給你一個 6，但其實是 7 月，因為月份從 0 開始。或是 [2,10,3].sort 給你 [10,2,3]，因為是按照字典序而非數字大小來排。但這些大家討厭的特殊之處或語言特性，或許用資安的角度來看就是另外一回事了。

前陣子無意間發現某個每週 400 萬次下載的 JavaScript 套件的 DoS 漏洞，那套件有個產生不重複名稱的功能，例如說輸入是 a,b,a,a，輸出會是 a, b, a_1, a_2，後面加上流水號來區隔。看起來沒什麼問題，在產生新名稱時的核心實作類似於底下這樣：

do {
  newName = `${name}_{count++}`
} while(usedName.has(newName))

usedName 是一個 Set，紀錄已經用過的名稱，然後 count 會一直遞增，直到找到一個新名稱為止。看起來沒什麼問題，但這個 count 如果都從 1 開始不太合理，每次都要重找，所以可以先記起來：

let nameCount = {}
let count = nameCount[name]

找到以後再寫回去 nameCount[name] = count，這樣下次碰到一樣的 key 時，就能直接沿用那個 count。

看起來沒什麼問題，直到 __proto__ 這個我很愛的東西出現為止。在 JavaScript 中，每一個物件都會有些內建的屬性，而 __proto__ 這個內建屬性就指向它的 prototype，也是另一個物件。

假設今天 name 是 __proto__，nameCount["__proto__"] 會是個物件，物件 ++ 以後會是 NaN，所以第一個重複的 key 會被命名為 __proto___NaN。

到這邊只是功能上的問題而已，看起來怪怪的，但無傷大雅。

但是，如果第二個重複的 key 出現會發生什麼事呢？

在上面的 do…while 中，原本預期 count++ 會一直遞增，但由於現在 count 是 NaN，NaN++ 之後還是 NaN，所以 count 永遠不會變。再者，__proto___NaN 這個名稱被用過了，所以 usedName.has(newName) 永遠都是 true。

因此，最終的結果就是一個無窮迴圈，永遠出不來，構成了一個 DoS 漏洞 🎉。

原本想拿個 CVE 但這個套件用的人多歸多，作者沒太多時間維護，沒有開 GitHub security 功能，跟作者溝通後我就自己提 PR 修掉了。

修復的方式也很簡單，原本 nameCount 是個 {}，改成 Object.create(null) 就好，就會是一個乾淨的、沒有內建 __proto__ 屬性的物件，輕鬆解決這個問題。

總之呢，同時身為工程師跟資安愛好者，我可以很清楚意識到在寫 code 累積的那些知識，讓我在資安 code review 或是找漏洞時都帶來了不少幫助。有時發現漏洞這件事可能也只是正常 code review 的 side effect，當你真正理解某段程式碼的運作時，自然而然就能發現其中有缺漏的地方（這概念也是從其他地方看來的，但我忘記出處了）。

而這些的前提，都建立在你擁有知識，知道有這些奇怪特性的存在之上。

如果你想了解更多 JavaScript 的有趣特性，之前提過的[《JavaScript 重修就好》](https://www.tenlong.com.tw/products/9786267757048)在昨天正式上架了，現在[實體書](https://www.books.com.tw/products/0010993971)跟電子書都買得到囉。若是想多理解前端相關資安，今天（7/20）博客來有一日限定的活動，買本 AI 的書再加資安的可以打 66 折，有興趣的可以多多參考。
