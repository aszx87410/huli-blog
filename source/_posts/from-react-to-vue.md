---
title: 從 React 到 Vue 的心得感想
date: 2024-03-13 11:40:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/from-react-to-vue/cover.png
---

如果有看過我的部落格的話，應該會知道我一直都是寫 React，完全沒有碰過 Vue，也沒有碰過 Angular。自從 2015 年接觸到 React 後，工作上就一直是用 React 了。

然而，最近因為工作上的需求，所以開始寫 Vue 了，而剛好也有讀者來問我從 React 跳到 Vue 的心得，因此這邊就簡單寫一篇來分享。

<!-- more -->

## 在開始之前...

雖然說要講從 React 跳到 Vue 的感想，但先讓我偷渡一下對於 Next.js 13.4，也就是 app router 搭配 RSC（React Server Components）的感想。照理來說應該要開另外一篇的，但篇幅不夠長，因此就偷渡在這裡了。

如果沒興趣的話，可以直接跳到下一段。

在目前的公司，React 跟 Vue 都會碰到，而且版本都滿新的，前者是 Next.js 14（剛用的時候是 13.4，第一個有 RSC 的版本），後者則是 Vue3。

因為都用了 Next.js 的最新版本，所以直上 RSC，想來體驗這個 React 未來的重點技術之一，先講結論：「不能只有我受苦，趕快來用」。

（話說如果還不清楚 RSC 是什麼，或是容易跟 SSR 搞混的話，建議可以先看這兩篇文章：[RSC From Scratch. Part 1: Server Components](https://github.com/reactwg/server-components/discussions/5) 以及 [Understanding React Server Components](https://vercel.com/blog/understanding-react-server-components)）

根據 RSC 的設計原則，如果運用得當的話，你的 bundle size 會變小，網站的性能也可能會變好，但我自己用過之後，認為它帶來的效益遠低於引進這項技術所增加的複雜度。

不過先強調一下，因為我用的是 Next.js 的 RSC，不代表所有的 RSC 都是同個樣子，所以這整段講的都會是「Next.js 的 RSC 的使用心得」，而不是「RSC 的使用心得」。

先來講缺點好了。

首先，光是要正確理解 client component 跟 server component 就需要一些時間，可能是嘗試的時間太早，甚至連 Next.js 的官方文件都寫得不是很清楚，需要自己一直不斷嘗試才能試出來到底是什麼樣子（例如說之前前端社群有一篇[貼文](https://www.facebook.com/groups/f2e.tw/posts/6773381989365775/)就在問這個，我當初也有類似的疑惑）。

再來的話，未來在寫 component 的時候都會需要考慮到這個是 client 還是 server 還是都可以，會增加心智負擔。

還有就是許多 server component 可能會直接打 API 去拿資料，因此 client 在拿到資料時，就已經是 render 好的結果了。雖然乍看之下不錯（畢竟是 RSC 的賣點），但這其實會讓前端變得很難 debug。

以前除了第一次的 SSR 以外，我只要打開 DevTools，就可以看到前端發了哪些請求，API 的 response 是什麼，但換成 server component 以後我看不到了，我只能看 server log 才能知道發生了什麼事情。

如果出事的話，我從前端沒辦法區分出是我的 Next.js server 出錯，還是我呼叫的 API 那邊出錯，這點在開發者體驗上扣分許多。

但以上這些其實都還好，最雷的是 Next.js 13.4 的推出有點太趕，要嘛很多功能都沒有做好，要嘛是文件沒有寫清楚。

舉例來說，Next.js 有一個叫做 middleware 的東西，很直覺就會理解成是一個在處理 request 之前會執行到的檔案。但文件沒有寫清楚的是，這個 middleware 跟你其他的程式碼，是跑在不同的執行環境的（現在我記得已經有補上了，Next.js 的改版也滿勤快的就是了）。

也就是說在 middleware 裡面寫一個 `global.a = 1`，你到 Next.js 的 server component 裡面 log 出 `global.a`，答案會是 undefined。

再者，middleware 並不是跑在完整的 Node.js 環境上面，而是跑在一個叫做 [Edge Runtime](https://nextjs.org/docs/app/building-your-application/rendering/edge-and-nodejs-runtimes) 的地方，有許多的功能跟 API 都不支援。

之所以這樣搞，是因為 Next.js 預設了這個 middleware 就是要跑在 edge 上，就算我們根本不會用到 edge 這個功能也一樣，而且目前依然沒辦法改變這點，更多討論可以看這一串：[Switchable Runtime for Middleware (Allow Node.js APIs in Middleware) #46722](https://github.com/vercel/next.js/discussions/46722)。

順帶一提，我目前完全不支持把 Next.js 當一個全端框架來用，也就是前後端專案全都掛在 Next.js 上，理由很簡單，那就是它本來就不適合這樣用。Next.js 它所提供的 server 目前更像是 BFF（Back-end For Front-end），可以當作前端跟其他後端的橋樑，但沒辦法自己實作出完整的功能（除非你的專案很小，功能很少）。

如果真的把後端功能搬到 Next.js 上，那注定是場悲劇。

講完了缺點，來講講優點，那大概就是 bundle size 真的有小一點。例如說 i18n 好了，以往沒有特別做什麼調整的話，大部分的 client 都會下載到「超出目前使用範圍以外」的字串，例如說所有的中文字串，或至少是當前 namespace 底下的字串。

但用了 RSC 以後，由於 server component 的 i18n 在 server 直接做掉了，所以這部分就不需要下載任何額外的字串。

除此之外，其實我沒體驗到太大的好處（而且因為公司專案的一些特性，在搭配上同時有 client 跟 server component 需要考慮，現有的 i18n 套件每一個都有問題，只好自己簡單做了一套）

總之呢，我個人是不太推薦使用 app router 的，帶來的效益遠低於導入的成本，還會把很多事情弄得更複雜。我是從去年七八月就開始用 Next.js 13.4 了，那時候的狀況更糟，文件跟程式碼的行為配對不上的事情也發生過。

如果有人跟我說 Next.js 13.4 以後的 app router 超好用，那我會覺得要嘛是用得不夠多，要嘛是專案很小，所以沒有體驗到壞處，更何況我都還沒講那一堆預設開啟而且有些關不掉的[快取策略](https://nextjs.org/docs/app/building-your-application/caching)。

以上就是偷渡的 Next.js RSC 心得，因為從去年七八月就開始用了，其實剛用的那兩三個月最有感，真的很多點可以吐槽，但現在已經有點忘了，我也害怕想起來。

## 從寫 React 轉去寫 Vue 的感想

話說這篇會盡量寫的是 React 與 Vue 本身的心得，而不是特定的函式庫或框架。

舉例來說，如果我原本在 React 都是用 Redux，轉到 Vue 之後用 Pinia，然後寫說：「哇，寫 Vue 真的太棒了啦，Pinia 好簡潔好好用，比 React 好太多了」，這個論述是有問題的，因為在 React 圈其實也有類似的 zustand 可以用。

所以這一句在比較的主體並不是 Vue 與 React，而是 Redux 與 Pinia，變成了特定函式庫的比較，這是這一篇想要避開的論述。

不過為了補充脈絡，還是先把這些函式庫與框架稍微講一下好了，React 的話目前我的起手式大概就是 Next.js 搭配 Zustand 搭配 tailwind，而 Vue 的話就是 Nuxt 搭配 Pinia 搭配 tailwind。

以使用體驗來說，我覺得兩個是差不多的（如果 Next.js 是 page router 的話），所以這部分就不多提了。

再來，使用的感想會與使用經驗多寡以及應用的專案有差，目前手邊大約有 4 個內部的中小型專案都用到 Vue，我寫 Vue 大概寫了四個月左右，其實也沒有很長，另外因為是內部工具，所以都沒有開啟 SSR，直接走純 client side render。

講完了這些前提以後，接著就來講講使用的感想，先來講我自己比較喜歡 Vue 的地方。

先講一下狀態管理的部分。

首先是 Vue 的雙向綁定真的滿香的，v-model 真的好用。以往在 React 都是 value + onChange 都寫，現在用 v-model 一行就搞定了。

而差異最大的我覺得在於 useEffect。在 React 中需要大量用到 useEffect 去處理一些事情，然後要考慮到 dependency 以及各種狀況，一不小心就可能寫壞。

但是在 Vue 中就沒有這種困擾，省了很多心智負擔，你要寫壞其實滿難的。

而這個特性的差異，也讓我對於專案的技術選擇多了一個思考的維度，那就是「下限」。以前我在思考技術時，比較容易思考到「一般的使用狀況」，像是我寫 React 寫久之後，其實不會特別覺得 useEffect 有什麼，寫得也算是順手。

但同時我也承認 useEffect 是一個需要經驗才能寫好的東西，有一定的學習門檻，這也表示它的下限可以很低。寫得爛的工程師，可以寫一堆 useEffect 然後 dependency 亂寫卻維持一個恐怖平衡，東西剛好可以動。若干年後如果我去接手，我會不知道從何改起，因為只要一往裡面加東西，就是整個壞掉，而且還是多個 effect 一起壞掉。

但我自己覺得 Vue 就不同了，你寫得再怎麼爛也就那樣了。同樣都是一個技術能力很差的人來寫，他所寫的 Vue 會比 React 好維護，我是這麼認為的，這就是我所說的「下限」。

那如果現在有個新的團隊，裡面都是前端超級新手，他們寫的專案你過半年之後要維護，已經可以預期到維護性可能會較差的情況下，選擇下限比較高的 Vue 似乎會比較好，至少你改得動。

而另外一個也是從團隊出發的角度是「上手難度」，如果團隊內的人手比較不足，前後端要互相支援的話，那 Vue 也是個會比 React 更好的選擇，因為更好入門，所以就算不熟悉前端也能夠快速上手。

總之呢，從狀態管理來看的話，我覺得 Vue 更直覺也更好上手一點，而 React 的話確實是比較複雜。

接著來談 render 的方式，React 就是 JSX 一路到底，整個 component 就是一個 function，裡面是 JSX。而 Vue 的話則是把 template 跟 functional 分開，我覺得兩者各有其優劣。

對於一些需要 early return 的狀況，例如說如果是載入中就只顯示 loading，React 我覺得會更加直覺一點，就 component 看個前幾行就知道了。而 Vue 的話則是 setup 的地方看完還要再回去看 template 才能確定。

除此之外，v-if 與 v-for 那些其實滿好用的，而且 template 看起來也比較整齊，在結構沒有相差很多的情況下可讀性比較好。

優點講完了，來講一些缺點。

第一個缺點是在 props 的部分我覺得 React 更加直覺，就是 function 的參數而已，而 Vue 的話則是要額外定義，而且在傳入的時候提倡的是 kebab-case，原本叫做 `testProps` 要改成 `test-props`，我自己不是很喜歡這樣，因為兩者不一致的話會導致搜尋有點困難。

雖然說我看文件也是可以用 `testProps`，但官方文件提倡的作法依然是 `test-props`。

第二個缺點是一個檔案只能有一個 component，我覺得這個滿不彈性的，會容易出現一大堆小的檔案。雖然以前也有人在 React 中提倡這種做法，一個檔案一個 component，但我認為那是不好的，因為有些 component 如果不能被其他元件重用，那就應該放在同個檔案，比較好找也比較好維護。

不過這點似乎也可以解決，我有查到相關的方法：

1. [Multiple Components in One File](https://michaelnthiessen.com/multiple-components-in-one-file)
2. [Writing multiple Vue components in a single file](https://codewithhugo.com/writing-multiple-vue-components-in-a-single-file/)

這樣看下來，好像我上面提的兩個缺點其實都有方法可以解決，純粹是我之前對 Vue 不夠熟所以不知道而已，之後再來試試看。

## 總結

以上就是我對使用 Next.js 13.4 app router + RSC 的心得，以及從寫 React 轉到寫 Vue 的心得。

總之呢，感想大概就是 Vue 確實簡單好上手，但還需要再觀察一陣子，畢竟 code 寫得越多才會越有感覺，像我這種只寫了三四個月的，通常還在甜蜜期，只體驗到好處而非壞處。當寫的程式碼愈多，專案也愈複雜的時候，應該就會遇到一些之前沒碰過的問題。

或許要再寫個一兩年才會有更多心得吧？不知道那時候的前端會長成什麼樣子。
