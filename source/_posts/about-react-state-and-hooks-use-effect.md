---
title: 淺談 React 中的 state 與 useEffect
catalog: true
date: 2020-09-09 19:28:40
tags: [React, Front-end]
categories:
  - React
---

## 前言

最近在臉書上的前端社群看到了一篇文章：[理解 React useEffect 02](https://grandruru.blogspot.com/2020/09/react-useeffect-02.html)，內容是有關於 useEffect 的使用方式，後來在留言串也有了一些[討論](https://www.facebook.com/groups/reactjs.tw/permalink/2723209931287921/)。

其實當初第一眼看到這篇文章的用法，我也是覺得有些奇怪，不過我其實多少能夠理解為什麼是這樣寫，只是還是覺得怪怪的。原本想留言，但是後來覺得「搞不好奇怪的是我」，就想說再思考一下。仔細思考過後，奇怪的還真的是我。

因此這篇來講一下我的想法，有錯的話歡迎在文章底下留言指正，或是在前端社群跟我討論也可以。在繼續閱讀之前，建議先看過上面那篇原文以及原文底下的討論，才會比較進入狀況。

<!-- more -->

## 比較沒有爭論的地方

首先有一個比較沒有爭論的地方，先點出來以後底下就不多談了，那就是原 po 在社團中所說的：

> useEffect 常常被設定在【一定】要搭配 useCallback、useMemo 等 Hook 使用，是【一定】要用嗎？

這個假設不確定是從哪裡聽來的，不過我個人倒是沒有聽過這種說法就是了。useEffect 本來就沒有一定要搭配什麼東西而用。想要理解 useEffect，並不需要他們。

useEffect 的用途就跟它的名字一樣：「拿來處理 side effects」用的。

useEffect 就是 useEffect，它跟其他那些 useCallback 或是 useMemo 並沒有什麼關聯，用途也完全不一樣。

不過我後來想想，會把這幾個搞混，可能跟 useEffect 的 dependencies array 有關吧？不過這就是另外的議題了，總之這幾個是可以完全不用混在一起的。

## 其他這篇文章要處理的部份

整理一下底下的人提的幾個問題：

1. 很少看到 useEffect 裡面做 api call
2. 非同步請求通常會用到 redux 的 middleware
3. 這個範例比較常見的寫法是在 onClick 的時候去呼叫搜尋，如果想要邊打字邊搜尋就是做在 input onChange，而不是原文的用法

第三個其實是我這篇文章特別想提的，前兩個我倒覺得沒什麼問題，而且可以一起回答。

許多非同步的操作會用 redux，並不代表非同步操作一定得用 redux。在有些情境之下，redux 其實是可以不需要用的。

以原 po 的例子來講，他就是要寫個簡單的搜尋功能，為什麼要用 redux？通常會需要用 redux 跟它的 middleware 有幾個原因：

1. 你某些狀態必須讓很多不同的元件存取，所以要放在一個 global 的地方，比較好拿
2. 某些非同步操作流程比較複雜，透過 redux-saga 或是 redux-observable 輔助會讓程式碼的可維護性更好

而這個範例既不是一也不是二，本來就沒有必要用 redux。

再者，在 component 裡面直接呼叫 API 本來就沒有不行，只是會需要處理一些問題，例如說 [race condition](https://overreacted.io/a-complete-guide-to-useeffect/#speaking-of-race-conditions)。

然後像這種拿資料的，有兩個相關的 hook 滿多人用的，一個是 [react-query](https://github.com/tannerlinsley/react-query)，另外一個是 [swr](https://github.com/vercel/swr)，這些也都是直接在 component 裡面呼叫 API。

不過「很少看到 useEffect 裡面做 api call」還有另外一種理解，那就是這指的並不是「在 component 裡面直接呼叫 API」這件事，而是在說比起在 useEffect 裡面直接呼叫，可能會包裝成另一個函式：

``` js
// 第一種寫法：直接寫在裡面
useEffect(() => {
  fetch(...)
})

// 第二種寫法：包成另一個 function
function fetchData() {
 fetch(...)
}

useEffect(() => {
  fetchData()
})
```

那這樣其實就是 code 的結構上面的一些討論而已，這個在範例中我覺得也沒有到這麼重要，不過這跟我們待會要講的第三點有些關係。

## 從實際範例去理解

上面所提到的第三點：「這個範例比較常見的寫法是在 onClick 的時候去呼叫搜尋，如果想要邊打字邊搜尋就是做在 input onChange，而不是原文的用法」，其實是我這篇想討論的重點。

為了更方便大家理解，就要先把範例講清楚，從範例去理解會更快一點。這邊會用一個跟原文不太一樣的範例，我覺得會更幫助理解一點。

這個例子是這樣的，畫面上有一個 input，當你打字的時候會呼叫 hacker news 的 api 搜尋相關主題，然後顯示在畫面上，如圖：

![](/img/useeffect/ui.png)

根據上面的敘述，我們可以很直覺地寫出以下的程式碼：

``` jsx
import React, { useState } from "react";

const baseUrl = "https://hn.algolia.com/api/v1/search?query=";

export default function App() {
  const [data, setData] = useState({ hits: [] });
  const [query, setQuery] = useState("");

  async function fetchData(keyword) {
    const result = await fetch(baseUrl + keyword).then((res) => res.json());
    setData(result);
  }

  const handleChange = (e) => {
    const value = e.target.value;
    setQuery(value);
    fetchData(value);
  };

  return (
    <>
      <input value={query} onChange={handleChange} />
      <ul>
        {data.hits.map((item) => (
          <li key={item.objectID}>
            <a href={item.url}>{item.title}</a>
          </li>
        ))}
      </ul>
    </>
  );
}
```

CodeSandbox 連結：[https://codesandbox.io/s/react-hook-normal-v1-y0l9e](https://codesandbox.io/s/react-hook-normal-v1-y0l9e)

用一個 state 叫做 query 來表示 input 的值，然後加上一個 handleChange 的事件去處理它，在裡面除了去更新 state 以外，也用 fetch 去抓 API 的資料然後 setData，就可以把資料顯示在畫面上。

好，一切都看似非常順利，沒有什麼問題。（實際的狀況會用 debounce 來處理發 request 那一段，但這不是重點所以就不加了）

但今天 PM 突然新增了一個需求：

> input 的預設值應該要是 `redux`，而且畫面一進來就要先去抓這個預設值的資料

此時如果你有寫過 class component，內心想的應該會是：

> 簡單嘛，不就把 query 預設值改成 redux，然後在 componentDidMount 的時候先去呼叫 fetchData 就好了嗎？

於是你就改出了以下程式碼：

``` jsx
import React, { useState, useEffect } from "react";

const baseUrl = "https://hn.algolia.com/api/v1/search?query=";

export default function App() {
  const [data, setData] = useState({ hits: [] });

  // 你改了這個
  const [query, setQuery] = useState("redux");

  async function fetchData(keyword) {
    const result = await fetch(baseUrl + keyword).then((res) => res.json());
    setData(result);
  }

  // 還有加了這個
  useEffect(() => {
    fetchData(query);
  }, []);

  const handleChange = (e) => {
    const value = e.target.value;
    setQuery(value);
    fetchData(value);
  };

  return (
    <>
      <input value={query} onChange={handleChange} />
      <ul>
        {data.hits.map((item) => (
          <li key={item.objectID}>
            <a href={item.url}>{item.title}</a>
          </li>
        ))}
      </ul>
    </>
  );
}

```


不過此時程式碼守門員 ESLint 跳出了一個熟悉的警告：

![](/img/useeffect/eslint.png)

> React Hook useEffect has a missing dependency: 'query'. Either include it or remove the dependency array. (react-hooks/exhaustive-deps)

這是因為 React 認為你在 useEffect 裡面用到了query 這個 dependency，為了怕你拿到舊的值而導致程式出 bug，特別提醒你說記得加上 dependencies。

不過在我們這個範例中，我們的需求的確是第一次 render 時才需要去呼叫 fetchData，所以這行為是沒錯的，因此暫時可以不用管它。

當你改好程式碼跑去找 PM 以後，他有點不好意思地看著你，跟你說：「抱歉，又要加一個新的需求了，老闆最近買了很多特斯拉的股票，所以請加上一個按鈕叫做 tesla，按下按鈕之後就會立刻把 input 的內容改成 tesla，並且搜尋這個關鍵字」

為了滿足老闆的需求，你又馬上改了一版給他：

``` jsx
import React, { useState, useEffect } from "react";

const baseUrl = "https://hn.algolia.com/api/v1/search?query=";

export default function App() {
  const [data, setData] = useState({ hits: [] });
  const [query, setQuery] = useState("redux");

  async function fetchData(keyword) {
    const result = await fetch(baseUrl + keyword).then((res) => res.json());
    setData(result);
  }

  useEffect(() => {
    fetchData(query);
  }, []);

  const handleChange = (e) => {
    const value = e.target.value;
    setQuery(value);
    fetchData(value);
  };

  // 你加上了這個
  const handleClick = () => {
    setQuery("tesla");
    fetchData("tesla");
  };

  return (
    <>
      <input value={query} onChange={handleChange} />
      <button onClick={handleClick}>tesla</button>
      <ul>
        {data.hits.map((item) => (
          <li key={item.objectID}>
            <a href={item.url}>{item.title}</a>
          </li>
        ))}
      </ul>
    </>
  );
}
```

範例程式碼：https://codesandbox.io/s/react-hook-normal-v2-zh7t7?file=/src/App.js

好，程式碼寫到這邊就差不多了，可以進入正題了。

上面的範例中，例如說以下程式碼：

``` js
const handleChange = (e) => {
  const value = e.target.value;
  setQuery(value);
  fetchData(value);
};
```

我們在寫程式的時候是這樣想的：「當使用者輸入的 input 改變的時候，我應該更新 state，然後同時也去呼叫 API」。

``` js
const handleClick = () => {
  setQuery("tesla");
  fetchData("tesla");
};
```

在使用者點擊特斯拉按鈕時，我應該更新 state，然後再去呼叫一次 API，才能抓到最新的資料。

我們思考的點是：「當我做了某個動作之後，應該做什麼事情」。例如說當使用者輸入文字的時候，就應該抓取新的清單；當使用者按下按鈕，就應該去抓 tesla 的資料。

接著讓我來示範另一種寫法：

``` jsx
import React, { useState, useEffect } from "react";

const baseUrl = "https://hn.algolia.com/api/v1/search?query=";

export default function App() {
  const [data, setData] = useState({ hits: [] });
  const [query, setQuery] = useState("redux");

  async function fetchData(keyword) {
    const result = await fetch(baseUrl + keyword).then((res) => res.json());
    setData(result);
  }

  // 只有底下程式碼有變，上面都沒變
  useEffect(() => {
    fetchData(query);
  }, [query]);

  const handleChange = (e) => {
    setQuery(e.target.value);
  };

  const handleClick = () => {
    setQuery("tesla");
  };

  return (
    <>
      <input value={query} onChange={handleChange} />
      <button onClick={handleClick}>tesla</button>
      <ul>
        {data.hits.map((item) => (
          <li key={item.objectID}>
            <a href={item.url}>{item.title}</a>
          </li>
        ))}
      </ul>
    </>
  );
}
```

這個寫法跟我們之前最大的不同，就在於思考的方式完全不一樣。

我們原本思考的點是「當我做了某個動作之後，應該做什麼事情」。

而改成這樣以後，思考的點變成：「當 state 改變時，我要做什麼」，這是很 reactive 的寫法，針對某個變化做出反應。

我先確立了一件事，就是「當 state 改變時，我要去 call API」。因此當使用者輸入文字時，我唯一要做的就是改變 state；當使用者按下按鈕時，我也只要把 state 改成特斯拉就好。

我認為在這個情境底下，最能解釋 useEffect 的意義：

``` js
useEffect(() => {
  fetchData(query);
}, [query]);
```

> 當 query 改變時，我要去執行一個 side effect（fetchData）

這就是 useEffect 的意思：當 dependencies 改變時，我想去執行什麼 side effects。

然後我們程式碼中的 fetchData 其實只有那個 useEffect 會用到，所以可以搬進去，變成：

``` js
useEffect(() => {
  async function fetchData() {
    const result = await fetch(baseUrl + query).then((res) => res.json());
    setData(result);
  }
  fetchData();
}, [query]);
```

改完之後，其實就跟原 po 在文中給的範例很像了。

如果你想要一個專有名詞的話，我會說我們一開始示範的做法叫做 imperative，現在的則叫做 reactive（但專有名詞我真滴不熟，沒有十足把握，用錯請指正）。

還記得 React 的核心理念嗎？UI 只是 state 的一種呈現方式，`UI = F(state)`。因此在畫面改變時，我們不需要去管它怎麼變動的，只需要去改變 state 就可以了。

上面這種 reactive 的寫法我覺得也很類似，我們只需要去改變 state，並且寫明了當 state 改變時，應該要執行哪些動作（side effects）就好，不需要明確針對每個動作去寫出應該做些什麼。

## 回到原文的範例

回到原文的範例，程式碼是這樣寫的：

``` jsx
import React, { useState, useEffect } from "react"
import axios from "axios"
import "./styles.css"

const baseUrl = "https://hn.algolia.com/api/v1/search?query="

export default function App() {
  const [data, setData] = useState({ hits: [] })
  const [query, setQuery] = useState("redux")
  const [url, setUrl] = useState(baseUrl+query)

  useEffect(() => {
    async function fetchData() {
      const result = await axios(url)
      setData(result.data)
    }
    console.log("hi")
    fetchData()
  }, [url])

  return (
    <>
      <input value={query} onChange={ event=>setQuery(event.target.value) } />
      <button onClick={ ()=>setUrl(baseUrl+query) }>Search</button>
      <ul>
        {data.hits.map((item) => (
          <li key={item.objectID}>
            <a href={item.url}>{item.title}</a>
          </li>
        ))}
      </ul>
    </>
  )
}
```

其中最令大家疑惑的一段，應該就是在按下搜尋按鈕時，大多數人會做的其實都是：

``` js
fetchData(baseUrl + query)
```

但是程式碼裡面卻只是：

``` js
setUrl(baseUrl+query)
```

然後再透過 `useEffect` 去呼叫 `fetchData `。

上面的範例，其實就是我剛剛所講的第二種方式。

思考的點在於：「只要 url 這個 state 改變了，我就去 call API 拿資料」，而不是「當使用者按下按鈕時我要 call API」。

這是兩種完全不同的思考方式。

平時在寫程式的時候，比較多人常用的應該都還是第一種，做什麼操作之後除了要改變 state，還要額外做什麼事，比較少人有第二種的概念，但我認為第二種其實才是 React 的精髓之一。

不過實際使用時還是要看使用的情境而定，並沒有說哪一種一定比較好。例如說像是原文的範例，我自己就覺得這情境底下用這個思考模式就是有一點奇怪，可能是因為功能還不夠多（？）

但是以我上面舉的那個邊打文字就要邊送出 API 的範例來說，如果你有注意到的話，會發現我們每次更改 state 以後，都需要再寫一個 fetchData 去拿資料，在這種狀況底下，我覺得第二種確實是更適合的。

最後提一個東西，在 React 的[官方文件](https://reactjs.org/docs/hooks-effect.html#example-using-hooks)當中有這樣一個範例（原本的範例沒有加上 dependencies，但[其他段落](https://reactjs.org/docs/hooks-effect.html#tip-optimizing-performance-by-skipping-effects)有補上去）：

``` jsx
import React, { useState, useEffect } from 'react';

function Example() {
  const [count, setCount] = useState(0);

  useEffect(() => {
    document.title = `You clicked ${count} times`;
  }, [count]);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}
```

這也是 reactive 的寫法，就是我上面一直強調的：「當 state 改變，要執行甚麼 side effect」。

如果你要把它改成另一種寫法，就會長這樣：

``` jsx
import React, { useState, useEffect } from 'react';

function Example() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => {
        document.title = `You clicked ${count + 1} times`;
        setCount(count + 1)
      }}>
        Click me
      </button>
    </div>
  );
}
```


## 總結

其實這篇我想討論的重點並不在 redux，也不在到底要從哪裡去 call API，這些都是其次。

重點是對 useEffect 這個 hook 的理解。

我對它的理解就是：「當 dependencies 改變之後要執行什麼 side effect，就寫在裡面」。

從這點延伸出去，就會有我上面所提的 reactive 的寫法：「當 state 改變以後，我要做些什麼」。

最後呢，有關於這些 hook 的東西，我首推 dan 哥的兩篇文章，寫得真的很讚：

1. [How Are Function Components Different from Classes?](https://overreacted.io/how-are-function-components-different-from-classes/)
2. [A Complete Guide to useEffect](https://overreacted.io/a-complete-guide-to-useeffect/)

這篇記錄了一下我對 useEffect 的理解，有什麼問題都可以再找我討論。

