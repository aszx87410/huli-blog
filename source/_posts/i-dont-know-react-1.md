---
title: I don't know React（一）
catalog: true
date: 2020-10-31 09:20:32
tags: [React, Front-end]
categories:
  - React
---

## 前言

> 附註：目前這個 blog 對於 JSX 的語法支援有問題，所以看程式碼的時候可能沒那麼容易閱讀，我會盡快再找時間修復。

這個標題致敬了有寫 JavaScript 的人就算沒看過也一定聽過的一系列書籍：Kyle Simpson 寫的 You Don't Know JS（中譯版翻成《你所不知道的 JS》），裡面講了許多很多人不知道的，有關於 JS 的東西。

而 I don't know React 是我對我自己的一系列紀錄，記錄了一些我所不知道的 React，而這些文章都是由我使用 React 的經驗總結而來。這一些我曾經碰到過的錯誤，有可能很基本很常見（官方文件上面就有寫的那種，只是我沒看清楚所以不知道），也有可能比較少見（我可能在工作上寫三四年才碰到）。

換句話說，寫這系列的精神跟 YDKJS 不一樣，前者是想告訴你一些 JS 當中比較少人知道的東西，是一種「我來教你寫 JS」的感覺，而我寫這系列之所以叫做「I don't konw」，是因為想用一系列的文章記錄自己寫 React 曾經有過的誤解或者是沒有注意到的地方，以及正確答案到底是什麼。

我也不知道這系列文會有幾篇，大概就是我每犯下一個就會來 po 個文。這系列有一個我覺得滿大的不同點，就是我會在文章開頭盡可能提供當時犯錯的場景重現，讓大家能有機會在看答案之前自己 debug，看看是否能找出錯誤在哪。我覺得這其實是最精華的部分，這不是什麼制式的面試考題，也不是從網路上隨便找來的 React 測驗，而是我在工作上碰到過的真實的狀況。

因為想要讓大家盡可能融入情境，也去思考我曾經碰過的問題，所以會有不少篇幅在於「定義以及重現問題」，如果你對自己尋找答案沒有興趣，也可以直接跳過這個部分去看解答。但我個人建議是自己先嘗試 debug，去發現問題在哪，才來看文章內的解答，才能完整地吸收文章想表達的東西。

總之呢，讓我們先來看看這一篇要講的案例吧！

<!-- more -->

## 實際案例重現

這次要來 demo 的案例是 Snackbar 這個 component，就是會出現在螢幕下面提示使用者的一個小巧可愛的元件。而我們的任務很簡單，就是要寫出一個 Snackbar 然後讓它可以正常運作就行了，因為這邊重點不在 style，所以我 style 的部分會隨便寫一寫，只是示意而已。

我們可以先寫一個基本的雛形出來，利用 `open` 這個 props 決定透明度，然後可以接受 `children` 的傳入並且 render 出來：

``` js
function Snackbar({ children, open }) {
  return (
    <div
      style={{
        background: "black",
        color: "white",
        transition: "all 0.3s",
        opacity: open ? 1 : 0
      }}
    >
      {children}
    </div>
  );
}
```

當 open 是 true 的時候就會看得到內容，像是這樣：

![](/img/react-1/p1.png)

那為什麼要這樣做呢？因為根據這個透明度的調整，我們可以自己寫另外一個會自動隱藏的 component，藉由 transition 來達成淡入以及淡出的效果：

``` js
const duration = 1000;
const transitionDuration = 300;

function AutoHideSnackbar({ children, onClose }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    setOpen(true);
    const timer = setTimeout(() => {
      setOpen(false);
    }, duration);

    const timer2 = setTimeout(() => {
      onClose();
    }, duration + transitionDuration);
    return () => {
      clearTimeout(timer);
      clearTimeout(timer2);
    };
  }, [onClose]);
  return <Snackbar open={open}>{children}</Snackbar>;
}
```

用的時候需要像這樣使用：

``` js
export default function App() {
  const [open, setOpen] = useState(false);

  const handleClick = () => setOpen(true);
  const handleClose = () => setOpen(false);

  return (
    <div className="App">
      <h1>Snackbar</h1>
      <button onClick={handleClick}>show</button>
      {open && (
        <AutoHideSnackbar onClose={handleClose}>hello~</AutoHideSnackbar>
      )}
    </div>
  );
}
```

當我們點擊按鈕的時候，會把這一層的 open 設定成 true，就會 render `<AutoHideSnackbar>` 這個 component，在 `AutoHideSnackbar` 裡面初始值的 open 是 false，所以會 render `<Snackbar open={false}>hello</Snackbar>`，這時候 Snackbar 透明度就會是 0，處於一個看不見的狀態。

render 並且 mount 以後，執行 `AutoHideSnackbar` 裡面的 useEffect，把 open 設定成 true，這時候 Snackbar 的透明度就會改成 1，因為從 0 變成 1 再加上有 transition，就達成 fade in 的效果，並且設定兩個 timer 來處理自動關閉。

1 秒過後第一個 timer 觸發，把 open 設成 false，再度觸發 transition，有了 fade out 的效果。transition 結束以後第二個 timer 觸發，呼叫 onClose，然後呼叫到了 App 的 handleClose，把 App 那一層的 open 也設定為 false，於是 `AutoHideSnackbar` 就 unmount 了，恢復成原始的樣子。

![](/img/react-1/tb-snackbar-01.gif)

做到這邊，一個會自動隱藏的 Snackbar 就誕生了，但其實還有地方可以再加強。

之前在使用 Ant Design 的時候有個用法深深地影響了我，那就是用 function call 的方式去 render component，而不是用 render 的。例如說你想顯示一個訊息，你可以直接這樣子做：

``` js
import { message } from 'antd'

export default function App() {
  const handleClick = () => {
    message.info("hello~")
  }

  return (
    <div>
      <button onClick={handleClick}>顯示訊息</button>
    </div>
  )
}
```

而不是這樣子（antd 沒有這種用法，只是示範而已）：

``` js
import { Message } from 'antd'

export default function App() {
  const [open, setOpen] = useState(false)
  const handleClick = () => {
    setOpen(true)
  }

  const handleClose = () => {
    setOpen(false)
  }

  return (
    <div>
      <button onClick={handleClick}>顯示訊息</button>
      <Message open={open} onClose={handleClose}>
        hello~
      </Message>
    </div>
  );
}
```

可以看出前者的用法比後者簡潔很多，因為後者必須要自己管理 component 開啟或是關閉的狀況，但前者完全不管這些。雖然說是比較方便沒錯，可是我會說前者「沒有那麼 React」，因為 React 的精神本來就是以 state 為核心，UI 只是 state 的副產物，所以開啟或是關閉的狀況，應該要存在於 state 裡面才對。

但儘管如此，我依然會傾向前者的用法，因為當我們在顯示訊息時，我們其實並不關心他是開啟還是關閉，我們不想知道這件事情，我們唯一想做的只有「顯示訊息」，所以這時候如果像 `alert` 或是 `confirm` 那樣只需要一個 function call，事情會簡單很多。

所以接著我們就來參考 Ant Design 的[原始碼](https://github.com/ant-design/ant-design/blob/481fd209e2fe7935e8b19369ecccb480de171865/components/modal/confirm.tsx)，讓我們的 Snackbar 也擁有這種 static method，可以更方便地顯示訊息。

程式碼會是這樣的：

``` js
Snackbar.show = function (children) {
  const div = document.createElement("div");
  document.body.appendChild(div);
  ReactDOM.render(
    <AutoHideSnackbar
      onClose={() => {
        const unmountResult = ReactDOM.unmountComponentAtNode(div);
        if (unmountResult && div.parentNode) {
          div.parentNode.removeChild(div);
        }
      }}
    >
      {children}
    </AutoHideSnackbar>,
    div
  );
};
```

其實就是在呼叫 function 時動態產生一個 div，然後直接使用 `ReactDOM.render` 把 AutoHideSnackbar render 上去，自動消失時再把 div 拿掉。透過這樣子的方式，就可以脫離原本的 React App，新建一個 React App 去 render Snackbar。

而且因為我們接收的參數 children 沒有限制，所以要顯示圖片也是可以的，像是這樣：

``` js
import React from "react";
import { Snackbar } from "./Snackbar";
import styled from "styled-components";
import warningSvg from "./icon.svg";
import SVG from "react-inlinesvg";

const Warning = styled(SVG).attrs({
  src: warningSvg
})`
  width: 24px;
  height: 24px;
`;

export default function App() {
  const showSnackbar = () => {
    Snackbar.show(
      <div>
        hey! <Warning />
      </div>
    );
  };
  return (
    <div className="App">
      <h1>Snackbar</h1>
      <p>靜態方式顯示 snackbar</p>
      <button onClick={showSnackbar}>顯示</button>
    </div>
  );
}
```

顯示的結果：

![](/img/react-1/tb-snackbar-02.gif)

好，這一切的一切看起來都十分完美，現在我們終於可以用一個簡單的 function call 就顯示出東西了，再也不用去維護那些麻煩的狀態...

直到你擦亮眼睛一看，發現了一件奇怪的事情，那就是你的 Snackbar 在使用 static method 那個方法的時候，fade in 居然消失了！你仔細看上面的 gif，就可以看出只有 fade out 的效果，沒有 fade in。

這就是我之前碰過的一個 bug，也就是這一篇的主角。

底下是可以完整重現這個 bug 以及上面所做的 component 的 CodeSandbox，推薦大家可以自己 fork 回去改改看，看能不能找出 bug 在哪裡，以及 root cause 到底是什麼，訓練一下自己 debug 的能力。

CodeSandbox: https://codesandbox.io/s/snackbar-debug-test-kw7iv?file=/src/App.js

接著提醒一件事情，上面的程式碼是真的會有 bug，至於我上面所說的一些有關於成因的判斷，不一定是正確的。這是我當初剛碰到這個 bug 時的第一判斷，有可能正確也有可能錯誤，現在你手中有可以完整重現問題的程式碼了，可以自己利用各種方式找出問題到底在哪裡。

底下我會先回憶一次自己當初是如何 debug 的，講完以後會開始講答案是什麼，如果想自己 debug 的人請勿往下繼續看，會被雷到。

防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    
防雷分隔線~    

## 我是怎麼 debug 的？

既然問題是出在 static method 那個用法，那我想說就朝這方向去研究好了。我做的第一件事情很簡單，就是先把每個 component 的 render 跟 useEffect 都加上 `console.log`，根據 log 出來的東西跟自己的想法對照，看看有沒有執行順序上跟我認知中不同的地方。

經過一段時間的嘗試，發現好像沒有什麼差別，不管用哪一個方法，都跟我認識的執行流程一樣。第一次 render `AutoHideSnackbar` 的時候 open 一定是 0，所以一開始一定是看不到的，接著 useEffect 完下一次 render 會變成 1，所以透明度會變成 1，因此會有個 fade in 的效果。

但最終會看到這樣的結果，fade in 的 transition 消失了，就代表出現在畫面上的時候，open 應該就是 1 了，否則不會看到這樣的結果。

debug 一陣子沒什麼頭緒之後，我開始懷疑起是不是因為某些非同步或是 React 的渲染機制，導致第一次 render 時 open 就是 true，所以我加了個 rAF，讓 open 屬性 delay 一下才變成 true：

``` js
export function AutoHideSnackbar({ children, onClose }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    // 原本是直接 setOpen(true)，我包了 rAF 在外面
    window.requestAnimationFrame(() => setOpen(true));
    const timer = setTimeout(() => {
      setOpen(false);
    }, duration);

    const timer2 = setTimeout(() => {
      onClose();
    }, duration + transitionDuration);
    return () => {
      clearTimeout(timer);
      clearTimeout(timer2);
    };
  }, [onClose]);
  return <Snackbar open={open}>{children}</Snackbar>;
}
```

加了之後發現就沒問題了，可以成功看到 fade in 的效果。不過儘管如此，我還是不知道原本為什麼會這樣。

接著我重新再測試了一遍，發現一件很嚴重的事情！

我並沒有把實驗的變因處理好，我一直以為是我用那個比較 tricky 的方法導致這個問題，所以一直往這個方向去找答案，去看 static method 到底跟一般的 render 有什麼不同，卻忽略了我上面的範例中，一般的 render 跟 static 的 render，還有一個變因不同，那就是「有沒有 render SVG」，我把 staic method 範例中的 SVG 拿掉，發現居然有 fade in 的效果了！

哇操，我前面花了兩三個小時都是在做白工找錯方向，而是還是因為自己漏看，沒有定義好問題範圍所導致的。知道這一點之後，進度就快多了。

我先把 `react-inlinesvg` 這套件換成普通的 img，發現一樣可以正常運作，而原本一般的 render 方式，加上了 `react-inlinesvg` 淡入效果也會消失。因此原因差不多可以確定了，就是 `react-inlinesvg` 這個 library 造成的。

但到底是為什麼呢？我去看了一下它的原始碼，看不到什麼可疑的東西。在沒有其他方法的情況之下，我用了最暴力但是也最有效的一招：「改 node_modules 裡面的程式碼」。這其實就跟我慣用的 debug 方式一樣，當你束手無策，完全不知道問題出在哪的時候，就開始刪 code。

刪掉一段發現問題還在，就代表那段 code 不是兇手。刪掉了某段 code 問題就不見之後，你就知道一定跟那段 code 有關了，有點像是對程式碼進行二分搜的感覺。如果熟悉執行流程的話做起來其實還滿快的，就一直刪 code 就好了。不過對 third party 做這件事麻煩的點在於你必須直接去改 node_modules 裡面的程式碼，那些程式碼都是經過 bable transpiled 過後的，可讀性會比較低，不過還是能看懂就是了。

經過這一段刪刪改改之後，我終於發現了出問題的地方，在這裡：https://github.com/gilbarbara/react-inlinesvg/blob/v2.1.1/src/index.tsx#L209

SVG 這個 component 在 componentDidMount 的時候會去呼叫 `this.load()`，而 `this.load` 裡面會去呼叫 `this.setState()`，經過我幾次測試之後發現把 `this.setState()` 註解掉就沒事了，因此可以推斷問題應該是出在這邊。

接著我突然想起以前好像在官方文件中看過在 componentDidMount 裡面 setState 會有一些什麼事情發生，於是就去 Google `componentDidMount setState`，找到了很多相關的範例。

為了確保沒找錯地方，我自己寫了一個簡單的 component，並且在 componentDidMount 裡面加上 `this.setState`，再讓 Snackbar 去 render 它，果真重現出了一樣的問題，那就是 fade in 消失了。

程式碼會像是這樣：

``` js
class Comp extends React.Component {
  componentDidMount() {
    this.setState({
      a: 1
    });
  }

  render() {
    return <div>hello</div>;
  }
}

// render 的時候
<AutoHideSnackbar onClose={handleClose}>
    <Comp />
</AutoHideSnackbar>
```

經歷過重重難關，問題的成因總算找到了，那就是在 componentDidMount 裡面 setState，會導致一些預期外的後果。

可是這預期外的後果到底是什麼呢？

## 看看官方文件怎麼說

只要用 `componentdidmount setstate` 這個很直白的關鍵字就可以找到許多資料，像是我以前也看過的：[一些自己寫 React 的好習慣- lifecycle method 跟 state 管理](https://medium.com/@as790726/%E4%B8%80%E4%BA%9B%E8%87%AA%E5%B7%B1%E5%AF%AB-react-%E7%9A%84%E5%A5%BD%E7%BF%92%E6%85%A3-lifecycle-method-%E8%B7%9F-state-%E7%AE%A1%E7%90%86-b37a12da968b)，或是這次文章的主軸：[官方文件](https://reactjs.org/docs/react-component.html#componentdidmount)。

文件裡面是這樣寫的：

> You may call setState() immediately in componentDidMount(). It will trigger an extra rendering, but it will happen before the browser updates the screen. This guarantees that even though the render() will be called twice in this case, the user won’t see the intermediate state.

在 setState 裡面如果同步去呼叫 componentDidMount，會立刻觸發第二次 render，而且會在瀏覽器更新畫面之前，因此第一次 render 的結果使用者並不會看到，只會顯示第二次的。

這就能解釋為什麼我們的淡入功能會壞掉了。

先假設我們程式碼長這樣（[CodeSandbox 範例](https://codesandbox.io/s/setstate-in-componentdidmount-4ncr8?file=/src/App.js)）：

``` js
class Comp extends React.Component {
  componentDidMount() {
    console.log("Comp componentDidMount");
    this.setState({
      a: 1
    });
  }

  render() {
    console.log("Comp render");
    return <div>hello</div>;
  }
}

export function Snackbar({ children, open }) {
  console.log("Snackbar render:", { open });
  return (
    <div
      style={{
        background: "black",
        color: "white",
        transition: "all 0.3s",
        opacity: open ? 1 : 0
      }}
    >
      {children}
    </div>
  );
}

export function AutoHideSnackbar({ children, onClose }) {
  const [open, setOpen] = useState(false);
  console.log("AutoHideSnackbar render:", { open });
  useEffect(() => {
    console.log("AutoHideSnackbar useEffect");
    setOpen(true);
    const timer = setTimeout(() => {
      setOpen(false);
    }, duration);

    const timer2 = setTimeout(() => {
      onClose();
    }, duration + transitionDuration);
    return () => {
      clearTimeout(timer);
      clearTimeout(timer2);
    };
  }, [onClose]);
  return <Snackbar open={open}>{children}</Snackbar>;
}
```

我們可以藉由觀察 log，來判斷出執行順序，而 log 的結果是這樣的：

1. AutoHideSnackbar render: {open: false}
2. Snackbar render: {open: false}
3. Comp render 
4. Comp componentDidMount 
5. AutoHideSnackbar useEffect 
6. AutoHideSnackbar render: {open: true}
7. Snackbar render: {open: true}
8. Comp render 

可以看出總共有兩次 render，第一次的話是：

1. AutoHideSnackbar render: {open: false}
2. Snackbar render: {open: false}
3. Comp render 
4. Comp componentDidMount 
5. AutoHideSnackbar useEffect 

在第一次 render 的時候，Snackbar 的 open 是 false 所以 opacity 是 0，接著 render 它的 children 也就是 Comp，render 完成以後 Comp 的 componentDidMount 執行 setState，因為在這邊執行了，所以根據文件所說，使用者不會看到第一次 render 的結果。

而 Comp 的 didMount 以後，就往上執行 AutoHideSnackbar 的 useEffect，這邊會把 open 設成 true。

這邊值得注意的一點是 React 的官網中[寫著](https://reactjs.org/docs/hooks-reference.html#useeffect)：

> The function passed to useEffect will run after the render is committed to the screen.

看起來「after the render is committed to the screen」這個行為大部分情況都是對的，useEffect 會在 browser 更新畫面之後才執行（`render is committed to the screen` 應該可以這樣理解吧？）。

但如果底下的元素有 class component 而且在 componentDidMount 裡面做了同步的 setState，就不會是這樣子了？不能確保執行 useEffect 的時候使用者已經看到上次 render 的畫面。

總之這邊執行完以後，就會執行第二次的 render：

1. AutoHideSnackbar render: {open: true}
2. Snackbar render: {open: true}
3. Comp render 

第二次的 render 中 opacity 會是 1，而根據官方文件所說的，使用者不會看到第一次 render 的結果，所以畫面上第一次出現時 opacity 就是 1 了，淡入的效果自然也就不見了。

## 後記

儘管理解了上面那個行為，我當初還是有一點想不透，那就是既然 componentDidMount 代表有把東西放到 DOM 上面了，使用者不就一定會看到嗎？那是怎麼做到「既 mount 卻又不讓使用者看到結果」的？

後來去了推特上面[發問](https://twitter.com/aszx87410/status/1304234775398416385)，感謝陳冠霖的回答，直接突破盲點：

> DOM 的更新跟畫面的更新是兩回事，pixel pipeline 要等 js 全部跑完才會做渲染的動作，舉個例子就是你用個 for loop 跑很多次 DOM update 但是畫面只會畫最後的結果

看完之後我才想到，對欸，更新 DOM 跟更新畫面是兩回事，DOM 更新了不代表 browser 就會 paint，所以的確可以做到在一個 cycle 裡面更新兩次 DOM，這樣第一個的結果就不會顯示在畫面上，只會顯示第二次的。

其實在碰到這些 React 的問題前，我一直以為自己對 React 或是對於 DOM 的運作都有一定程度的認識，可是卻屢屢遭受打擊，發現自己還是遺漏了許多重要的部分，寫一寫都會有：「我居然對 React 這麼陌生嗎QQ」的感嘆。

不過也是沒有辦法的事，反正碰到了不會的就學起來，碰到的問題多了之後，也會知道更多的解決方法，就會對這些運作機制愈來愈了解了。

以上就是 I don't know React 的第一篇，當初花了一個早上的時間還跑去問同事，一開始一直糾結於是 static 的那種方式造成問題，整個走錯方向，直到某一刻突然開竅發現差別其實不是在那個，而是在 render 的東西不一樣。

Debug 一旦有正確抓到問題的成因，通常離找到解法就不遠了，也更能知道怎麼下關鍵字去搜尋。因為這次的經驗也提醒了我自己，debug 的時候記得把不相干的東西排除乾淨，才能真正確認問題的根源。


