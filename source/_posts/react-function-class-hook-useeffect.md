---
title: 從實際案例看 class 與 function component 的差異
date: 2020-06-15 22:19:37
tags: [Front-end,React]
categories:
  - React
---

## 前言

要學習一個新的東西，光用看的還真的沒什麼用，直接動手下去做才是比較好的方法。因為上一份工作快離職時 React hook 才剛出來，所以我之前從來沒寫過 hook，只有看過一些基本的教學而已。而前陣子開始工作之後，才終於開始寫 function component + hook。

雖然剛開始還是滿懷念 class 的寫法，但寫久之後覺得 hook 也挺不錯的。在使用 hook 的過程中也有碰到一些剛轉換的人常碰到的問題，仔細研究後發現這篇文章要提的案例還滿不錯的，如果能夠理解這個案例，應該就可以掌握到 class 與 function component 根本上的不同，因此寫了這篇來記錄一下心得。

話說如果你已經寫 function component 一陣子，hook 也用得滿習慣的，而且都有把官方文件還有 dan 哥的文章好好看過，基本上不會從這篇文章獲得任何新知識。這篇適合的對象是剛轉換到 function component，而且不太確定跟 class 的差異是什麼的人。

<!-- more -->

## 實際案例

這個案例是我在串接 [Google reCAPTCHA](https://developers.google.com/recaptcha) 的時候所碰到的，所以讓我先來順便講一下 reCAPTCHA 的串接。

相信大家應該都對 reCAPTCHA 不陌生，因為在網路上滿常看到的。目前有分成兩個版本，v2 跟 v3，然後 v2 也有分幾個不同的型態，其中有一個叫做 checkbox 的版本，就是我們最常見的那個要你勾選「我不是機器人」的框框：

![](https://static.coderbridge.com/img/aszx87410/2004360581674cf3ae8d223b9ee2b2f5.png)

串接方法很簡單，首先你必須載入 reCAPTCHA 的 script：

``` js
<script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit"
    async defer>
</script>
```

onload 這個參數需要傳給他 callback function 的名稱，在 script 載入完成以後會呼叫。而 `render=explicit` 則是告訴他說我們要自己呼叫程式碼去 render 出那個框框（另外一種 implicit 可以透過 `data-xxx` 這種形式把屬性放在 html 元素，讓 Google 自己去渲染出那個框框）。

當 script 載入完成以後，會去呼叫你提供的 callback function，也會多一個全域變數 `grecaptcha` 可以使用，再來你就可以用：

``` js
grecaptcha.render('html_element', {
    sitekey : 'your_site_key',
    callback: function(token) {
      console.log(token)
    }
  });
};
```

把 `html_element` 變成顯示 reCAPTCHA 的框框，並且在使用者點選時透過傳入的 callback function 拿到 token。

這邊我有做了一個小範例：[codepen](https://codepen.io/aszx87410/pen/ExPKRdO?editors=1010)，畫面長得像這樣：

![](https://static.coderbridge.com/img/aszx87410/cea36c0cdd044637b14ef3c079a3ca2d.png)

程式碼其實很簡單：

```
<div id="robot"></div>
Your token:
<div id="token"></div>
```

``` js
window.onloadCallback = function() {
  grecaptcha.render(document.querySelector('#robot'), {
    // test site key from https://developers.google.com/recaptcha/docs/faq
    sitekey : '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
    callback: function(token) {
      document.querySelector('#token').innerText = token
    }
  });
};
```

好，這個 reCAPTCHA 就是我們今天的主角。在介紹完使用方法以後，我們來看一下在 React 裡應該要怎麼來實作。

## React 實作：Class component 版

在新增一個 component 的時候，我會先思考一件事，那就是我想要怎麼用它。這點非常重要，因為會決定這個元件長什麼樣子。

如果有一個 reCAPTCHA 的元件，我會希望能這樣用：

``` jsx
<ReCAPTCHA sitekey={siteKey} onChange={onChange} />
```

這個 component 應該要能做到：

1. 自動幫我們載入需要的 script
2. 自動產生一個 checkbox 的元素
3. 當使用者打勾時，透過 onChange 把 token 傳回來

接著就讓我們來實作這個 component 吧！完整的程式碼會長這樣：

``` jsx
class ReCAPTCHA extends React.Component {
  constructor(props) {
    super(props);
    this.divRef = React.createRef();
    this.callbackName = "__recaptcha__cb";
  }

  componentDidMount() {
    // 檢查是否已經載入完成
    if (!window.grecaptcha) {
      return this.init();
    }
    this.handleLoad();
  }
  
  // 負責來執行 callback function
  handleCallback = token => {
    this.props.onChange(token);
  };

  handleLoad = () => {
    // 載入完成，渲染元素
    const { sitekey } = this.props;
    window.grecaptcha.render(this.divRef.current, {
      sitekey,
      callback: this.handleCallback
    });
  };

  init = () => {
    window[this.callbackName] = this.handleLoad;
    const script = document.createElement("script");
    script.src = `https://www.google.com/recaptcha/api.js?onload=${
      this.callbackName
    }&render=explicit`;
    script.async = true;
    document.body.appendChild(script);
  };

  render() {
    return <div ref={this.divRef} />;
  }
}
```

在 `componentDidMount` 的時候我們去檢查是不是已經有 `grecaptcha` 的存在，沒有的話就載入，有的話就直接呼叫 `this.handleLoad`，並且在裡面處理 render 的相關事項。而載入的部分則是動態產生 script 標籤插入到 document 裡面，我們就不用自己在 HTML 手動把 script 引入，方便很多。而 `handleLoad` 的地方其實就只是呼叫上面有寫過的 `grecaptcha.render` 而已：

``` jsx
handleLoad = () => {
  // 載入完成，渲染元素
  const { sitekey } = this.props;
  window.grecaptcha.render(this.divRef.current, {
    sitekey,
    callback: this.handleCallback
  });
};
```

做完這個 component 之後，上層去 render 它，然後傳入一個 onChange 的 callback function，最後介面會長這樣：

![](https://static.coderbridge.com/img/aszx87410/6176df0e2eea4593bbc35439c83a38a6.png)

完整程式碼會長這樣：

``` jsx
import React, { useState } from "react";

class ReCAPTCHA extends React.Component {
  constructor(props) {
    super(props);
    this.divRef = React.createRef();
    this.callbackName = "__recaptcha__cb";
  }

  componentDidMount() {
    // 檢查是否已經載入完成
    if (!window.grecaptcha) {
      return this.init();
    }
    this.handleLoad();
  }

  handleCallback = token => {
    this.props.onChange(token);
  };

  handleLoad = () => {
    // 載入完成，渲染元素
    const { sitekey } = this.props;
    window.grecaptcha.render(this.divRef.current, {
      sitekey,
      callback: this.handleCallback
    });
  };

  init = () => {
    window[this.callbackName] = this.handleLoad;
    const script = document.createElement("script");
    script.src = `https://www.google.com/recaptcha/api.js?onload=${
      this.callbackName
    }&render=explicit`;
    script.async = true;
    document.body.appendChild(script);
  };

  render() {
    return <div ref={this.divRef} />;
  }
}

const sitekey = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";
export default function App() {
  const [token, setToken] = useState("");
  return (
    <div className="App">
      <ReCAPTCHA sitekey={sitekey} onChange={setToken} />
      <h2>Token</h2>
      <p>{token}</p>
    </div>
  );
}
```

這邊有完整的 codesandbox demo：https://codesandbox.io/s/practical-rgb-r785j?file=/src/App.js （備註：這個 component 其實有些問題沒有解掉，但因為重點不在撰寫 reCAPTCHA library，所以就不多提了）

這個 component 其實有一個重點，那就是在 `componentDidMount` 的時候我們去檢查 script 是不是已經載入完畢，沒有的話就先載入，載入完成以後執行 `window.grecaptcha.render`。而 `window.grecaptcha.render` 這個 function 只會被呼叫一次而已。除非 component 被 unmount 然後再被 mount，才會再呼叫一次 `window.grecaptcha.render`。

而事實上如果你想在「同一個元素（this.divRef）」身上呼叫第二次 `window.grecaptcha.render` 也是不行的，會跳出一個錯誤提示：`Uncaught Error: reCAPTCHA has already been rendered in this element`，跟你說這個元件已經被 render 過了。

而這篇文章其實就跟這個行為有關，因為這個元件不能再被 render 一次，所以我們的重點是：「`window.grecaptcha.render` 只能呼叫一次，而且一旦設定好 callback function，就不能改變了」。

理解這個重點以後，reCAPTCHA 其實就可以退場了。因為這篇會出現 `reCAPTCHA`，就只是因為它的這個行為而已。我們其實可以自己模擬一次這個行為，然後改寫成一個 function：

``` jsx
import React, { useState } from "react";

let isCalled = false;
const grecaptcha = {
  render: function(element, { callback }) {
    if (isCalled) throw new Error("You can only call me once");
    isCalled = true;
    element.innerText = "click me if you are not robot";
    element.addEventListener("click", function() {
      callback("you got token!");
    });
  }
};

class ReCAPTCHA extends React.Component {
  constructor(props) {
    super(props);
    this.divRef = React.createRef();
  }

  componentDidMount() {
    this.handleLoad();
  }

  handleCallback = token => {
    this.props.onChange(token);
  };

  handleLoad = () => {
    grecaptcha.render(this.divRef.current, {
      callback: this.handleCallback
    });
  };

  render() {
    return <div ref={this.divRef} />;
  }
}

export default function App() {
  const [token, setToken] = useState("");
  return (
    <div className="App">
      <ReCAPTCHA onChange={setToken} />
      <h2>Token</h2>
      <p>{token}</p>
    </div>
  );
}
```

介面長這樣：

![](https://static.coderbridge.com/img/aszx87410/fdcf848f290e4ed9ba5de4569d3924cc.png)

可以動的範例程式碼在這：https://codesandbox.io/s/simulate-grecaptcha-5z90f

其實就是自己簡單模擬 reCAPTCHA 的行為而已，我們的重點只有：「`grecaptcha.render` 只能被呼叫一遍」。

## 主角登場：React hook

前面鋪陳了這麼多 reCAPTCHA 的行為以及 class component 的實作，現在終於輪到 React hook 登場了，接著就讓我們直接把上面的範例改成用 hook 來做：

``` jsx
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();
  const handleCallback = token => {
    onChange(token);
  };
  const handleLoad = () => {
    grecaptcha.render(divRef.current, {
      callback: handleCallback
    });
  };

  useEffect(() => {
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};
```

程式碼變得清爽好多，React hook 讚讚讚！

目前我們就只是照著之前 class component 的邏輯來改寫而已，在 `componentDidMount` 的時候執行 `handleLoad`，然後 `handleLoad` 裡面去呼叫 `grecaptcha.render` 並且設置 callback function，交由 `handleCallback` 來處理，最後再透過 `props.onChange` 把 token 傳回去。

試了一下，會發現功能完全沒有問題。這邊是完整程式碼：https://codesandbox.io/s/simulate-grecaptcha-react-hook-kxerd?file=/src/App.js:391-714

可是...真的沒問題嗎？

乍看之下是這樣，可是其實不然，這樣寫是有問題的，而這就是這篇文章真正要講的重點。

大家可以自己想想看會有什麼問題，再接著往下看。如果你看到這邊已經想到了，而且也知道怎麼解了，那代表你對 hook 有一定的熟悉程度，恭喜恭喜。

## 真正的問題

前面花了很多篇幅在介紹 reCAPTCHA 的使用以及「 `grecaptcha.render` 只能被呼叫一遍，所以 callback function 的綁定只能進行一遍」這件事情，因為這跟這篇文章要提出的一個重要問題有關，這個問題就是：

> 如果 props 的 onChange 換了，會發生什麼事？

你可能會想說：「咦？換掉就換掉啊，會怎樣嗎？」

我提供一個簡單的範例：

``` jsx
export default function App() {
  const [isOld, setIsOld] = useState(true);
  const oldFunction = () => console.log("old function");
  const newFunction = () => console.log("new function");

  return (
    <div className="App">
      <ReCAPTCHA onChange={isOld ? oldFunction : newFunction} />
      <button
        onClick={() => {
          console.log("Switch to new function");
          setIsOld(false);
        }}
      >
        change function
      </button>
    </div>
  );
}
```

這個範例會根據 state isOld 來決定傳入哪一個 function，預設傳入 oldFunction，點擊按鈕之後會把 isOld 設定成 false，就會傳入 newFunction，然後從 console 就可以看出來，最後被呼叫的到底是哪一個 function，我們改成這樣以後來試試看上面 hook 的範例：

![](https://static.coderbridge.com/img/aszx87410/82ce45b832234064894f7fc4a170b241.gif)

跟你想的一樣嗎？我們明明就把 onChange 這個 props 換成了新的 function，為什麼被呼叫到的還是舊的？我這邊附上完整程式碼讓大家想一下：

``` js
import React, { useState, useRef, useEffect } from "react";

let isCalled = false;
const grecaptcha = {
  render: function(element, { callback }) {
    if (isCalled) throw new Error("You can only call me once");
    isCalled = true;
    element.innerText = "click me if you are not robot";
    element.addEventListener("click", function() {
      callback("you got token!");
    });
  }
};

const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();
  const handleCallback = token => {
    onChange(token);
  };
  const handleLoad = () => {
    grecaptcha.render(divRef.current, {
      callback: handleCallback
    });
  };

  useEffect(() => {
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};

export default function App() {
  const [isOld, setIsOld] = useState(true);
  const oldFunction = () => console.log("old function");
  const newFunction = () => console.log("new function");

  return (
    <div className="App">
      <ReCAPTCHA onChange={isOld ? oldFunction : newFunction} />
      <button
        onClick={() => {
          console.log("Switch to new function");
          setIsOld(false);
        }}
      >
        change function
      </button>
    </div>
  );
}
```

可以跑的範例：https://codesandbox.io/s/simulate-grecaptcha-react-hook-change-props-chl50?file=/src/App.js

大家在邊想的同時，我們可以邊來看之前的 class component，它會有這個問題嗎？

![](https://static.coderbridge.com/img/aszx87410/cf6d199aec7a4d7d8c0a1f1398179213.gif)

不會，運作地十分良好。

（一樣附上完整程式碼：https://codesandbox.io/s/change-props-onchange-jkm1n?file=/src/App.js）

可是為什麼 hook 會有問題，class 就不會？我們不是用同樣的邏輯來改寫的嗎？

我們來細看一下 class 的運作，自己先看這段重點程式碼模擬一遍：

``` js
handleCallback = token => {
  this.props.onChange(token);
};

handleLoad = () => {
  grecaptcha.render(this.divRef.current, {
    callback: this.handleCallback
  });
};
```

在呼叫 `grecaptcha.render` 時，我們把 callback function 綁定到 `this.handleCallback`，而這個 function 會呼叫 `this.props.onChange(token)`，所以一定可以呼叫到最新的 props 裡面的 onChange 事件，完全沒有問題。

那 hook 呢？

``` js
const handleCallback = token => {
  onChange(token);
};
const handleLoad = () => {
  grecaptcha.render(divRef.current, {
    callback: handleCallback
  });
};

useEffect(() => {
  handleLoad();
}, []);
```

在元素第一次 render 完以後會去執行 `useEffect` 裡面的 `handleLoad`，而裡面會把 callback 綁定到 `handleCallback`，在裡面再去呼叫 `onChange` 這個 props，看起來也沒問題啊？

不，問題可大了。

function 跟 class component 最大的差異，就在於：「function component 會記住當下傳入的值」。這點或許聽起來有點難體會，但只要你把 mental model 建立好我相信就沒問題。你要牢記一件事，那就是：

> Function component 的每一次 render，都是「重新」呼叫一次 function

聽起來有點廢話，但重點是「重新」這兩個字，以這個方式去思考，你就能理解 function component 的重點。我們用這個方式再重新看一遍上面的流程，底下我有附上每一個步驟的編號，請按照編號閱讀：

``` js
// 1. 第一次 render，onChange = oldFunction
// 2. 呼叫 ReCAPTCHA({ onChange: oldFunction })
// 3. 這邊的 onChange 會等於 oldFunction（這是重點，畫三顆星星必考）
const ReCAPTCHA = ({ onChange }) => {
  // 4. 建立 ref
  const divRef = useRef();

  // 5. 建立函式 handleCallback
  // 11. 當 callback 被觸發時，呼叫 onChange（oldFunction）
  // 這是重點，畫五顆星星必考
  const handleCallback = token => {
    onChange(token);
  };

  // 6. 建立函式 handleLoad
  // 10. 執行 handleLoad，把 callback 綁定到 handleCallback
  const handleLoad = () => {
    grecaptcha.render(divRef.current, {
      callback: handleCallback
    });
  };

  // 7. 宣告 useEffect
  // 9. render 完畢，執行 handleLoad
  useEffect(() => {
    handleLoad();
  }, []);

  // 8. render
  return <div ref={divRef} />;
};
```

當使用者點擊「change function」之後，流程是這樣的：

``` js
// 1. 第二次 render，onChange = newFunction
// 2. 呼叫 ReCAPTCHA({ onChange: newFunction })
// 3. 這邊的 onChange 會等於 newFunction
const ReCAPTCHA = ({ onChange }) => {
  // 4. 建立 ref
  const divRef = useRef();

  // 5. 建立函式 handleCallback
  const handleCallback = token => {
    onChange(token);
  };

  // 6. 建立函式 handleLoad
  const handleLoad = () => {
    grecaptcha.render(divRef.current, {
      callback: handleCallback
    });
  };

  // 7. 宣告 useEffect
  // 9. render 完畢，但因為不是第一次，所以不會執行 handleLoad
  useEffect(() => {
    handleLoad();
  }, []);

  // 8. render
  return <div ref={divRef} />;
};
```

這裡的重點有幾個：

1. 第一次 render 裡的 `handleCallback` 跟第二次裡的 `handleCallback`，是兩個完全不同的 function，不是同一個
2. 因此你綁定的是第一次的 `handleCallback`，就只會執行第一次的，而且第一次的 onChange 是 oldFunction
3. 所以儘管你改變了 onChange，只有第二次的 `handleCallback` 會執行到新的 newFunction，但你綁定的 callback 是第一次的 `handleCallback`

這邊的關鍵在於：「第一次 render 裡的 function」跟「第二次 render 裡的 function」已經是完全不同的東西了。在使用 hook 時，有個 eslint 的提示會一直提醒你使用 useEffect 或是 useCallback 的時候要加上的 dependency array，就是為了要讓你能夠獲取到最新的值。

其實在寫上面那段 hook 的程式碼時，eslint 就有跳提醒了，那我們按照它講的來修修看：

``` js
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();

  // 當 onChange 改變時，就會產生新的 handleCallback
  const handleCallback = useCallback(
    token => {
      onChange(token);
    },
    [onChange]
  );  

  // 當 handleCallback 改變時，就會重新呼叫
  useEffect(() => {
    const handleLoad = () => {
      grecaptcha.render(divRef.current, {
        callback: handleCallback
      });
    };
    handleLoad();
  }, [handleCallback]);

  return <div ref={divRef} />;
};
```

看起來好像沒什麼問題，有把 dependency 都修好，就能確保 `handleCallback` 呼叫到的一定是最新的 onChange 事件，馬上來試試看：

![](https://static.coderbridge.com/img/aszx87410/47ed0b7274e24a039c283c9898a1fdd8.gif)

完了，怎麼出錯了。

當我們 onChange 改變時，handleCallback 就會跟著變，然後連帶的 useEffect 那一段也會重新執行，所以 `grecaptcha.render` 就被呼叫了兩遍，就跳出了這個錯誤。還記得我前面特別強調這點嗎？這個問題之所以比較麻煩，就是因為 `grecaptcha.render` 只能呼叫一遍，所以我們這樣改是行不通的。

接著給大家一個小考驗，大家可以自己試試看開這個 codesandbox 來改，看看能不能改對：https://codesandbox.io/s/react-hook-change-props-fix-gi10h?file=/src/App.js

改對的標準是：

1. 按下「click me if you are not robot」時，console 會印出 old function
2. 按下「change function」不會出錯
3. 再按「click me if you are not robot」時，console 會印出 new function

有達成這三點，你就成功了。

強烈建議大家立刻點開 codesandbox 去試試看，因為沒有試的話，看下面的範例你可能會沒什麼感覺。但如果你有試過，就會深有同感。若是你試了一段時間還是沒成功，可以接著看下面的段落，或許會發現你的錯誤解法。

## 為什麼你的解法行不通？

首先呢，`handleLoad` 一定只能呼叫一次，所以 useEffect 放的 dependency array 絕對是空陣列，這個沒有問題。而你要思考的就是怎麼樣去改傳入的 callback 以及 `handleCallback`。

### 嘗試一

你可能試過這種解法，直接把 useEffect 的依賴改成空陣列，然後其他不動：

``` js
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();

  // 當 onChange 改變時，就會產生新的 handleCallback
  const handleCallback = useCallback(
    token => {
      onChange(token);
    },
    [onChange]
  );

  useEffect(() => {
    const handleLoad = () => {
      grecaptcha.render(divRef.current, {
        callback: handleCallback
      });
    };
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};
```

看起來好像很合理，onChange 變的時候我就改變我的 handleCallback，確認可以在裡面呼叫到最新的 onChange，然後每一次 grecaptcha 改變時都會呼叫到我傳入的 function，也就是 handleCallback，十分合理。

不，你又忽略了前面強調的 mental model：

> Function component 的每一次 render，都是「重新」呼叫一次 function

我寫一遍執行順序給你看，記得按照順序看：

``` js
// 1. 第一次執行，呼叫 ReCAPTCHA({ onChange: oldFunction })
// 5. 第二次執行，呼叫 ReCAPTCHA({ onChange: newFunction })
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();

  // 2. 第一次執行，產生 handleCallback1
  // 6. 第二次執行，產生 handleCallback2
  // 8. 當 grecaptcha 的 callback 觸發時，會呼叫到的是 handleCallback1
  // 而 handleCallback1 裡的 onChange 是 oldFunction
  // 因為在建立 handleCallback1 時，傳入的 onChange 是 oldFunction
  const handleCallback = useCallback(
    token => {
      onChange(token);
    },
    [onChange]
  );

  // 3. 第一次 render，執行這個 function
  // 4. 把 grecaptcha 的 callback 設成 handleCallback1
  // 7. 第二次 render，不執行這一段
  useEffect(() => {
    const handleLoad = () => {
      grecaptcha.render(divRef.current, {
        callback: handleCallback
      });
    };
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};
```

或是看這張圖片可能比較容易理解：

![](https://static.coderbridge.com/img/aszx87410/7ca5607102a544e4b5095b5f5ab153bd.png)

每一次 render 就是重新呼叫一次 function，你第一次的 function call 會建立一個 handleCallback，當 props.onChange 改變以後，又會建立一個新的 handleCallback，這兩個同名，但是卻是不同的 function。

### 嘗試二

前面說過最大的問題是「當 onChange 改變時會產生不同的 function」，所以想要解決這個問題，就必須有某個「不會變動的東西」。

此時你可能會靈機一動，想說：那這種情況是不是就是 useRef 登場的時候了？

``` jsx
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();
  const handleCallback = useRef(onChange);

  // 當 onChange 改變時，去改變 handleCallback.current
  useEffect(() => {
    handleCallback.current = onChange
  }, [onChange])

  useEffect(() => {
    const handleLoad = () => {
      grecaptcha.render(divRef.current, {
        callback: handleCallback.current
      });
    };
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};
```

把 `handleCallback.current` 傳給 callback，所以每次點擊時都會呼叫到 `handleCallback.current`，然後我在 useEffect 裡面再去隨著 onChange 更改 `handleCallback.current`，看起來十分合理。

不，還是不合理，請看底下的圖：

![](https://static.coderbridge.com/img/aszx87410/6a1e7bfa64a04bcc997235aa493acd71.png)

這其實是一個「重新賦值」的問題，我們先把 `handleCallback.current` 看成是一個變數 A 好了，我們在第一次 render 的時候，在 13 行把 callback 設成 A，然後在二次的 render 的時候，我們執行：`handleCallback.current = newFunction`，也就是 `A = newFunction`，我們把 A 重新賦值了，可是原本綁定到 callback 去的還是原本的 A，不會因為你把 A 重新賦值就改變。

## 嘗試三

這時你可能會想說，那既然問題好像是出在直接把 `handleCallback.current` 掛在 callback 上面，那我再宣告一個 function 不就好了嗎：

``` js
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();
  const cbRef = useRef(onChange);

  const handleCallback = () => {
    cbRef.current()
  } 

  useEffect(() => {
    cbRef.current = onChange
  }, [onChange])

  useEffect(() => {
    const handleLoad = () => {
      grecaptcha.render(divRef.current, {
        callback: handleCallback
      });
    };
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};
```

每次點擊時都會去呼叫 `handleCallback`，然後在裡面呼叫 `cbRef.current()`，每當 onChange 改變時，我就去改變 `cbRef.current`，根本完美。

沒錯，你成功了！而且 `handleCallback` 其實可以用 useCallback 包起來，就不會每一次 render 時都產生一個新的 `handleCallback`。

或甚至是你其實根本不需要宣告一個 function，直接用箭頭函式就行了：

``` js
const ReCAPTCHA = ({ onChange }) => {
  const divRef = useRef();
  const cbRef = useRef(onChange);

  useEffect(() => {
    cbRef.current = onChange
  }, [onChange])

  useEffect(() => {
    const handleLoad = () => {
      grecaptcha.render(divRef.current, {
        callback: () => {
          cbRef.current()
        }
      });
    };
    handleLoad();
  }, []);

  return <div ref={divRef} />;
};
```

最後的程式碼長這樣，大家可以自己玩玩看：https://codesandbox.io/s/react-hook-change-props-solution-ll8os?file=/src/App.js

## 回顧與思考

在兜了這麼多圈之後，終於找到了解法。可是為什麼以前寫 class component 的時候，從來沒有碰過這個問題？因為我們隨時都可以用 `this.props.onChange` 拿到最新的屬性。

可是 function component 並不是這樣的，每一次 render 就是一次 function call，而傳進來的 props 就會是「當時」的 props，不會因為 props 改變而改變。這個就是 function component 與 class component 最大的差別。

原本我一直不是很理解之前 dan 哥說的：「唯有拋下 class component，你才能真正理解 hook」是什麼意思，但我現在懂了。以前在 class component 時你會以那些 lifecycle 去思考，去想說「didMount 要做什麼」、「update 的時候要做什麼」，但 hook 的重點會放在「每一次 render」。

class component 是以 class 的 instance 為主體去思考，而 hook 是以 function 為主體去思考。以前在寫 class 的時候，你只會知道 render 這個 method 是每一次 render 都會執行到，其他的 lifecycle 不會。

但是 function component 就是「每一次 render 都會把整個 function 重新執行一遍」，是很不一樣的。最後再強調一次這點：

> function component 的每一次渲染，都是一個新的 function call

## 總結

雖然說 React hook 看起來容易上手，程式碼也比較少，但我認為今天特地提的這個案例，並沒有讓 hook 在實戰的使用上變得更簡單，某種程度上反而更容易讓新手寫出 bug。或者更精確地說，會出 bug 的地方不一樣。

以前在寫 class 的時候，新手的第一個障礙是 this 的理解，第二個障礙是 props 與 state 永遠會拿到「最新的」而不是當時的。而 function 的障礙就是 closure，如果沒有正確的 mental model，很容易就會在 hook 裡面迷失，畢竟寫 class 跟寫 function component 真的完全不一樣。

原本我以為只是從 class 換到 functoon 只是換一種寫法，沒想到連整個思考模式都換了，衷心佩服 React 團隊的成員，一次次帶給前端這個領域一些全新的東西。

關於 function component 與 class component 的差異，誠心推薦大家去讀 dan 哥的文章，寫的真的很讚，可以先看這一篇：[How Are Function Components Different from Classes?](https://overreacted.io/how-are-function-components-different-from-classes/) 來理解差別，然後再看這篇：[A Complete Guide to useEffect](https://overreacted.io/a-complete-guide-to-useeffect/) 來了解 useEffect，看完之後再來看我文章提到的這個例子會更有感覺，而且可能會覺得：「咦？你這篇在寫什麼廢話，這不是很基本嗎」

這篇文章就差不多到這邊結束了，剛好在學習 hook 的過程中有一個實戰案例可以分享。

最後，特別感謝 [Onedegree](https://www.yourator.co/companies/AIFinancialTechnology) 的前端同事們跟我一起討論這個問題。