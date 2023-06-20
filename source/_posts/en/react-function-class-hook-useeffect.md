---
title: Differences between class and function components from practical examples
date: 2020-06-15 22:19:37
tags: [Front-end,React]
categories:
  - React
---

## Introduction

To learn something new, it's not very useful to just read about it. The best way is to get your hands dirty and start doing it. Since React hooks had just come out when I was about to leave my previous job, I had never written hooks before, only seen some basic tutorials. But after starting my new job, I finally started writing function components + hooks.

Although I initially missed the class syntax, I found hooks to be quite good after writing them for a while. In the process of using hooks, I also encountered some common problems that people who are new to them often face. After careful study, I found that the case I want to discuss in this article is quite good. If you can understand this case, you should be able to grasp the fundamental differences between class and function components. Therefore, I wrote this article to record my experience.

By the way, if you have been writing function components for a while, are quite used to hooks, and have read the official documentation and Dan Abramov's articles carefully, you probably won't gain any new knowledge from this article. This article is suitable for those who have just switched to function components and are not sure what the differences are between them and class components.

<!-- more -->

## Practical example

This case is what I encountered when integrating [Google reCAPTCHA](https://developers.google.com/recaptcha), so let me first talk about integrating reCAPTCHA.

I believe that most people are familiar with reCAPTCHA because it is quite common on the Internet. There are currently two versions, v2 and v3, and v2 also has several different types, one of which is called the checkbox version, which is the one we see most often that asks you to check the "I'm not a robot" box:

![](https://static.coderbridge.com/img/aszx87410/2004360581674cf3ae8d223b9ee2b2f5.png)

The integration method is very simple. First, you must load the reCAPTCHA script:

``` js
<script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit"
    async defer>
</script>
```

The `onload` parameter needs to be passed the name of the callback function, which will be called after the script is loaded. `render=explicit` tells it that we want to call the code ourselves to render that box (the other implicit method can put attributes in the html element in the form of `data-xxx`, allowing Google to render that box itself).

After the script is loaded, the callback function you provided will be called, and there will be a global variable `grecaptcha` that you can use. Then you can use:

``` js
grecaptcha.render('html_element', {
    sitekey : 'your_site_key',
    callback: function(token) {
      console.log(token)
    }
  });
};
```

to turn `html_element` into the box that displays reCAPTCHA, and get the token through the callback function passed in when the user clicks.

Here I have made a small example: [codepen](https://codepen.io/aszx87410/pen/ExPKRdO?editors=1010), and the interface looks like this:

![](https://static.coderbridge.com/img/aszx87410/cea36c0cdd044637b14ef3c079a3ca2d.png)

The code is actually very simple:

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

Okay, this reCAPTCHA is our protagonist today. After introducing how to use it, let's take a look at how to implement it in React.

## React implementation: Class component version

When adding a new component, I always think about one thing first, which is how I want to use it. This is very important because it will determine what the component looks like.

If there is a reCAPTCHA component, I would like to use it like this:

``` jsx
<ReCAPTCHA sitekey={siteKey} onChange={onChange} />
```

This component should be able to:

1. Automatically load the required script for us
2. Automatically generate a checkbox element
3. When the user checks it, pass the token back through onChange

Let's implement this component! The complete code will look like this:

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

In `componentDidMount`, we check if `grecaptcha` exists. If it doesn't, we load it. If it does, we call `this.handleLoad` and handle the rendering-related issues inside. The loading part dynamically generates a script tag and inserts it into the document, so we don't have to manually import the script into the HTML, which is much more convenient. The `handleLoad` part is just calling `grecaptcha.render` as written above:

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

After completing this component, render it on the upper level and pass in an `onChange` callback function. The interface will look like this:

![](https://static.coderbridge.com/img/aszx87410/6176df0e2eea4593bbc35439c83a38a6.png)

The complete code will look like this:

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

Here is the complete codesandbox demo: https://codesandbox.io/s/practical-rgb-r785j?file=/src/App.js (Note: this component actually has some unresolved issues, but since the focus is not on writing the reCAPTCHA library, we won't mention them too much.)

The key point of this component is actually that we check whether the script has been loaded completely in `componentDidMount`. If not, we load it first, and then execute `window.grecaptcha.render` after loading is complete. The `window.grecaptcha.render` function will only be called once. Unless the component is unmounted and then remounted, `window.grecaptcha.render` will be called again.

In fact, if you want to call `window.grecaptcha.render` a second time on the same element (`this.divRef`), it is not possible and an error message will pop up: `Uncaught Error: reCAPTCHA has already been rendered in this element`, which tells you that the component has already been rendered.

This article is actually related to this behavior, because this component cannot be rendered again, so our focus is: "`window.grecaptcha.render` can only be called once, and once the callback function is set, it cannot be changed."

After understanding this key point, reCAPTCHA can actually exit the stage. Because the appearance of "reCAPTCHA" in this article is only because of this behavior. We can actually simulate this behavior ourselves and rewrite it into a function:

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

The interface looks like this:

![](https://static.coderbridge.com/img/aszx87410/fdcf848f290e4ed9ba5de4569d3924cc.png)

The example code that can run is here: https://codesandbox.io/s/simulate-grecaptcha-5z90f

It's just a simple simulation of reCAPTCHA's behavior. Our focus is only: "`grecaptcha.render` can only be called once."

## The protagonist appears: React hook

After laying out so much of reCAPTCHA's behavior and class component implementation, it's finally time for React hook to appear. Let's directly rewrite the above example using hooks:

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

The code becomes much cleaner. React hook is awesome!

Currently, we are just following the logic of the previous class component. In `componentDidMount`, we execute `handleLoad`, and then call `grecaptcha.render` inside `handleLoad` and set the callback function to be handled by `handleCallback`, and finally pass the token back through `props.onChange`.

When we try it out, we find that the functionality is completely fine. Here is the complete code: https://codesandbox.io/s/simulate-grecaptcha-react-hook-kxerd?file=/src/App.js:391-714

But... is it really okay?

At first glance, it seems like this, but actually it's not. This is the real point that this article wants to make.

You can think about what the problem might be and continue reading. If you have already figured it out and know how to solve it, congratulations, you have a certain level of familiarity with hooks.

## The Real Problem

The previous sections introduced the use of reCAPTCHA and the fact that "`grecaptcha.render` can only be called once, so the binding of the callback function can only be done once." This is related to an important issue that this article wants to raise, which is:

> What happens if the `onChange` prop is changed?

You might say, "Oh? If it's changed, it's changed. What's the problem?"

I'll provide a simple example:

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

This example will determine which function to pass based on the `isOld` state. By default, it passes `oldFunction`. After clicking the button, `isOld` is set to `false`, so it passes `newFunction`. You can see which function is called in the console. Now let's try the example of the hook after modifying it:

![](https://static.coderbridge.com/img/aszx87410/82ce45b832234064894f7fc4a170b241.gif)

Is it the same as you thought? Even though we changed the `onChange` prop to the new function, why is the old one still being called? I'll provide the complete code for you to think about:

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

Runnable example: https://codesandbox.io/s/simulate-grecaptcha-react-hook-change-props-chl50?file=/src/App.js

While you're thinking about it, let's take a look at the previous class component. Does it have this problem?

![](https://static.coderbridge.com/img/aszx87410/cf6d199aec7a4d7d8c0a1f1398179213.gif)

No, it works perfectly.

(Complete code: https://codesandbox.io/s/change-props-onchange-jkm1n?file=/src/App.js)

But why does the hook have a problem while the class component doesn't? Didn't we use the same logic to rewrite them?

Let's take a closer look at how the class component works. First, take a look at this important code that simulates it:

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

When calling `grecaptcha.render`, we bind the callback function to `this.handleCallback`, and this function calls `this.props.onChange(token)`. Therefore, it can always call the latest `onChange` event in the props without any problems.

What about the hook?

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

After the element is first rendered, `useEffect` inside `handleLoad` is executed, which binds the callback to `handleCallback`. Then it calls `onChange` in the props. It seems fine, right?

No, the problem is much bigger.

The biggest difference between a function and a class component is that "a function component remembers the values passed in at that moment." This may sound a bit difficult to understand, but as long as you have a good mental model, I believe there is no problem. You need to remember one thing, that is:

> Every time a function component is rendered, the function is "re-called."

It may sound a bit redundant, but the key is the word "re-called." If you think about it in this way, you can understand the key points of function components. Let's take another look at the process above. I have included a number for each step, so please read it according to the number:

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

When the user clicks "change function," the process is as follows:

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

There are several key points here:

1. The `handleCallback` in the first render and the `handleCallback` in the second render are two completely different functions, not the same one.
2. Therefore, you are binding the first `handleCallback`, so only the first one will be executed, and the `onChange` in the first one is `oldFunction`.
3. Therefore, even if you change `onChange`, only the second `handleCallback` will execute the new `newFunction`, but the callback you bound is the first `handleCallback`.

The key here is that the "function in the first render" and the "function in the second render" are completely different things. When using hooks, there is an eslint prompt that reminds you to add a dependency array when using useEffect or useCallback, in order to get the latest value.

Actually, when writing the above hook code, eslint prompted us, so let's fix it according to what it said:

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

It looks like there is no problem, all the dependencies have been fixed, and we can ensure that `handleCallback` always calls the latest onChange event. Let's try it out:

![](https://static.coderbridge.com/img/aszx87410/47ed0b7274e24a039c283c9898a1fdd8.gif)

Oops, it's not working.

When we change onChange, handleCallback will also change, and then the useEffect section will also be executed again, so `grecaptcha.render` will be called twice, resulting in this error. Do you remember that I emphasized this earlier? The reason why this problem is more troublesome is that `grecaptcha.render` can only be called once, so this modification will not work.

Next, I will give you a small test. You can try to open this codesandbox and modify it to see if you can get it right: https://codesandbox.io/s/react-hook-change-props-fix-gi10h?file=/src/App.js

The standard for getting it right is:

1. When you click "click me if you are not robot", the console will print the old function.
2. Clicking "change function" will not cause an error.
3. When you click "click me if you are not robot" again, the console will print the new function.

If you achieve these three points, you have succeeded.

I strongly recommend that you try it out on codesandbox immediately, because if you don't try it out, you may not feel much from the example below. But if you have tried it, you will deeply understand. If you have tried for a while and still haven't succeeded, you can continue to read the following paragraph, maybe you will find your mistake.

## Why doesn't your solution work?

First of all, `handleLoad` can only be called once, so the dependency array in useEffect is definitely an empty array, which is not a problem. And what you need to think about is how to change the callback passed in and `handleCallback`.

### Attempt 1

You may have tried this solution, directly changing the dependency of useEffect to an empty array, and leaving everything else unchanged:

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

It looks reasonable. When onChange changes, I change my handleCallback, and make sure that I can call the latest onChange inside it. Then every time grecaptcha changes, it will call the function I passed in, which is handleCallback, which is very reasonable.

No, you have ignored the mental model emphasized earlier:

> Every time a function component is rendered, the function is "re-called" once.

I will write the execution order for you to see, please read it in order:

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

Or this picture may be easier to understand:

![](https://static.coderbridge.com/img/aszx87410/7ca5607102a544e4b5095b5f5ab153bd.png)

Each render is a re-call of the function. Your first function call will create a handleCallback, and when props.onChange changes, a new handleCallback will be created, which has the same name but is a different function.

### Attempt 2

As mentioned earlier, the biggest problem is that "different functions will be generated when onChange changes", so there must be something "unchanging".

At this point, you may have a sudden inspiration and think: Isn't this the time for useRef?

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

Pass `handleCallback.current` to the callback, so that `handleCallback.current` will be called every time you click, and then I will change `handleCallback.current` in useEffect along with onChange. It looks very reasonable.

No, it's still unreasonable. Please see the picture below:

![](https://static.coderbridge.com/img/aszx87410/6a1e7bfa64a04bcc997235aa493acd71.png)

This is actually a "reassignment" problem. Let's first consider `handleCallback.current` as a variable A. In the first render, we set the callback to A at line 13. Then in the second render, we execute: `handleCallback.current = newFunction`, which means `A = newFunction`. We have reassigned A, but the original binding to the callback is still the original A and will not change just because you have reassigned A.

## Attempt Three

At this point, you may think that since the problem seems to be with directly attaching `handleCallback.current` to the callback, why not declare another function:

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

Every time you click, it will call `handleCallback` and then call `cbRef.current()`. Whenever `onChange` changes, I will change `cbRef.current`, which is perfect.

Yes, you did it! And `handleCallback` can actually be wrapped in `useCallback`, so that a new `handleCallback` is not generated every time it is rendered.

Or even better, you don't even need to declare a function, just use an arrow function:

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

The final code looks like this, and you can play with it yourself: https://codesandbox.io/s/react-hook-change-props-solution-ll8os?file=/src/App.js

## Review and Reflection

After going through so many rounds, we finally found a solution. But why didn't I encounter this problem when I was writing class components before? Because we can always use `this.props.onChange` to get the latest properties.

But function components are not like this. Each render is a function call, and the props passed in will be the "current" props, and will not change because the props change. This is the biggest difference between function components and class components.

I used to not really understand what Dan meant when he said, "Only by abandoning class components can you truly understand hooks." But now I understand. When writing class components before, you would think about what to do in each lifecycle, such as "what to do in didMount" and "what to do when updating". But the focus of hooks is on "every render".

Class components think in terms of class instances, while hooks think in terms of functions. When writing classes before, you only knew that the `render` method would be executed every time, and other lifecycles would not.

But function components are "every render will execute the entire function again", which is very different. Finally, I emphasize this point again:

> Every render of a function component is a new function call.

## Summary

Although React hooks seem easy to get started with and have less code, I think the case I mentioned today does not make hooks easier to use in practice, and to some extent, it makes it easier for beginners to write bugs. Or more precisely, the places where bugs occur are different.

When writing classes before, the first obstacle for beginners was understanding `this`, and the second obstacle was that `props` and `state` always got the "latest" instead of the original. The obstacle of function components is closure. If you don't have the correct mental model, it's easy to get lost in hooks, after all, writing class components and function components are really different.

I originally thought that switching from class to function was just a different way of writing, but I didn't expect to change the entire thinking mode, and I sincerely admire the members of the React team, who have brought new things to the front-end field time and time again.

I highly recommend reading Dan's article on the differences between function components and class components. It's really great. You can start with this one: [How Are Function Components Different from Classes?](https://overreacted.io/how-are-function-components-different-from-classes/) to understand the differences, and then read this one: [A Complete Guide to useEffect](https://overreacted.io/a-complete-guide-to-useeffect/) to understand `useEffect`. After reading it, you will have a better understanding of the example I mentioned in this article, and you may even think, "Hey? What are you talking about? Isn't this very basic?"

The article is almost finished here, and there happens to be a practical case to share while learning hooks.

Finally, special thanks to the front-end colleagues at [Onedegree](https://www.yourator.co/companies/AIFinancialTechnology) for discussing this issue with me.
