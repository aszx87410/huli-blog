---
title: A Discussion on state and useEffect in React
catalog: true
date: 2020-09-09 19:28:40
tags: [React, Front-end]
categories:
  - React
photos: /img/about-react-state-and-hooks-use-effect/cover-en.png
---

## Introduction

Recently, I came across an article on the front-end community on Facebook: [Understanding React useEffect 02](https://grandruru.blogspot.com/2020/09/react-useeffect-02.html), which discusses the usage of useEffect. There was also some [discussion](https://www.facebook.com/groups/reactjs.tw/permalink/2723209931287921/) in the comments section. 

Initially, I found the usage in the article a bit strange, but I could somewhat understand why it was written that way. However, I still found it odd. I wanted to leave a comment, but then I thought, "Maybe I'm the one who's mistaken," so I decided to think about it some more. After careful consideration, I realized that I was the one who was mistaken.

Therefore, in this post, I will share my thoughts. If there are any mistakes, please feel free to leave a comment below or discuss it with me in the front-end community. Before continuing to read, I recommend reading the original article and the discussion below it to better understand the context.

<!-- more -->

## Areas with Little Controversy

Firstly, there is an area with little controversy that I want to point out, which is what the original post said in the community:

> useEffect is often set to be used with useCallback, useMemo, and other Hooks. Is it necessary to use them?

I'm not sure where this assumption came from, but I personally have never heard of such a statement. useEffect does not necessarily have to be used with anything. To understand useEffect, you don't need them.

The purpose of useEffect is just like its name: "to handle side effects."

useEffect is useEffect, and it has no relation to useCallback or useMemo. Their purposes are completely different.

However, I later thought that the reason why these Hooks might be confused with useEffect is probably related to the dependencies array of useEffect. But this is another issue, and these Hooks can be used separately.

## Other Parts to be Addressed in this Article

Let's summarize the questions raised by people below:

1. It is rare to see api calls being made inside useEffect.
2. Asynchronous requests are usually handled with redux middleware.
3. The more common way to write this example is to call the search function on onClick. If you want to search while typing, you should do it on input onChange, not in the way described in the original article.

The third point is actually what I want to emphasize in this post. I don't think there is much of a problem with the first two points, and they can be answered together.

Many asynchronous operations are handled with redux, but that doesn't mean that asynchronous operations must always use redux. In some situations, redux is not necessary.

In the example given by the original post, he just wants to write a simple search function. Why use redux? There are several reasons why you might need to use redux and its middleware:

1. You need to access certain states from many different components, so it's better to put them in a global place.
2. Some asynchronous operation flows are more complicated, and using redux-saga or redux-observable can make the code more maintainable.

However, this example is neither one nor the other, so there is no need to use redux.

Furthermore, calling the API directly inside the component is not impossible, but it requires handling some issues, such as [race conditions](https://overreacted.io/a-complete-guide-to-useeffect/#speaking-of-race-conditions).

For data retrieval like this, there are two related Hooks that many people use: [react-query](https://github.com/tannerlinsley/react-query) and [swr](https://github.com/vercel/swr), both of which call the API directly inside the component.

However, "It is rare to see api calls being made inside useEffect" can also be interpreted as not directly calling the API inside useEffect, but wrapping it in another function:

``` js
// first way of coding
useEffect(() => {
  fetch(...)
})

// second way of coding
function fetchData() {
 fetch(...)
}

useEffect(() => {
  fetchData()
})
```

This is just a discussion about the structure of the code, and I don't think it's that important in this example. However, this is related to the third point we will discuss later.

## Understanding through Practical Examples

The third point mentioned above, "The more common way to write this example is to call the search function on onClick. If you want to search while typing, you should do it on input onChange, not in the way described in the original article," is actually the main point I want to discuss in this post.

In order to make it easier for everyone to understand, let's first explain the example. Understanding from the example will be faster. Here is a slightly different example, which I think will help you understand better.

The example is as follows: there is an input on the screen, and when you type, it will call the hacker news API to search for related topics and display them on the screen, as shown in the figure:

![](/img/useeffect/ui.png)

According to the above description, we can write the following code very intuitively:

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

CodeSandbox link: [https://codesandbox.io/s/react-hook-normal-v1-y0l9e](https://codesandbox.io/s/react-hook-normal-v1-y0l9e)

Use a state called `query` to represent the value of the input, and then add a `handleChange` event to handle it. In addition to updating the state, use `fetch` to fetch the API data and then `setData`, and the data can be displayed on the screen.

Okay, everything seems to be going smoothly, and there are no problems. (In actual situations, `debounce` is used to handle the request sending part, but this is not the focus, so it is not added.)

But today, the PM suddenly added a new requirement:

> The default value of the input should be `redux`, and the data of this default value should be fetched when the page is loaded.

If you have written class components before, you might think:

> It's simple, just change the default value of `query` to `redux`, and then call `fetchData` in `componentDidMount`, right?

So you changed the code to the following:

``` jsx
import React, { useState, useEffect } from "react";

const baseUrl = "https://hn.algolia.com/api/v1/search?query=";

export default function App() {
  const [data, setData] = useState({ hits: [] });

  // You updated this
  const [query, setQuery] = useState("redux");

  async function fetchData(keyword) {
    const result = await fetch(baseUrl + keyword).then((res) => res.json());
    setData(result);
  }

  // and this
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

However, at this time, the code gatekeeper ESLint raised a familiar warning:

![](/img/useeffect/eslint.png)

> React Hook useEffect has a missing dependency: 'query'. Either include it or remove the dependency array. (react-hooks/exhaustive-deps)

This is because React thinks that you are using the `query` dependency in `useEffect`. To prevent you from getting the old value and causing bugs in the program, it reminds you to remember to add dependencies.

However, in our example, our requirement is indeed to call `fetchData` only when the page is first rendered, so this behavior is correct, so you can temporarily ignore it.

When you go to find the PM after changing the code, he looks at you a little embarrassed and says, "Sorry, there is a new requirement again. The boss has bought a lot of Tesla's stocks recently, so please add a button called `tesla`. After clicking the button, the content of the input will be changed to `tesla`, and this keyword will be searched."

To meet the boss's requirements, you immediately made another version for him:

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

  // You added this
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

Example code: https://codesandbox.io/s/react-hook-normal-v2-zh7t7?file=/src/App.js

Okay, the code is almost done, let's get to the point.

In the above example, for example, the following code:

``` js
const handleChange = (e) => {
  const value = e.target.value;
  setQuery(value);
  fetchData(value);
};
```

When we write code, we think like this: "When the user changes the input, I should update the state and call the API at the same time."

``` js
const handleClick = () => {
  setQuery("tesla");
  fetchData("tesla");
};
```

When the user clicks the Tesla button, I should update the state and then call the API again to get the latest data.

The point we are thinking about is: "What should I do after I have done something?" For example, when the user enters text, a new list should be fetched; when the user clicks a button, Tesla's data should be fetched.

Next, let me demonstrate another way of writing:

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

  // only the code below changed
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

The biggest difference between this writing and our previous one is that the way of thinking is completely different.

The point we originally thought about was "What should I do after I have done something?"

After changing to this way, the point of thinking becomes: "What should I do when the state changes?" This is a very reactive way of writing, responding to a certain change.

I first established one thing, that is, "when the state changes, I need to call the API." Therefore, when the user enters text, the only thing I need to do is to change the state; when the user clicks the button, I only need to change the state to Tesla.

I think in this context, it can best explain the meaning of `useEffect`:

``` js
useEffect(() => {
  fetchData(query);
}, [query]);
```

> When the query changes, I want to execute a side effect (fetchData).

This is the meaning of useEffect: when the dependencies change, I want to execute some side effects.

Then, the fetchData in our code is only used by that useEffect, so we can move it inside, like this:

``` js
useEffect(() => {
  async function fetchData() {
    const result = await fetch(baseUrl + query).then((res) => res.json());
    setData(result);
  }
  fetchData();
}, [query]);
```

After the change, it looks very similar to the example given in the original post.

If you want a technical term, I would say that the approach we demonstrated at the beginning is called imperative, while the current one is called reactive (but I'm not very familiar with technical terms, so please correct me if I'm wrong).

Do you remember the core concept of React? UI is just a way of presenting state, `UI = F(state)`. Therefore, when the screen changes, we don't need to worry about how it changes, we just need to change the state.

I think the reactive approach above is very similar. We just need to change the state and specify which actions (side effects) should be executed when the state changes, without explicitly writing what should be done for each action.

## Back to the original example

In the original example, the code is written like this:

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

The most confusing part for most people is probably what most people would do when they press the search button:

``` js
fetchData(baseUrl + query)
```

But in the code, it is only:

``` js
setUrl(baseUrl+query)
```

And then `useEffect` is used to call `fetchData`.

The above example is actually the second approach I mentioned earlier.

The point of thinking is: "Whenever the url state changes, I will call the API to get data", rather than "When the user clicks the button, I will call the API".

These are two completely different ways of thinking.

When writing code, most people probably still use the first approach, which is to change the state and do something else after the operation. Few people have the concept of the second approach, but I think the second approach is actually one of the essences of React.

However, the actual usage depends on the context, and there is no saying which one is better. For example, in the example where I have to send an API while typing, if you notice, you will find that every time the state changes, we need to write another fetchData to get the data. In this case, I think the second approach is more suitable.

Finally, there is something in the official [React documentation](https://reactjs.org/docs/hooks-effect.html#example-using-hooks) that has an example like this (the original example did not add dependencies, but it was added in [other paragraphs](https://reactjs.org/docs/hooks-effect.html#tip-optimizing-performance-by-skipping-effects)):

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

This is also a reactive approach, which is what I have been emphasizing: "What side effect should be executed when the state changes."

If you want to change it to another approach, it will look like this:

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

## Summary

Actually, the main point I want to discuss in this article is not Redux, nor where to call the API, these are secondary.

The focus is on understanding the useEffect hook.

My understanding of it is: "Write what side effect to execute after the dependencies change."

From this point, there will be the reactive approach I mentioned above: "What should I do after the state changes."

Finally, regarding these hooks, I highly recommend Dan's two articles, which are really great:

1. [How Are Function Components Different from Classes?](https://overreacted.io/how-are-function-components-different-from-classes/)
2. [A Complete Guide to useEffect](https://overreacted.io/a-complete-guide-to-useeffect/)

This article records my understanding of useEffect. If you have any questions, you can discuss them with me.

## Postscript (added on 2020-09-10)

After the article was published, someone in the [community](https://www.facebook.com/groups/reactjs.tw/permalink/2725146031094311/?__cft__[0]=AZXWpC3mxMQ4Ucyj0n6JXK7gGPPqb1GzcjZG0rCwbGXkOcuMCCn_PzeZHTNfpH0s9hq8rHBL_h5QQ2QqzD3X_9yqa_kopA4qMhOzcIKV7-lIXe8ftgtwLCQZX9_W4-Q0h-5iFLPIQuaXQmbWcwnwI_UM18_37Nf5fiG9V1HuNOjxzs7wldMgkBUfwFnT6I9uvxc&__tn__=%2CO%2CP-R) reminded me that what I was talking about was just one part of `useEffect`.

`useEffect` is not that complicated. It's just a "side effect that will be executed after the function component is rendered", that's it. It doesn't even have anything to do with state. Later, I thought about it and felt that this was indeed the correct understanding of `useEffect`.

As for what was mentioned in this article, it can be said to be one of the ways to use `useEffect`.

Because the second parameter of `useEffect` can specify "when there are changes in which dependencies, I want to execute this side effect", and you can put state in the dependencies, then it becomes what this article says: "What I want to do when the state changes". So what this article mentions is just one way to use `useEffect`, and it doesn't see the full picture of `useEffect`.

`useEffect` is just a "side effect that will be executed after the function component is rendered".

And the usage mentioned in the article is just to add dependencies to `useEffect`, becoming "a side effect that will be executed after the function component is rendered, if the state has changed".

In addition, the phrase "if the state has changed" is not so accurate, because `useEffect` will also be executed during `didMount`, but at that time the state has not changed, it is still the initial value. So a more precise statement may be: "After the function component is rendered, if it is `didMount` or the state has changed, the side effect will be executed".

Thanks to [Chen Guanlin](https://medium.com/@as790726) for the correction.
