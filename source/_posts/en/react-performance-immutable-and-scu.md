---
title: 'React Performance Optimization Challenge: Understanding Immutable Data and shouldComponentUpdate'
date: 2018-01-15 22:10
tags: [Front-end,React]
categories:
  - React
---

Recently, while refactoring a project at my company, I tried some things and found that I didn't really understand React's rendering mechanism and when `render` would be triggered. Later, I found that not only me, but many people were not familiar with the whole mechanism, so I decided to write this article to share my experience.

Actually, it's not too bad if you don't know how to optimize, but the worse thing is that you think you're optimizing, but you're actually slowing down performance, and the root cause is that you're not familiar enough with the whole mechanism of React. The "optimized" component is slower! This is serious.

Therefore, this article will cover the following topics:

1. The difference between `Component` and `PureComponent`
2. The role of `shouldComponentUpdate`
3. React's rendering mechanism
4. Why use Immutable data structures

To determine how much you understand the above, let's take a few quizzes right away! Some of them have traps, so please keep your eyes open!

<!-- more -->

# React Quiz

## Question 1

The following code is a very simple web page with just a button and a component called `Content`. When the button is clicked, it changes the state of the `App` component.

``` javascript
class Content extends React.Component {
  render () {
    console.log('render content!');
    return <div>Content</div>
  }
}
  
class App extends React.Component {
  handleClick = () => {
    this.setState({
      a: 1
    })
  }
  render() {
    console.log('render App!');
    return (
      <div>
        <button onClick={this.handleClick}>setState</button>
        <Content />
      </div>
    );
  }
}
  
ReactDOM.render(
  <App />,
  document.getElementById('container')
);
```

Question: What will be output to the console when you click the button?

A. Nothing (neither the `render` function of `App` nor the `render` function of `Content` is executed)
B. Only `render App!` (only the `render` function of `App` is executed)
C. `render App!` and `render content!` (both `render` functions are executed)

## Question 2

The following code is also very simple, divided into three components: `App`, `Table`, and `Row`. `App` passes `list` to `Table`, and `Table` uses `map` to render each `Row`.

``` js
class Row extends Component {
  render () {
    const {item, style} = this.props;
    return (
      <tr style={style}>
        <td>{item.id}</td>
      </tr>
    )
  }
}
  
class Table extends Component {
  render() {
    const {list} = this.props;
    const itemStyle = {
      color: 'red'
    }
    return (
      <table>
          {list.map(item => <Row key={item.id} item={item} style={itemStyle} />)}
      </table>
    )
  }
}
  
class App extends Component {
  state = {
    list: Array(10000).fill(0).map((val, index) => ({id: index}))
  }
  
  handleClick = () => {
    this.setState({
      otherState: 1
    })
  }
  
  render() {
    const {list} = this.state;
    return (
      <div>
        <button onClick={this.handleClick}>change state!</button>
        <Table list={list} />
      </div>
    );
  }
}
```

The problem with this code is that when the button is clicked, the `render` function of `App` is triggered, and then the `render` function of `Table` is also triggered, so the entire list is re-rendered.

However, when we click the button, `list` hasn't changed at all, so it doesn't need to be re-rendered. So clever Xiao Ming changed `Table` from a `Component` to a `PureComponent`, which won't re-render as long as `state` and `props` haven't changed, like this:

``` js
class Table extends PureComponent {
  render() {
    const {list} = this.props;
    const itemStyle = {
      color: 'red'
    }
    return (
      <table>
          {list.map(item => <Row key={item.id} item={item} style={itemStyle} />)}
      </table>
    )
  }
}
  
// 不知道什麼是 PureComponent 的朋友，可以想成他自己幫你加了下面的 function
shouldComponentUpdate (nextProps, nextState) {
  return !shallowEqual(this.props, nextProps) || !shallowEqual(this.state, nextState)
}
```

After changing `Table` from a `Component` to a `PureComponent`, will efficiency be improved if we do the same operation again, that is, click the `change state` button to change the state of `App`?

A. Yes, in this case, `PureComponent` is more efficient than `Component`
B. No, both are about the same
C. No, in this case, `Component` is more efficient than `PureComponent`

# Question 3

Next, let's look at an example that is very similar to the previous one, except that this time the list changes when the button is pressed:

``` js
class Row extends Component {
  render () {
    const {item, style} = this.props;
    return (
      <tr style={style}>
        <td>{item.id}</td>
      </tr>
    )
  }
}
  
class Table extends PureComponent {
  render() {
    const {list} = this.props;
    const itemStyle = {
      color: 'red'
    }
    return (
      <table>
          {list.map(item => <Row key={item.id} item={item} style={itemStyle} />)}
      </table>
    )
  }
}
  
class App extends Component {
  state = {
    list: Array(10000).fill(0).map((val, index) => ({id: index}))
  }
  
  handleClick = () => {
    this.setState({
      list: [...this.state.list, 1234567] // 增加一個元素
    })
  }
  
  render() {
    const {list} = this.state;
    return (
      <div>
        <button onClick={this.handleClick}>change state!</button>
        <Table list={list} />
      </div>
    );
  }
}
```

At this point, the `PureComponent` optimization of `Table` is no longer useful because `list` has changed, so the `render` function will be triggered. To continue optimizing, a more common approach is to change `Row` to a `PureComponent`, which ensures that the same `Row` will not be rendered again.

``` js
class Row extends PureComponent {
  render () {
    const {item, style} = this.props;
    return (
      <tr style={style}>
        <td>{item.id}</td>
      </tr>
    )
  }
}
  
class Table extends PureComponent {
  render() {
    const {list} = this.props;
    const itemStyle = {
      color: 'red'
    }
    return (
      <table>
          {list.map(item => <Row key={item.id} item={item} style={itemStyle} />)}
      </table>
    )
  }
}
```

Question: After changing `Row` from a `Component` to a `PureComponent`, if we do the same operation again, that is, click the `change state` button to change the `list`, will efficiency be improved?

A. Yes, in this case, `PureComponent` is more efficient than `Component`
B. No, both are about the same
C. No, in this case, `Component` is more efficient than `PureComponent`

# React's Rendering Mechanism

Before revealing the answers, let's briefly review how React renders your screen.

First of all, everyone knows that you can return what you want to render in the `render` function, for example:

``` js
class Content extends React.Component {
  render () {
    return <div>Content</div>
  }
}
```

It should be noted that what is returned here will not be directly placed on the DOM, but will first go through a layer of virtual DOM. In fact, you can simply think of this virtual DOM as a JavaScript object. For example, the result rendered by the Content above may be:

``` js
{
  tagName: 'div',
  children: 'Content'
}
```

The last step is for React to perform virtual DOM diff, compare the last and current virtual DOM, and update the changed parts to the real DOM.

In short, a layer of virtual DOM is added between the React Component and the DOM, the things you want to render are first converted into virtual DOM, and then the things that need to be updated are updated to the real DOM.

In this way, the number of times the real DOM is touched can be reduced and performance can be improved.

For example, suppose we implement a very simple example that changes the state after clicking a button:

``` js
class Content extends React.Component {
  render () {
    return <div>{this.props.text}</div>
  }
}
  
class App extends React.Component {
  state = {
    text: 'hello'
  }
  handleClick = () => {
    this.setState({
      text: 'world'
    })
  }
  render() {
    return (
      <div>
        <button onClick={this.handleClick}>setState</button>
        <Content text={this.state.text} />
      </div>
    );
  }
}
```

At the beginning of the program execution, the rendering order is as follows:

1. Call the render of App
2. Call the render of Content
3. Get the virtual DOM
4. Compare with the last virtual DOM
5. Apply the changes to the real DOM

At this time, the overall virtual DOM should look like this:

``` js
{
  tagName: 'div',
  children: [
    {
      tagName: 'button',
      children: 'setState'
    }, {
      tagName: 'div',
      children: 'hello'
    }
  ]
}
```

When you click the button and change the state, the execution order is the same as before:

1. Call the render of App
2. Call the render of Content
3. Get the virtual DOM

At this time, the obtained virtual DOM should look like this:

``` js
{
  tagName: 'div',
  children: [
    {
      tagName: 'button',
      children: 'setState'
    }, {
      tagName: 'div',
      children: 'world' // 只有這邊變了
    }
  ]
}
```

The virtual DOM diff algorithm of React will find that only one place has changed, and then replace the text there, and other parts will not be affected.

In fact, the [official document](https://reactjs.org/docs/reconciliation.html#motivation) explains this part very well:

> When you use React, at a single point in time you can think of the render() function as creating a tree of React elements. On the next state or props update, that render() function will return a different tree of React elements. React then needs to figure out how to efficiently update the UI to match the most recent tree.

In summary, you can think of the render function as creating a tree of React elements, and then React compares this tree with the last one to find out how to efficiently update the UI to match the most recent tree.

Therefore, to successfully update the UI, you must go through two steps:

1. render function
2. virtual DOM diff

Therefore, if you want to optimize performance, you have two directions:

1. Do not trigger the render function
2. Keep the virtual DOM consistent

Let's start with the latter!

# Improving React Performance: Keeping the Virtual DOM Consistent

Because of the protection of the virtual DOM, you usually don't have to worry too much about React's performance.

For example, the first question in the Q&A at the beginning:

``` js
class Content extends React.Component {
  render () {
    console.log('render content!');
    return <div>Content</div>
  }
}
  
class App extends React.Component {
  handleClick = () => {
    this.setState({
      a: 1
    })
  }
  render() {
    console.log('render App!');
    return (
      <div>
        <button onClick={this.handleClick}>setState</button>
        <Content />
      </div>
    );
  }
}
  
ReactDOM.render(
  <App />,
  document.getElementById('container')
);
```

Every time you click the button, because the state of App has changed, the render function of App will be triggered first, and because it returns `<Content />`, the render function of Content will also be triggered.

So every time you click the button, the render function of these two components will be called once. Therefore, the answer is `C. render App! and render content! (Both render functions are executed)`

However, even so, the real DOM will not change. Because during the virtual DOM diff, React will find that the current and last virtual DOM are exactly the same (because nothing has changed), so it will not make any changes to the DOM.

If you can maintain the similarity of the structure of the virtual DOM as much as possible, you can reduce some unnecessary operations. There are still many optimizations that can be done in this regard, which can be referred to in the [official document](https://reactjs.org/docs/reconciliation.html), which is written in detail.

# Boosting React Performance: Avoid Triggering Render Function

Although we don't need to worry too much, the virtual DOM diff also takes execution time. Although it's fast, it's still not as fast as not calling it at all, right?

For situations where "we already know there should be no changes," we shouldn't even call the render function because it's unnecessary. If the render function isn't called, the virtual DOM diff doesn't need to be executed, which improves performance.

You may have heard of the `shouldComponentUpdate` function, which is used for this purpose. If you return false in this function, the render function won't be called again.

``` js
class Content extends React.Component {
  shouldComponentUpdate () {
    return false;
  }
  render () {
    console.log('render content!');
    return <div>Content</div>
  }
}
  
class App extends React.Component {
  handleClick = () => {
    this.setState({
      a: 1
    })
  }
  render() {
    console.log('render App!');
    return (
      <div>
        <button onClick={this.handleClick}>setState</button>
        <Content />
      </div>
    );
  }
}
```

After adding it, you'll notice that the Content render function won't be triggered no matter how many times you press the button.

But be careful when using this, as you may encounter situations where the state and UI don't match if you're not careful. For example, the state may have changed to "world," but the UI still displays "Hello":

``` js
class Content extends React.Component {
  shouldComponentUpdate(){
    return false;
  }
  
  render () {
    return <div>{this.props.text}</div>
  }
}
  
class App extends React.Component {
  state = {
    text: 'hello'
  }
  handleClick = () => {
    this.setState({
      text: 'world'
    })
  }
  render() {
    return (
      <div>
        <button onClick={this.handleClick}>setState</button>
        <Content text={this.state.text} />
      </div>
    );
  }
}
```

In the example above, the state did change to "world" after pressing the button, but because the `shouldComponentUpdate` of Content always returns false, the render won't be triggered again, and you won't see the corresponding new state on the screen.

However, this is a bit extreme because usually, you won't always return false unless you're sure that this component doesn't need to re-render at all.

Instead, there's a more reasonable criterion:

> If none of the props and state have changed, return false.

``` js
class Content extends React.Component {
  shouldComponentUpdate(nextProps, nextState){
    return !shallowEqual(this.props, nextProps) || !shallowEqual(this.state, nextState);
  }
  
  render () {
    return <div>{this.props.text}</div>
  }
}
```

Suppose `this.props` is:

``` js
{
  text: 'hello'
}
```

And `nextProps` is:

``` js
{
  text: 'world'
}
```

When comparing them, you'll notice that `props.text` has changed, so it's natural to call the render function again. Also, `shallowEqual` is used here to compare the differences between the previous and current states, not `deepEqual`.

This is due to performance considerations. Don't forget that comparing like this also consumes resources, especially when your object is very deep, and there are many things to compare. Therefore, we tend to use `shallowEqual` to compare only one layer.

Also, as mentioned earlier, there's `PureComponent`, which is another type of component provided by React. The difference is that it automatically adds the comparison mentioned above. If you want to see the source code, it's [here](https://github.com/facebook/react/blob/1637b43e27c40c73f9489603145f9bb1d0ece618/packages/react-reconciler/src/ReactFiberClassComponent.js#L194):

``` js
if (type.prototype && type.prototype.isPureReactComponent) {
  return (
    !shallowEqual(oldProps, newProps) || !shallowEqual(oldState, newState)
  );
}
```

Now, let's reveal the answer to the second question. The answer is: `A. Yes, in this case, PureComponent is more efficient than Component` because after inheriting PureComponent, if the props and state haven't changed, the render function won't be executed, and the virtual DOM diff won't be executed, saving a lot of overhead.

# shallowEqual and Immutable Data Structures

When you first start learning React, you may be told that you can't modify data like this:

``` js
// 不能這樣
const newObject = this.state.obj
newObject.id = 2;
this.setState({
  obj: newObject
})
  
// 也不能這樣
const arr = this.state.arr;
arr.push(123);
this.setState({
  list: arr
})
```

Instead, you should do it like this:

``` js
this.setState({
  obj: {
    ...this.state.obj,
    id: 2
  }
})
  
this.setState({
  list: [...this.state.arr, 123]
})
```

Do you know why?

This is related to what we talked about earlier. As mentioned above, using `PureComponent` is normal because if the state and props haven't changed, the render function shouldn't be triggered.

And as mentioned earlier, `PureComponent` helps you `shallowEqual` the state and props to determine whether to call the render function.

In this case, if you use the first method mentioned above, you'll encounter problems, such as:

``` js
const newObject = this.state.obj
newObject.id = 2;
this.setState({
  obj: newObject
})
```

In the code above, `this.state.obj` and `newObject` actually point to the same object, the same memory block. So when we're doing `shallowEqual`, we'll judge that these two things are equal, and the render function won't be executed.

At this point, we need Immutable data, which means "once a data is created, it will never change". So, if you need to modify the data, you can only create a new one.

``` js
const obj = {
  id: 1,
  text: 'hello'
}
  
obj.text = 'world' // 這樣不行，因為你改變了 obj 這個物件
  
// 你必須要像這樣創造一個新的物件
const newObj = {
  ...obj,
  text: 'world'
}
```

With the concept of Immutable, `shallowEqual` won't fail because if we have new data, we can ensure that it is a new object. This is why we always generate a new object when using `setState`, instead of directly manipulating the existing one.

``` js
// 沒有 Immutable 的概念前 
const props = {
  id: 1,
  list: [1, 2, 3]
}
  
const list = props.list;
list.push(4)
nextProps = {
  ...props,
  list
}
  
props.list === nextProps.list // true
  
// 有了 Immutable 的概念後
const props = {
  id: 1,
  list: [1, 2, 3]
}
  
const nextProps = {
  ...props,
  list: [...props.list, 4]
}
  
props.list === nextProps.list // false
```

One thing to note here is that the spread operator only copies the first layer of data, it is not a deep clone:

``` js
const test = {
  a: 1,
  nest: {
    title: 'hello'
  }
}
  
const copy = {...test}
  
copy.nest === test.nest // true
```

So when your state has a more complex structure, changing the data will become more complicated because you have to do similar things for each layer to avoid directly modifying the object you want to change:

``` js
// 沒有 Immutable 的概念前 
const props = {
  title: '123',
  list: [
    {
      id: 1,
      name: 'hello'
    }, {
      id: 2,
      name: 'world'
    }
  ]
}
  
const list = props.list;
list[1].name = 'world2'; // 直接改
nextProps = {
  ...props,
  list
}
  
props.list === nextProps.list // true
props.list[1] === nextProps.list[1] // true
  
// 有了 Immutable 的概念後
const props = {
  title: '123',
  list: [
    {
      id: 1,
      name: 'hello'
    }, {
      id: 2,
      name: 'world'
    }
  ]
}
  
// 要注意這邊只是 shallow copy 而已
// list[0] === props.list[0] => true
const list = [...props.list.slice(0, 1)]
const data = props.list[1];
  
const nextProps = {
  ...props,
  list: [...list, {
    ...data, // 再做一次 spread oprator
    name: 'world2'
  }]
}
  
props.list === nextProps.list // false
props.list[0] === nextProps.list[0] // true
props.list[1] === nextProps.list[1] // false
```

If your state structure has many layers, it will become very difficult to change. In this case, you have three options:

1. Avoid having too many layers of state, try to flatten it (refer to [normalizr](https://github.com/paularmstrong/normalizr))
2. Find a library that will help you with Immutable, such as Facebook's [Immutable.js](https://facebook.github.io/immutable-js/)
3. Just use deep clone to copy all the data, and then change it however you want (not recommended)

Note: Thanks to KanYueh Chen for pointing out the above paragraph.

# Pitfalls of PureComponent

After following the rules of Immutable, we naturally want to set all Components as PureComponent because the default of PureComponent is reasonable. If the data hasn't changed, the render function won't be called, which can save a lot of unnecessary comparisons.

Let's go back to the last question of the quiz:

``` js
class Row extends PureComponent {
  render () {
    const {item, style} = this.props;
    return (
      <tr style={style}>
        <td>{item.id}</td>
      </tr>
    )
  }
}
  
class Table extends PureComponent {
  render() {
    const {list} = this.props;
    const itemStyle = {
      color: 'red'
    }
    return (
      <table>
          {list.map(item => <Row key={item.id} item={item} style={itemStyle} />)}
      </table>
    )
  }
}
```

We changed `Row` to PureComponent, so it won't re-render as long as the state and props haven't changed. So the answer should be "A. Yes, in this case, PureComponent is more efficient than Component"?

Wrong. If you look at the code more carefully, you will find that the answer is actually "C. No, in this case, Component is more efficient than PureComponent".

Your premise is correct, "if the state and props haven't changed, PureComponent is more efficient than Component". But there is another sentence that is also correct: "If your state or props 'will always change', then PureComponent won't be faster".

So the difference in using these two lies in whether the state and props will change frequently or not.

In the example above, the trap is in the `itemStyle` props. We create a new object every time we render, so for Row, even though props.item is the same, props.style is "always different".

If you already know that the props comparison will fail every time, then PureComponent is useless and even worse. Why? Because it does `shallowEqual`.

Don't forget that `shallowEqual` also takes time to execute.

If you already expect that the props or state of a certain component will "change frequently", then you don't need to switch to PureComponent because your implementation will become slower.

To sum up, when studying performance-related issues, I highly recommend this article: [React, Inline Functions, and Performance](https://cdb.reacttraining.com/react-inline-functions-and-performance-bdff784f5578), which has solved many of my doubts and brought me many new ideas.

For example, the article mentioned at the end that sometimes PureComponent can actually slow down, which I also learned from this article. I highly recommend everyone to take the time to read it.

Recently, I worked with my colleagues to rebuild a project, and the original consensus was to use PureComponent as much as possible. However, after reading this article and carefully considering it, I realized that it's better not to use it if you don't know the underlying principles. Therefore, I suggested that we switch to using Component for everything, and slowly adjust when we encounter performance issues that need to be optimized.

Finally, I'd like to share a quote I really like from the article on optimizing nested React components (which also discusses the issues with PureComponent):

> Just because you can optimize, doesn't mean you should.

References:
- [High Performance React: 3 New Tools to Speed Up Your Apps](https://medium.freecodecamp.org/make-react-fast-again-tools-and-techniques-for-speeding-up-your-react-app-7ad39d3c1b82)
- [reactjs - Reconciliation](https://reactjs.org/docs/reconciliation.html#motivation)
- [reactjs- Optimizing Performance](https://reactjs.org/docs/optimizing-performance.html)
- [React is Slow, React is Fast: Optimizing React Apps in Practice](https://marmelab.com/blog/2017/02/06/react-is-slow-react-is-fast.html)
- [Efficient React Components: A Guide to Optimizing React Performance](https://www.toptal.com/react/optimizing-react-performance)
