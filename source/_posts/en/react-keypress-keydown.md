---
title: 'Understanding keyPress and keyDown events in React source code'
date: 2019-03-24 22:10
tags: [Front-end,React]
categories:
  - React
---

## Introduction

Recently, a student asked me a question about the difference between keyPress and keyDown events in React, as well as the difference between keyCode and charCode. Sometimes, they could get the values, but sometimes they couldn't, and they were confused.

At first, I thought React had done some processing, so I looked at the source code. Later, I found that React did indeed do some processing, but in fact, this problem had nothing to do with React. The difference between keyPress and keyDown is a native JavaScript event mechanism.

Although this problem has nothing to do with React, it is still a good thing to be able to refer to React's implementation through an actual problem, and React's comments are well written.

Therefore, this article will first show you the differences between these two events, and finally, we will see how React handles them.

<!-- more -->

## Differences between keyPress and keyDown

First, let's take a look at the differences between keyPress and keyDown events. We can directly ask MDN to explain this part for us:

> The keypress event is fired when a key that produces a character value is pressed down. Examples of keys that produce a character value are alphabetic, numeric, and punctuation keys. Examples of keys that don't produce a character value are modifier keys such as Alt, Shift, Ctrl, or Meta.

Source: https://developer.mozilla.org/en-US/docs/Web/Events/keypress

> The keydown event is fired when a key is pressed down.
> 
> Unlike the keypress event, the keydown event is fired for all keys, regardless of whether they produce a character value.

Source: https://developer.mozilla.org/en-US/docs/Web/Events/keydown

In short, keyDown is triggered when you press any key, but keyPress is only triggered when the key you press can produce a character. In other words, you are typing when you press this key.

For example, when you press `a`, a character `a` will appear on the screen, so both keyDown and keyPress will be triggered. But if you press `shift`, nothing will appear on the screen, so only keyDown will be triggered.

W3C provides a very good webpage: [Key and Character Codes vs. Event Types](https://www.w3.org/2002/09/tests/keys.html), which allows you to experiment for yourself.

In the figure below, I enter `a`, and both events will be triggered. Then I press `shift`, only keyDown will be triggered, and then I press backspace to delete the text, only keyDown will be triggered:

![keyboard](https://user-images.githubusercontent.com/2755720/54873875-07980e80-4e1b-11e9-91a4-1a3cc7036b8d.gif)

So I believe you should be very clear about the differences between these two events. keyDown can be regarded as "pressing a key", and keyPress can be regarded as an event triggered when "entering something".

Next, let's talk about the differences between keyCode and charCode.

## Differences between keyCode and charCode

Let's talk about charCode first. Maybe you have seen a function in JavaScript like this:

``` js
console.log(String.fromCharCode(65)) // A
```

charCode is actually a number representing a character, or more precisely, its Unicode encoding.

If you are not familiar with this, you can refer to this article: [[Guide] Understanding the encoding that cannot be understood in web pages: the use of Unicode in JavaScript](https://pjchender.blogspot.com/2018/06/guide-unicode-javascript.html).

In JavaScript, you can also use another function to get the encoding of a character:

```
console.log('嗨'.charCodeAt(0)) // 21992
```

If you convert 21992 to hexadecimal, it becomes 0x55E8, which is the Unicode for "嗨":

![hi](https://user-images.githubusercontent.com/2755720/54873879-0d8def80-4e1b-11e9-86fe-e907bc0591ab.png)

(Source: https://www.cns11643.gov.tw/wordView.jsp?ID=90944)

So what is keyCode? Since charCode represents the code of a character, keyCode obviously represents the code of a key.

Each "key" also has its own code, and sometimes it can be confusing because it may be the same as charCode.

For example: the keyCode of the "A" key is 65, and the charCode of the "A" character is also 65. This is probably designed for some convenience, but you should note that:

> When I press the "A" key, I may want to type "a" or "A", there are two possibilities.

Or take another example, when you want to type the number 1, if you use the key above Q instead of the numeric keypad, the character you want to type may be "1" or "!" or even "ㄅ", because they are all on the same key.

One key corresponds to more than one character, so you cannot determine what the user wants to type from keyCode alone.

Now that we've talked about the relationship between keyPress and keyDown, let's think about these two and their relationship with keyCode and charCode.

As mentioned earlier, keyPress is triggered when you want to enter text, so this event will get charCode because you need to know what the user typed. Why not keyCode? Because you don't know what he typed from keyCode, so it's useless to get keyCode.

keyDown is triggered when you press any key, and you must get keyCode at this time because you need to know what key the user pressed. If you get charCode, you won't get a value when you press shift or ctrl, because this is not a character, so you won't know what the user pressed.

In summary, when you want to detect user input, use keyPress and use charCode to see what the user just typed; when you want to detect the user pressing a key, use keyDown and use keyCode to get the key the user pressed.

This is the difference between keyPress, keyDown, keyCode, and charCode.

By the way, when inputting Chinese, keyPress will not have a value, and keyDown will return a mysterious code 229:

![chinese](https://user-images.githubusercontent.com/2755720/54873906-71181d00-4e1b-11e9-8745-ef2e21a79d7c.gif)

## key and which

In the keyPress and keyDown events, there are actually two more properties: key and which.

Let's first look at what which is:

> The which read-only property of the KeyboardEvent interface returns the numeric keyCode of the key pressed, or the character code (charCode) for an alphanumeric key pressed.

Source: https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/which

In my understanding, when you use which in keyPress, you should get charCode; when you use it in keyDown, it should be keyCode. Therefore, when writing code, you can use event.which to get this information without distinguishing between keyCode or charCode.

However, the reference materials attached to MDN are quite vague, so I am not sure about this part:

> which holds a system- and implementation-dependent numerical code signifying the unmodified identifier associated with the key pressed. In most cases, the value is identical to keyCode.

Source: https://www.w3.org/TR/2014/WD-DOM-Level-3-Events-20140925/#widl-KeyboardEvent-which

Let's take a look at the `key` property:

> The KeyboardEvent.key read-only property returns the value of the key pressed by the user while taking into considerations the state of modifier keys such as the shiftKey as well as the keyboard locale/layou

Source: https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent/key

In short, `key` will be a string representing the key or character that was pressed. For example, if you type "A", `key` will be "A". If you press the Shift key, `key` will be "Shift".

It's important to note that this property can be accessed in both the `keyPress` and `keyDown` events. So even in a `keyDown` event, you can still know what key or character the user just typed.

However, when it comes to detecting user input, the `keyPress` event is the most appropriate, unless you want to detect other non-character keys (such as Ctrl, Delete, Shift, etc.) in which case you would use the `keyDown` event.

To summarize, the `which`, `keyCode`, and `charCode` properties may behave differently across different browsers, making cross-browser support a challenging aspect. However, as older browsers are gradually being phased out, most users are likely using browsers that are more standards-compliant, so compatibility is not the focus of this article.

Now let's move on to the most exciting part: the React source code.

## Exploring the React Source Code

The React source code is so large, where do we even begin?

Here's a super useful method: GitHub search. Usually, if you search for the function name or related keywords, you can narrow down the scope and find the corresponding source code with just a little bit of manual searching. It's a convenient and useful method.

Let's use `keyPress` as our keyword and see what we get. We get 12 results:

![search](https://user-images.githubusercontent.com/2755720/54873885-21d1ec80-4e1b-11e9-8f52-714a52c2c46c.png)

After a quick glance, we can see that many of them are tests, which we can skip. You should be able to quickly locate a few relevant files, such as these two:

1. [packages/react-dom/src/events/SyntheticKeyboardEvent.js](https://github.com/facebook/react/blob/b87aabdfe1b7461e7331abb3601d9e6bb27544bc/packages/react-dom/src/events/SyntheticKeyboardEvent.js)
2. [packages/react-dom/src/events/getEventKey.js](https://github.com/facebook/react/blob/b87aabdfe1b7461e7331abb3601d9e6bb27544bc/packages/react-dom/src/events/getEventKey.js)

Yes, these two are our main focus today.

Let's start with `SyntheticKeyboardEvent.js`. If you're familiar with React, you should know that the events you get inside it are not native events, but rather events that have been wrapped by React. This `SyntheticKeyboardEvent` is the event that has been wrapped by React, and it's what you get when you use `onKeyPress` or `onKeyDown`.

For convenience, let's break it down into several functions and take a closer look.

``` js
charCode: function(event) {
  // `charCode` is the result of a KeyPress event and represents the value of
  // the actual printable character.
  
  // KeyPress is deprecated, but its replacement is not yet final and not
  // implemented in any major browser. Only KeyPress has charCode.
  if (event.type === 'keypress') {
    return getEventCharCode(event);
  }
  return 0;
}
```

The comments here are great. It mentions that `keyPress` has been deprecated, but the replacement is not ready yet. It also mentions that only `keyPress` has `charCode`.

So this function checks if the event type is `keyPress`. If it is, it returns `getEventCharCode(event)`, otherwise it returns 0.

Now let's take a look at what `getEventCharCode` does (note that this function is in another file):

``` js
/**
 * `charCode` represents the actual "character code" and is safe to use with
 * `String.fromCharCode`. As such, only keys that correspond to printable
 * characters produce a valid `charCode`, the only exception to this is Enter.
 * The Tab-key is considered non-printable and does not have a `charCode`,
 * presumably because it does not produce a tab-character in browsers.
 *
 * @param {object} nativeEvent Native browser event.
 * @return {number} Normalized `charCode` property.
 */
function getEventCharCode(nativeEvent) {
  let charCode;
  const keyCode = nativeEvent.keyCode;
  
  if ('charCode' in nativeEvent) {
    charCode = nativeEvent.charCode;
  
    // FF does not set `charCode` for the Enter-key, check against `keyCode`.
    if (charCode === 0 && keyCode === 13) {
      charCode = 13;
    }
  } else {
    // IE8 does not implement `charCode`, but `keyCode` has the correct value.
    charCode = keyCode;
  }
  
  // IE and Edge (on Windows) and Chrome / Safari (on Windows and Linux)
  // report Enter as charCode 10 when ctrl is pressed.
  if (charCode === 10) {
    charCode = 13;
  }
  
  // Some non-printable keys are reported in `charCode`/`keyCode`, discard them.
  // Must not discard the (non-)printable Enter-key.
  if (charCode >= 32 || charCode === 13) {
    return charCode;
  }
  
  return 0;
}
```

Let's break it down into sections for easier understanding:

``` js
/**
 * `charCode` represents the actual "character code" and is safe to use with
 * `String.fromCharCode`. As such, only keys that correspond to printable
 * characters produce a valid `charCode`, the only exception to this is Enter.
 * The Tab-key is considered non-printable and does not have a `charCode`,
 * presumably because it does not produce a tab-character in browsers.
 *
 * @param {object} nativeEvent Native browser event.
 * @return {number} Normalized `charCode` property.
 */
```

The comment at the beginning tells you that `charCode` represents the character code, so you can use `String.fromCharCode` to find the corresponding character.

Therefore, only characters that can be printed (or displayed) have `charCode`, and Enter is an exception because Enter produces a blank line. But Tab is not, because pressing Tab does not produce a character representing Tab.

``` js
let charCode;
const keyCode = nativeEvent.keyCode;
  
if ('charCode' in nativeEvent) {
  charCode = nativeEvent.charCode;
  
  // FF does not set `charCode` for the Enter-key, check against `keyCode`.
  if (charCode === 0 && keyCode === 13) {
    charCode = 13;
  }
} else {
  // IE8 does not implement `charCode`, but `keyCode` has the correct value.
  charCode = keyCode;
}
```

Here, processing is done for browser compatibility. FireFox does not set `charCode` for Enter, so you need to check if the `keyCode` is 13. And IE8 does not implement `charCode`, so the value of `keyCode` is used instead.

``` js
// IE and Edge (on Windows) and Chrome / Safari (on Windows and Linux)
// report Enter as charCode 10 when ctrl is pressed.
if (charCode === 10) {
  charCode = 13;
}
  
// Some non-printable keys are reported in `charCode`/`keyCode`, discard them.
// Must not discard the (non-)printable Enter-key.
if (charCode >= 32 || charCode === 13) {
  return charCode;
}
```

This is a special case where the `charCode` is 10 when the user presses Ctrl + Enter, and React wants to treat this as pressing Enter.

Also, some characters that cannot be printed should be removed, so a range check is performed at the end.

That's how `charCode` is handled. It's actually quite interesting when you look closely, as it checks for special cases and browser compatibility.

Now let's go back to `SyntheticKeyboardEvent.js` to see how `keyCode` is handled:

``` js
keyCode: function(event) {
  // `keyCode` is the result of a KeyDown/Up event and represents the value of
  // physical keyboard key.
  
  // The actual meaning of the value depends on the users' keyboard layout
  // which cannot be detected. Assuming that it is a US keyboard layout
  // provides a surprisingly accurate mapping for US and European users.
  // Due to this, it is left to the user to implement at this time.
  if (event.type === 'keydown' || event.type === 'keyup') {
    return event.keyCode;
  }
  return 0;
}
```

Here, it is said that the value of `keyCode` actually depends on the keyboard, meaning that some keyboards may produce different `keyCode`s. However, since most users in the US and Europe use a US keyboard, `keyCode` is simply returned without special handling.

Actually, I didn't fully understand this part, I just guessed the meaning roughly. The "keyboard layout" referred to here may be a layout like QWERTY or Dvorak, where the arrangement of keys is completely different. But if this results in different `keyCode`s, does that mean that some websites may have bugs?

However, most people have the same keyboard layout, so this issue doesn't seem to be a big concern.

``` js
which: function(event) {
  // `which` is an alias for either `keyCode` or `charCode` depending on the
  // type of the event.
  if (event.type === 'keypress') {
    return getEventCharCode(event);
  }
  if (event.type === 'keydown' || event.type === 'keyup') {
    return event.keyCode;
  }
  return 0;
}
```

Finally, for `which`, if it is `keypress`, `charCode` is returned, and if it is `keydown` or `keyup`, `keyCode` is returned.

So far, we have seen how React handles `charCode`, `keyCode`, and `which`. `charCode` checks for special cases and browser compatibility, `keyCode` is simply returned, and `which` returns the corresponding value depending on the event.

Finally, let's take a look at how `key` is handled, which is in another file called `getEventKey.js`:

``` js
/**
 * Normalization of deprecated HTML5 `key` values
 * @see https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent#Key_names
 */
const normalizeKey = {
  Esc: 'Escape',
  Spacebar: ' ',
  Left: 'ArrowLeft',
  Up: 'ArrowUp',
  Right: 'ArrowRight',
  Down: 'ArrowDown',
  Del: 'Delete',
  Win: 'OS',
  Menu: 'ContextMenu',
  Apps: 'ContextMenu',
  Scroll: 'ScrollLock',
  MozPrintableKey: 'Unidentified',
};
  
/**
 * Translation from legacy `keyCode` to HTML5 `key`
 * Only special keys supported, all others depend on keyboard layout or browser
 * @see https://developer.mozilla.org/en-US/docs/Web/API/KeyboardEvent#Key_names
 */
const translateToKey = {
  '8': 'Backspace',
  '9': 'Tab',
  '12': 'Clear',
  '13': 'Enter',
  '16': 'Shift',
  '17': 'Control',
  '18': 'Alt',
  '19': 'Pause',
  '20': 'CapsLock',
  '27': 'Escape',
  '32': ' ',
  '33': 'PageUp',
  '34': 'PageDown',
  '35': 'End',
  '36': 'Home',
  '37': 'ArrowLeft',
  '38': 'ArrowUp',
  '39': 'ArrowRight',
  '40': 'ArrowDown',
  '45': 'Insert',
  '46': 'Delete',
  '112': 'F1',
  '113': 'F2',
  '114': 'F3',
  '115': 'F4',
  '116': 'F5',
  '117': 'F6',
  '118': 'F7',
  '119': 'F8',
  '120': 'F9',
  '121': 'F10',
  '122': 'F11',
  '123': 'F12',
  '144': 'NumLock',
  '145': 'ScrollLock',
  '224': 'Meta',
};
  
/**
 * @param {object} nativeEvent Native browser event.
 * @return {string} Normalized `key` property.
 */
function getEventKey(nativeEvent: KeyboardEvent): string {
  if (nativeEvent.key) {
    // Normalize inconsistent values reported by browsers due to
    // implementations of a working draft specification.
  
    // FireFox implements `key` but returns `MozPrintableKey` for all
    // printable characters (normalized to `Unidentified`), ignore it.
    const key = normalizeKey[nativeEvent.key] || nativeEvent.key;
    if (key !== 'Unidentified') {
      return key;
    }
  }
  
  // Browser does not implement `key`, polyfill as much of it as we can.
  if (nativeEvent.type === 'keypress') {
    const charCode = getEventCharCode(nativeEvent);
  
    // The enter-key is technically both printable and non-printable and can
    // thus be captured by `keypress`, no other non-printable key should.
    return charCode === 13 ? 'Enter' : String.fromCharCode(charCode);
  }
  if (nativeEvent.type === 'keydown' || nativeEvent.type === 'keyup') {
    // While user keyboard layout determines the actual meaning of each
    // `keyCode` value, almost all function keys have a universal value.
    return translateToKey[nativeEvent.keyCode] || 'Unidentified';
  }
  return '';
}
```

Here, processing is also done for browser compatibility. If the event already has a `key`, it is first normalized to return the result in a consistent format. FireFox sets all printable characters to `MozPrintableKey`, which is normalized to `Unidentified`.

If the normalized `key` is not `Unidentified`, it is returned, otherwise further processing is done.

This further processing refers to polyfilling. If there is no `key` available, processing is done based on `charCode` or `keyCode` to return the corresponding character or key name.

That's about it for how React handles these keyboard-related events.

The code comments are well written and provide a lot of relevant information. The code is short and not complicated, and it looks easy to read, making it a good entry point for beginners.

## Conclusion

I've used these keyboard-related events so many times before, but I've never thought about their differences. Either I just wrote something and it caused a bug, or I just copied the best answer from Stack Overflow without really understanding the differences.

This time, I happened to delve into it because I wanted to help someone, and I didn't expect that a simple keyboard event would be so deep. You may need to step on a few mines to really appreciate it. The most troublesome thing is actually browser compatibility, as each browser may have its own implementation, and how to handle these different situations is the tricky part.

When it comes to React source code, what most people think of is the rendering mechanism or component handling, which is very complex and requires a certain understanding of the overall architecture to understand. 

This article chose to start with keyboard events to see how React handles them. I believe everyone can understand the code and it doesn't seem particularly difficult. I just want to tell you that if you want to study other people's source code, you don't necessarily have to understand the whole project, you can start with some small parts. You can learn a lot from it.

Please paste the Markdown content you want me to translate.
