---
title: Writing a Simple and Usable ESLint Plugin
catalog: true
date: 2021-03-20 22:27:27
tags: [Front-end]
categories:
  - Front-end
---

## Introduction

Whenever I start a JavaScript-related project, my go-to setup is usually ESLint + Prettier. If you haven't heard of them, let me briefly explain. Prettier is used to format your code, so you don't have to argue with others about whether to add semicolons, whether to break `{` for if blocks, or how many characters per line. With Prettier, you let it decide (although there are configuration files you can adjust).

This is actually quite helpful for teams because it unifies the code format, and the basic coding style will be consistent. Although ESLint also has some formatting-related parts, it focuses more on best practices when writing code, such as declaring variables before using them and using `const` for variables that won't change. This is beyond the scope of formatting.

Therefore, using ESLint with Prettier can ensure the minimum quality of the entire codebase, at least avoiding terrible formatting. The most common rule people use with ESLint is probably the [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript), which explains each rule in detail.

When I was writing code before, I suddenly thought of a place where ESLint might be suitable, so I tried it out and found that making a "usable" plugin was easier than I thought. This article records the process and experience.

<!-- more -->

## Background

The situation I encountered at the time was like this. In the project, we used [react-i18next](https://react.i18next.com/latest/usetranslation-hook) to manage i18n-related things. A piece of code may look like this:

``` js
import { useTranslation } from 'react-i18next'
import { NS_GENERAL } from '@/i18n/namespaces'

function Hello() {
  const { t } = useTranslation(NS_GENERAL)
  return (
    <div>{t('welcome_message')}</div>
  )
}
```

Using `useTranslation` can get a function `t`, which can get the translated string by passing in the key. Behind the scenes, there will be multiple language files:

``` js
// en-us/general.json
{
  "welcome_message": "Hello!"
}

// zh-hant/general.json
{
  "welcome_message": "你好！"
}
```

This is the basic principle of i18n. Adding keys to language files can display different texts in different languages. Although it looks simple, one of the more complicated things about i18n is when you have parameters, which I won't go into here.

We usually don't put all translations in the same file. We use namespaces to split them. As for how to split them, it depends on the project. Some may be based on pages, and some may be based on usage. For example, the `general` mentioned above may be more common and shared translations:

``` js
// en-us/general.json
{
  "contact_us": "contact us",
  "close": "close",
  "try_again": "Please try again"
}

// zh-hant/general.json
{
  "contact_us": "聯絡我們",
  "close": "關閉",
  "try_again": "請再試一次"
}
```

The translations specific to login or authentication-related pages may look like this:

``` js
// zh-hant/auth.json
{
  "username_error": "使用者名稱格式錯誤",
  "password_error": "帳號或密碼輸入錯誤",
  "login_success": "登入成功！"
}
```

Splitting translations into different namespaces has the advantage that when I browse page A, I don't need to download the translations of page B together. I only download what I need, saving resources.

When a component needs to use multiple namespaces, there are several different ways to write it. One way is to use it like this:

``` js
import { useTranslation } from 'react-i18next'
import { NS_GENERAL, NS_AUTH } from '@/i18n/namespaces'

function Page() {
  const { t: tGeneral } = useTranslation(NS_GENERAL)
  const { t: tAuth } = useTranslation(NS_AUTH)
  return (
    <div>
      {tGeneral('contact_us')}
      <p>{tAuth('login_success')}</p>
    </div>
  )
}
```

Okay, the first problem is here.

When the team has few members, such as only one or two, everyone's naming will be consistent. For example, for the `authorization` namespace, it is named `const { t: tAuthorization} = useTranslation()`. But when there are more people, someone may abbreviate it to `const { t: tAuth }`. Although this is not a big problem, I think it is better to avoid multiple naming situations in the same codebase if possible.

So how to avoid it? One way is to grab it yourself during code review, but this is not very effective and takes time. The other way you should have thought of is to use ESLint! For things that can be done by the program, let the program do it.

There is another problem with i18n, which is that sometimes our engineers get the key, but other departments have not added this i18n key to the language file yet, and the screen will show the naked key. In situations like this, ESLint can also be used to identify which keys exist in the code but not in the language file before deployment.

Combining the above ideas, at that time, I wanted to write two rules:

1. Check if the aliases used for the namespace are the same.
2. Check which keys exist in the code but not in the language file.

It is not difficult to write a usable ESLint plugin. The basic knowledge required is covered in this article: [Visit AST with Babel-plugin](https://blog.techbridge.cc/2018/09/22/visit-ast-with-babel-plugin/). A basic understanding of AST is sufficient. I also learned by reading this article and experimenting with it. Assuming that you have read this article, I will explain how to proceed.

## Practical

The first thing to do is to open our powerful [AST Explorer](http://astexplorer.net/), select ESLint in the transform section, and the template will be automatically loaded in the lower left corner:

![](https://static.coderbridge.com/img/aszx87410/bf677339575647dc9bdd29cc03b4a4a2.png)

``` js
export default function(context) {
  return {
    TemplateLiteral(node) {
      context.report({
        node,
        message: 'Do not use template literals',

        fix(fixer) {
          if (node.expressions.length) {
            // Can't auto-fix template literal with expressions
            return;
          }
          
          return [
            fixer.replaceTextRange([node.start, node.start + 1], '"'),
            fixer.replaceTextRange([node.end - 1, node.end], '"'),
          ];
        },
      });
    }
  };
};
```

You will find that ESLint and Babel are actually the same. You can operate on a specific node and use `context.report` in ESLint to report errors. The message is the error you will see in the console, and `fix` is used for the auto fix function, which is a bit more complicated, but we won't worry about it for now.

Next, write our sample code in the upper left corner:

``` js
import { useTranslation } from 'react-i18next'
import { NS_GENERAL, NS_AUTH } from '@/i18n/namespaces'

function Page() {
  const { t: tGeneral } = useTranslation(NS_GENERAL)
  const { t: tAuth } = useTranslation(NS_AUTH)
  return (
    <div>
      {tGeneral('contact_us')}
      <p>{tAuth('login_success')}</p>
    </div>
  )
}
```

Then, directly view the AST on the right. We are concerned with the Variable Declarator.

![](https://static.coderbridge.com/img/aszx87410/ae85c9da19b94c9da0d7687607047a17.png)

Continuing to look down the AST, you will find that `const { t: tGeneral } = useTranslation(NS_GENERAL)` can be divided into two parts: `{t: tGeneral}` on the left and `useTranslation(NS_GENERAL)` on the right.

The left side is the id of this Variable Declarator node, and the right side is the init.

Clicking on init will show callee and arguments:

![](https://static.coderbridge.com/img/aszx87410/9f304ff5534c49df8759a1d65f169d13.png)

callee.name is `useTranslation`, and arguments[0].name is `NS_GENERAL`.

Clicking on the id on the other side will show that properties[0].key.name is `t`, and properties[0].value.name is `tGeneral`.

With these, we have found all the elements we need. We can write a basic code based on the node position of the AST:

``` js
// 正確的命名
const NS_RULES = {
  NS_GENERAL: 'tGeneral',
  NS_AUTH: 'tTest'
}

export default function(context) {
  return {
    VariableDeclarator(node) {
      // 判斷是不是 useTranslation
      if (node.init.callee.name === 'useTranslation') {
        // 抓出 namespace 跟 alias
        const ns = node.init.arguments[0].name
        const alias = node.id.properties[0].value.name
        if (alias !== NS_RULES[ns]) {
          context.report({
            node,
            message: `Wrong alias, should use ${NS_RULES[ns]}`,
          })
        }
      }
    }
  }
}
```

The result will look like this:

![](https://static.coderbridge.com/img/aszx87410/b14435b7cdd44b6bb206dce3cba40c72.png)

In fact, we only make simple judgments based on the content of the AST nodes. But once we get here, we have completed about 80% of the work, and the result above is what we want.

However, our ESLint plugin is too specific to the sample code, so it will break with a slight change. For example, adding a line `var a` will result in an error: `Cannot read property 'callee' of null`. This is because the type of `var a` is also `VariableDeclarator`, but `init` is null, so `init.callee` will report an error.

In fact, these syntaxes can have various combinations, so the appearance of the final node has many possibilities. The reason why the title is "usable" is that I don't want to work too hard. The code structure for using i18n will be the same, so I only need to focus on one. If so, you can avoid access errors using the latest optional chaining:

``` js
// 正確的命名
const NS_RULES = {
  NS_GENERAL: 'tGeneral',
  NS_AUTH: 'tTest'
}

export default function(context) {
  return {
    VariableDeclarator(node) {
      // 判斷是不是 useTranslation
      if (node.init?.callee?.name === 'useTranslation') {
        // 抓出 namespace 跟 alias
        const ns = node.init?.arguments?.[0]?.name
        const alias = node.id?.properties?.[0].value?.name
        if (alias !== NS_RULES[ns]) {
          context.report({
            node,
            message: `Wrong alias, should use ${NS_RULES[ns]}`,
          })
        }
      }
    }
  }
}
```

However, it seems that AST Explorer does not yet support optional chaining.

At this point, our goal has actually been achieved, and we have written an ESLint rule that will help you catch errors in aliases. However, this writing method actually has several shortcomings, that is, we have written things too tightly, so we cannot catch them if the structure changes. For example:

```
var a = NS_AUTH
const { t: tAuth } = useTranslation(a)
```

If the namespace grabbed by the plugin is `a`, instead of `NS_AUTH`, it should be possible to find the value of `a` and discover that it is `NS_AUTH` if it has been processed correctly. However, as I mentioned earlier, since the structure of this i18n is always the same when used, we won't encounter this problem for the time being.

The same approach applies to finding missing keys. We can use the AST to find function calls, and then call the functions we defined earlier, such as `t`, `tGeneral`, and `tAuth`, to extract the parameters, which should be the i18n keys that should exist. Then we can check if they exist in the language file.

Here's a simple example:

``` js
// 正確的命名
const NS_RULES = {
  NS_GENERAL: 'tGeneral',
  NS_AUTH: 'tAuth'
}

// 應該從語言檔讀入
const KEYS = ['contact', 'login_success']

export default function(context) {
  return {
    CallExpression(node) {
      if (Object.values(NS_RULES).includes(node.callee.name)) {
        if (!KEYS.includes(node.arguments[0].value)) {
          context.report({
            node,
            message: `i18n key: ${node.arguments[0].value} not found`
          })
        }
      }
    }
  }
}
```

The result will look like this:

![](https://static.coderbridge.com/img/aszx87410/33ee7bcd006c44e7995bc9884be70914.png)

As long as we understand the structure of the AST, we can quickly write a simple and usable ESLint plugin.

## Conclusion

I would describe the ESLint plugin I wrote in this article as "rudimentary", as it only meets the minimum requirements and has no options to adjust or handle more complex situations.

If you want to write a less rudimentary ESLint plugin, it's not a simple task. Let's take `no-alert` as an example. It needs to consider different situations and options settings. The source code is here: [eslint/lib/rules/no-alert.js](https://github.com/eslint/eslint/blob/master/lib/rules/no-alert.js).

This article is just a small attempt to write some targeted and simple rules to get started. If there are similar needs in the future, we can study how to write more complete rules.

References:

1. [How To Write Your First ESLint Plugin](https://dev.to/spukas/how-to-write-your-first-eslint-plugin-145)
2. [Create custom ESLint rules in 2 minutes](https://www.webiny.com/blog/create-custom-eslint-rules-in-2-minutes-e3d41cb6a9a0)
