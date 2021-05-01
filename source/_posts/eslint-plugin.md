---
title: 寫一個簡單堪用的 ESLint plugin
catalog: true
date: 2021-03-20 22:27:27
tags: [Front-end]
categories:
  - Front-end
---

## 前言

只要是開發 JavaScript 相關的專案，我的起手式通常都是 ESLint + Prettier，如果你沒有聽過這兩套的話我稍微講一下，Prettier 是幫你格式化程式碼用的，用了之後不必再跟其他人爭論到底要不要加分號，if 區塊的 `{` 要不要換行，一行最多到底能幾個字。只要用 Prettier，就是讓它幫你全權決定（雖然也有設定檔可以調整就是了）。

這其實對團隊滿有幫助的，因為程式碼格式可以統一，要空幾格也可以統一，在基本的 coding style 上面會長差不多。而 ESLint 雖然也有些跟格式相關的部分，但更多的是寫程式時候的一些 best practice，例如說使用變數前要先宣告、不會更改的變數用 const 之類的，這已經脫離了格式的範圍。

所以 ESLint 搭配 Prettier，就可以讓整個 codebase 的品質有最低限度的保障，至少不會出現排版很慘烈的狀況。而使用 ESLint 時最多人搭配的規則應該就是 [Airbnb JavaScript Style Guide](https://github.com/airbnb/javascript)，裡面有每一條規則的詳細解釋。

之前在寫 code 時我突然想到一個地方好像很適合用 ESLint，就嘗試了看看，發現要做一個「堪用」的 plugin 比想像中簡單一些，就以這篇文章記錄一下過程跟心得。

<!-- more -->

## 問題背景

當時碰到的狀況是這樣的，在專案裡面我們用 [react-i18next](https://react.i18next.com/latest/usetranslation-hook) 來管理 i18n 相關的東西，一段程式碼可能會長得像下面這樣：

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

使用 `useTranslation` 可以拿到一個 function t，把 key 丟進去之後就可以得到翻譯後的字串，而背後對應到的會是多個語言檔：

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

這就是 i18n 的基本原理，語言檔加上對應的 key，就可以根據不同語言顯示不同的文字。看起來雖然簡單，但 i18n 比較麻煩的事情之一就是當你有參數的時候，在這邊就先不多提了。

而我們通常不會把所有翻譯都放在同一個檔案裡面，會用 namespace 去切分，至於要怎麼切就看專案，有些可能根據頁面分，有些根據使用到的地方，例如說上面提到的 general，可能就會是比較常見的、需要共用的翻譯：

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

而登入或是身份驗證相關頁面專屬的翻譯，可能會長這樣：

``` js
// zh-hant/auth.json
{
  "username_error": "使用者名稱格式錯誤",
  "password_error": "帳號或密碼輸入錯誤",
  "login_success": "登入成功！"
}
```

把翻譯切分成不同的 namespace 的好處就在於我在瀏覽 A 頁面的時候，就不需要把 B 頁面的翻譯一起下載下來，用到哪個就下載哪個，節省資源。

當一個 component 需要用到多個 namespace 的時候有幾種不同的寫法，有一種寫法會是這樣用：

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

好，第一個問題來了。

當 team member 人少時，例如說只有一兩個，大家的命名會一致，比如說對於 authorization 這個 namespace，就是命名成 `const { t: tAuthorization} = useTranslation()`，但當人多了以後可能會有人簡寫成 `const { t: tAuth }`，雖然說這不是什麼大問題，但我認為同一個 codebase 裡面出現多種不同的命名狀況，能避免的話還是避免掉會比較好。

那要怎麼避免呢？一種就是在 code review 的時候自己去抓出來，但這個沒什麼效益而且花時間，另一種你應該已經想到了，就是透過 ESLint！像是這種可以交給程式去做的事情，交給程式就對了。

而 i18n 還有另外一個問題，那就是有時候我們工程師拿到 key 了，但是其他部門其實還沒有把這個 i18n key 新增到語言檔裡面，在畫面上就會看到裸露的 key。像這種情況，其實也可以透過 ESLint 把沒配對到的 key 抓出來，在部署前就提前知道哪些 key 是不存在的。

綜合以上想法，那時候我就想寫兩個 rule：

1. 檢查 namespace 是不是用的 alias 都一樣
2. 檢查哪些 key 存在在程式碼裡面，卻不在語言檔裡

想要寫一個堪用的 ESLint plugin 不難，需要的基礎知識在這一篇：[透過製作 Babel-plugin 初訪 AST](https://blog.techbridge.cc/2018/09/22/visit-ast-with-babel-plugin/) 都有，稍微了解一下 AST 即可，當初我也是看這一篇然後邊看邊弄的，底下我就預設大家看過這篇了，直接來講應該怎麼弄。

## 實戰

首先第一件事情就是打開我們強大的 [AST Explorer](http://astexplorer.net/)，在 transform 那邊選擇 ESLint，就會看到左下角自動載入了範本：

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

會發現 ESLint 跟 babel 其實都是一樣的，可以針對某個特定的節點去做操作，而 ESLint 是用 `context.report` 來回報錯誤，message 就是你會在 console 看到的那些錯誤，`fix` 則是給 auto fix 功能用的，這個比較複雜一點，我們先不管它。

再來呢，就是在左上角先把我們的範例程式碼給寫好：

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

接著直接在右邊看 AST，我們關心的是 Variable Declarator

![](https://static.coderbridge.com/img/aszx87410/ae85c9da19b94c9da0d7687607047a17.png)

再繼續往下看 AST，你會發現 `const { t: tGeneral } = useTranslation(NS_GENERAL)` 可以先簡單分為兩個部分，左邊的 `{t: tGeneral}` 跟右邊的 `useTranslation(NS_GENERAL)`。

左邊是在這個 Variable Declarator node 的 id 的地方，右邊則是 init 的地方。

init 點下去會看到 callee 跟 arguments

![](https://static.coderbridge.com/img/aszx87410/9f304ff5534c49df8759a1d65f169d13.png)

callee.name 就是 `useTranslation`，arguments[0].name 則是 `NS_GENERAL`。

而另外一邊 id 點下去可以找到 properties[0].key.name 是 `t`，properties[0].value.name 是 `tGeneral`

有了這些之後，其實我們想找的元素都找齊了，就可以根據 AST 的這些節點位置來寫一段基本的程式碼：

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

結果會長這樣：

![](https://static.coderbridge.com/img/aszx87410/b14435b7cdd44b6bb206dce3cba40c72.png)

其實我們只是根據 AST 上的節點內容去做簡單的判斷，但是只要做到這邊，差不多就完成八成了，上面的結果其實已經是我們要的了。

但是我們的 ESLint plugin 其實太針對範例程式碼，所以只要輕輕改一下就會壞掉，例如說加一行 `var a`，就會跑出錯誤：`Cannot read property 'callee' of null`，這是因為 `var a` 的 type 也是 `VariableDeclarator`，只是 `init` 是 null，因為 `init.callee` 就報錯了。

其實這些語法可以有各種的組合，所以最後節點的長相有超級多種可能，標題之所以寫「堪用」，就是因為我不想努力了，針對 i18n 的使用場景程式碼結構都會長一樣，所以我只要針對一種就好。如果是這樣的話，只要用最新的 optional chaining 就可以避免這種存取錯誤的問題：

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

不過 AST Explorer 好像還沒支援 optional chaining 就是了。

寫到這邊，其實我們的目標就已經達成了，寫出一個會幫你抓錯誤的 alias 的 ESLint rule。不過這個寫法其實有幾個缺陷，那就是我們把東西寫太死，所以結構變了就抓不出來了，例如說：

```
var a = NS_AUTH
const { t: tAuth } = useTranslation(a)
```

plugin 所抓到的 namespace 就會是 `a`，而不是 `NS_AUTH`，但如果有做好處理的話，應該是可以去找 a 的值發現是 NS_AUTH。不過前面我講過了，因為這個 i18n 使用的時候結構都會一樣，所以暫時不會碰到這種問題。

另外一個找出遺漏的 key 其實也是一樣的做法，就是根據 AST 找出 function call，然後呼叫的 function 名稱是我們剛剛定義好的那些像是 t, tGeneral, tAuth 之類的，把參數取出來，就是應該要存在的 i18n key，接著去語言檔裡面找一下是否存在。

簡單做個示範：

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

結果會長這樣：

![](https://static.coderbridge.com/img/aszx87410/33ee7bcd006c44e7995bc9884be70914.png)

只要掌握 AST 的結構依樣畫葫蘆，就可以快速寫出一個簡單堪用的 ESLint plugin。

## 結語

這篇寫出來的 ESLint plugin 我大概會用「簡陋」來形容，就是滿足了最低限度的需求而已，沒有 options 可以調整，也沒有對比較複雜的狀況做處理。

如果你要寫一個沒那麼簡陋的 ESLint plugin，其實不是一件簡單的事，就舉 `no-alert` 為例好了，裡面需要考慮到不同狀況以及 options 的設置，原始碼在這邊：[eslint/lib/rules/no-alert.js](https://github.com/eslint/eslint/blob/master/lib/rules/no-alert.js)。

這篇算是做個小嘗試而已，先寫寫看比較針對性而且簡單的的規則來入門，未來如果還有類似的需求，可以再研究該怎麼寫得更完整。

參考資料：

1. [How To Write Your First ESLint Plugin](https://dev.to/spukas/how-to-write-your-first-eslint-plugin-145)
2. [Create custom ESLint rules in 2 minutes](https://www.webiny.com/blog/create-custom-eslint-rules-in-2-minutes-e3d41cb6a9a0)
