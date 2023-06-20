---
title: 'In-depth Session and Cookie: Implementation in Express, PHP, and Rails'
date: 2019-08-09 22:10
tags: [Web]
categories:
  - Web
---

## Introduction

This is a series of three articles that I call the Session and Cookie Trilogy. The goal of the series is to discuss this classic topic from shallow to deep, from understanding concepts to understanding implementation methods. This is the last article in the series, and the complete links to the three articles are as follows:

1. [Plain Talk on Session and Cookie: Starting with Running a Grocery Store](https://medium.com/@hulitw/session-and-cookie-15e47ed838bc)
2. [Shallow Talk on Session and Cookie: Let's Read RFC Together](https://github.com/aszx87410/blog/issues/45)
3. [In-depth Session and Cookie: Implementation in Express, PHP, and Rails](https://github.com/aszx87410/blog/issues/46)

The first article talks about Session and Cookie in plain language without too many technical terms. The second article directly looks at the three RFCs of Cookie to understand what Session is, and also supplements some knowledge related to Cookie. This article will delve into Session and take a look at three different Session implementation methods.

These three are Node.js Web framework Express, PHP, and Ruby on Rails. I chose these three because their implementation of Session mechanism is different, and I think they are suitable objects for reference.

<!-- more -->

Okay, let's get started!

## Express

[Express](https://expressjs.com/) itself is an extremely lightweight framework with many basic functions under other frameworks, which need to be installed with middleware to use.

Let's start with a brief introduction to the concept of middleware. In Express, when a Request is received, it is handed over to the corresponding middleware for processing, and after processing, it becomes a Response returned. So the essence of Express is actually a bunch of middleware.

If we explain it with a picture, it would look like this:

![Screenshot 2019-08-08 23.22.26](https://user-images.githubusercontent.com/2755720/62776748-10456480-bade-11e9-8000-6604aca08c8c.png)

For example, a basic code segment would look like this:

``` js
const express = require('express')
const app = express()
const port = 5001
  
// global 的 middleware
app.use((req, res, next) => {
  req.greeting = 'hello'
  next()
})
  
// 特定 route 的 middleware
app.get('/', (req, res) => {
  res.end(req.greeting)
})
  
app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`)
})
```

The first middleware is global, so any request will first reach this middleware, and you can set some things for the req or res parameters here, and finally call `next` to transfer control to the next middleware.

The next middleware can get the information processed by the previous middleware and output the content. If next is not called, it means that you do not want to transfer control to the next middleware.

In Express, the middleware that manages Session is [express-session](https://github.com/expressjs/session), and the sample code looks like this (rewritten from the official website example):

``` js
const express = require('express')
const session = require('express-session')
  
const app = express()
const port = 5001
  
// 使用 session middleware
app.use(session({
  secret: 'keyboard cat'
}))
   
app.get('/', function(req, res, next) {
  
  // 可以用 req.session 拿取存在 session 的值
  // 這邊判斷有沒有 req.session.views
  // 如果有的話就 +1，反之初始化成 1
  // 所以 req.session 可讀也可寫
  if (req.session.views) {
    req.session.views++
    res.write('views: ' + req.session.views)
    res.end()
  } else {
    req.session.views = 1
    res.end('welcome to the session demo. refresh!')
  }
})
  
app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`)
})
```

After using the session middleware, you can directly use `req.session.key` to access the information you want. The same variable can be written and read, which is similar to PHP's $_SESSION.

Next, let's take a look at the express-session code! The main code is in [index.js](https://github.com/expressjs/session/blob/master/index.js), which is about 700 lines long and is unlikely to be explained line by line.

And well-written libraries will spend a lot of effort on backward compatibility and data validity checks, which are some more trivial and less helpful things for understanding mechanisms.

So I will simply organize the code, remove less important parts, and reorganize the code, and only select relevant paragraphs.

We will focus on three key points:

1. How sessionID is generated
2. How sessionID is stored
3. How session information is stored

Let's take a look at where sessionID is generated first:

``` js
// get the session id generate function
var generateId = opts.genid || generateSessionId
  
// generates the new session
store.generate = function(req){
  req.sessionID = generateId(req);
  req.session = new Session(req);
  req.session.cookie = new Cookie(cookieOptions);
  
  if (cookieOptions.secure === 'auto') {
    req.session.cookie.secure = issecure(req, trustProxy);
  }
};
  
function generateSessionId(sess) {
  return uid(24);
}
```

The customizability of `express-session` is high, as you can pass in your own function to generate the sessionID. If not passed, it defaults to using `uid(24)`, where `uid` refers to the [uid-safe](https://github.com/crypto-utils/uid-safe) library, which generates a random ID of length 24 bytes.

The documentation specifically mentions this length:

> Asynchronously create a UID with a specific byte length. Because base64 encoding is used underneath, this is not the string length. For example, to create a UID of length 24, you want a byte length of 18.

So if you input 24, the resulting string will have a length of 32 characters.

So how is this sessionID stored in a cookie?

``` js
var cookie = require('cookie')
var signature = require('cookie-signature')
  
// get the session cookie name
var name = opts.name || opts.key || 'connect.sid'
  
// get the cookie signing secret
var secret = opts.secret
  
if (secret && !Array.isArray(secret)) {
  secret = [secret];
}
  
// set-cookie
onHeaders(res, function(){
  
  // set cookie
  setcookie(res, name, req.sessionID, secrets[0], req.session.cookie.data);
});
  
function setcookie(res, name, val, secret, options) {
  var signed = 's:' + signature.sign(val, secret);
  var data = cookie.serialize(name, signed, options);
  
  debug('set-cookie %s', data);
  
  var prev = res.getHeader('Set-Cookie') || []
  var header = Array.isArray(prev) ? prev.concat(data) : [prev, data];
  
  res.setHeader('Set-Cookie', header)
}
```

The key for the sessionID stored in the cookie can also be specified, but the default is `connect.sid`, so when you see this key, you know it is the default sessionID name for `express-session`.

The content is a bit special, starting with `s:` followed by the result of `signature.sign(sessionID, secret)`.

Here, we need to look at the [cookie-signature](https://github.com/tj/node-cookie-signature) library, with a simple example below:

``` js
var cookie = require('cookie-signature');
  
var val = cookie.sign('hello', 'tobiiscool');
val.should.equal('hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI');
```

What does the `sign` function do? The source code is simple:

``` js
var crypto = require('crypto');
  
/**
 * Sign the given `val` with `secret`.
 *
 * @param {String} val
 * @param {String} secret
 * @return {String}
 * @api private
 */
  
exports.sign = function(val, secret){
  if ('string' != typeof val) throw new TypeError("Cookie value must be provided as a string.");
  if ('string' != typeof secret) throw new TypeError("Secret string must be provided.");
  return val + '.' + crypto
    .createHmac('sha256', secret)
    .update(val)
    .digest('base64')
    .replace(/\=+$/, '');
};
```

It simply generates a [digest](https://en.wikipedia.org/wiki/Cryptographic_hash_function) using hmac-sha256 for the content to be signed, and appends it to the end of the string, with `.` used to separate the data.

If you don't know what hmac is, it is simply a way to generate a digest for a message, to ensure data integrity and prevent tampering. You can think of it as a unique code corresponding to the message. If the message is changed, the code will also be different.

In the example above, `hello` is signed using the `tobiiscool` secret, resulting in `DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI`. The complete string becomes `hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI`, with my data in front and the digest at the end.

If someone tries to tamper with the data, such as changing the front to `hello2`, the digest will not match the new data, and I will know that someone has tampered with the data. Therefore, this method is used to ensure data integrity, and the principle is similar to [JWT](https://jwt.io/). You can see the data, but you cannot change it, because any changes will be detected.

You may wonder: why not encrypt the entire sessionID? Why use this method? I guess it's because the original data is not afraid of being seen by others, but only afraid of being changed. If the original data is sensitive information, encryption will be used. However, since the original data is only the sessionID, it doesn't matter if it is seen by others, as long as data integrity is ensured. Moreover, encryption requires more system resources than this message verification, so this method is used.

So, going back to the beginning, `express-session` stores the sessionID in a cookie, with the key being `connect.sid`, and the value being `s:{sessionID}.{hmac-sha256(sessionID, secret)}`.

If you are curious, you can go to any website that uses Express and check the cookie content to find the actual data (or run one yourself). Here's an example using my own: my `connect.sid` is `s%3AfZZVCDHefchle2LDK4PzghaR3Ao9NruG.J%2BsOPkTubkeMJ4EMBcnunPXW0Y7TWTucRSKIPNVgnRM`, which becomes `s:fZZVCDHefchle2LDK4PzghaR3Ao9NruG.J+sOPkTubkeMJ4EMBcnunPXW0Y7TWTucRSKIPNVgnRM` after decoding special characters.

In other words, my sessionID is `fZZVCDHefchle2LDK4PzghaR3Ao9NruG`, and the authentication code is `J+sOPkTubkeMJ4EMBcnunPXW0Y7TWTucRSKIPNVgnRM`.

After knowing how to store the sessionID, it should be easy to understand how to retrieve it from the cookie by simply reversing the process:

``` js
// get the session ID from the cookie
var cookieId = req.sessionID = getcookie(req, name, secrets);
  
function getcookie(req, name, secrets) {
  var header = req.headers.cookie;
  var raw;
  var val;
  
  // read from cookie header
  if (header) {
    var cookies = cookie.parse(header);
  
    raw = cookies[name];
  
    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }
  
  return val;
}
  
/**
 * Verify and decode the given `val` with `secrets`.
 *
 * @param {String} val
 * @param {Array} secrets
 * @returns {String|Boolean}
 * @private
 */
function unsigncookie(val, secrets) {
  for (var i = 0; i < secrets.length; i++) {
    var result = signature.unsign(val, secrets[i]);
  
    if (result !== false) {
      return result;
    }
  }
  
  return false;
}
```

Now, the last question remains: where is the session information stored? Is it stored in memory, files, or somewhere else?

Actually, this is clearly written in the code. By default, it is stored in memory:

``` js
var warning = 'Warning: connect.session() MemoryStore is not\n'
  + 'designed for a production environment, as it will leak\n'
  + 'memory, and will not scale past a single process.';
  
// get the session store
var store = opts.store || new MemoryStore()
  
// notify user that this store is not
// meant for a production environment
/* istanbul ignore next: not tested */
if (env === 'production' && store instanceof MemoryStore) {
  console.warn(warning);
}
```

So how is it stored? You can refer to [session/memory.js](https://github.com/expressjs/session/blob/master/session/memory.js):

``` js
function MemoryStore() {
  Store.call(this)
  this.sessions = Object.create(null)
}
  
MemoryStore.prototype.get = function get(sessionId, callback) {
  defer(callback, null, getSession.call(this, sessionId))
}
  
MemoryStore.prototype.set = function set(sessionId, session, callback) {
  this.sessions[sessionId] = JSON.stringify(session)
  callback && defer(callback)
}
  
function getSession(sessionId) {
  var sess = this.sessions[sessionId]
  
  if (!sess) {
    return
  }
  
  // parse
  sess = JSON.parse(sess)
  
  return sess
}
```

First, create a clean object using `Object.create(null)` (this is a common method, for those who haven't seen it before, you can refer to: [Detailed Explanation of Object.create(null)](https://juejin.im/post/5acd8ced6fb9a028d444ee4e)). Then, use the sessionID as the key and `JSON.stringify(session)` as the value, and store it in this object.

So, in essence, the session information of express-session is stored in a variable by default, so if you end the process and restart it, all session data will be lost. There may also be memory leak issues, so it is not recommended for production use.

If you want to use it in production, you must find a `store` to use, such as [connect-redis](https://github.com/tj/connect-redis#readme), which can be used with express-session to store session information in redis.

The above is the original code analysis of the commonly used middleware in Express: express-session. From the above paragraphs, we clearly know how the sessionID is generated and how it is stored in cookies, as well as where the session information is stored.

## PHP (version 7.2)

PHP has built-in session mechanism, so you don't need to use any framework, and the usage is also very simple:

``` php
<?php
session_start();
  
if (empty($_SESSION['views'])) {
  $_SESSION['views'] = 1;
} else {
  $_SESSION['views']++;
}
  
echo $_SESSION['views'];
?>
```

In fact, it is similar to the usage of express-session, except that one is `req.session` and the other is `$_SESSION`.

I originally wanted to look at the PHP source code directly, just like I did with express-session, and then find out how to implement it. However, because PHP's source code is all in C, it is difficult for someone like me who has hardly written C to understand, so I can only do it the other way around. First, I will introduce how PHP's Session mechanism is implemented, and then look for evidence from the source code.

First of all, PHP's Session mechanism is similar to express-session, both of which store a sessionID in a cookie and store session information on the server. express-session is stored in memory by default, while PHP is stored in a file by default.

All of these can be adjusted in the PHP configuration file, which is written in `php.ini`. Below is an example of some related settings in my file:

``` ini
[Session]
; Handler used to store/retrieve data.
; http://php.net/session.save-handler
session.save_handler=files
  
; Argument passed to save_handler.  In the case of files, this is the path
; where data files are stored. Note: Windows users have to change this
; variable in order to use PHP's session functions.
;
; The path can be defined as:
;
;     session.save_path = "N;/path"
  
session.save_path="/opt/lampp/temp/"
  
; Name of the session (used as cookie name).
; http://php.net/session.name
session.name=PHPSESSID
  
; Handler used to serialize data.  php is the standard serializer of PHP.
; http://php.net/session.serialize-handler
session.serialize_handler=php
```

In the cookie, you can see a `PHPSESSID`, which looks something like this: `fc46356f83dcf5712205d78c51b47c4d`, which is the sessionID used by PHP.

Then, you can check `session.save_path` to see where your session information is stored. The file name is easy to recognize, it is `sess_` plus the sessionID:

```
root@debian:/opt/lampp/temp# ls
  
adminer.invalid
adminer.version
sess_04719a35fb67786d574ec6eca969f7cb
sess_fc46356f83dcf5712205d78c51b47c4d
```

If you open the session file, the content will be the result after serialization:

```
views|i:5;
```

This is the true face of PHP session. All session information is stored in a file.

If you want to study the relevant source code of PHP session, the most important files are these two: [ext/session/session.c](https://github.com/php/php-src/blob/PHP-7.2/ext/session/session.c) and [ext/session/mod_files.c](https://github.com/php/php-src/blob/PHP-7.2/ext/session/mod_files.c). The former manages the session life cycle, and the latter is responsible for storing or reading the session in the file. The latter is actually similar to the Store we saw in express-session. As long as you follow the same interface, you can write another mod yourself, such as mod_redis.c.

Next, let's find out how the sessionID is generated. You can directly search for relevant keywords in mod_files.c, and you will find the following code:

``` c
/*
 * Create session ID.
 * PARAMETERS: PS_CREATE_SID_ARGS in php_session.h
 * RETURN VALUE: Valid session ID(zend_string *) or NULL for FAILURE.
 *
 * PS_CREATE_SID_FUNC() must check collision. i.e. Check session data if
 * new sid exists already.
 * *mod_data is guaranteed to have non-NULL value.
 * NOTE: Default php_session_create_id() does not check collision. If
 * NULL is returned, session module create new ID by using php_session_create_id().
 * If php_session_create_id() fails due to invalid configuration, it raises E_ERROR.
 * NULL return value checks from php_session_create_id() is not required generally.
 */
PS_CREATE_SID_FUNC(files)
{
  zend_string *sid;
  int maxfail = 3;
  PS_FILES_DATA;
  
  do {
    sid = php_session_create_id((void**)&data);
    if (!sid) {
      if (--maxfail < 0) {
        return NULL;
      } else {
        continue;
      }
    }
    /* Check collision */
    /* FIXME: mod_data(data) should not be NULL (User handler could be NULL) */
    if (data && ps_files_key_exists(data, ZSTR_VAL(sid)) == SUCCESS) {
      if (sid) {
        zend_string_release(sid);
        sid = NULL;
      }
      if (--maxfail < 0) {
        return NULL;
      }
    }
  } while(!sid);
  
  return sid;
}
```

Here, `php_session_create_id` is called to generate the sessionID, and then it checks if there are any duplicate IDs generated, retrying up to three times if necessary. `php_session_create_id` is located in the session.c file:

``` c
#define PS_EXTRA_RAND_BYTES 60
  
PHPAPI zend_string *php_session_create_id(PS_CREATE_SID_ARGS) /* {{{ */
{
  unsigned char rbuf[PS_MAX_SID_LENGTH + PS_EXTRA_RAND_BYTES];
  zend_string *outid;
  
  /* Read additional PS_EXTRA_RAND_BYTES just in case CSPRNG is not safe enough */
  if (php_random_bytes_throw(rbuf, PS(sid_length) + PS_EXTRA_RAND_BYTES) == FAILURE) {
    return NULL;
  }
  
  outid = zend_string_alloc(PS(sid_length), 0);
  ZSTR_LEN(outid) = bin_to_readable(rbuf, PS(sid_length), ZSTR_VAL(outid), (char)PS(sid_bits_per_character));
  
  return outid;
}
```

The key point is actually only this one: `php_random_bytes_throw`. If you continue to trace it, you will find [ext/standard/php_random.h](https://github.com/php/php-src/blob/623911f993f39ebbe75abe2771fc89faf6b15b9b/ext/standard/php_random.h#L32), and then find [ext/standard/random.c](https://github.com/php/php-src/blob/8fc58a1a1d32dd288bf4b9e09f9302a99d7b35fe/ext/standard/random.c#L89), which is the actual place where random numbers are generated.

However, it takes a long time to understand the function found at the end, so I didn't look into it in detail. In any case, there are different ways of generating sessionIDs on different operating systems, one of which even uses [/dev/urandom](https://en.wikipedia.org/wiki//dev/random).

After knowing how the sessionID is generated, let's take a look at how PHP serializes session information. You can see a function called `session_encode` in the [official documentation](https://www.php.net/manual/en/function.session-encode.php), and the output is exactly the same as the data we see in the session file. The description of this function is:

> session_encode() returns a serialized string of the contents of the current session data stored in the $_SESSION superglobal.

> By default, the serialization method used is internal to PHP, and is not the same as serialize(). The serialization method can be set using session.serialize_handler.

Next, we directly search for `session_encode` in session.c, and find this section:

``` c
/* {{{ proto string session_encode(void)
   Serializes the current setup and returns the serialized representation */
static PHP_FUNCTION(session_encode)
{
  zend_string *enc;
  
  if (zend_parse_parameters_none() == FAILURE) {
    return;
  }
  
  enc = php_session_encode();
  if (enc == NULL) {
    RETURN_FALSE;
  }
  
  RETURN_STR(enc);
}
```

It's just a wrapper for `php_session_encode`, and `php_session_encode` just calls something else:

``` c
static zend_string *php_session_encode(void) /* {{{ */
{
  IF_SESSION_VARS() {
    if (!PS(serializer)) {
      php_error_docref(NULL, E_WARNING, "Unknown session.serialize_handler. Failed to encode session object");
      return NULL;
    }
    return PS(serializer)->encode();
  } else {
    php_error_docref(NULL, E_WARNING, "Cannot encode non-existent session");
  }
  return NULL;
}
/* }}} */
```

The key point is `return PS(serializer)->encode();`. Actually, when you get to this point, you may get stuck because you don't know where `serializer` comes from. But if you look down a bit, you'll find something that should be related:

``` c
#define PS_DELIMITER '|'
  
PS_SERIALIZER_ENCODE_FUNC(php) /* {{{ */
{
  smart_str buf = {0};
  php_serialize_data_t var_hash;
  PS_ENCODE_VARS;
  
  PHP_VAR_SERIALIZE_INIT(var_hash);
  
  PS_ENCODE_LOOP(
    smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
    if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
      PHP_VAR_SERIALIZE_DESTROY(var_hash);
      smart_str_free(&buf);
      return NULL;
    }
    smart_str_appendc(&buf, PS_DELIMITER);
    php_var_serialize(&buf, struc, &var_hash);
  );
  
  smart_str_0(&buf);
  
  PHP_VAR_SERIALIZE_DESTROY(var_hash);
  return buf.s;
}
/* }}} */
```

You will know it is related because of the line `#define PS_DELIMITER '|'`, which appears in the session file, and you can guess that it is used to separate something. The actual value is handled by `php_var_serialize`.

If you continue to trace `php_var_serialize`, you can find [ext/standard/var.c](https://github.com/php/php-src/blob/7686b0b88906e2522300b9e631ddde2051de839f/ext/standard/var.c#L1112) (you can easily find this file using GitHub's search function), and finally you will find the real processing place: [php_var_serialize_intern](https://github.com/php/php-src/blob/7686b0b88906e2522300b9e631ddde2051de839f/ext/standard/var.c#L883), which calls different functions for different forms.

For our example, the views stored in the session are represented by a number, so it will run this function:

``` c
static inline void php_var_serialize_long(smart_str *buf, zend_long val) /* {{{ */
{
  smart_str_appendl(buf, "i:", 2);
  smart_str_append_long(buf, val);
  smart_str_appendc(buf, ';');
}
/* }}} */
```

By following this, we can see why the serialized session result was `views|i:5;`. The `|` is used to separate the key and value, `i` represents the type, `5` represents the actual number, and `;` is the end symbol.

The above is the related source code analysis of PHP Session mechanism. We have briefly looked at how to generate sessionID and how to serialize session information. We also know that by default, the cookie name will be called PHPSESSID, and the session content will be stored in a file.

Finally, I would like to share two interesting articles related to PHP Session:

1. [HITCON CTF 2018 - One Line PHP Challenge](https://blog.orange.tw/2018/10/hitcon-ctf-2018-one-line-php-challenge.html)
2. [[Web Security] LFI Leads to RCE via Session File](https://cyku.tw/lfi-leads-to-rce-via-session-file/)


## Rails (version 5.2)

Rails is a Ruby web framework, commonly known as Ruby on Rails. I chose this framework because I already knew that its method of storing sessions is different. I was curious about how Rails generates sessionIDs, so I searched for "session" in the GitHub repo and found this file: [rails/actionpack/test/dispatch/session/cookie_store_test.rb](https://github.com/rails/rails/blob/5-2-stable/actionpack/test/dispatch/session/cookie_store_test.rb). It is a test, but sometimes tests are very helpful in finding code because they contain a lot of related functions and parameters.

I observed it for a while and found that the term "session_id" appeared many times in the file. So I used this keyword to search and found [rails/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb](https://github.com/rails/rails/blob/5-2-stable/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb), where the comments clearly explain how Rails implements sessions:

``` ruby
# This cookie-based session store is the Rails default. It is
# dramatically faster than the alternatives.
#
# Sessions typically contain at most a user_id and flash message; both fit
# within the 4K cookie size limit. A CookieOverflow exception is raised if
# you attempt to store more than 4K of data.
#
# The cookie jar used for storage is automatically configured to be the
# best possible option given your application's configuration.
#
# If you only have secret_token set, your cookies will be signed, but
# not encrypted. This means a user cannot alter their +user_id+ without
# knowing your app's secret key, but can easily read their +user_id+. This
# was the default for Rails 3 apps.
#
# Your cookies will be encrypted using your apps secret_key_base. This
# goes a step further than signed cookies in that encrypted cookies cannot
# be altered or read by users. This is the default starting in Rails 4.
#
# Configure your session store in <tt>config/initializers/session_store.rb</tt>:
#
#   Rails.application.config.session_store :cookie_store, key: '_your_app_session'
#
# In the development and test environments your application's secret key base is
# generated by Rails and stored in a temporary file in <tt>tmp/development_secret.txt</tt>.
# In all other environments, it is stored encrypted in the
# <tt>config/credentials.yml.enc</tt> file.
#
# If your application was not updated to Rails 5.2 defaults, the secret_key_base
# will be found in the old <tt>config/secrets.yml</tt> file.
#
# Note that changing your secret_key_base will invalidate all existing session.
# Additionally, you should take care to make sure you are not relying on the
# ability to decode signed cookies generated by your app in external
# applications or JavaScript before changing it.
#
# Because CookieStore extends Rack::Session::Abstract::Persisted, many of the
# options described there can be used to customize the session cookie that
# is generated. For example:
#
#   Rails.application.config.session_store :cookie_store, expire_after: 14.days
#
# would set the session cookie to expire automatically 14 days after creation.
# Other useful options include <tt>:key</tt>, <tt>:secure</tt> and
# <tt>:httponly</tt>.
```

Rails uses cookie-based sessions by default because it is faster than other solutions. Although cookies have size limitations, they can only store flash messages and user IDs, which are far from the 4k limit.

In Rails 3, cookies are only signed, not encrypted, which means that users can see the user ID but cannot change it (just like the sessionID we see in express-session, visible but cannot be changed).

In Rails 4 and later, the cookie value is encrypted, and nothing can be seen. In the test environment, Rails automatically generates a secret for encryption, which can also be set through the Rails configuration file.

In this file, there is also a function called `generate_sid`, which is used to generate sessionIDs. This function exists in [rails/actionpack/lib/action_dispatch/middleware/session/abstract_store.rb](https://github.com/rails/rails/blob/5-2-stable/actionpack/lib/action_dispatch/middleware/session/abstract_store.rb):

``` ruby
def generate_sid
    sid = SecureRandom.hex(16)
    sid.encode!(Encoding::UTF_8)
    sid
end
```

It directly calls the Ruby library [SecureRandom](https://ruby-doc.org/stdlib-2.5.1/libdoc/securerandom/rdoc/SecureRandom.html) to generate random numbers as sessionIDs.

As for the key in the cookie, it can be adjusted by setting `app.config.session_store`. According to the code [here](https://github.com/rails/rails/blob/5-2-stable/railties/lib/rails/application/finisher.rb#L39):

``` ruby
# Setup default session store if not already set in config/application.rb
initializer :setup_default_session_store, before: :build_middleware_stack do |app|
    unless app.config.session_store?
        app_name = app.class.name ? app.railtie_name.chomp("_application") : ""
        app.config.session_store :cookie_store, key: "_#{app_name}_session"
    end
end
```

The default value will be `_#{app_name}_session`, for example, if my app_name is huli, the cookie name will be _huli_session.

Then the place where the session information is actually written into the cookie is in [rails/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb](https://github.com/rails/rails/blob/5-2-stable/actionpack/lib/action_dispatch/middleware/session/cookie_store.rb):

``` ruby
def set_cookie(request, session_id, cookie)
  cookie_jar(request)[@key] = cookie
end

def get_cookie(req)
  cookie_jar(req)[@key]
end

def cookie_jar(request)
  request.cookie_jar.signed_or_encrypted
end
```

It will call `signed_or_encrypted` related to the cookie to handle it.

Then I searched the documentation and found that the [official document](https://guides.rubyonrails.org/security.html#sessions) actually explains it very clearly:

> The session ID is generated using SecureRandom.hex which generates a random hex string using platform specific methods (such as OpenSSL, /dev/urandom or Win32 CryptoAPI) for generating cryptographically secure random numbers. Currently it is not feasible to brute-force Rails' session IDs.

The above paragraph describes how the sessionID is generated.

> The CookieStore uses the encrypted cookie jar to provide a secure, encrypted location to store session data. Cookie-based sessions thus provide both integrity as well as confidentiality to their contents. The encryption key, as well as the verification key used for signed cookies, is derived from the secret_key_base configuration value.
> 
> As of Rails 5.2 encrypted cookies and sessions are protected using AES GCM encryption. This form of encryption is a type of Authenticated Encryption and couples authentication and encryption in single step while also producing shorter ciphertexts as compared to other algorithms previously used. The key for cookies encrypted with AES GCM are derived using a salt value defined by the config.action_dispatch.authenticated_encrypted_cookie_salt configuration value.

This paragraph describes that AES GCM is used for encryption starting from Rails 5.2. There is another paragraph below that I didn't copy, mainly mentioning what was written in the code comments before, that before Rails 4, only HMAC was used for verification, not encryption.

And I found that this document is really well written after reading it. In addition to explaining these mechanisms clearly, it also introduces the Session Fixation Attack and CSRF that we mentioned in the previous article.

If you want to study further, you can refer to the implementation of Cookie related in Rails: [rails/actionpack/lib/action_dispatch/middleware/cookies.rb](https://github.com/rails/rails/blob/5-2-stable/actionpack/lib/action_dispatch/middleware/cookies.rb), where the comments have detailed explanations, such as the encryption part:

``` ruby
# Returns a jar that'll automatically encrypt cookie values before sending them to the client and will decrypt them for read.
# If the cookie was tampered with by the user (or a 3rd party), +nil+ will be returned.
#  
# If +secret_key_base+ and +secrets.secret_token+ (deprecated) are both set,
# legacy cookies signed with the old key generator will be transparently upgraded.
#  
# If +config.action_dispatch.encrypted_cookie_salt+ and +config.action_dispatch.encrypted_signed_cookie_salt+
# are both set, legacy cookies encrypted with HMAC AES-256-CBC will be transparently upgraded.
#  
# This jar requires that you set a suitable secret for the verification on your app's +secret_key_base+.
#  
# Example:
#  
#   cookies.encrypted[:discount] = 45
#   # => Set-Cookie: discount=DIQ7fw==--K3n//8vvnSbGq9dA--7Xh91HfLpwzbj1czhBiwOg==; path=/
#  
#   cookies.encrypted[:discount] # => 45
def encrypted
  @encrypted ||= EncryptedKeyRotatingCookieJar.new(self)
end
```

If you scroll down, you can see the complete code of `EncryptedKeyRotatingCookieJar`, or you can go further down and see [rails/activesupport/lib/active_support/message_encryptor.rb](https://github.com/rails/rails/blob/5-2-stable/activesupport/lib/active_support/message_encryptor.rb), which is responsible for encryption, and the code looks like this:

``` ruby
def _encrypt(value, **metadata_options)
    cipher = new_cipher
    cipher.encrypt
    cipher.key = @secret
  
    # Rely on OpenSSL for the initialization vector
    iv = cipher.random_iv
    cipher.auth_data = "" if aead_mode?
  
    encrypted_data = cipher.update(Messages::Metadata.wrap(@serializer.dump(value), metadata_options))
    encrypted_data << cipher.final
  
    blob = "#{::Base64.strict_encode64 encrypted_data}--#{::Base64.strict_encode64 iv}"
    blob = "#{blob}--#{::Base64.strict_encode64 cipher.auth_tag}" if aead_mode?
    blob
end
```

The cipher used here comes from openssl, so the bottom layer uses openssl.

That should be enough for now, let's not go any deeper.

## Conclusion

In this article, we looked at three different ways of storing sessions. The first is express-session, which stores session information in memory; the second is PHP, which stores it in a file; and the last is Rails, which uses the cookie-based session mentioned earlier to encrypt and store information directly in a cookie.

In this series, in the first article, we understood the concept, in the second article, we deepened our understanding of Session by reading RFC again, and in the last article, we directly referred to the implementation of some mainstream frameworks to see how the sessionID we mentioned earlier should be generated, where session information should be stored, and how cookie-based sessions should be implemented.

The purpose of writing this series is to help everyone understand these concepts clearly at once, so that they don't have to look them up again every time they encounter them in the future.

Finally, I hope this series is helpful to everyone, and if there are any errors, please leave a comment below.

Here is the complete list of articles in this series:

1. [Plain Session and Cookie: Starting with Running a Grocery Store](https://medium.com/@hulitw/session-and-cookie-15e47ed838bc)
2. [Shallow Talk about Session and Cookie: Let's Read RFC Together](https://github.com/aszx87410/blog/issues/45)
3. [Deep Dive into Session and Cookie: Implementation in Express, PHP, and Rails](https://github.com/aszx87410/blog/issues/46)
```
