---
title: How to Build Your Own Online Judge System
catalog: true
header-img: /img/header_img/article-bg.png
date: 2020-03-23 22:58:31
tags: [Others]
categories:
  - Others
---

## Introduction

First, let's briefly introduce what an Online Judge (OJ) system is. Simply put, it is a system like LeetCode that allows you to submit code for problem-solving and then lets the system check it and give you the final result. Below is a screenshot of LeetCode:

![LeetCode interface](https://static.coderbridge.com/img/aszx87410/47ea051cb4244849908286177e42a38f.png)

Before LeetCode became popular, the most well-known OJ was probably [UVa Online Judge](https://onlinejudge.org/), also known as ACM. In Taiwan, [ZeroJudge](https://zerojudge.tw/) is more famous.

If you happen to have a need and want to build your own OJ, what should you do?

<!-- more -->

## Open Source OJ Systems

A search on the internet will reveal several open-source OJ systems, among which the following three have more stars and appear to be more stable:

1. [DMOJ](https://github.com/DMOJ/online-judge)
2. [NOJ](https://github.com/ZsgsDesign/NOJ)
3. [QDUOJ](https://github.com/QingdaoU/OnlineJudge)

### DMOJ

![](https://static.coderbridge.com/img/aszx87410/0664ed7eeb6b478db132935202dee433.png)

This system appears to have the most complete and feature-rich functionality, and supports the most languages, up to 60 or so! It also supports third-party logins such as Google, Facebook, and Github. The backend is written in Python and is continuously maintained, with fairly complete [documentation](https://docs.dmoj.ca/#/site/installation).

The only drawback is that the interface is a bit plain and not as appealing.

### NOJ

![](https://static.coderbridge.com/img/aszx87410/950d37d94365471ab8cf0b1f5f820d31.png)

This system was developed by the Nanjing University of Posts and Telecommunications in China and is written in Laravel. The interface uses Material UI and looks more modern, but the documentation is less complete.

### QDUOJ

This system was developed by Qingdao University in China. The backend is written in Python + Django, the frontend is in Vue, and it is deployed using Docker, making it simple and fast. The supported programming languages are C, C++, Java, and Python. The interface uses Ant Design.

![](https://static.coderbridge.com/img/aszx87410/8d236caa632b42c6bde5c33c06f2ef3f.png)

Which one to choose depends on your needs. If the documentation provided on GitHub is complete, just follow the instructions. If it is incomplete, you can ask questions through Issues. You don't need to worry too much if you don't speak English well, as these three repositories can be communicated in Chinese.

I chose the last one, the OJ system open-sourced by Qingdao University, because I really like the interface and it is the easiest to deploy among the three.

The deployment process is here: https://github.com/QingdaoU/OnlineJudgeDeploy/tree/2.0. Since it is deployed using Docker, it is really easy. Basically, just download the docker-compose.yml file and run a command to finish it.

Let's take a look at the contents of docker-compose.yml:

```
version: "3"
services:

  oj-redis:
    image: redis:4.0-alpine
    container_name: oj-redis
    restart: always
    volumes:
      - ./data/redis:/data
  
  oj-postgres:
    image: postgres:10-alpine
    container_name: oj-postgres
    restart: always
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=onlinejudge
      - POSTGRES_USER=onlinejudge
      - POSTGRES_PASSWORD=onlinejudge

  judge-server:
    image: registry.cn-hangzhou.aliyuncs.com/onlinejudge/judge_server
    container_name: judge-server
    restart: always
    read_only: true
    cap_drop:
      - SETPCAP
      - MKNOD
      - NET_BIND_SERVICE
      - SYS_CHROOT
      - SETFCAP
      - FSETID
    tmpfs:
      - /tmp
    volumes:
      - ./data/backend/test_case:/test_case:ro
      - ./data/judge_server/log:/log
      - ./data/judge_server/run:/judger
    environment:
      - SERVICE_URL=http://judge-server:8080
      - BACKEND_URL=http://oj-backend:8000/api/judge_server_heartbeat/
      - TOKEN=CHANGE_THIS
      # - judger_debug=1
  
  oj-backend:
    image: registry.cn-hangzhou.aliyuncs.com/onlinejudge/oj_backend
    container_name: oj-backend
    restart: always
    depends_on:
      - oj-redis
      - oj-postgres
      - judge-server
    volumes:
      - ./data/backend:/data
    environment:
      - POSTGRES_DB=onlinejudge
      - POSTGRES_USER=onlinejudge
      - POSTGRES_PASSWORD=onlinejudge
      - JUDGE_SERVER_TOKEN=CHANGE_THIS
      # - FORCE_HTTPS=1
      # - STATIC_CDN_HOST=cdn.oj.com
    ports:
      - "0.0.0.0:80:8000"
      - "0.0.0.0:443:1443"
```

You can see that it is divided into four services: Redis, Postgres, judge-server, and oj-backend.

However, I had one more requirement at the time, which was to support JavaScript. To achieve this goal, it was not enough to just deploy it. I also had to study how it worked.

## Further Study of QDUOJ

First, let's take a look at the architecture of this system. According to the documentation on GitHub, it is divided into several modules:

1. Backend(Django): https://github.com/QingdaoU/OnlineJudge
2. Frontend(Vue): https://github.com/QingdaoU/OnlineJudgeFE
3. Judger Sandbox(Seccomp): https://github.com/QingdaoU/Judger
4. JudgeServer(A wrapper for Judger): https://github.com/QingdaoU/JudgeServer

The issue that we are most concerned about (how to add a new language) has already been raised in an issue: [How to add more language support, such as Ruby](https://github.com/QingdaoU/OnlineJudge/issues/149).

It is mentioned that modifying this file is enough: https://github.com/QingdaoU/OnlineJudge/blob/master/judge/languages.py.

This file is a configuration file, and you can guess what the Judge Server will do here. Here, the configuration of each language will have `compile_command` and `command`. The former is used to obtain the compilation command, and the latter is used to obtain the command to run the program. Since the input and output of this OJ are all through `stdin`/`stdout`, when you want to add a new programming language, you just need to tell the system how to execute it.

On the contrary, some OJs use functions to fill in the blanks, such as LeetCode mentioned at the beginning. At this time, if you want to add a new language, it will be more troublesome because you need to provide a function template additionally.

In theory, we just need to add such settings:

``` python
js_lang_config = {
   "run": {
       "exe_name": "solution.js",
       "command": "/usr/bin/nodejs {exe_path}",
       "seccomp_rule": "general",
   }
}
```

But if you run it like this, you will find a problem. Someone has already reported it: [problem with adding js to language configs](https://github.com/QingdaoU/JudgeServer/issues/16). The solution is to set `seccomp_rule` to `None`.

What is `seccomp`? This is related to the principle of OJ! You can think carefully about the most important question in OJ:

> How to safely execute user-submitted code?

If you don't know what this question is asking, you can imagine the following situations:

1. What if someone writes a code that restarts the computer?
2. What if someone writes an infinite loop?
3. What if someone writes a program that sends the host account password to an external server?

From this, it can be seen that executing code is not that simple, and this is also the core part of OJ.

The QDUOJ Judger source code is here: https://github.com/QingdaoU/Judger/tree/newnew/src.

It is written in C, forks a new process, sets some rules, and then uses [execve](https://github.com/QingdaoU/Judger/blob/newnew/src/child.c#L163) to execute the command. In the [code](https://github.com/QingdaoU/Judger/blob/b6414e7a6715eb013b1ffeb7cfb04626a3ff5b4e/src/rules/general.c), it can also be seen that [seccomp](https://blog.betamao.me/2019/01/23/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bseccomp/) is used to prevent the content mentioned above.

In short, QDUOJ is well-layered, and the execution process is roughly as follows:

1. Enter the front-end page made by Vue.
2. Submit the code and call the back-end API (Python).
3. The back-end API then calls the Judge Server API (Go).
4. The Judge Server API calls the Judger to execute the command (C, execve + seccomp execution).

So each project is responsible for its own tasks.

Going back to the issue of adding JavaScript mentioned earlier, even if `seccomp_rule` is set to `None`, there will still be errors when executing JavaScript. After studying for a day or two, I found that the problem was that the memory limit of the problem was too small. I guess that Node.js will consume more memory when it is executed, so as long as the memory is increased (for example, to 1024MB), it will be solved.

However, it is not over yet. There is one last problem, which is that the Node.js version on Ubuntu 16.04 is quite old, and a new version is needed to use ES6 syntax. The solution is to modify the [Dockerfile](https://github.com/Lidemy/JudgeServer/commit/9a98532f0f3504da20d13bd0aec4f4279a2a1fd2) of the JudgeServer and add a command to install the new version of Node.js.

After all the changes are made, you can deploy your own version! Just build the docker image first, and then modify the docker-compose file that we operated at the beginning.

In summary, if you don't want to make any changes and just want to deploy, I highly recommend QDUOJ. It's easy to deploy and has a nice interface.

## Writing your own OJ

I once tried to write my own OJ, but it was a very basic version: https://lidemy-oj.netlify.com/problems

![](https://static.coderbridge.com/img/aszx87410/016853899af54a40b11801d3e1d5f8d7.png)

At that time, I didn't think of using Linux commands to run it. Instead, I found the library [VM2](https://github.com/patriksimek/vm2) and thought it would be useful, so I had the idea of writing this simple OJ.

This simple OJ only supports JavaScript and uses the function writing method like LeetCode instead of standard input and output. I spent some time writing the prototype of the Judger:

``` js
const {VM} = require('vm2');
const lodash = require('lodash')

const RESULT_CODE = {
  AC: 'AC',
  WA: 'WA',
  CE: 'CE',
  RE: 'RE',
  TLE: 'TLE'
}

class Judge {
  constructor(schema, functionCode, timeout = 3000) {
    this.schema = schema
    this.functionCode = functionCode
    this.vm = new VM({
        timeout,
        sandbox: {
          __equal: lodash.isEqual
        }
    });
  }

  t(any) {
    return JSON.stringify(any)
  }

  addWrapper(schema, code, testCase) {
    return `
      ${code}
      (() => __equal(${schema.funcName}.apply(null, ${this.t(testCase.input)}), ${this.t(testCase.output)}))()
    `
  }

  runTest(testCase) {
    try {
      this.vm.run(this.functionCode)
    } catch(e) {
      return RESULT_CODE.RE
    }

    const wrapperedCode = this.addWrapper(this.schema, this.functionCode, testCase)
    try {
      return this.vm.run(wrapperedCode) ? RESULT_CODE.AC: RESULT_CODE.WA
    } catch(e) {
      return e.message === 'Script execution timed out.' ? RESULT_CODE.TLE : RESULT_CODE.WA
      console.log('err', e)
    }
  }

  run() {
    const testCases = this.schema.testCases
    const testResult = testCases.map(testCase => this.runTest(testCase))
    const correctCount = testResult.reduce((sum, res) => sum + (res === 'AC'), 0)
    return {
      score: Math.ceil(correctCount * ( 100 / testResult.length )),
      result: testResult
    }
  }
}

const test1 = {
  input: [1, 2],
  output: 3
}

const test2 = {
  input: [2, 4],
  output: 6
}

const problemSchema = {
  funcName: 'add',
  testCases: [test1, test2]
}

const input = `function add(a, b){
    return 3
  }`

const judge = new Judge(problemSchema, input)
const result = judge.run()
console.log(result)
```

The key code is `addWrapper` and `runTest`. In `addWrapper`, the function code passed in is executed, and the result is compared with the output to return true or false, indicating whether the match is successful or failed, and whether the answer is correct.

Then `problemSchema` is the format of the problem, which needs to have a `funcName` and `testCases`, and each test case has an `input` and `output`. With the above code, a super simple JS function-based Judger can be implemented.

However, this Judger has many shortcomings and cannot be compared with the execution method mentioned above.

Later, when I was researching, I found some good open-source solutions that can be referred to if someone wants to write their own OJ in the future.

The first is the sandbox [isolate](https://github.com/ioi/isolate) open-sourced by IOI, which can safely execute commands.

The second is even more amazing, it directly gives you the Judge API, and it's free: [Judge0 API](https://github.com/judge0/api). As long as you pass in the input according to its format, it will tell you the judging result, so you don't even need to make your own Judge Server.

## Conclusion

I wanted to build an OJ before, so I looked for a lot of information, and the biggest problem I encountered was: "I want an OJ that supports JavaScript", because many of them don't support it. Later, I had to write my own, which is the little toy written in JS mentioned above. Although it is still usable, many functions are incomplete, and it only supports the simplest answering.

Until January of this year, I wanted to create a real OJ. I originally considered whether to write it myself, but later thought it was too troublesome and decided to find an existing one to modify and add JS support. Although I still encountered some problems, fortunately, I succeeded in the end.

The final result is here: https://oj.lidemy.com/

This OJ is designed to accompany my latest free online course: [[ALG101] Don't rush to write LeetCode](https://lidemy.com/p/alg101-leetcode), which is a course for beginners. I hope to lay a solid foundation through a series of simple problems and cultivate programming thinking ability. Interested friends can take a look.
