---
layout: note
title: "YAML解析差異怪物"
date: 2025-07-01 20:46:25
---
同一個 YAML 拿給不同的程式語言，居然可以產生多種不同的結果？

有一種攻擊手法叫做 parser differential，利用不同 parser 之間的差異來創造出魔法。舉個例子，?a=1&a=2，請問後端拿到的 a 是多少？

有些會是前面的 1，有些會是後面的 2，有些給你一個陣列 [1,2]，有些幫你拼在一起變 "1,2"，這就算是一種 parser differential 了，針對同一個字串的解析結果不同。

同樣一個東西 A 解讀的結果跟 B 解讀的結果不同，怎麼想都會有問題。就算不是資安上的問題好了，也很可能某天會造成程式的 bug，導致某些邏輯錯誤。

因此，只要有 parser 的地方，就會有很多去研究 parser 的人，以及很多試圖找出 parser 之間差異的人。

前不久就讀到了 @taramtrampam 的一篇文章，寫說他看到 @joernchen 的推特，用了同一個 yaml 檔案，讓三個程式語言解讀出不同的結果，例如說用 golang 就會出現 lang: go，用 ruby 就會出現 lang: ruby，以此類推。

而他看到之後覺得很有趣，就繼續深挖，最後創造出了一個可以讓 Ruby, Java, NodeJS, Go, Python, Rust 都解讀出不同結果的 YAML monsters，也就是大家圖中看到的這個 YAML。

看來 YAML 除了著名的「挪威問題」以外，還有很多有趣的功能呢

（挪威問題是，當你在 YAML 寫 str: TW 時，str 就是個字串 "TW"，但你如法炮製寫 str: NO 時，str 就變成了 false，因為在 YAML 中 NO 是一種 false，所以要寫成 str: "NO" 才會是字串 😅）

補充文章：

- <https://gist.github.com/taramtrampam/fca4e599992909b48a3ba1ce69e215a2>
- <https://gitlab-com.gitlab.io/gl-security/security-tech-notes/security-research-tech-notes/devfile/>
