# Facebook notes import

This documents the current manual workflow for importing posts from the
Facebook page into `source/notes/*.md`.

## Goal

Import recent posts from <https://www.facebook.com/huli.blog> as standalone
notes:

- one Markdown file per Facebook post
- `layout: note`
- short hand-written title
- slug in English
- links from Huli's own comments should be inline in the note when possible

## 1. Check the newest local note

```sh
find source/notes -maxdepth 1 -name '*.md' -print0 \
  | xargs -0 awk 'FNR==1{file=FILENAME} /^title:/{title=$0} /^date:/{print $0 " | " title " | " file}' \
  | sort -r \
  | head -10
```

Use this to decide which Facebook posts are newer than the local notes.

## 2. Fetch the Facebook page HTML

Facebook's normal desktop user agent often returns an error or a login shell.
The most reliable logged-out fetch so far is using a Googlebot user agent:

```sh
node - <<'NODE'
const fs = require('fs');

(async () => {
  const res = await fetch('https://www.facebook.com/huli.blog/', {
    headers: {
      'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'accept-language': 'zh-TW,zh;q=0.9,en;q=0.8'
    },
    redirect: 'follow'
  });

  const html = await res.text();
  fs.writeFileSync('/tmp/huli_fb_page.html', html);
  console.log(res.status, res.url, html.length);
})();
NODE
```

The useful data is embedded in the returned HTML as JSON-like Relay data.
Look for these fields:

- `creation_time`
- `post_id`
- `url`
- `message: { "__typename": "TextWithEntities", "text": ... }`

## 3. Extract candidate posts

This rough parser finds post messages and nearby timestamps/URLs. The HTML
contains duplicate story blocks, so dedupe by post id and message prefix.

```sh
node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('/tmp/huli_fb_page.html', 'utf8');

function decodeJsonString(value) {
  try {
    return JSON.parse('"' + value + '"');
  } catch {
    return value;
  }
}

const postRe = /"post_id":"(\d+)"[\s\S]{0,20000}?"message":\{"__typename":"TextWithEntities","text":"((?:\\.|[^"\\])*)"/g;
const posts = [];
let match;

while ((match = postRe.exec(html))) {
  const context = html.slice(Math.max(0, match.index - 50000), match.index + 50000);
  const times = [...context.matchAll(/"creation_time":(\d+)/g)]
    .map(item => Number(item[1]))
    .sort((a, b) => b - a);
  const postUrl = context
    .match(/https:\\\/\\\/www\.facebook\.com\\\/huli\.blog\\\/posts\\\/[^"\\]+/)?.[0]
    ?.replaceAll('\\/', '/');

  posts.push({
    post_id: match[1],
    date: times[0] ? new Date(times[0] * 1000).toISOString() : null,
    url: postUrl,
    text: decodeJsonString(match[2])
  });
}

const seen = new Set();
for (const post of posts) {
  const key = post.post_id + ':' + post.text.slice(0, 80);
  if (seen.has(key)) continue;
  seen.add(key);
  console.log('\n---');
  console.log(post.date, post.post_id);
  console.log(post.url);
  console.log(post.text.slice(0, 1200));
}
NODE
```

Pick posts newer than the newest local note.

## 4. Fetch an individual post for comment links

Many Facebook posts put related links in comments. Fetch the permalink with
the same Googlebot user agent:

```sh
node - <<'NODE'
const fs = require('fs');

const url = 'https://www.facebook.com/huli.blog/posts/REPLACE_WITH_PFBID';

(async () => {
  const res = await fetch(url, {
    headers: {
      'user-agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'accept-language': 'zh-TW,zh;q=0.9,en;q=0.8'
    }
  });

  const html = await res.text();
  fs.writeFileSync('/tmp/huli_fb_post.html', html);
  console.log(res.status, res.url, html.length);
})();
NODE
```

Then inspect text snippets and external URLs:

```sh
node - <<'NODE'
const fs = require('fs');
const html = fs.readFileSync('/tmp/huli_fb_post.html', 'utf8');

function decodeJsonString(value) {
  try {
    return JSON.parse('"' + value + '"');
  } catch {
    return value;
  }
}

const texts = [...html.matchAll(/"text":"((?:\\.|[^"\\])*)"/g)]
  .map(match => decodeJsonString(match[1]));

const uniqueTexts = [];
const seenTexts = new Set();
for (const text of texts) {
  const key = text.slice(0, 80);
  if (!seenTexts.has(key)) {
    seenTexts.add(key);
    uniqueTexts.push(text);
  }
}

for (const text of uniqueTexts.filter(text => /https?:|連結|參考|Postmortem|公告|文章/.test(text))) {
  console.log('\n---TEXT---\n' + text.slice(0, 2000));
}

const urls = [...html.matchAll(/https?:\\\/\\\/[^"\\]+/g)]
  .map(match => match[0].replaceAll('\\/', '/'));

console.log('\n---URLS---');
console.log([...new Set(urls)]
  .filter(url => !/fbcdn|facebook\.com\/ajax|static\.xx|lookaside|l\.facebook/.test(url))
  .join('\n'));
NODE
```

When a comment contains links from `Huli 隨意聊`, prefer integrating them into
the original paragraph. Avoid adding a separate `相關連結` heading unless there
is truly no natural place to put the link.

Also remove text such as:

- `連結放留言`
- `留言區附上`
- `文章留言會放連結`
- `細節放留言`

## 5. Create the note file

Use this format:

```md
---
layout: note
title: "短標題"
date: 2026-05-19 21:41:49
---
貼文內容...
```

Rules:

- file path: `source/notes/<english-slug>.md`
- date should be Asia/Tokyo local time, matching the rest of the notes
- title should be short
- keep the original wording unless link cleanup is needed
- inline comment links into relevant text
- do not include the Facebook permalink

Example conversion:

```md
稍微看了一下 TanStack 發的 [Postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)，剛好這塊我小熟，可以稍微聊一下。
```

## 6. Verify

```sh
npm run build
```

Then check:

```sh
node - <<'NODE'
const fs = require('fs');
const list = fs.readFileSync('public/notes/index.html', 'utf8');
const feed = fs.readFileSync('public/notes/atom.xml', 'utf8');

console.log({
  listHasNewNote: list.includes('/notes/REPLACE_SLUG/'),
  feedHasNewNote: feed.includes('https://blog.huli.tw/notes/REPLACE_SLUG/'),
  feedTitle: (feed.match(/<title>(.*?)<\/title>/) || [])[1]
});
NODE
```

If a dev server is needed:

```sh
npm run dev -- --port 4001
```

## Caveats

- Facebook's HTML shape changes often; these regexes are intentionally
  lightweight and may need adjustment.
- The page HTML may include duplicate story blocks.
- Some comment text in the fetched HTML may come from readers. Only import
  links/comments that are clearly from `Huli 隨意聊`.
- The crawler HTML may expose posts that are not visible with a normal browser
  session and vice versa. Always compare dates and content with existing notes.
