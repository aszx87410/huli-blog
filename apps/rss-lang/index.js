const fs = require('fs');
const path = require('path');

const basePath = path.join(__dirname, '../../')

function getNewRssFeed(rawRssFeed, fn) {
  let newFeed = rawRssFeed
  let startIndex = 0
  let endIndex = 0
  while((startIndex = rawRssFeed.indexOf('<entry>', startIndex+1)) >= 0) {
    endIndex = rawRssFeed.indexOf('</entry>', endIndex+1)
    const entry = rawRssFeed.slice(startIndex, endIndex + 8)
    const link = entry.match(/<id>[^<]*<\/id>/)
    if (!link) {
      console.log({
        startIndex,
        endIndex,
        entry
      })
    }
    if (fn(link[0])) {
      console.log('[RSS] Remove', link[0])
      newFeed = newFeed.replace(entry, '')
    }
  }
  return newFeed
}


async function main() {
  const rssPath = path.join(basePath, 'public/atom.xml')
  const rawRssFeed = fs.readFileSync(rssPath, 'utf-8')

  console.log('Generate English RSS feed')
  const enRss = getNewRssFeed(rawRssFeed, (link) => !link.includes('/en/'))
  fs.writeFileSync(path.join(basePath, 'public/atom-en.xml'), enRss)
  
  console.log('\nGenerate Chinese RSS feed')
  const chRss = getNewRssFeed(rawRssFeed, (link) => link.includes('/en/'))
  fs.writeFileSync(path.join(basePath, 'public/atom-ch.xml'), chRss)

}

main().catch(err => {
  console.error('Fatal error', err)
  throw new Error(err)
});