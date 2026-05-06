const path = require('path');

const NOTES_BASE = 'notes';
const NOTES_FEED_LIMIT = 20;
const NOTES_PER_PAGE = 20;

function isNotePage(page) {
    return page
        && page.layout === 'note'
        && typeof page.source === 'string'
        && /^notes\/[^/]+\.md$/.test(page.source);
}

function noteSlug(page) {
    return path.basename(page.source, path.extname(page.source));
}

function normalizeNote(page) {
    const slug = noteSlug(page);
    page.path = `${NOTES_BASE}/${slug}/index.html`;
    page.lang = 'zh-tw';
    page.toc = false;
    page.comments = true;
    page.__note = true;
    return page;
}

function noteTimestamp(note) {
    return note.date && typeof note.date.valueOf === 'function'
        ? note.date.valueOf()
        : new Date(note.date).getTime();
}

function notePermalink(config, note) {
    return `${config.url.replace(/\/$/, '')}/${note.path.replace(/index\.html$/, '')}`;
}

function escapeXml(value) {
    return String(value || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;');
}

function cdata(value) {
    return `<![CDATA[${String(value || '').replace(/\]\]>/g, ']]]]><![CDATA[>')}]]>`;
}

function atomDate(date) {
    return date && typeof date.toISOString === 'function'
        ? date.toISOString()
        : new Date(date).toISOString();
}

function getNotes(pages) {
    const list = pages.toArray ? pages.toArray() : Array.from(pages);
    const notes = list.filter(isNotePage).map(normalizeNote);
    const missingTitle = notes.find(note => !note.title);
    if (missingTitle) {
        throw new Error(`Note "${missingTitle.source}" is missing required front matter: title`);
    }

    return notes.sort((a, b) => noteTimestamp(b) - noteTimestamp(a));
}

function renderNotesFeed(config, notes) {
    const siteUrl = config.url.replace(/\/$/, '');
    const feedUrl = `${siteUrl}/${NOTES_BASE}/atom.xml`;
    const pageUrl = `${siteUrl}/${NOTES_BASE}/`;
    const updated = notes.length > 0 ? atomDate(notes[0].updated || notes[0].date) : atomDate(new Date());
    const entries = notes.slice(0, NOTES_FEED_LIMIT).map(note => {
        const permalink = notePermalink(config, note);
        const updated = atomDate(note.updated || note.date);
        const published = atomDate(note.date);

        return [
            '  <entry>',
            `    <title>${escapeXml(note.title)}</title>`,
            `    <id>${escapeXml(permalink)}</id>`,
            `    <link href="${escapeXml(permalink)}"/>`,
            `    <updated>${updated}</updated>`,
            `    <published>${published}</published>`,
            `    <content type="html">${cdata(note.content)}</content>`,
            '  </entry>'
        ].join('\n');
    }).join('\n');

    return [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        '  <title>Huli 隨意聊</title>',
        `  <id>${escapeXml(pageUrl)}</id>`,
        `  <link href="${escapeXml(pageUrl)}"/>`,
        `  <link rel="self" href="${escapeXml(feedUrl)}"/>`,
        `  <updated>${updated}</updated>`,
        entries,
        '</feed>'
    ].filter(Boolean).join('\n');
}

function notesPagePath(pageNumber) {
    return pageNumber === 1
        ? `${NOTES_BASE}/index.html`
        : `${NOTES_BASE}/page/${pageNumber}/index.html`;
}

function buildNotesPage(notes, pageNumber, totalPages) {
    const start = (pageNumber - 1) * NOTES_PER_PAGE;
    const pageNotes = notes.slice(start, start + NOTES_PER_PAGE);

    return {
        path: notesPagePath(pageNumber),
        layout: ['notes', 'index'],
        data: {
            title: pageNumber === 1 ? '隨意聊' : `隨意聊 - 第 ${pageNumber} 頁`,
            path: notesPagePath(pageNumber),
            lang: 'zh-tw',
            __notes: true,
            notes: pageNotes,
            totalNotes: notes.length,
            currentPage: pageNumber,
            totalPages,
            perPage: NOTES_PER_PAGE
        }
    };
}

hexo.extend.filter.register('before_generate', function () {
    getNotes(this.locals.get('pages'));
});

hexo.extend.filter.register('before_post_render', function (data) {
    if (isNotePage(data)) {
        normalizeNote(data);
    }
    return data;
});

hexo.extend.helper.register('is_notes_page', function () {
    return !!(this.page && (this.page.__notes || this.page.__note || this.page.layout === 'note'));
});

hexo.extend.helper.register('note_permalink', function (note) {
    return notePermalink(this.config, note);
});

hexo.extend.generator.register('notes', function (locals) {
    const notes = getNotes(locals.pages);
    const totalPages = Math.max(1, Math.ceil(notes.length / NOTES_PER_PAGE));
    const pages = [];

    for (let pageNumber = 1; pageNumber <= totalPages; pageNumber++) {
        pages.push(buildNotesPage(notes, pageNumber, totalPages));
    }

    return pages.concat([
        {
            path: `${NOTES_BASE}/atom.xml`,
            data: renderNotesFeed(this.config, notes)
        }
    ]);
});
