/* QSC documentation navigation and offline search enhancements.
 * Works with generated static Doxygen pages and file:// URLs.
 * No external scripts, cookies, or network services are required.
 */
(function () {
    'use strict';

    const searchIcon = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><circle cx="10.8" cy="10.8" r="6.8"></circle><path d="m16 16 5 5"></path></svg>';
    const sunIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.9 4.9l1.5 1.5m11.2 11.2 1.5 1.5M2 12h2m16 0h2M4.9 19.1l1.5-1.5M17.6 6.4l1.5-1.5"/></svg>';
    const moonIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5 8.5 8.5 0 1 0 20.5 14.5Z"/></svg>';
    const menuIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>';
    const currentFile = decodeURIComponent(window.location.pathname.split('/').pop() || 'index.html');
    const root = document.documentElement;

    function readTheme() {
        try {
            return window.localStorage.getItem('qsc-doc-theme');
        }
        catch (_) {
            return null;
        }
    }

    function setTheme(value) {
        const light = value === 'light';
        root.classList.toggle('light-mode', light);
        root.classList.toggle('dark-mode', !light);
        const button = document.getElementById('qsc-theme-toggle');

        if (button) {
            button.innerHTML = light ? moonIcon : sunIcon;
            button.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
            button.setAttribute('title', light ? 'Switch to dark theme' : 'Switch to light theme');
        }

        try {
            window.localStorage.setItem('qsc-doc-theme', light ? 'light' : 'dark');
        }
        catch (_) {
            // Storage may not be available for local file pages.
        }
    }

    function createChrome() {
        if (!document.querySelector('link[rel="icon"]')) {
            const favicon = document.createElement('link');
            favicon.rel = 'icon';
            favicon.type = 'image/png';
            favicon.href = 'qsc_favicon.png';
            document.head.appendChild(favicon);
        }
        const header = document.getElementById('top');

        if (!header || document.getElementById('qsc-global-nav')) {
            return;
        }

        const nav = document.createElement('div');
        nav.id = 'qsc-global-nav';
        nav.innerHTML =
            '<a class="qsc-brand" href="index.html" aria-label="QSC documentation home"><img src="qsc_brand_logo.png" width="48" height="48" alt=""/><span class="qsc-brand-qrcs">QRCS</span><span class="qsc-brand-rule" aria-hidden="true"></span><span class="qsc-brand-name">QSC</span><span class="qsc-brand-label">Quantum-Resilient<br/>Cryptographic SDK</span></a>' +
            '<nav class="qsc-nav-items" id="qsc-nav-items" aria-label="Primary navigation"><a href="index.html"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m3 10 9-7 9 7v11h-6v-7H9v7H3Z"/></svg><span>Home</span></a><a href="qsc_getting_started.html"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 6C9.2 4.3 6 4.2 3 5v14c3-.8 6.2-.7 9 1m0-14c2.8-1.7 6-1.8 9-1v14c-3-.8-6.2-.7-9 1M12 6v14"/></svg><span>Getting Started</span></a><a href="qsc_api_catalog.html"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg><span>API Reference</span></a><a href="files.html"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m12 2 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 17l9 5 9-5"/></svg><span>Modules</span></a><a href="qsc_getting_started.html#contracts"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M13 2H5a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V10l-8-8Zm0 0v8h8M7 15h10M7 19h7"/></svg><span>Guides</span></a><a href="qsc_api_catalog.html#testing"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 2h6M10 2v7l-6.5 10A2 2 0 0 0 5.2 22h13.6a2 2 0 0 0 1.7-3L14 9V2M7 16h10"/></svg><span>Validation</span></a><a href="qsc_getting_started.html#choose"><svg class="qsc-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M9.3 9a2.8 2.8 0 0 1 5.5.7c0 2-2.8 2.5-2.8 4.8m0 3.3v.2"/></svg><span>Help</span></a></nav>' +
            '<div class="qsc-nav-tools"><button class="qsc-search-trigger" type="button" data-qsc-open-search="true" aria-label="Search documentation">' +
            searchIcon + '<span>Search documentation…</span><kbd>Ctrl+K</kbd></button>' +
            '<button type="button" id="qsc-theme-toggle" class="qsc-icon-button" title="Toggle theme" aria-label="Toggle theme">' + sunIcon + '</button>' +
            '<button type="button" id="qsc-menu-toggle" class="qsc-icon-button qsc-menu-button" aria-controls="qsc-nav-items" aria-expanded="false" aria-label="Open navigation">' + menuIcon + '</button></div>';
        header.appendChild(nav);

        const active = currentFile === 'index.html' || !currentFile ? 'index.html' :
            (currentFile === 'qsc_getting_started.html' || currentFile === 'qsc_api_catalog.html' || currentFile === 'annotated.html' || currentFile === 'files.html' ? currentFile : '');
        const selected = nav.querySelector('.qsc-nav-items a[href="' + active + '"]');

        if (selected) {
            selected.setAttribute('aria-current', 'page');
        }

        document.getElementById('qsc-theme-toggle').addEventListener('click', function () {
            setTheme(root.classList.contains('light-mode') ? 'dark' : 'light');
        });
        document.getElementById('qsc-menu-toggle').addEventListener('click', function () {
            const list = document.getElementById('qsc-nav-items');
            const isOpen = list.classList.toggle('qsc-nav-open');
            this.setAttribute('aria-expanded', String(isOpen));
            this.setAttribute('aria-label', isOpen ? 'Close navigation' : 'Open navigation');
        });
        setTheme(readTheme() === 'light' ? 'light' : 'dark');
    }

    function createBreadcrumb() {
        if (document.body.classList.contains('qsc-landing')) {
            return;
        }

        const content = document.getElementById('doc-content');
        const heading = content && content.querySelector('.header .title');

        if (!content || !heading || content.querySelector('.qsc-breadcrumb')) {
            return;
        }

        const isStruct = /^struct|^union|^annotated|^classes|^functions/.test(currentFile);
        const isFile = /_8[hc](_source)?\.html$/.test(currentFile) || /^dir_|^files|^globals/.test(currentFile);
        const family = isStruct ? ['Data structures', 'annotated.html'] : isFile ? ['File reference', 'files.html'] : ['Documentation', 'index.html'];
        const label = heading.textContent.trim().replace(/\s+/g, ' ');
        const breadcrumb = document.createElement('nav');
        breadcrumb.className = 'qsc-breadcrumb';
        breadcrumb.setAttribute('aria-label', 'Breadcrumb');
        const home = document.createElement('a');
        home.href = 'index.html';
        home.textContent = 'Overview';
        breadcrumb.appendChild(home);
        const separator = document.createElement('span');
        separator.className = 'qsc-crumb-divider';
        separator.setAttribute('aria-hidden', 'true');
        separator.textContent = '/';
        breadcrumb.appendChild(separator);
        const category = document.createElement('a');
        category.href = family[1];
        category.textContent = family[0];
        breadcrumb.appendChild(category);
        const separator2 = separator.cloneNode(true);
        breadcrumb.appendChild(separator2);
        const current = document.createElement('span');
        current.className = 'qsc-crumb-current';
        current.textContent = label;
        breadcrumb.appendChild(current);
        content.insertBefore(breadcrumb, content.firstChild);
    }

    let searchLoaded = false;
    let searchLoading = false;
    let results = [];
    let selectedResult = -1;
    let previousFocus = null;
    let overlay;
    let searchField;
    let resultContainer;
    let countLabel;

    function ensureSearchIndex() {
        if (searchLoaded || searchLoading) {
            return;
        }

        searchLoading = true;
        const script = document.createElement('script');
        script.src = 'qsc_search_data.js';
        script.addEventListener('load', function () {
            searchLoaded = true;
            searchLoading = false;
            renderSearch();
        });
        script.addEventListener('error', function () {
            searchLoading = false;
            countLabel.textContent = 'SEARCH INDEX UNAVAILABLE';
            resultContainer.textContent = 'The local search index could not be loaded. Use the API catalog or file index.';
            resultContainer.classList.add('qsc-search-empty');
        });
        document.head.appendChild(script);
    }

    function createSearch() {
        overlay = document.createElement('div');
        overlay.id = 'qsc-search-dialog';
        overlay.className = 'qsc-search-overlay';
        overlay.hidden = true;
        overlay.innerHTML = '<div class="qsc-search-panel" role="dialog" aria-modal="true" aria-label="Search QSC documentation">' +
            '<div class="qsc-search-input-row">' + searchIcon +
            '<input id="qsc-search-input" type="search" autocomplete="off" spellcheck="false" aria-label="Search files, functions and structures" placeholder="Search files, functions, structures…"/>' +
            '<button class="qsc-search-close" type="button" data-qsc-close="true" aria-label="Close search">ESC</button></div>' +
            '<div class="qsc-search-count" id="qsc-search-count">SEARCH REFERENCE</div>' +
            '<div class="qsc-search-results" id="qsc-search-results" role="listbox" aria-label="Search results"></div>' +
            '<div class="qsc-search-footer"><span><kbd>&uarr;</kbd><kbd>&darr;</kbd> Navigate</span><span><kbd>Enter</kbd> Open</span><span><kbd>Esc</kbd> Close</span><span>Offline index</span></div></div>';
        document.body.appendChild(overlay);
        searchField = overlay.querySelector('#qsc-search-input');
        resultContainer = overlay.querySelector('#qsc-search-results');
        countLabel = overlay.querySelector('#qsc-search-count');
        overlay.addEventListener('click', function (event) {
            if (event.target === overlay || event.target.closest('[data-qsc-close]')) {
                closeSearch();
            }
        });
        searchField.addEventListener('input', renderSearch);
        searchField.addEventListener('keydown', function (event) {
            if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                event.preventDefault();
                if (!results.length) {
                    return;
                }
                selectedResult = (selectedResult + (event.key === 'ArrowDown' ? 1 : -1) + results.length) % results.length;
                highlightSelection();
            }
            else if (event.key === 'Enter' && results.length) {
                event.preventDefault();
                window.location.href = results[Math.max(selectedResult, 0)].h;
            }
        });
    }

    function openSearch() {
        if (!overlay) {
            createSearch();
        }
        previousFocus = document.activeElement;
        overlay.hidden = false;
        searchField.value = '';
        selectedResult = -1;
        searchField.focus();
        countLabel.textContent = 'LOADING LOCAL SEARCH INDEX…';
        ensureSearchIndex();
        if (searchLoaded) {
            renderSearch();
        }
    }

    function closeSearch() {
        if (overlay) {
            overlay.hidden = true;
        }
        if (previousFocus && previousFocus.focus) {
            previousFocus.focus();
        }
    }

    function highlightSelection() {
        Array.from(resultContainer.querySelectorAll('a.qsc-result')).forEach(function (item, index) {
            item.classList.toggle('qsc-result-active', index === selectedResult);
            item.setAttribute('aria-selected', String(index === selectedResult));
            if (index === selectedResult) {
                item.scrollIntoView({ block: 'nearest' });
            }
        });
    }

    function rank(item, searchTerms) {
        const name = item.n.toLowerCase();
        const detail = (item.d || '').toLowerCase();
        const text = name + ' ' + detail;
        if (!searchTerms.every(function (term) { return text.includes(term); })) {
            return -1;
        }
        let score = 0;
        const whole = searchTerms.join(' ');
        if (name === whole) { score += 1000; }
        if (name.startsWith(whole)) { score += 500; }
        if (name.includes(whole)) { score += 200; }
        if (item.t === 'Header') { score += 30; }
        if (item.t === 'Function') { score += 20; }
        score -= name.length * .1;
        return score;
    }

    function renderSearch() {
        if (!searchLoaded || !window.QSC_SEARCH_INDEX || !resultContainer) {
            return;
        }
        const query = searchField.value.trim().toLowerCase();
        const terms = query.split(/\s+/).filter(Boolean);
        const index = window.QSC_SEARCH_INDEX;
        const scored = index.map(function (item) { return { item: item, score: terms.length ? rank(item, terms) : (item.f ? 120 : -1) }; })
            .filter(function (candidate) { return candidate.score >= 0; })
            .sort(function (a, b) { return b.score - a.score || a.item.n.localeCompare(b.item.n); });
        results = scored.slice(0, 35).map(function (candidate) { return candidate.item; });
        selectedResult = -1;
        resultContainer.replaceChildren();
        resultContainer.classList.remove('qsc-search-empty');
        countLabel.textContent = terms.length ? scored.length.toLocaleString() + ' MATCH' + (scored.length === 1 ? '' : 'ES') + ' — TOP RESULTS' : 'SUGGESTED API ENTRIES';

        if (!results.length) {
            const empty = document.createElement('p');
            empty.className = 'qsc-search-empty';
            empty.textContent = 'No matches found. Try a header name, symbol prefix (qsc_), or algorithm family.';
            resultContainer.appendChild(empty);
            return;
        }

        results.forEach(function (item, indexValue) {
            const link = document.createElement('a');
            link.className = 'qsc-result';
            link.href = item.h;
            link.setAttribute('role', 'option');
            link.setAttribute('aria-selected', 'false');
            link.id = 'qsc-result-' + indexValue;
            const title = document.createElement('span');
            title.className = 'qsc-result-title';
            const name = document.createElement('span');
            name.textContent = item.n;
            const type = document.createElement('span');
            type.className = 'qsc-result-type';
            type.textContent = item.t.toUpperCase();
            title.appendChild(name);
            title.appendChild(type);
            const detail = document.createElement('span');
            detail.className = 'qsc-result-detail';
            detail.textContent = item.d || item.h.split('#')[0];
            link.appendChild(title);
            link.appendChild(detail);
            link.addEventListener('mouseenter', function () {
                selectedResult = indexValue;
                highlightSelection();
            });
            resultContainer.appendChild(link);
        });
    }


    function initializeEditorialScrolling() {
        if (!document.body.classList.contains('qsc-landing')) {
            return;
        }
        const content = document.getElementById('doc-content');
        // Doxygen's resizable navigation assigns a fixed inline height to #doc-content.
        // Landing pages instead use document scrolling to avoid two competing scroll roots.
        if (content) {
            content.style.setProperty('height', 'auto', 'important');
            content.style.setProperty('overflow', 'visible', 'important');
        }
        if (!document.body.classList.contains('qsc-concept-landing')) {
            const back = document.createElement('button');
            back.className = 'qsc-back-to-top';
            back.type = 'button';
            back.setAttribute('aria-label', 'Back to top of page');
            back.innerHTML = '<span aria-hidden="true">↑</span> Back to top';
            document.body.appendChild(back);
            const refresh = function () {
                back.hidden = window.scrollY < 220;
            };
            back.addEventListener('click', function () {
                if (content) {
                    content.scrollTop = 0;
                }
                window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
                document.documentElement.scrollTop = 0;
                document.body.scrollTop = 0;
            });
            window.addEventListener('scroll', refresh, { passive: true });
            refresh();
        }
    }

    function initializeQscNavigation() {
        createChrome();
        initializeEditorialScrolling();
        createBreadcrumb();
        document.addEventListener('click', function (event) {
            const button = event.target.closest('[data-qsc-open-search]');
            if (button) {
                event.preventDefault();
                openSearch();
            }
        });
        document.addEventListener('keydown', function (event) {
            const el = document.activeElement;
            const typing = el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
                event.preventDefault();
                openSearch();
            }
            else if (event.key === '/' && !typing && !event.ctrlKey && !event.metaKey && !event.altKey) {
                event.preventDefault();
                openSearch();
            }
            else if (event.key === 'Escape' && overlay && !overlay.hidden) {
                closeSearch();
            }
            else if (event.key === 'Tab' && overlay && !overlay.hidden) {
                const focusable = Array.from(overlay.querySelectorAll('input, button, a[href]')).filter(function (node) { return node.offsetParent !== null; });
                if (focusable.length) {
                    const first = focusable[0];
                    const last = focusable[focusable.length - 1];
                    if (event.shiftKey && document.activeElement === first) {
                        event.preventDefault();
                        last.focus();
                    }
                    else if (!event.shiftKey && document.activeElement === last) {
                        event.preventDefault();
                        first.focus();
                    }
                }
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeQscNavigation);
    }
    else {
        initializeQscNavigation();
    }
}());
