/*
 * In-place filtering for the dashboards (SOC + Executive).
 *
 * Every filter on these pages is a plain `?query` link or a GET form, so
 * without this script they still work as normal page loads. With it, the next
 * view is fetched and swapped into the page's root element instead:
 *   - the page keeps its scroll position (no jump to the top and back down);
 *   - the region the click changed gets a brief ring + label (focus effect);
 *   - the 5-minute auto-refresh updates in place too.
 * Anything unexpected (expired session → login redirect, an error page) falls
 * back to a normal page load.
 *
 * Usage (from a page's nonce'd inline script):
 *   const nav = DashboardInplace.init({
 *     rootId: 'exec-root',              // element swapped on every update
 *     filterBarSelector: '.exec-filterbar',
 *     sections: { 'exec-crit': 'crit' },// optional <details> id → ?open= key
 *     liveRegionId: 'exec-live',        // optional aria-live element
 *     onSwap(opts) { ... },             // rebuild charts etc. after a swap
 *   });
 *   nav.go(url, { push: true, flashRange: true });
 *
 * Markup hooks the script understands:
 *   [data-flash-label]  text shown on the ring when that element is flashed
 *   [data-flash-range]  regions that change with the filter bar
 *   [data-flash-scope]  (with an id) a region whose own links re-render it,
 *                       e.g. a table's sort headers and pagination
 *   [data-range-scope]  the filter summary in the filter bar (always visible)
 *   [data-details-all="open|close"]  expand / collapse every section
 *   .js-autosubmit      select that applies its form on change
 *
 * The ring styles (.inplace-flash, .inplace-flash-tag) live in base.html.
 */
(function () {
    'use strict';

    var FLASH_MS = 2300;
    var AUTO_REFRESH_MS = 300000;
    var IDLE_GRACE_MS = 15000;

    function reducedMotion() {
        return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }

    function flash(el, label) {
        if (!el) return;
        el.classList.remove('inplace-flash');
        el.querySelectorAll(':scope > .inplace-flash-tag').forEach(function (t) { t.remove(); });
        void el.offsetWidth;  // restart the animation if it is still running
        el.classList.add('inplace-flash');
        if (label) {
            var tag = document.createElement('span');
            tag.className = 'inplace-flash-tag';
            tag.setAttribute('aria-hidden', 'true');  // the live region reads it
            tag.textContent = label;
            el.prepend(tag);
        }
        setTimeout(function () {
            el.classList.remove('inplace-flash');
            el.querySelectorAll(':scope > .inplace-flash-tag').forEach(function (t) { t.remove(); });
        }, FLASH_MS);
    }

    // Rendered (not inside a closed <details>) and at least partly on screen.
    function onScreen(el) {
        if (!el) return false;
        var closed = el.closest('details:not([open])');
        if (closed && closed !== el) return false;
        var r = el.getBoundingClientRect();
        return r.bottom > 0 && r.top < window.innerHeight;
    }

    function rendered(el) {
        var closed = el.closest('details:not([open])');
        return !closed || closed === el;
    }

    function init(cfg) {
        var ROOT_ID = cfg.rootId;
        var rootSel = '#' + ROOT_ID;
        var SECTIONS = cfg.sections || {};
        var ORDER = Object.keys(SECTIONS).map(function (k) { return SECTIONS[k]; });
        var live = cfg.liveRegionId ? document.getElementById(cfg.liveRegionId) : null;
        var indicator = document.getElementById('page-loading-indicator');
        var inflight = null;

        // ── Collapsible sections: independent; every update sends exactly
        //    the set the viewer has open (?open=a,b), plus a link's target.
        function sectionOf(id) {
            var el = id && document.getElementById(id);
            var box = el && el.closest('details');
            return box && SECTIONS[box.id] ? SECTIONS[box.id] : '';
        }

        function openSections(extra) {
            var keys = [];
            Object.keys(SECTIONS).forEach(function (id) {
                var d = document.getElementById(id);
                if (d && d.open) keys.push(SECTIONS[id]);
            });
            if (extra) keys.push(extra);
            return ORDER.filter(function (k) { return keys.indexOf(k) >= 0; });
        }

        function withOpenSections(href, hash) {
            var u = new URL(href, window.location.href);
            if (ORDER.length) u.searchParams.set('open', openSections(sectionOf(hash)).join(','));
            return u;
        }

        function refreshToggleAll() {
            var all = document.querySelectorAll(rootSel + ' details[id]');
            var open = document.querySelectorAll(rootSel + ' details[id][open]');
            document.querySelectorAll(rootSel + ' [data-details-all]').forEach(function (btn) {
                btn.hidden = false;
                btn.disabled = btn.dataset.detailsAll === 'open'
                    ? open.length === all.length : open.length === 0;
            });
        }

        function syncOpenParam() {
            if (!ORDER.length) return;
            var u = new URL(window.location.href);
            u.searchParams.set('open', openSections().join(','));
            history.replaceState(history.state, '', u.href);
            refreshToggleAll();
        }

        // ── The swap ──────────────────────────────────────────────────────
        async function go(url, opts) {
            opts = opts || {};
            var target = new URL(url, window.location.href);
            var hash = target.hash.slice(1);
            target.hash = '';
            var root = document.getElementById(ROOT_ID);
            if (!root) { window.location.href = url; return; }

            // Remember where the destination sits on screen now, so it can stay put.
            var anchorId = hash || opts.flashScopeId || '';
            var before = anchorId ? document.getElementById(anchorId) : null;
            var anchorOffset = onScreen(before) ? before.getBoundingClientRect().top : null;
            var scrollY = window.scrollY;

            if (inflight) inflight.abort();
            inflight = new AbortController();
            root.setAttribute('aria-busy', 'true');
            if (!opts.quiet && indicator) indicator.classList.add('is-active');
            var done = function () { if (indicator) indicator.classList.remove('is-active'); };
            var fullLoad = function () { window.location.href = target.href + (hash ? '#' + hash : ''); };

            var res;
            try {
                res = await fetch(target.href, {
                    credentials: 'same-origin',
                    headers: { 'X-Requested-With': 'XMLHttpRequest' },
                    signal: inflight.signal,
                });
            } catch (err) {
                if (err.name === 'AbortError') return;
                root.removeAttribute('aria-busy');
                done();
                // Network down: a background refresh just tries again next time.
                if (!opts.quiet) fullLoad();
                return;
            }
            var fresh = null;
            if (res.ok && new URL(res.url).pathname === target.pathname) {
                fresh = new DOMParser().parseFromString(await res.text(), 'text/html').getElementById(ROOT_ID);
            }
            if (!fresh) { fullLoad(); return; }
            root.replaceWith(fresh);
            done();
            if (opts.push) history.pushState({ inplace: true }, '', target.href);
            if (cfg.onSwap) cfg.onSwap(opts);
            refreshToggleAll();

            // Bootstrap sets `scroll-behavior: smooth` on :root, so corrective
            // scrolls must say 'instant' or the page visibly glides.
            var after = anchorId ? document.getElementById(anchorId) : null;
            if (after && anchorOffset !== null) {
                window.scrollBy({ top: after.getBoundingClientRect().top - anchorOffset, behavior: 'instant' });
            } else if (after && hash && !opts.keepScroll) {
                window.scrollTo({ top: scrollY, behavior: 'instant' });
                after.scrollIntoView({ behavior: reducedMotion() ? 'instant' : 'smooth', block: 'start' });
            } else {
                window.scrollTo({ top: scrollY, behavior: 'instant' });
            }

            // Point the eye at what changed.
            var message = '';
            if (!opts.quiet) {
                if (after) {
                    message = after.dataset.flashLabel || '';
                    flash(after, message);
                } else if (opts.flashRange) {
                    var scope = fresh.querySelector('[data-range-scope]');
                    message = scope ? (scope.dataset.flashLabel || scope.textContent.trim()) : '';
                    if (scope) flash(scope, '');
                    var blocks = Array.prototype.filter.call(
                        fresh.querySelectorAll('[data-flash-range]'), rendered);
                    var firstVisible = blocks.find(onScreen);
                    blocks.forEach(function (el) { flash(el, el === firstVisible ? message : ''); });
                }
                if (live) live.textContent = 'อัปเดตแล้ว' + (message ? ': ' + message : '');
            }

            // Keyboard users keep their place: refocus the equivalent control.
            if (opts.focusHref) {
                var same = Array.prototype.find.call(fresh.querySelectorAll('a[href]'), function (a) {
                    return a.getAttribute('href') === opts.focusHref;
                });
                if (same) same.focus({ preventScroll: true });
                else if (after) { after.setAttribute('tabindex', '-1'); after.focus({ preventScroll: true }); }
            }
        }

        function formUrl(form) {
            var params = new URLSearchParams(new FormData(form));
            return withOpenSections('?' + params.toString()).href;
        }

        // ── Wiring ────────────────────────────────────────────────────────
        document.addEventListener('click', function (e) {
            var allBtn = e.target.closest(rootSel + ' [data-details-all]');
            if (allBtn) {
                var open = allBtn.dataset.detailsAll === 'open';
                document.querySelectorAll(rootSel + ' details[id]').forEach(function (d) { d.open = open; });
                syncOpenParam();
                return;
            }
            if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            var a = e.target.closest(rootSel + ' a[href^="?"]');
            if (!a || a.target) return;
            e.preventDefault();
            var raw = a.getAttribute('href');
            var hash = raw.indexOf('#') >= 0 ? raw.split('#')[1] : '';
            var inFilterBar = cfg.filterBarSelector && a.closest(cfg.filterBarSelector);
            var scopeEl = !hash && !inFilterBar ? a.closest('[data-flash-scope][id]') : null;
            go(withOpenSections(raw, hash).href, {
                push: true, focusHref: raw,
                flashRange: !hash && !!inFilterBar,
                flashScopeId: scopeEl ? scopeEl.id : '',
            });
        });

        document.addEventListener('submit', function (e) {
            var form = e.target.closest(rootSel + ' form');
            if (!form || (form.method || 'get').toLowerCase() !== 'get') return;
            e.preventDefault();
            go(formUrl(form), { push: true, flashRange: true });
        });

        // base.html binds `.js-autosubmit` once at page load with a full
        // form.submit(). Take the change first (capture) so swapped-in selects
        // work too, and stop the full reload.
        document.addEventListener('change', function (e) {
            var el = e.target;
            if (!el.matches || !el.matches(rootSel + ' .js-autosubmit') || !el.form) return;
            e.stopPropagation();
            go(formUrl(el.form), { push: true, flashRange: true });
        }, true);

        // `toggle` does not bubble, so listen in the capture phase.
        document.addEventListener('toggle', function (e) {
            if (e.target.matches && e.target.matches(rootSel + ' details[id]')) syncOpenParam();
        }, true);

        window.addEventListener('popstate', function () {
            go(window.location.href, { keepScroll: true, quiet: true });
        });

        refreshToggleAll();

        // Quiet auto-refresh: idle viewer only, visible tab, online, and not
        // while a form control has focus. Refreshes in place, so the scroll
        // position and open sections stay.
        var userActiveUntil = 0;
        ['pointerdown', 'keydown', 'input', 'change', 'focusin'].forEach(function (name) {
            document.addEventListener(name, function () { userActiveUntil = Date.now() + IDLE_GRACE_MS; },
                { capture: true, passive: true });
        });
        var interactive = 'input, select, textarea, [contenteditable="true"]';
        setInterval(function () {
            if (document.visibilityState !== 'visible') return;
            if (Date.now() < userActiveUntil) return;
            if (navigator.onLine === false) return;
            var active = document.activeElement;
            if (active && active !== document.body && active.matches(interactive)) return;
            go(withOpenSections(window.location.href).href, { keepScroll: true, quiet: true });
        }, AUTO_REFRESH_MS);

        return { go: go, withOpenSections: withOpenSections, flash: flash };
    }

    window.DashboardInplace = { init: init };
})();
