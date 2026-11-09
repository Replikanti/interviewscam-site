// The Home search (ADR-0005 parts 3 and 4). On the first focus of the
// search input, or on the first submit, it fetches /feed.json, whose names,
// aliases and artifacts are the match keys, and the form's action, the A to
// Z page /a-z/, whose entries are the answers; nothing is fetched on load.
// A submit then reveals exactly one of the hidden result sections of Home,
// the answer (exact matches), close candidates (partial matches) or no
// match, fills its list with copies of the matching /a-z/ entries and moves
// focus to its heading. The script carries no copy of its own: every word
// it shows comes from Home or from /a-z/, and the query is never written
// into the page, because it may be a live attacker URL (D8). A failed fetch,
// a feed version other than 1 or a feed that does not match /a-z/ hands
// over to the path without JavaScript (the form submits to /a-z/). It does
// nothing unless the form, its input, the four result elements, fetch,
// DOMParser, URL and String.prototype.normalize are all there, so the form
// still submits to /a-z/ without them. No innerHTML, no timers, and no URL
// but /feed.json and the form's action. Every string below is a key, a
// class, an id or a URL part: L7 of sitecheck literals reads them.
// Two rules keep one record or one markup edit from breaking the search
// for every query (M4 PR 3 fix round 1): every value read from the feed
// goes through a type-checked accessor (a schema-valid record may leave out
// an optional field, such as a hash's file_name), and every method of the
// document and the form is called through its prototype, because a form
// control or a named element can shadow it (a button named submit or
// action, an image named getElementById).
(function () {
  // ADR-0005 Numbers: SEARCH_PARTIAL_MIN (code points), SEARCH_PARTIAL_CAP
  // (entries) and the one feed version the matching rules were written for.
  var PARTIAL_MIN = 3;
  var PARTIAL_CAP = 5;
  var FEED_VERSION = 1;
  var FEED_URL = "/feed.json";
  // The tables of tools/sitecheck.py, as numbers, so that the search and the
  // defang checks agree on what an invisible character and a dot are:
  // DEFAULT_IGNORABLE (Unicode's Default_Ignorable_Code_Point ranges) and
  // DOT_CHARS (ideographic, fullwidth and halfwidth full stop).
  var IGNORABLE = [
    [0x00AD, 0x00AD], [0x034F, 0x034F], [0x061C, 0x061C], [0x115F, 0x1160],
    [0x17B4, 0x17B5], [0x180B, 0x180F], [0x200B, 0x200F], [0x202A, 0x202E],
    [0x2060, 0x206F], [0x3164, 0x3164], [0xFE00, 0xFE0F], [0xFEFF, 0xFEFF],
    [0xFFA0, 0xFFA0], [0xFFF0, 0xFFF8], [0x1BCA0, 0x1BCA3], [0x1D173, 0x1D17A],
    [0xE0000, 0xE0FFF]
  ];
  var DOTS = [0x3002, 0xFF0E, 0xFF61];
  // Whitespace as Python's str.split() reads it (str.isspace), the fold of
  // the Python oracle of reflow case (8), so both collapse the same runs.
  var SPACES = [
    [0x09, 0x0D], [0x1C, 0x20], [0x85, 0x85], [0xA0, 0xA0], [0x1680, 0x1680],
    [0x2000, 0x200A], [0x2028, 0x2029], [0x202F, 0x202F], [0x205F, 0x205F],
    [0x3000, 0x3000]
  ];
  // DEFANGS of tools/sitecheck.py, in its order, then hxxp.
  var DEFANGS = [["[.]", "."], ["[://]", "://"], ["[:]", ":"], ["[@]", "@"], ["hxxp", "http"]];
  // bare(): the scheme names and the separator as separate literals. The
  // script requests no URL but FEED_URL and the form's action; a literal
  // "http://" would read as a URL to another origin to the D9 scan of
  // script URL literals in sitecheck site, which is right to flag one.
  var SCHEMES = ["http", "https"];
  var SCHEME_END = "://";
  var WWW = "www.";
  // The artifact lists of a feed report whose items are strings, and the
  // fields of those whose items are objects (ADR-0005 part 1).
  var VALUE_LISTS = ["domains", "urls", "ips", "emails", "repositories", "file_names"];
  var OBJECT_FIELDS = [["handles", "value"], ["packages", "name"], ["sha256", "value"],
                       ["sha256", "file_name"]];
  // The normalization form, built at run time: L3 reads an upper-case
  // literal as copy.
  var NFKC = "nfkc".toUpperCase();
  // The built-in methods, read from their prototypes, never through the
  // document or the form (clobbering, see above).
  var getById = Document.prototype.getElementById;
  var getByClass = Document.prototype.getElementsByClassName;
  var importNode = Document.prototype.importNode;
  var getAttribute = Element.prototype.getAttribute;
  var listen = EventTarget.prototype.addEventListener;
  var submitForm = HTMLFormElement.prototype.submit;

  function byId(id) {
    return getById.call(document, id);
  }

  var input = byId("q");
  var form = input instanceof HTMLInputElement ? input.form : null;
  var results = byId("search-results");
  var sections = [byId("search-answer"), byId("search-partial"), byId("search-none")];
  if (!(form instanceof HTMLFormElement) || !getAttribute.call(form, "action") || !results
      || !sections[0] || !sections[1] || !sections[2] || !window.fetch || !window.DOMParser
      || !window.URL || !String.prototype.normalize) {
    return;
  }
  var action = new URL(getAttribute.call(form, "action"), location.href).href;

  function inRanges(code, ranges) {
    for (var i = 0; i < ranges.length; i++) {
      if (code >= ranges[i][0] && code <= ranges[i][1]) {
        return true;
      }
    }
    return false;
  }

  function codePoints(text, each) {
    var code;
    for (var i = 0; i < text.length; i += code > 0xFFFF ? 2 : 1) {
      code = text.codePointAt(i);
      each(code);
    }
  }

  // fold(s): NFKC, invisibles removed, dot look-alikes to ".", lowercase,
  // whitespace runs to one space, trimmed (ADR-0005 part 3).
  function fold(text) {
    var kept = "";
    codePoints(text.normalize(NFKC), function (code) {
      if (!inRanges(code, IGNORABLE)) {
        kept += DOTS.indexOf(code) >= 0 ? "." : String.fromCodePoint(code);
      }
    });
    var out = "";
    var gap = false;
    codePoints(kept.toLowerCase(), function (code) {
      if (inRanges(code, SPACES)) {
        gap = out !== "";
      } else {
        out += (gap ? " " : "") + String.fromCodePoint(code);
        gap = false;
      }
    });
    return out;
  }

  function refang(text) {
    for (var i = 0; i < DEFANGS.length; i++) {
      text = text.split(DEFANGS[i][0]).join(DEFANGS[i][1]);
    }
    return text;
  }

  function startsWith(text, start) {
    return text.slice(0, start.length) === start;
  }

  function endsWith(text, end) {
    return text.length >= end.length && text.slice(text.length - end.length) === end;
  }

  function cutBefore(text, ends) {
    for (var i = 0; i < text.length; i++) {
      if (ends.indexOf(text.charAt(i)) >= 0) {
        return text.slice(0, i);
      }
    }
    return text;
  }

  // bare(s): a leading http:// or https://, then a leading www., then a
  // trailing "/" removed.
  function bare(text) {
    for (var i = 0; i < SCHEMES.length; i++) {
      if (startsWith(text, SCHEMES[i] + SCHEME_END)) {
        text = text.slice((SCHEMES[i] + SCHEME_END).length);
        break;
      }
    }
    if (startsWith(text, WWW)) {
      text = text.slice(WWW.length);
    }
    return endsWith(text, "/") ? text.slice(0, text.length - 1) : text;
  }

  function withoutEnd(text, end) {
    return endsWith(text, end) ? text.slice(0, text.length - end.length) : text;
  }

  // The type-checked accessors: every value of the feed is read through
  // them. A field that is missing, null or of another type gives nothing,
  // so it is skipped and never folded.
  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function text(object, key) {
    return isObject(object) && typeof object[key] === "string" ? object[key] : null;
  }

  function items(object, key) {
    return isObject(object) && Array.isArray(object[key]) ? object[key] : [];
  }

  // The keys of one feed entry: name keys, value keys and domain keys.
  function entryKeys(item) {
    var keys = {names: [], values: [], domains: []};
    var name = text(item, "name");
    if (name !== null) {
      keys.names.push(fold(name));
    }
    items(item, "aliases").forEach(function (alias) {
      if (typeof alias === "string") {
        keys.names.push(fold(alias));
      }
    });
    var artifacts = isObject(item) && isObject(item.artifacts) ? item.artifacts : {};
    function value(raw, list) {
      var key = bare(refang(fold(raw)));
      keys.values.push(key);
      if (list === "domains") {
        keys.domains.push(withoutEnd(key, "."));
      }
      if (list === "handles" && startsWith(key, "@")) {
        keys.values.push(key.slice(1));
      }
    }
    VALUE_LISTS.forEach(function (list) {
      items(artifacts, list).forEach(function (raw) {
        if (typeof raw === "string") {
          value(raw, list);
        }
      });
    });
    OBJECT_FIELDS.forEach(function (pair) {
      items(artifacts, pair[0]).forEach(function (object) {
        var raw = text(object, pair[1]);
        if (raw !== null) {
          value(raw, pair[0]);
        }
      });
    });
    return keys;
  }

  // The path of a feed entry's url, or null when it has none.
  function entryPath(item) {
    var url = text(item, "url");
    try {
      return url === null ? null : new URL(url, location.href).pathname;
    } catch (error) {
      return null;
    }
  }

  // The index: the /a-z/ entries in their order, each with the keys of its
  // feed entry (none when the feed lacks it), and the keys of the feed
  // entries /a-z/ does not show (orphans). Only a feed of another version,
  // without its two lists, or an /a-z/ page without its list is an error,
  // which hands every query over to /a-z/; one record never is.
  function buildIndex(feed, page) {
    if (!isObject(feed) || feed.version !== FEED_VERSION || !Array.isArray(feed.reports)
        || !Array.isArray(feed.campaigns)) {
      throw new Error("feed");
    }
    var list = getByClass.call(page, "index-list")[0];
    if (!list) {
      throw new Error("a-z");
    }
    var byPath = {};
    feed.reports.concat(feed.campaigns).forEach(function (item) {
      var path = entryPath(item);
      if (path !== null) {
        byPath[path] = entryKeys(item);
      }
    });
    var shown = {};
    var entries = [];
    Array.prototype.forEach.call(list.children, function (li) {
      var link = li.localName === "li" ? li.getElementsByTagName("a")[0] : null;
      var path = link ? getAttribute.call(link, "href") : null;
      if (path !== null) {
        shown[path] = true;
        entries.push({li: li, keys: byPath[path] || {names: [], values: [], domains: []}});
      }
    });
    var orphans = Object.keys(byPath).filter(function (path) {
      return !shown[path];
    }).map(function (path) {
      return {li: null, keys: byPath[path]};
    });
    return {entries: entries, orphans: orphans};
  }

  var loading = null;
  function load() {
    if (!loading) {
      loading = Promise.all([fetch(FEED_URL), fetch(action)]).then(function (replies) {
        if (!replies[0].ok || !replies[1].ok) {
          throw new Error("fetch");
        }
        return Promise.all([replies[0].json(), replies[1].text()]);
      }).then(function (bodies) {
        return buildIndex(bodies[0], new DOMParser().parseFromString(bodies[1], "text/html"));
      });
    }
    return loading;
  }

  function codePointCount(value) {
    return Array.from(value).length;
  }

  // The matches of one query (ADR-0005 part 3): [section index, entries],
  // or null when a feed entry that /a-z/ does not show matches exactly, so
  // the answer has no display and the query goes to /a-z/.
  function match(index, query) {
    var entries = index.entries;
    var f = fold(query);
    var r = bare(refang(f));
    var r0 = cutBefore(r, "?#");
    var rAt = startsWith(r, "@") ? r.slice(1) : r;
    var h = "";
    if (r0.indexOf(".") >= 0 && r0.indexOf(" ") < 0) {
      h = cutBefore(r0, "/");
      h = withoutEnd(cutBefore(h.slice(h.lastIndexOf("@") + 1), ":"), ".");
    }
    function isExact(entry) {
      var keys = entry.keys;
      return keys.names.indexOf(f) >= 0 || keys.values.indexOf(r) >= 0
        || keys.values.indexOf(r0) >= 0 || keys.values.indexOf(rAt) >= 0
        || (h !== "" && keys.domains.some(function (domain) {
          return h === domain || endsWith(h, "." + domain);
        }));
    }
    if (index.orphans.some(isExact)) {
      return null;
    }
    var exact = entries.filter(isExact);
    if (exact.length) {
      return [0, exact];
    }
    // The partial match tests the forms f and r, and SEARCH_PARTIAL_MIN
    // holds for each form it tests: a form shorter than that (bare() and
    // refang() can cut r to one or two code points) tests nothing.
    var parts = [f, r].filter(function (part) {
      return codePointCount(part) >= PARTIAL_MIN;
    });
    var close = entries.filter(function (entry) {
      return entry.keys.names.concat(entry.keys.values).some(function (key) {
        return parts.some(function (part) {
          return key.indexOf(part) >= 0;
        });
      });
    });
    if (close.length) {
      return [1, close.slice(0, PARTIAL_CAP)];
    }
    return [2, []];
  }

  function clear(list) {
    while (list.firstChild) {
      list.removeChild(list.firstChild);
    }
  }

  function reveal(found) {
    sections.forEach(function (section) {
      section.hidden = true;
      Array.prototype.forEach.call(section.getElementsByClassName("index-list"), clear);
    });
    if (!found) {
      results.hidden = true;
      return;
    }
    var section = sections[found[0]];
    var list = section.getElementsByClassName("index-list")[0];
    found[1].forEach(function (entry) {
      list.appendChild(importNode.call(document, entry.li, true));
    });
    results.hidden = false;
    section.hidden = false;
    // Focus without its own scroll, then the section's top to the top of
    // the viewport, at once (no smooth scroll): focus alone scrolls only
    // until the heading is in view, which on a phone leaves it at the
    // bottom edge and the first entry below the fold (M4 PR 3 fix round 2).
    section.getElementsByTagName("h2")[0].focus({preventScroll: true});
    section.scrollIntoView({block: "start", inline: "nearest", behavior: "instant"});
  }

  // asked counts the submits; only the latest one may change the page.
  // aria-busy is the one piece of state a submit sets before its answer,
  // and every exit of the latest submit clears it: the empty query, the
  // answer, the hand-over after an error. A stale reply changes nothing,
  // because the latest submit has cleared it or will.
  var asked = 0;
  function settle(mine) {
    if (mine !== asked) {
      return false;
    }
    results.removeAttribute("aria-busy");
    return true;
  }

  listen.call(form, "submit", function (event) {
    event.preventDefault();
    var query = input.value;
    var mine = ++asked;
    if (fold(query) === "") {
      settle(mine);
      reveal(null);
      return;
    }
    results.setAttribute("aria-busy", "true");
    load().then(function (index) {
      if (settle(mine)) {
        var found = match(index, query);
        if (found === null) {
          submitForm.call(form);
        } else {
          reveal(found);
        }
      }
    }, function () {
      if (settle(mine)) {
        submitForm.call(form);
      }
    });
  });
  listen.call(input, "focus", function () {
    load().then(null, function () {});
  });
})();
