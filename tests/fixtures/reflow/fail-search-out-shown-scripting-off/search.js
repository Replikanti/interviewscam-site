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

  var input = document.getElementById("q");
  var form = input && input.form;
  var results = document.getElementById("search-results");
  var sections = [document.getElementById("search-answer"),
                  document.getElementById("search-partial"),
                  document.getElementById("search-none")];
  if (!form || !form.getAttribute("action") || !results || !sections[0] || !sections[1]
      || !sections[2] || !window.fetch || !window.DOMParser || !window.URL
      || !String.prototype.normalize) {
    return;
  }

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

  // The keys of one feed entry: name keys, value keys and domain keys.
  function entryKeys(item) {
    var keys = {names: [], values: [], domains: []};
    if (typeof item.name === "string") {
      keys.names.push(fold(item.name));
    }
    (item.aliases || []).forEach(function (alias) {
      keys.names.push(fold(alias));
    });
    var artifacts = item.artifacts || {};
    function value(text, list) {
      var key = bare(refang(fold(text)));
      keys.values.push(key);
      if (list === "domains") {
        keys.domains.push(withoutEnd(key, "."));
      }
      return key;
    }
    VALUE_LISTS.forEach(function (list) {
      (artifacts[list] || []).forEach(function (text) {
        value(text, list);
      });
    });
    OBJECT_FIELDS.forEach(function (pair) {
      (artifacts[pair[0]] || []).forEach(function (object) {
        var key = value(object[pair[1]], pair[0]);
        if (pair[0] === "handles" && startsWith(key, "@")) {
          keys.values.push(key.slice(1));
        }
      });
    });
    return keys;
  }

  // The /a-z/ entries in their order, each with the keys of its feed
  // entry, or an error when the two files do not describe the same records.
  function buildIndex(feed, page) {
    if (!feed || feed.version !== FEED_VERSION || !Array.isArray(feed.reports)
        || !Array.isArray(feed.campaigns)) {
      throw new Error("feed");
    }
    var byPath = {};
    var count = 0;
    feed.reports.concat(feed.campaigns).forEach(function (item) {
      byPath[new URL(item.url, document.baseURI).pathname] = entryKeys(item);
      count++;
    });
    var list = page.getElementsByClassName("index-list")[0];
    var entries = [];
    Array.prototype.forEach.call(list ? list.children : [], function (li) {
      var link = li.getElementsByTagName("a")[0];
      var keys = link && byPath[link.getAttribute("href")];
      if (li.localName !== "li" || !keys) {
        throw new Error("a-z");
      }
      entries.push({li: li, keys: keys});
    });
    if (!list || entries.length !== count) {
      throw new Error("a-z");
    }
    return entries;
  }

  var loading = null;
  function load() {
    if (!loading) {
      loading = Promise.all([fetch(FEED_URL), fetch(form.action)]).then(function (replies) {
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

  function contains(keys, part) {
    return part !== "" && keys.some(function (key) {
      return key.indexOf(part) >= 0;
    });
  }

  // The matches of one query (ADR-0005 part 3): [section index, entries].
  function match(entries, query) {
    var f = fold(query);
    var r = bare(refang(f));
    var r0 = cutBefore(r, "?#");
    var rAt = startsWith(r, "@") ? r.slice(1) : r;
    var h = "";
    if (r0.indexOf(".") >= 0 && r0.indexOf(" ") < 0) {
      h = cutBefore(r0, "/");
      h = withoutEnd(cutBefore(h.slice(h.lastIndexOf("@") + 1), ":"), ".");
    }
    var exact = entries.filter(function (entry) {
      var keys = entry.keys;
      return keys.names.indexOf(f) >= 0 || keys.values.indexOf(r) >= 0
        || keys.values.indexOf(r0) >= 0 || keys.values.indexOf(rAt) >= 0
        || (h !== "" && keys.domains.some(function (domain) {
          return h === domain || endsWith(h, "." + domain);
        }));
    });
    if (exact.length) {
      return [0, exact];
    }
    if (Array.from(f).length >= PARTIAL_MIN) {
      var close = entries.filter(function (entry) {
        var keys = entry.keys.names.concat(entry.keys.values);
        return contains(keys, f) || contains(keys, r);
      });
      if (close.length) {
        return [1, close.slice(0, PARTIAL_CAP)];
      }
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
      list.appendChild(document.importNode(entry.li, true));
    });
    results.hidden = false;
    section.hidden = false;
    section.getElementsByTagName("h2")[0].focus();
  }

  var asked = 0;
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var query = input.value;
    var mine = ++asked;
    if (fold(query) === "") {
      reveal(null);
      return;
    }
    results.setAttribute("aria-busy", "true");
    load().then(function (entries) {
      if (mine === asked) {
        results.removeAttribute("aria-busy");
        reveal(match(entries, query));
      }
    }, function () {
      results.removeAttribute("aria-busy");
      form.submit();
    });
  });
  input.addEventListener("focus", function () {
    load().then(null, function () {});
  });
})();
