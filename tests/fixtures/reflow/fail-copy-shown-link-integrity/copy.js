// The Copy buttons (ADR-0004 part 11). Every button.copy names the element
// whose text it copies by id in data-copy-target and carries its two status
// texts, from data/labels.toml, in data-copy-done and data-copy-failed; the
// status goes into the polite live region right after the button. Without
// the clipboard API or a secure context the buttons stay hidden and the page
// is unchanged. The text is copied exactly as shown (defanged), never
// rewritten, and the script has no timers, no inline handlers and no URLs.
(function () {
  if (!window.isSecureContext || !navigator.clipboard) {
    return;
  }
  Array.prototype.forEach.call(document.querySelectorAll("button.copy"), function (button) {
    var target = document.getElementById(button.getAttribute("data-copy-target"));
    var status = button.nextElementSibling;
    if (!target || !status || !status.classList.contains("copy-status")) {
      return;
    }
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(target.textContent).then(function () {
        status.textContent = button.getAttribute("data-copy-done");
      }, function () {
        status.textContent = button.getAttribute("data-copy-failed");
      });
    });
  });
})();
