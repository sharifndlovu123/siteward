(function () {
  var box = document.getElementById("results");
  if (!box) { return; }
  var url = box.getAttribute("data-status-url");
  function tick() {
    fetch(url, { cache: "no-store" })
      .then(function (response) {
        var done = response.headers.get("X-Scan-Done") === "1";
        return response.text().then(function (html) { box.innerHTML = html; return done; });
      })
      .then(function (done) { if (!done) { setTimeout(tick, 1000); } })
      .catch(function () { setTimeout(tick, 3000); });
  }
  setTimeout(tick, 1000);
})();
