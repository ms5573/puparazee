(function () {
  var form = document.getElementById("check-form");
  var input = document.getElementById("url");
  var result = document.getElementById("result");
  var button = form.querySelector("button");

  var labels = {
    likely_affected: "Likely affected",
    likely_patched: "Likely patched",
    eol: "End of life",
    not_php: "Not PHP",
    unknown: "Unknown",
  };

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var url = input.value.trim();
    if (!url) {
      showError("Enter a website address.");
      return;
    }
    button.disabled = true;
    result.className = "result";
    result.replaceChildren();
    var pending = document.createElement("div");
    pending.className = "result-body";
    pending.textContent = "Checking headers…";
    result.appendChild(pending);

    var controller = new AbortController();
    var timer = setTimeout(function () {
      controller.abort();
    }, 20000);

    fetch("/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ url: url }),
      signal: controller.signal,
    })
      .then(function (response) {
        return response.json().then(function (data) {
          return { ok: response.ok, data: data };
        });
      })
      .then(function (payload) {
        if (!payload.ok || !payload.data || payload.data.error) {
          var message = payload.data && payload.data.message ? payload.data.message : "The check could not be completed.";
          showError(message);
          return;
        }
        showResult(payload.data);
      })
      .catch(function () {
        showError("The checker could not be reached. Try again in a moment.");
      })
      .finally(function () {
        clearTimeout(timer);
        button.disabled = false;
      });
  });

  function row(term, value) {
    var dt = document.createElement("dt");
    dt.textContent = term;
    var dd = document.createElement("dd");
    dd.textContent = value;
    return [dt, dd];
  }

  function showResult(data) {
    result.className = "result result-" + (labels[data.status] ? data.status : "unknown");
    result.replaceChildren();
    var body = document.createElement("div");
    body.className = "result-body";

    var heading = document.createElement("h3");
    heading.textContent = labels[data.status] || "Result";
    body.appendChild(heading);

    var summary = document.createElement("p");
    summary.textContent = data.summary || "";
    body.appendChild(summary);

    var list = document.createElement("dl");
    var fields = [
      ["Reported PHP", data.phpVersion || "Not in headers"],
      ["WordPress headers", data.wordpress ? "Yes" : "No"],
      ["X-Powered-By", data.xPoweredBy || "Not sent"],
      ["Server", data.server || "Not sent"],
      ["HTTP status", data.httpStatus ? String(data.httpStatus) : "Unknown"],
      ["Checked URL", data.finalUrl || ""],
    ];
    fields.forEach(function (field) {
      row(field[0], field[1]).forEach(function (node) {
        list.appendChild(node);
      });
    });
    body.appendChild(list);

    if (data.schemeNote) {
      var note = document.createElement("p");
      note.textContent = data.schemeNote;
      body.appendChild(note);
    }

    var fine = document.createElement("p");
    fine.className = "fine";
    fine.textContent = data.disclaimer || "This is not a confirmed exploit test. Header versions can overstate exposure when a fix has been backported.";
    body.appendChild(fine);
    result.appendChild(body);
  }

  function showError(message) {
    result.className = "result result-error";
    result.replaceChildren();
    var body = document.createElement("div");
    body.className = "result-body";
    var heading = document.createElement("h3");
    heading.textContent = "Check not completed";
    var text = document.createElement("p");
    text.textContent = message;
    body.appendChild(heading);
    body.appendChild(text);
    result.appendChild(body);
  }
})();
