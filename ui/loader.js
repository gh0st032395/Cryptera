(function () {
    var status = document.getElementById("statusText");
    if (status) status.textContent = "Bootstrap...";
    var s = document.createElement("script");
    s.type = "module";
    s.src = "./app.js";
    s.onload = function () {
        if (status && status.textContent === "Bootstrap...") {
            status.textContent = "JS loaded";
        }
    };
    s.onerror = function () {
        if (status) status.textContent = "app.js load failed";
    };
    document.body.appendChild(s);
})();
