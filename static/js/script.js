/* =========================================================
   INFRASHIELD — OS COMPLIANCE ENGINE JAVASCRIPT
========================================================= */


/* =========================================================
   THEME TOGGLE
========================================================= */

const themeToggle =
    document.getElementById("themeToggle");

const themeIcon =
    document.getElementById("themeIcon");

const themeText =
    document.getElementById("themeText");


function applyTheme(theme) {

    document.documentElement.setAttribute(
        "data-theme",
        theme
    );


    localStorage.setItem(
        "infrashield-theme",
        theme
    );


    if (themeIcon && themeText) {
        if (theme === "dark") {
            themeIcon.textContent = "☀️";
            themeText.textContent = "Light";
        } else {
            themeIcon.textContent = "🌙";
            themeText.textContent = "Dark";
        }
    }

}


/* =========================================================
   INITIAL THEME
========================================================= */

const savedTheme =
    localStorage.getItem("infrashield-theme") || "dark";


applyTheme(savedTheme);


/* =========================================================
   TOGGLE
========================================================= */

if (themeToggle) {

    themeToggle.addEventListener(
        "click",
        function () {

            const currentTheme =
                document.documentElement.getAttribute(
                    "data-theme"
                );


            const newTheme =
                currentTheme === "dark"
                    ? "light"
                    : "dark";


            applyTheme(newTheme);

        }
    );

}


/* =========================================================
   SECURITY SCAN
========================================================= */

const scanButton =
    document.getElementById("scanButton");

const scanButtonText =
    document.getElementById("scanButtonText");

const scanMessage =
    document.getElementById("scanMessage");


if (scanButton) {

    scanButton.addEventListener(
        "click",
        function () {


            scanButton.disabled = true;


            if (scanButtonText) {

                scanButtonText.textContent =
                    "Scanning System...";

            }


            if (scanMessage) {

                scanMessage.textContent =
                    "Running Linux security checks...";

            }


            /*
             * Give the user visual feedback
             * before refreshing the dashboard.
             */

            setTimeout(
                function () {

                    if (scanMessage) {

                        scanMessage.textContent =
                            "Scan completed. Updating results...";

                    }

                },
                500
            );


            setTimeout(
                function () {

                    window.location.reload();

                },
                900
            );

        }
    );

}
// Cross-tab theme sync
window.addEventListener("storage", (e) => {
    if (e.key === "infrashield-theme") {
        document.documentElement.setAttribute("data-theme", e.newValue);
    }
});

// Cross-tab scan sync
window.addEventListener("storage", (e) => {
    if (e.key === "infrashield-scan-trigger") {
        window.location.reload();
    }
});
