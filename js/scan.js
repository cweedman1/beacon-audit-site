const scanForm = document.querySelector("[data-scan-form]");
const scanResult = document.querySelector("[data-scan-result]");

if (scanForm && scanResult) {
  scanForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const formData = new FormData(scanForm);
    const domain = String(formData.get("domain") || "").trim();

    if (!domain) {
      scanResult.textContent = "Enter a domain to prepare a website review.";
      return;
    }

    scanResult.innerHTML = [
      `<strong>${domain}</strong> is ready for a website review.`,
      "A production review connects server-side checks and explains the results in plain English."
    ].join("<br>");
  });
}
