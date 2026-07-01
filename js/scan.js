const scanForm = document.querySelector("[data-scan-form]");
const scanResult = document.querySelector("[data-scan-result]");
const beaconApiBase = String(window.BEACON_API_URL || "").replace(/\/$/, "");

if (scanForm && scanResult) {
  scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(scanForm);
    const domain = String(formData.get("domain") || "").trim();

    if (!domain) {
      scanResult.textContent = "Enter a domain to prepare a website review.";
      return;
    }

    const submitButton = scanForm.querySelector("button[type='submit']");
    if (submitButton) submitButton.disabled = true;
    scanResult.textContent = "Running public website review...";

    try {
      const response = await fetch(`${beaconApiBase}/v1/free-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: domain })
      });
      const payload = await response.json();

      if (!response.ok) {
        const message = payload?.detail?.message || payload?.message || "The website review could not be completed.";
        scanResult.textContent = message;
        return;
      }

      scanResult.innerHTML = renderScanSummary(payload);
    } catch (error) {
      scanResult.textContent = "The website review service is not reachable right now. Please try again shortly.";
    } finally {
      if (submitButton) submitButton.disabled = false;
    }
  });
}

function renderScanSummary(report) {
  const grade = escapeHtml(report?.overall?.grade || "Not verified");
  const status = escapeHtml(report?.overall?.status || "Review completed");
  const summary = escapeHtml(report?.summary || report?.overall?.summary || "Beacon completed the public website review.");
  const issues = Array.isArray(report?.top_issues) ? report.top_issues.slice(0, 3) : [];
  const fixes = Array.isArray(report?.recommended_fixes) ? report.recommended_fixes.slice(0, 3) : [];

  return [
    `<strong>Beacon Grade: ${grade}</strong>`,
    `<span>${status}</span>`,
    `<p>${summary}</p>`,
    renderList("Top issues", issues.map((item) => item.title)),
    renderList("Recommended fixes", fixes.map((item) => item.title))
  ].join("");
}

function renderList(label, items) {
  if (!items.length) return "";
  return `<strong>${label}</strong><ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;"
  }[character]));
}