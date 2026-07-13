const scanForm = document.querySelector("[data-scan-form]");
const scanResult = document.querySelector("[data-scan-result]");
const beaconApiBase = String(window.BEACON_API_URL || "").replace(/\/$/, "");

const scanSteps = [
  { label: "Preparing scan", detail: "Preparing the website address and starting the review." },
  { label: "Resolving domain", detail: "Reviewing public domain records." },
  { label: "Verifying HTTPS", detail: "Confirming certificate and secure connection signals." },
  { label: "Reviewing Security Headers", detail: "Looking at browser-facing protection settings." },
  { label: "Analyzing website performance", detail: "Reading public page experience signals." },
  { label: "Detecting technologies", detail: "Looking for platform and infrastructure clues." },
  { label: "Building recommendations", detail: "Prioritizing the work in plain English." },
  { label: "Finalizing report", detail: "Assembling the customer-ready report." },
  { label: "Report ready", detail: "Beacon has completed the review." }
];

const holdStageIndex = 4;

const categoryLabels = {
  security: "Security",
  performance: "Performance",
  seo: "SEO",
  accessibility: "Accessibility",
  infrastructure: "Infrastructure"
};

const categoryDescriptions = {
  security: "Browser, email, and trust signals.",
  performance: "Speed and page experience.",
  seo: "Search visibility basics.",
  accessibility: "Usability and access checks.",
  infrastructure: "DNS, hosting, and delivery signals."
};

const checkedSignals = [
  { title: "Website Performance", detail: "Performance and page experience signals." },
  { title: "SSL", detail: "HTTPS certificate and connection checks." },
  { title: "DNS", detail: "Public records and domain routing." },
  { title: "Security Headers", detail: "Browser-facing protection settings." },
  { title: "Technology Detection", detail: "Public platform and infrastructure clues." },
  { title: "Beacon Analysis", detail: "Plain-English priority and effort review." }
];

const publicChecks = [
  "DNS",
  "HTTPS",
  "Security Headers",
  "Website Performance",
  "Technology Detection"
];

if (scanForm && scanResult) {
  scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(scanForm);
    const rawDomain = String(formData.get("domain") || "");
    const domain = normalizeDomain(rawDomain);

    if (!domain) {
      showNotice("Enter your company's website to prepare a website review.");
      return;
    }

    if (!isValidHostname(domain)) {
      showNotice("We couldn't reach that website. Please check the website address and try again.", "error");
      return;
    }

    const submitButton = scanForm.querySelector("button[type='submit']");
    const originalButtonText = submitButton ? submitButton.textContent : "";

    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Reviewing Website...";
    }

    scanForm.classList.add("is-loading");
    document.body.classList.remove("scan-has-report");
    document.body.classList.add("scan-is-running");
    scanResult.classList.add("is-active");
    scanResult.innerHTML = renderProgress(domain);

    const progress = createProgressController();
    progress.start();

    try {
      const response = await fetch(`${beaconApiBase}/v1/free-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: domain })
      });
      const payload = await response.json();

      if (!response.ok) {
        progress.stop();
        const message = payload?.detail?.message || payload?.message || "The website review could not be completed.";
        showNotice(message, "error");
        return;
      }

      await progress.complete();
      await collapseProgress();
      scanResult.innerHTML = renderScanReport(payload);
      document.body.classList.remove("scan-is-running");
      document.body.classList.add("scan-has-report");
      requestAnimationFrame(() => {
        const report = scanResult.querySelector("[data-report]");
        if (report) report.classList.add("is-visible");
      });
    } catch (error) {
      progress.stop();
      document.body.classList.remove("scan-is-running");
      showNotice("The website review service is not reachable right now. Please try again shortly.", "error");
    } finally {
      scanForm.classList.remove("is-loading");
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = originalButtonText;
      }
    }
  });
}

function renderProgress(domain) {
  return `
    <section class="scan-progress" aria-label="Website review progress">
      <div class="scan-progress__summary">
        <p class="eyebrow">Beacon is reviewing</p>
        <h2>${escapeHtml(normalizeDomain(domain))}</h2>
        <div class="scan-progress__wait-note">
          <strong>Building your Beacon report</strong>
          <p>Most website reviews finish in 30-60 seconds.</p>
          <p>Some websites may take up to 90 seconds.</p>
          <p>Please keep this page open while Beacon completes the review.</p>
        </div>
        <p>Beacon is checking public website signals and preparing a plain-English report.</p>
      </div>
      <ol class="scan-progress__steps">
        ${scanSteps.map((step, index) => `
          <li data-scan-step="${index}">
            <span class="scan-progress__marker" aria-hidden="true">
              <span class="scan-progress__check">${icon("check")}</span>
              <span class="scan-progress__dot"></span>
            </span>
            <span>
              <strong>${step.label}</strong>
              <small>${step.detail}</small>
            </span>
          </li>
        `).join("")}
      </ol>
    </section>
  `;
}

function createProgressController() {
  let currentIndex = 0;
  let timer = null;
  let stopped = false;

  function setActive(index) {
    scanResult.querySelectorAll("[data-scan-step]").forEach((step) => {
      step.classList.remove("is-active");
    });

    const current = scanResult.querySelector(`[data-scan-step="${index}"]`);
    if (current) current.classList.add("is-active");
    currentIndex = index;
  }

  function completeStep(index) {
    const current = scanResult.querySelector(`[data-scan-step="${index}"]`);
    if (current) {
      current.classList.remove("is-active");
      current.classList.add("is-complete");
    }
  }

  function scheduleNext() {
    if (stopped || currentIndex >= holdStageIndex) return;
    timer = window.setTimeout(() => {
      if (stopped) return;
      completeStep(currentIndex);
      setActive(currentIndex + 1);
      scheduleNext();
    }, 520);
  }

  return {
    start() {
      setActive(0);
      scheduleNext();
    },
    stop() {
      stopped = true;
      if (timer) window.clearTimeout(timer);
    },
    async complete() {
      this.stop();

      for (let index = currentIndex; index < scanSteps.length; index += 1) {
        setActive(index);
        await wait(index === scanSteps.length - 1 ? 300 : 180);
        completeStep(index);
      }
    }
  };
}

async function collapseProgress() {
  const panel = scanResult.querySelector(".scan-progress");
  if (!panel) return;
  panel.classList.add("is-collapsing");
  await wait(220);
}

function renderScanReport(report) {
  const grade = String(report?.overall?.grade || "Not verified");
  const gradeTone = toneForGrade(grade);
  const status = report?.overall?.status || "Review completed";
  const summary = report?.summary || report?.overall?.summary || "Beacon completed the public website review.";
  const effort = report?.estimated_effort || "Review recommended";
  const completedIn = formatElapsed(report);
  const categories = report?.categories && typeof report.categories === "object" ? report.categories : {};
  const issues = Array.isArray(report?.top_issues) ? report.top_issues.slice(0, 3) : [];
  const fixes = Array.isArray(report?.recommended_fixes) ? report.recommended_fixes.slice(0, 6) : [];
  const domain = normalizeDomain(report?.url || "");
  const primaryIssue = issues[0]?.title || fixes[0]?.title || "Review the recommendations below.";

  return `
    <article class="scan-report scan-report--enter" data-report>
      <header class="scan-report__hero tone-${gradeTone}">
        <div class="scan-report__grade-block">
          <p class="eyebrow">Beacon Grade</p>
          <div class="scan-report__grade">${escapeHtml(grade)}</div>
          <p class="scan-report__status">${escapeHtml(status)}</p>
        </div>
        <div class="scan-report__summary">
          <div class="scan-report__kicker">
            <span>${icon("globe")}</span>
            <span>${escapeHtml(domain || "Reviewed website")}</span>
          </div>
          <h2>Website health report</h2>
          <p>${escapeHtml(summary)}</p>
          ${completedIn ? `<p class="scan-report__duration">Review completed in ${escapeHtml(completedIn)}</p>` : ""}
          <dl class="scan-report__facts">
            <div>
              <dt>Fix first</dt>
              <dd>${escapeHtml(primaryIssue)}</dd>
            </div>
            <div>
              <dt>Estimated effort</dt>
              <dd>${escapeHtml(effort)}</dd>
            </div>
          </dl>
        </div>
      </header>

      <section class="scan-report__section scan-report__section--categories" aria-labelledby="category-grades-heading">
        <div class="scan-report__section-header">
          <div>
            <p class="eyebrow">Category Grades</p>
            <h3 id="category-grades-heading">How the website performed.</h3>
          </div>
        </div>
        <div class="category-grade-grid">
          ${renderCategoryCards(categories)}
        </div>
      </section>

      <section class="scan-report__section scan-report__section--issues" aria-labelledby="fix-first-heading">
        <div class="scan-report__section-header">
          <div>
            <p class="eyebrow">Fix First</p>
            <h3 id="fix-first-heading">The highest-value issues to review.</h3>
          </div>
        </div>
        <div class="issue-list">
          ${issues.length ? issues.map(renderIssueCard).join("") : renderEmptyCard("No top issues were returned.", "Beacon did not identify a priority issue in the quick scan response.")}
        </div>
      </section>

      <section class="scan-report__section scan-report__section--work-plan" aria-labelledby="work-plan-heading">
        <div class="scan-report__section-header">
          <div>
            <p class="eyebrow">Recommended Work Plan</p>
            <h3 id="work-plan-heading">Actions ordered by priority and effort.</h3>
          </div>
        </div>
        <div class="work-plan-grid">
          ${fixes.length ? fixes.map(renderFixCard).join("") : renderEmptyCard("No recommended fixes were returned.", "Use the category grades and summary as the starting point for review.")}
        </div>
      </section>

      <section class="scan-report__section scan-report__section--checked" aria-labelledby="checked-heading">
        <div class="scan-report__section-header">
          <div>
            <p class="eyebrow">What Beacon Checked</p>
            <h3 id="checked-heading">Trusted public signals, translated.</h3>
          </div>
        </div>
        <div class="checked-grid">
          ${checkedSignals.map(renderCheckedSignal).join("")}
        </div>
      </section>

      ${renderReportDetails(report)}

      ${renderHelpSection()}

      <footer class="scan-report__footer">
        <p>Beacon combines trusted public website analysis with plain-English recommendations so business owners know what to fix first.</p>
      </footer>
    </article>
  `;
}

function renderCategoryCards(categories) {
  return Object.keys(categoryLabels).map((key) => {
    const category = categories[key] || {};
    const grade = category.grade || gradeFromScore(category.score);
    const score = Number.isFinite(category.score) ? `${category.score}/100` : "Not verified";
    const status = statusForCategory(category, grade);
    const tone = toneForGrade(grade);

    return `
      <article class="category-grade-card tone-${tone}">
        <div class="category-grade-card__top">
          <span class="category-grade-card__icon" aria-hidden="true">${icon(key)}</span>
          <span class="category-grade-card__score">${escapeHtml(score)}</span>
        </div>
        <div>
          <p class="card__meta">${escapeHtml(categoryLabels[key])}</p>
          <div class="category-grade-card__grade">${escapeHtml(grade || "Not verified")}</div>
          <p>${escapeHtml(status)}</p>
          <small>${escapeHtml(categoryDescriptions[key])}</small>
        </div>
      </article>
    `;
  }).join("");
}

function renderIssueCard(issue) {
  const severity = issue?.severity || "info";
  const tone = toneForSeverity(severity);

  return `
    <article class="issue-card tone-${tone}">
      <div class="issue-card__heading">
        <span class="severity-pill tone-${tone}">${escapeHtml(labelize(severity))}</span>
        <h4>${escapeHtml(issue?.title || "Review issue")}</h4>
      </div>
      ${issue?.explanation ? `<p>${escapeHtml(issue.explanation)}</p>` : ""}
      <div class="issue-card__detail">
        <strong>${icon("impact")} Why it matters</strong>
        <p>${escapeHtml(issue?.business_impact || "This can affect customer trust, usability, or visibility.")}</p>
      </div>
      <div class="issue-card__detail">
        <strong>${icon("fix")} Recommended fix</strong>
        <p>${escapeHtml(issue?.recommended_fix || "Review this item with the person who manages the website.")}</p>
      </div>
    </article>
  `;
}

function renderFixCard(fix) {
  const priority = fix?.priority || "medium";
  const tone = toneForSeverity(priority);

  return `
    <article class="work-card tone-${tone}">
      <div class="work-card__top">
        <span class="severity-pill tone-${tone}">${escapeHtml(labelize(priority))}</span>
        <span class="work-card__effort">${icon("clock")}${escapeHtml(fix?.estimated_effort || "Confirm effort")}</span>
      </div>
      <h4>${escapeHtml(fix?.title || "Recommended improvement")}</h4>
      <p>${escapeHtml(fix?.business_impact || "This improvement supports customer trust and website quality.")}</p>
    </article>
  `;
}

function renderCheckedSignal(item) {
  return `
    <article class="checked-item">
      <span aria-hidden="true">${icon("check")}</span>
      <div>
        <strong>${escapeHtml(item.title)}</strong>
        <p>${escapeHtml(item.detail)}</p>
      </div>
    </article>
  `;
}

function renderReportDetails(report) {
  const metadata = report?.report_metadata && typeof report.report_metadata === "object" ? report.report_metadata : {};
  const completedAt = formatCompletedAt(metadata.completed_at);
  const duration = formatScanDuration(metadata.scan_duration_seconds);

  return `
    <section class="scan-report__section scan-report__section--details" aria-labelledby="report-details-heading">
      <div class="scan-report__section-header">
        <div>
          <p class="eyebrow">Report Details</p>
          <h3 id="report-details-heading">Review record.</h3>
        </div>
      </div>
      <div class="report-details">
        <dl class="report-details__meta">
          ${completedAt ? `<div><dt>Completed</dt><dd>${escapeHtml(completedAt)}</dd></div>` : ""}
          ${duration ? `<div><dt>Scan Duration</dt><dd>${escapeHtml(duration)}</dd></div>` : ""}
        </dl>
        <div class="report-details__checks">
          <strong>Public checks completed</strong>
          <ul>
            ${publicChecks.map((check) => `<li><span aria-hidden="true">${icon("check")}</span>${escapeHtml(check)}</li>`).join("")}
          </ul>
        </div>
      </div>
    </section>
  `;
}

function renderHelpSection() {
  return `
    <section class="scan-report__section scan-report__section--help" aria-labelledby="report-help-heading">
      <div class="report-help">
        <div>
          <p class="eyebrow">Need Help?</p>
          <h3 id="report-help-heading">Need help implementing these recommendations?</h3>
        </div>
        <div>
          <p>Some organizations prefer to make these improvements themselves.</p>
          <p>Others prefer help prioritizing and implementing them.</p>
          <p>If you'd like assistance, we'd be happy to help.</p>
          <a href="mailto:contact@beacon-audit.com">contact@beacon-audit.com</a>
        </div>
      </div>
    </section>
  `;
}

function renderEmptyCard(title, message) {
  return `
    <article class="empty-report-card">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(message)}</p>
    </article>
  `;
}

function showNotice(message, tone = "default") {
  document.body.classList.remove("scan-is-running");
  document.body.classList.remove("scan-has-report");
  scanResult.classList.add("is-active");
  scanResult.innerHTML = `
    <div class="scan-notice scan-notice--${escapeHtml(tone)}">
      <strong>${tone === "error" ? "Review unavailable" : "Before you start"}</strong>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
}

function statusForCategory(category, grade) {
  if (category?.status === "not_verified" || category?.score === null) return "Not verified";
  if (!grade) return "Review returned";
  const tone = toneForGrade(grade);
  if (tone === "excellent") return "Healthy";
  if (tone === "good") return "Good";
  if (tone === "fair") return "Needs review";
  if (tone === "poor") return "Fix soon";
  return "Review returned";
}

function gradeFromScore(score) {
  if (!Number.isFinite(score)) return null;
  if (score >= 97) return "A+";
  if (score >= 93) return "A";
  if (score >= 90) return "A-";
  if (score >= 87) return "B+";
  if (score >= 83) return "B";
  if (score >= 80) return "B-";
  if (score >= 77) return "C+";
  if (score >= 73) return "C";
  if (score >= 70) return "C-";
  if (score >= 60) return "D";
  return "F";
}

function formatElapsed(report) {
  return formatScanDuration(report?.report_metadata?.scan_duration_seconds);
}

function formatScanDuration(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) return "";
  return `${Math.round(seconds)} seconds`;
}

function formatCompletedAt(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit"
  });
}

function toneForGrade(grade) {
  const normalized = String(grade || "").toUpperCase();
  if (normalized.startsWith("A")) return "excellent";
  if (normalized.startsWith("B")) return "good";
  if (normalized.startsWith("C")) return "fair";
  if (normalized.startsWith("D") || normalized.startsWith("F")) return "poor";
  return "neutral";
}

function toneForSeverity(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "poor";
  if (normalized === "medium") return "fair";
  if (normalized === "low") return "good";
  return "neutral";
}

function normalizeDomain(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return "";
  try {
    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    return new URL(withProtocol).hostname.replace(/\.$/, "");
  } catch (error) {
    return raw
      .replace(/^https?:\/\//i, "")
      .split(/[/?#]/, 1)[0]
      .replace(/\.$/, "");
  }
}

function isValidHostname(value) {
  const hostname = String(value || "");
  if (!hostname || hostname.length > 253 || !hostname.includes(".")) return false;
  if (/[^a-z0-9.-]/.test(hostname)) return false;
  if (hostname.startsWith(".") || hostname.endsWith(".") || hostname.includes("..")) return false;
  return hostname.split(".").every((label) => (
    label.length > 0
    && label.length <= 63
    && !label.startsWith("-")
    && !label.endsWith("-")
  ));
}

function labelize(value) {
  return String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function wait(milliseconds) {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function icon(name) {
  const icons = {
    security: '<svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 5 3 8 7 10 4-2 7-5 7-10V6l-7-3Z"/><path d="m9 12 2 2 4-4"/></svg>',
    performance: '<svg viewBox="0 0 24 24"><path d="M4 14a8 8 0 1 1 16 0"/><path d="m12 14 4-5"/><path d="M4 18h16"/></svg>',
    seo: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>',
    accessibility: '<svg viewBox="0 0 24 24"><circle cx="12" cy="4" r="2"/><path d="M4 8h16"/><path d="M12 10v10"/><path d="m8 20 4-10 4 10"/></svg>',
    infrastructure: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="6" rx="2"/><rect x="4" y="14" width="16" height="6" rx="2"/><path d="M8 8h.01M8 18h.01"/></svg>',
    globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20"/><path d="M12 2a15 15 0 0 0 0 20"/></svg>',
    impact: '<svg viewBox="0 0 24 24"><path d="M3 17h18"/><path d="m6 14 4-4 3 3 5-7"/><path d="M18 6h-4"/><path d="M18 6v4"/></svg>',
    fix: '<svg viewBox="0 0 24 24"><path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18v3h3l6.3-6.3a4 4 0 0 0 5.4-5.4l-3 3-3-3 3-3Z"/></svg>',
    clock: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>'
  };

  return icons[name] || icons.check;
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
