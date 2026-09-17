"use strict";

const number = new Intl.NumberFormat("en-US");
const countryNames = typeof Intl.DisplayNames === "function"
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function countryLabel(code) {
  if (!code || code === "ZZ") return "Unknown / private";
  try { return countryNames ? countryNames.of(code) : code; }
  catch (_) { return code; }
}

function renderRanking(id, rows, labeler = value => value) {
  const list = document.getElementById(id);
  list.replaceChildren();
  if (!rows.length) {
    const item = document.createElement("li");
    item.className = "empty";
    item.textContent = "No observations in this window.";
    list.append(item);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    const count = document.createElement("span");
    label.className = "label";
    count.className = "value";
    label.textContent = labeler(row.label);
    count.textContent = number.format(row.count);
    item.append(label, count);
    list.append(item);
  }
}

function renderChart(rows) {
  const chart = document.getElementById("daily-chart");
  chart.replaceChildren();
  const visible = rows.slice(-30);
  const peak = Math.max(1, ...visible.map(row => row.count));
  chart.setAttribute("aria-label", visible.map(row => `${row.date}: ${row.count}`).join(", "));
  for (const row of visible) {
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.tabIndex = 0;
    bar.style.height = `${Math.max(2, (row.count / peak) * 100)}%`;
    bar.dataset.label = `${row.date}: ${number.format(row.count)}`;
    chart.append(bar);
  }
}

function render(data) {
  const totals = data.totals;
  setText("connections", number.format(totals.connections));
  setText("unique-ips", number.format(totals.unique_public_ips));
  setText("logins", number.format(totals.login_attempts));
  setText("commands", number.format(totals.commands));
  setText("transfers", number.format(totals.downloads + totals.uploads));

  const updated = new Date(data.generated_at);
  setText("freshness", `Updated ${updated.toLocaleString(undefined, { timeZone: "UTC", timeZoneName: "short" })}`);
  const partial = data.coverage.range_complete ? "complete" : "partial";
  setText("coverage", `${data.window_days}-day rolling window · ${partial} coverage · ${data.coverage.first_observation.slice(0, 10)} to ${data.coverage.last_observation.slice(0, 10)}`);

  renderRanking("top-ips", data.top_ips);
  renderRanking("top-countries", data.top_countries, countryLabel);
  renderRanking("top-commands", data.top_commands, value => value === "other" ? "Other / unclassified" : value);
  renderChart(data.daily_connections);
}

fetch("data/stats.json", { cache: "no-store" })
  .then(response => {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  })
  .then(render)
  .catch(() => {
    document.querySelector(".dot").classList.add("error");
    setText("freshness", "Snapshot unavailable");
    setText("coverage", "The latest aggregate file could not be loaded. No raw data is requested by this page.");
  });

