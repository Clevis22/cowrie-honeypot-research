"use strict";

const number = new Intl.NumberFormat("en-US");
const countryNames = typeof Intl.DisplayNames === "function"
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;
const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function countryLabel(code) {
  if (!code || code === "ZZ") return "Unknown / private";
  try { return countryNames ? countryNames.of(code) : code; }
  catch (_) { return code; }
}

function renderRanking(id, rows, labeler = value => value) {
  const list = document.getElementById(id);
  list.replaceChildren();
  if (!rows || !rows.length) {
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
    label.title = row.label;
    count.textContent = number.format(row.count);
    item.append(label, count);
    list.append(item);
  }
}

function setAxis(id, labels) {
  const box = document.getElementById(id);
  box.replaceChildren(...labels.map(label => {
    const span = document.createElement("span");
    span.textContent = label;
    return span;
  }));
}

function renderBars(id, rows, labeler) {
  const chart = document.getElementById(id);
  chart.replaceChildren();
  if (!rows.length) return;
  const peak = Math.max(1, ...rows.map(row => row.count));
  chart.setAttribute("aria-label", rows.map(row => labeler(row)).join(", "));
  for (const row of rows) {
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.tabIndex = 0;
    bar.style.height = `${Math.max(2, (row.count / peak) * 100)}%`;
    bar.dataset.label = labeler(row);
    chart.append(bar);
  }
}

function renderChart(rows) {
  const visible = rows.slice(-30);
  renderBars("daily-chart", visible, row => `${row.date}: ${number.format(row.count)}`);
  const peak = Math.max(1, ...visible.map(row => row.count));
  document.getElementById("daily-chart").setAttribute(
    "aria-label", visible.map(row => `${row.date}: ${row.count}`).join(", "));
  return peak;
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

function renderAllTime(data) {
  const totals = data.all_time;
  const coverage = data.coverage;
  setText("at-connections", number.format(totals.connections));
  setText("at-ips", number.format(totals.unique_public_ips));
  setText("at-logins", number.format(totals.login_attempts));
  setText("at-commands", number.format(totals.commands));
  setText("at-captures", number.format(totals.downloads + totals.uploads));

  const first = coverage.first_observation ? coverage.first_observation.slice(0, 10) : "—";
  const last = coverage.last_observation ? coverage.last_observation.slice(0, 10) : "—";
  setText("alltime-coverage",
    `All-time archive · ${coverage.days_observed} day(s) · ${first} to ${last} · ` +
    `${number.format(totals.logins_accepted)} accepted / ${number.format(totals.logins_rejected)} rejected · ` +
    `${number.format(totals.unique_hashes)} unique files · ${number.format(totals.unique_usernames)} usernames`);

  renderRanking("at-top-ips", data.top.ips);
  renderRanking("at-top-countries", data.top.countries, countryLabel);
  renderRanking("at-top-commands", data.top.commands, value => value === "other" ? "Other / unclassified" : value);
  renderRanking("at-top-usernames", data.top.usernames);
  renderRanking("at-top-hashes", data.top.hashes, value => value.length > 22 ? `${value.slice(0, 22)}…` : value);

  const monthly = data.monthly_connections || [];
  renderBars("at-monthly", monthly, row => `${row.month}: ${number.format(row.count)}`);
  setAxis("at-monthly-axis", monthly.length
    ? [monthly[0].month, monthly[Math.floor(monthly.length / 2)].month, monthly[monthly.length - 1].month]
    : []);

  const hours = data.hour_of_day || [];
  renderBars("at-hour", hours.map((count, hour) => ({ label: `${pad(hour)}:00`, count })), row => `${row.label} UTC: ${number.format(row.count)}`);
  setAxis("at-hour-axis", ["00", "06", "12", "18", "23"]);

  const weekday = data.weekday || [];
  renderBars("at-weekday", weekday.map((count, index) => ({ label: WEEKDAYS[index], count })), row => `${row.label} UTC: ${number.format(row.count)}`);
  setAxis("at-weekday-axis", WEEKDAYS);
}

function load(url, handler) {
  return fetch(url, { cache: "no-store" })
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then(handler);
}

load("data/stats.json", render).catch(() => {
  document.querySelector(".dot").classList.add("error");
  setText("freshness", "Snapshot unavailable");
  setText("coverage", "The latest aggregate file could not be loaded. No raw data is requested by this page.");
});

load("data/alltime.json", renderAllTime).catch(() => {
  setText("alltime-coverage", "The all-time aggregate is not available yet.");
});
