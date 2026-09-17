"use strict";

const number = new Intl.NumberFormat("en-US");
const countryNames = typeof Intl.DisplayNames === "function"
  ? new Intl.DisplayNames(["en"], { type: "region" })
  : null;
const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const LABELS = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "90d": "Last 90 days", all: "All time" };

let stats = null;
let alltime = null;
let current = "30d";

const $ = id => document.getElementById(id);

function setText(id, value) {
  $(id).textContent = value;
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function countryLabel(code) {
  if (!code || code === "ZZ") return "Unknown / private";
  try { return countryNames ? countryNames.of(code) : code; }
  catch (_) { return code; }
}

function dayLabel(ts) {
  return new Date(ts * 1000).toLocaleDateString("en-GB", { timeZone: "UTC", day: "2-digit", month: "short" });
}

function hourLabel(ts) {
  return `${pad(new Date(ts * 1000).getUTCHours())}:00`;
}

function renderRanking(id, rows, labeler = value => value) {
  const list = $(id);
  list.replaceChildren();
  if (!rows || !rows.length) {
    const item = document.createElement("li");
    item.className = "empty";
    item.textContent = "None in this timeframe.";
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
  const box = $(id);
  box.replaceChildren(...labels.map(text => {
    const span = document.createElement("span");
    span.textContent = text;
    return span;
  }));
}

function renderBars(id, points, describe) {
  const chart = $(id);
  chart.replaceChildren();
  if (!points.length) return;
  const peak = Math.max(1, ...points.map(point => point.count));
  chart.setAttribute("aria-label", points.map(describe).join(", "));
  for (const point of points) {
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.tabIndex = 0;
    bar.style.height = `${Math.max(2, (point.count / peak) * 100)}%`;
    bar.dataset.label = describe(point);
    chart.append(bar);
  }
}

function normalize(key) {
  if (key === "all") {
    if (!alltime) return null;
    const t = alltime.all_time;
    const monthly = alltime.monthly_connections || [];
    return {
      totals: { connections: t.connections, unique: t.unique_public_ips, logins: t.login_attempts,
                accepted: t.logins_accepted, rejected: t.logins_rejected, commands: t.commands,
                captures: t.downloads + t.uploads },
      ips: alltime.top.ips, countries: alltime.top.countries, commands: alltime.top.commands,
      usernames: alltime.top.usernames, hashes: alltime.top.hashes,
      points: monthly.map(row => ({ label: row.month, count: row.count })),
      hour: alltime.hour_of_day, weekday: alltime.weekday,
      days: alltime.coverage.days_observed, approx: true,
      note: `Archived through ${alltime.coverage.last_observation.slice(0, 10)} ` +
            `(the current day's logs rotate before archiving) · ${alltime.coverage.days_observed} day(s) · ` +
            `${number.format(t.unique_hashes)} unique files · ${number.format(t.unique_usernames)} usernames`,
    };
  }
  if (stats && !stats.windows) {
    // Backward compatibility with the pre-window snapshot shape.
    const t = stats.totals;
    return {
      totals: { connections: t.connections, unique: t.unique_public_ips, logins: t.login_attempts,
                commands: t.commands, captures: t.downloads + t.uploads },
      ips: stats.top_ips, countries: stats.top_countries, commands: stats.top_commands,
      usernames: [], hashes: [],
      points: (stats.daily_connections || []).map(row => ({ label: row.date.slice(5), count: row.count })),
      hour: null, weekday: null, days: 30, approx: false,
      note: `${LABELS[key] || "Recent"} · rolling window`,
    };
  }
  const window = stats && stats.windows ? stats.windows[key] : null;
  if (!window) return null;
  const t = window.totals;
  const series = window.series;
  const hourly = series.bucket_seconds === 3600;
  const points = series.counts.map((count, index) => {
    const ts = series.start + index * series.bucket_seconds;
    return { label: hourly ? hourLabel(ts) : dayLabel(ts), count };
  });
  return {
    totals: { connections: t.connections, unique: t.unique_public_ips, logins: t.login_attempts,
              accepted: t.logins_accepted, rejected: t.logins_rejected, commands: t.commands,
              captures: t.downloads + t.uploads },
    ips: window.top_ips, countries: window.top_countries, commands: window.top_commands,
    usernames: window.top_usernames, hashes: window.top_hashes,
    points, hour: null, weekday: null,
    days: key === "24h" ? 1 : key === "7d" ? 7 : key === "30d" ? 30 : 90,
    approx: false,
    note: `${hourly ? "Hourly" : "Daily"} buckets · ${number.format(t.logins_accepted)} accepted / ` +
          `${number.format(t.logins_rejected)} rejected logins`,
  };
}

function render() {
  const data = normalize(current);
  if (!data) return;
  setText("connections", number.format(data.totals.connections));
  setText("unique-ips", number.format(data.totals.unique));
  setText("logins", number.format(data.totals.logins));
  setText("commands", number.format(data.totals.commands));
  setText("captures", number.format(data.totals.captures));
  setText("window-note", data.note);

  renderBars("series", data.points, point => `${point.label}: ${number.format(point.count)}`);
  const points = data.points;
  setAxis("series-axis", points.length
    ? [points[0].label, points[Math.floor(points.length / 2)].label, points[points.length - 1].label]
    : []);

  const busiest = data.ips && data.ips[0];
  const share = busiest && data.totals.connections
    ? Math.round((100 * busiest.count) / data.totals.connections) : null;
  const rate = data.days ? Math.round(data.totals.connections / data.days) : null;
  const context = [];
  if (rate) context.push(`~${number.format(rate)} connection attempts/day`);
  context.push(`${number.format(data.totals.unique)} distinct public sources${data.approx ? " (approx.)" : ""}`);
  if (busiest && share !== null) {
    context.push(`busiest source ${busiest.label} (${number.format(busiest.count)}, ${share}%)`);
  }
  setText("context-line", context.join(" · "));
  let hostile = `In this timeframe the sensor recorded ${number.format(data.totals.connections)} ` +
    `connection attempts from ${number.format(data.totals.unique)} distinct public sources`;
  if (rate) hostile += `, about ${number.format(rate)} a day`;
  hostile += ".";
  if (busiest && share !== null) hostile += ` The busiest single source accounted for ${share}% of them.`;
  setText("hostile-line", hostile);

  renderRanking("top-ips", data.ips);
  renderRanking("top-countries", data.countries, countryLabel);
  renderRanking("top-commands", data.commands, value => value === "other" ? "Other / unclassified" : value);
  renderRanking("top-usernames", data.usernames);
  renderRanking("top-hashes", data.hashes, value => value.length > 22 ? `${value.slice(0, 22)}…` : value);

  const clock = $("clock");
  if (data.hour && data.weekday) {
    clock.hidden = false;
    renderBars("hour", data.hour.map((count, hour) => ({ label: `${pad(hour)}:00`, count })),
      point => `${point.label} UTC: ${number.format(point.count)}`);
    setAxis("hour-axis", ["00", "06", "12", "18", "23"]);
    renderBars("weekday", data.weekday.map((count, index) => ({ label: WEEKDAYS[index], count })),
      point => `${point.label}: ${number.format(point.count)}`);
    setAxis("weekday-axis", WEEKDAYS);
  } else {
    clock.hidden = true;
  }

  for (const button of document.querySelectorAll("#picker button")) {
    button.setAttribute("aria-pressed", String(button.dataset.window === current));
  }
}

function selectWindow(key, updateUrl = true) {
  current = key;
  if (updateUrl) history.replaceState(null, "", `?window=${key}`);
  render();
}

function load(url) {
  return fetch(url, { cache: "no-store" }).then(response => {
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  });
}

const requested = new URLSearchParams(location.search).get("window");
if (LABELS[requested]) current = requested;

Promise.allSettled([load("data/stats.json"), load("data/alltime.json")]).then(([statsResult, alltimeResult]) => {
  if (statsResult.status === "fulfilled") stats = statsResult.value;
  if (alltimeResult.status === "fulfilled") alltime = alltimeResult.value;
  if (statsResult.status !== "fulfilled" || !stats) {
    setText("freshness", "Snapshot unavailable");
  } else {
    const updated = new Date(stats.generated_at);
    setText("freshness", `Updated ${updated.toLocaleString(undefined, { timeZone: "UTC", timeZoneName: "short" })}`);
    setText("coverage", ` · ${stats.coverage.first_observation.slice(0, 10)} to ${stats.coverage.last_observation.slice(0, 10)}`);
  }
  if (!alltime) {
    const button = document.querySelector('#picker button[data-window="all"]');
    if (button) button.disabled = true;
    if (current === "all") current = "30d";
  }
  document.getElementById("picker").addEventListener("click", event => {
    const button = event.target.closest("button[data-window]");
    if (button && !button.disabled) selectWindow(button.dataset.window);
  });
  render();
});
