// ─────────────────────────────────────────────────────────────
// CHARTS & VISUALIZATIONS
// ─────────────────────────────────────────────────────────────
function trendPct(s) {
    if (!s || s.length < 2) return null;
    var a = s[0], b = s[s.length - 1];
    if (!a && !b) return null;
    var p = a === 0 ? 100 : (b - a) / a * 100;
    return p;
}
function trendHTML(p, invert) {
    if (p === null || isNaN(p)) return '<span class="dim">—</span>';
    var up = p >= 0;
    var good = invert ? !up : up;
    return '<span class="trend ' + (good ? 'up' : 'down') + '">' + (up ? '↗' : '↘') + ' ' + Math.abs(p).toFixed(2) + '%</span>';
}
function areaChart(el, data, labels, color) {
    color = color || '#da7751';
    if (!data.length) { el.innerHTML = '<div class="empty">No data</div>'; return; }
    var W = el.clientWidth || 600, H = el.clientHeight || 200, pad = { l: 8, r: 44, t: 14, b: 22 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var max = Math.max.apply(null, [1].concat(data));
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    var pt = function(v, i) { return [pad.l + (i / Math.max(1, data.length - 1)) * cw, pad.t + ch - (v / max) * ch]; };
    var line = '';
    data.forEach(function(v, i) { var xy = pt(v, i); line += (i ? 'L' : 'M') + xy[0] + ',' + xy[1]; });
    s += '<path d="' + line + ' L' + (pad.l + cw) + ',' + (pad.t + ch) + ' L' + pad.l + ',' + (pad.t + ch) + ' Z" fill="' + color + '" opacity=".14"/>';
    s += '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="1.6"/>';
    (labels || []).forEach(function(l, i) {
        if (i % Math.ceil((labels.length || 1) / 6)) return;
        var x = pad.l + (i / Math.max(1, labels.length - 1)) * cw;
        s += '<text x="' + x + '" y="' + (H - 6) + '" fill="#5d6375" font-size="9.5" text-anchor="middle">' + esc(l) + '</text>';
    });
    s += '<text x="' + (W - 4) + '" y="' + (pad.t + 8) + '" fill="#9298ab" font-size="9.5" text-anchor="end">' + fmtK(max) + '</text></svg>';
    el.innerHTML = s;
}
function hbarsLegend(el, items, valKey, fmtFn) {
    if (!items.length) { el.innerHTML = '<div class="empty">No model data yet</div>'; return; }
    var max = Math.max.apply(null, items.map(function(i) { return Number(i[valKey]) || 0; }).concat([1e-9]));
    var s = '<div style="display:flex;gap:14px;height:100%"><div style="flex:1;display:flex;flex-direction:column;justify-content:space-around">';
    items.forEach(function(m, i) {
        s += '<div style="display:flex;align-items:center;gap:8px"><span style="width:170px;text-align:right;font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(m.name) + '</span><div style="flex:1;height:10px;background:#101320;border-radius:2px"><div style="width:' + (Number(m[valKey]) / max * 100).toFixed(1) + '%;height:100%;background:' + P[i % P.length] + ';border-radius:2px"></div></div></div>';
    });
    s += '<div style="display:flex;justify-content:space-between;color:var(--dim);font-size:9.5px;margin-left:178px"><span>0</span><span>' + fmtFn(max / 2) + '</span><span>' + fmtFn(max) + '</span></div></div>';
    s += '<div style="width:190px;overflow:auto;display:flex;flex-direction:column;gap:5px;font-size:10.5px;color:var(--muted)">';
    items.forEach(function(m, i) {
        s += '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + P[i % P.length] + ';margin-right:6px"></i>' + esc(m.name) + '</span>';
    });
    s += '</div></div>';
    el.innerHTML = s;
}
function stackedTime(el, days, map) {
    if (!days.length) { el.innerHTML = '<div class="empty">No guardrail data yet</div>'; return; }
    var W = el.clientWidth || 600, H = el.clientHeight || 250, pad = { l: 30, r: 8, t: 10, b: 20 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var totals = days.map(function(d) { return CHECKS.reduce(function(a, arr) { return a + (map[d + '|' + arr[0]] || 0); }, 0); });
    var max = Math.max.apply(null, [1].concat(totals));
    var bw = Math.max(2, cw / days.length - 2);
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    [0, .5, 1].forEach(function(t) {
        var y = pad.t + ch - t * ch;
        s += '<line x1="' + pad.l + '" y1="' + y + '" x2="' + (W - pad.r) + '" y2="' + y + '" stroke="#20243a" stroke-width=".5"/><text x="' + (pad.l - 5) + '" y="' + (y + 3) + '" fill="#5d6375" font-size="9" text-anchor="end">' + Math.round(max * t) + '</text>';
    });
    days.forEach(function(d, i) {
        var y = pad.t + ch;
        CHECKS.forEach(function(arr) {
            var n = arr[0], c = arr[1], v = map[d + '|' + n] || 0;
            if (!v) return;
            var h = (v / max) * ch;
            y -= h;
            s += '<rect x="' + (pad.l + i * (cw / days.length)) + '" y="' + y + '" width="' + bw + '" height="' + h + '" fill="' + c + '"/>';
        });
    });
    days.forEach(function(d, i) {
        if (i % Math.ceil(days.length / 6)) return;
        s += '<text x="' + (pad.l + i * (cw / days.length)) + '" y="' + (H - 5) + '" fill="#5d6375" font-size="9">' + esc(d.slice(5)) + '</text>';
    });
    el.innerHTML = s + '</svg>';
}
function multiLine(el, days, series) {
    if (!series.length) { el.innerHTML = '<div class="empty">No data</div>'; return; }
    var W = el.clientWidth || 600, H = el.clientHeight || 300, pad = { l: 36, r: 8, t: 10, b: 20 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var allVals = [];
    series.forEach(function(sr) { allVals = allVals.concat(sr.values); });
    var max = Math.max.apply(null, [1].concat(allVals));
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    [0, .25, .5, .75, 1].forEach(function(t) {
        var y = pad.t + ch - t * ch;
        s += '<line x1="' + pad.l + '" y1="' + y + '" x2="' + (W - pad.r) + '" y2="' + y + '" stroke="#20243a" stroke-width=".5"/><text x="' + (pad.l - 5) + '" y="' + (y + 3) + '" fill="#5d6375" font-size="9" text-anchor="end">' + fmtK(max * t) + '</text>';
    });
    series.forEach(function(sr) {
        var p = '';
        sr.values.forEach(function(v, i) {
            var x = pad.l + (i / Math.max(1, sr.values.length - 1)) * cw, y = pad.t + ch - (v / max) * ch;
            p += (i ? 'L' : 'M') + x + ',' + y;
        });
        s += '<path d="' + p + '" fill="none" stroke="' + sr.color + '" stroke-width="1.2"/>';
    });
    days.forEach(function(d, i) {
        if (i % Math.ceil(days.length / 5)) return;
        var x = pad.l + (i / Math.max(1, days.length - 1)) * cw;
        s += '<text x="' + x + '" y="' + (H - 5) + '" fill="#5d6375" font-size="9" text-anchor="middle">' + esc(d.slice(5)) + '</text>';
    });
    var legendHTML = '';
    series.forEach(function(sr) { legendHTML += '<span><i style="background:' + sr.color + '"></i>' + esc(sr.name) + '</span>'; });
    el.innerHTML = s + '</svg><div class="legend">' + legendHTML + '</div>';
}
function donut(el, okPct, okN, failN) {
    var r1 = 75 + 56 * Math.sin(Math.max(.02, (1 - okPct / 100) * 6.283));
    var r2 = 75 - 56 * Math.cos(Math.max(.02, (1 - okPct / 100) * 6.283));
    el.innerHTML = '<div style="display:flex;align-items:center;gap:18px;height:100%;justify-content:center"><svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="56" fill="#2b8a5e" opacity=".9"/><path d="M75 19 A56 56 0 0 1 ' + r1 + ' ' + r2 + '" stroke="var(--red2)" stroke-width="3" fill="none"/><circle cx="75" cy="75" r="34" fill="var(--card)"/><text x="75" y="72" text-anchor="middle" fill="var(--dim)" font-size="9">' + (100 - okPct).toFixed(0) + '%</text><text x="75" y="86" text-anchor="middle" fill="var(--dim)" font-size="9">' + okPct.toFixed(0) + '%</text></svg><div style="font-size:11px;color:var(--muted);display:flex;flex-direction:column;gap:6px"><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--red2);margin-right:6px"></i>Failed Requests</span><span><i style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#2b8a5e;margin-right:6px"></i>Successful Requests</span></div></div>';
}
function forecastBand(el, hist) {
    if (!hist || hist.length < 2) { el.innerHTML = '<div class="empty">Not enough history</div>'; return; }
    var W = el.clientWidth || 500, H = el.clientHeight || 170, pad = { l: 26, r: 6, t: 10, b: 16 }, cw = W - pad.l - pad.r, ch = H - pad.t - pad.b;
    var delta = (hist[hist.length - 1] - hist[0]) / (hist.length - 1);
    var fc = [];
    for (var i = 0; i < 6; i++) fc.push(Math.max(0, hist[hist.length - 1] + delta * (i + 1)));
    var histMax = Math.max.apply(null, [1].concat(hist));
    var band = fc.map(function(v) { return Math.max(v * .25, histMax * .06); });
    var fcWithBand = fc.map(function(v, i) { return v + band[i]; });
    var max = Math.max.apply(null, hist.concat(fcWithBand)) * 1.1;
    var X = function(i) { return pad.l + (i / (hist.length - 1)) * cw * .62; };
    var XF = function(i) { return pad.l + cw * .62 + (i / 6) * cw * .38; };
    var s = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    var p = '';
    hist.forEach(function(v, i) { var y = pad.t + ch - (v / max) * ch; p += (i ? 'L' : 'M') + X(i) + ',' + y; });
    s += '<path d="' + p + '" fill="none" stroke="#e6e8f2" stroke-width="1"/>';
    var ly = pad.t + ch - (hist[hist.length - 1] / max) * ch, lx = X(hist.length - 1);
    var up = '', lo = '';
    fc.forEach(function(v, i) { up += 'L' + XF(i + 1) + ',' + (pad.t + ch - ((v + band[i]) / max) * ch) + ' '; });
    for (var j = fc.length - 1; j >= 0; j--) lo += 'L' + XF(j + 1) + ',' + (pad.t + ch - (Math.max(0, fc[j] - band[j]) / max) * ch) + ' ';
    s += '<path d="M' + lx + ',' + ly + ' ' + up + lo + ' Z" fill="#da7751" opacity=".22"/>';
    var fl = 'M' + lx + ',' + ly;
    fc.forEach(function(v, i) { fl += ' L' + XF(i + 1) + ',' + (pad.t + ch - (v / max) * ch); });
    s += '<path d="' + fl + '" fill="none" stroke="#e6b17e" stroke-width="1"/></svg>';
    el.innerHTML = s;
}
function spark(el, data, color) {
    color = color || '#da7751';
    if (!data || data.length < 2) { el.innerHTML = ''; return; }
    var W = el.clientWidth || 180, H = 40, max = Math.max.apply(null, [1].concat(data));
    var p = '';
    data.forEach(function(v, i) { p += (i ? 'L' : 'M') + (i / (data.length - 1)) * W + ',' + (H - 4 - (v / max) * (H - 8)); });
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" style="width:100%;height:40px"><path d="' + p + '" fill="none" stroke="' + color + '" stroke-width="1"/></svg>';
}

// ─────────────────────────────────────────────────────────────
// CALENDAR HEATMAP
// ─────────────────────────────────────────────────────────────
function renderCalendarHeatmap(el, data) {
    var cells = (data && data.cells) || [];
    if (!cells.length) { el.innerHTML = '<div class="empty">No activity recorded yet</div>'; return; }
    var byDate = {};
    cells.forEach(function(c) { byDate[c.date] = c; });
    var totals = cells.map(function(c) { return c.total; }).filter(function(t) { return t > 0; }).sort(function(a, b) { return a - b; });
    function levelFor(total) {
        if (!total) return 0;
        if (!totals.length) return 1;
        var n = totals.length;
        var q = function(p) { return totals[Math.min(n - 1, Math.floor(p * (n - 1)))]; };
        if (total <= q(0.25)) return 1;
        if (total <= q(0.5)) return 2;
        if (total <= q(0.75)) return 3;
        return 4;
    }
    var today = new Date();
    var oldest = cells.length ? new Date(cells[0].date + 'T00:00:00') : new Date(today.getTime() - 90 * 86400000);
    var start = new Date(oldest);
    start.setDate(start.getDate() - start.getDay());
    var days = [];
    for (var d = new Date(start); d <= today; d.setDate(d.getDate() + 1)) days.push(new Date(d));
    var weeks = [];
    for (var i = 0; i < days.length; i += 7) weeks.push(days.slice(i, i + 7));
    function fmtDate(dt) { return dt.getFullYear() + '-' + String(dt.getMonth() + 1).padStart(2, '0') + '-' + String(dt.getDate()).padStart(2, '0'); }
    var html = '<div class="cal-heatmap-wrap"><div class="cal-heatmap">';
    weeks.forEach(function(week) {
        html += '<div class="cal-col">';
        week.forEach(function(dt) {
            var key = fmtDate(dt);
            var c = byDate[key];
            var total = c ? c.total : 0;
            var blocked = c ? c.blocked : 0;
            var flagged = c ? c.flagged : 0;
            var level = levelFor(total);
            var cls = 'cal-cell' + (blocked > 0 ? ' has-blocked' : '');
            html += '<div class="' + cls + '" data-level="' + level + '" data-date="' + key + '" data-total="' + total + '" data-blocked="' + blocked + '" data-flagged="' + flagged + '" onmouseenter="_calHover(event,this)" onmouseleave="_calHoverOut()"></div>';
        });
        html += '</div>';
    });
    html += '</div><div class="cal-legend">Less <span class="cal-cell" data-level="0"></span><span class="cal-cell" data-level="1"></span><span class="cal-cell" data-level="2"></span><span class="cal-cell" data-level="3"></span><span class="cal-cell" data-level="4"></span> More · outline = day with a blocked action</div></div>';
    el.innerHTML = html;
}
function _calHover(evt, cellEl) {
    var tip = $('calTooltip');
    var date = cellEl.getAttribute('data-date');
    var total = cellEl.getAttribute('data-total');
    var blocked = cellEl.getAttribute('data-blocked');
    var flagged = cellEl.getAttribute('data-flagged');
    tip.innerHTML = '<b>' + esc(date) + '</b><div class="ct-row">' + esc(total) + ' action' + (total === '1' ? '' : 's') + '</div><div class="ct-row">' + esc(blocked) + ' blocked</div><div class="ct-row">' + esc(flagged) + ' flagged</div>';
    tip.style.display = 'block';
    var r = cellEl.getBoundingClientRect();
    tip.style.left = Math.min(window.innerWidth - 230, r.left) + 'px';
    tip.style.top = Math.max(4, r.top - 74) + 'px';
}
function _calHoverOut() { $('calTooltip').style.display = 'none'; }
