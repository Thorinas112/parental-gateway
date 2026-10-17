/* ==========================================================================
   pgChart - tiny dependency-free SVG charts for the usage dashboard
   ========================================================================== */
(function (global) {
  'use strict';

  /* ------------------------------------------------------------ formatting */
  function formatBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    const units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    let value = n / 1024;
    let i = 0;
    while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
    return (value >= 100 ? Math.round(value) : value.toFixed(value >= 10 ? 1 : 2)) + ' ' + units[i];
  }

  function formatRate(bytesPerSecond) {
    return formatBytes(bytesPerSecond) + '/s';
  }

  function formatTime(ts, spanSeconds) {
    const d = new Date(ts * 1000);
    if (spanSeconds <= 2 * 3600) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (spanSeconds <= 3 * 86400) return d.toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  }

  function formatTimeFull(ts) {
    return new Date(ts * 1000).toLocaleString([], {
      weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  }

  /* nice y-axis ceiling: 1, 2, 2.5, 5 x 10^n */
  function niceCeiling(value) {
    if (!value || value <= 0) return 1;
    const exponent = Math.floor(Math.log10(value));
    const base = Math.pow(10, exponent);
    const normalised = value / base;
    let nice;
    if (normalised <= 1) nice = 1;
    else if (normalised <= 2) nice = 2;
    else if (normalised <= 2.5) nice = 2.5;
    else if (normalised <= 5) nice = 5;
    else nice = 10;
    return nice * base;
  }

  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ==================================================================== area */
  /**
   * Stacked area chart.
   *
   * pgChart.area(element, {
   *   points: [{ts, up, down}],   // ascending by ts
   *   height: 260,
   *   colors: { up: '#22d3ee', down: '#6366f1' },
   *   labels: { up: 'Upload', down: 'Download' },
   *   spanSeconds: 86400
   * })
   */
  function area(el, opts) {
    const options = opts || {};
    const points = (options.points || []).slice().sort(function (a, b) { return a.ts - b.ts; });
    const height = options.height || 260;
    const colors = options.colors || { up: '#22d3ee', down: '#6366f1' };
    const labels = options.labels || { up: 'Upload', down: 'Download' };

    el.classList.add('pgchart');
    el.style.position = 'relative';

    if (!points.length) {
      el.innerHTML = '<div class="pgchart-empty">No traffic recorded yet.<br>' +
        '<span>Samples appear within a minute of the first device sending data.</span></div>';
      return;
    }

    const width = Math.max(320, el.clientWidth || 640);
    const pad = { top: 14, right: 14, bottom: 30, left: 62 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const span = options.spanSeconds || Math.max(1, points[points.length - 1].ts - points[0].ts);
    const t0 = options.from != null ? options.from : points[0].ts;
    const t1 = options.to != null ? options.to : points[points.length - 1].ts;
    const tRange = Math.max(1, t1 - t0);

    let maxTotal = 0;
    points.forEach(function (p) {
      const total = (Number(p.up) || 0) + (Number(p.down) || 0);
      if (total > maxTotal) maxTotal = total;
    });
    const yMax = niceCeiling(maxTotal);

    const x = function (ts) { return pad.left + ((ts - t0) / tRange) * plotW; };
    const y = function (v) { return pad.top + plotH - (v / yMax) * plotH; };

    /* ---- paths: stack download (bottom) then upload (above it) ---- */
    let downTop = '', upTop = '';
    points.forEach(function (p, i) {
      const down = Number(p.down) || 0;
      const total = down + (Number(p.up) || 0);
      downTop += (i ? 'L' : 'M') + x(p.ts).toFixed(1) + ',' + y(down).toFixed(1);
      upTop += (i ? 'L' : 'M') + x(p.ts).toFixed(1) + ',' + y(total).toFixed(1);
    });
    const base = y(0).toFixed(1);
    const downArea = downTop + 'L' + x(points[points.length - 1].ts).toFixed(1) + ',' + base +
      'L' + x(points[0].ts).toFixed(1) + ',' + base + 'Z';
    const upArea = upTop + 'L' + x(points[points.length - 1].ts).toFixed(1) + ',' +
      y(points[points.length - 1].down).toFixed(1) + 'L' + reversePath(downTop) + 'Z';

    /* ---- axes ---- */
    const gridCount = 4;
    let grid = '', yLabels = '';
    for (let i = 0; i <= gridCount; i++) {
      const value = (yMax / gridCount) * i;
      const gy = y(value);
      grid += '<line class="pg-grid" x1="' + pad.left + '" x2="' + (width - pad.right) +
        '" y1="' + gy.toFixed(1) + '" y2="' + gy.toFixed(1) + '"/>';
      yLabels += '<text class="pg-axis" x="' + (pad.left - 9) + '" y="' + (gy + 4).toFixed(1) +
        '" text-anchor="end">' + esc(formatBytes(value)) + '</text>';
    }

    const tickCount = Math.min(6, Math.max(2, Math.floor(plotW / 90)));
    let xLabels = '';
    for (let i = 0; i <= tickCount; i++) {
      const ts = t0 + (tRange / tickCount) * i;
      const anchor = i === 0 ? 'start' : i === tickCount ? 'end' : 'middle';
      xLabels += '<text class="pg-axis" x="' + x(ts).toFixed(1) + '" y="' + (height - 8) +
        '" text-anchor="' + anchor + '">' + esc(formatTime(ts, span)) + '</text>';
    }

    const svg =
      '<svg class="pg-svg" width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '">' +
      '<defs>' +
      '<linearGradient id="pgUp" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="' + colors.up + '" stop-opacity="0.55"/>' +
      '<stop offset="100%" stop-color="' + colors.up + '" stop-opacity="0.06"/></linearGradient>' +
      '<linearGradient id="pgDown" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="' + colors.down + '" stop-opacity="0.55"/>' +
      '<stop offset="100%" stop-color="' + colors.down + '" stop-opacity="0.06"/></linearGradient>' +
      '</defs>' +
      grid + yLabels + xLabels +
      '<path d="' + downArea + '" fill="url(#pgDown)" stroke="' + colors.down + '" stroke-width="1.6" stroke-linejoin="round"/>' +
      '<path d="' + upArea + '" fill="url(#pgUp)" stroke="' + colors.up + '" stroke-width="1.6" stroke-linejoin="round"/>' +
      '<line class="pg-cross" x1="0" x2="0" y1="' + pad.top + '" y2="' + (pad.top + plotH) + '" visibility="hidden"/>' +
      '<circle class="pg-dot" r="3.5" fill="' + colors.up + '" visibility="hidden"/>' +
      '<circle class="pg-dot" r="3.5" fill="' + colors.down + '" visibility="hidden"/>' +
      '</svg>';

    el.innerHTML = svg +
      '<div class="pg-legend">' +
      '<span class="pg-key"><i style="background:' + colors.up + '"></i>' + esc(labels.up) + '</span>' +
      '<span class="pg-key"><i style="background:' + colors.down + '"></i>' + esc(labels.down) + '</span>' +
      '</div>' +
      '<div class="pg-tooltip" hidden></div>';

    /* ---- hover ---- */
    const svgEl = el.querySelector('.pg-svg');
    const cross = el.querySelector('.pg-cross');
    const dots = el.querySelectorAll('.pg-dot');
    const tooltip = el.querySelector('.pg-tooltip');

    function hide() {
      cross.setAttribute('visibility', 'hidden');
      dots.forEach(function (d) { d.setAttribute('visibility', 'hidden'); });
      tooltip.hidden = true;
    }

    svgEl.addEventListener('mousemove', function (event) {
      const rect = svgEl.getBoundingClientRect();
      const mx = event.clientX - rect.left;
      const ratio = Math.min(1, Math.max(0, (mx - pad.left) / plotW));
      const targetTs = t0 + ratio * tRange;

      let nearest = points[0];
      let best = Infinity;
      points.forEach(function (p) {
        const d = Math.abs(p.ts - targetTs);
        if (d < best) { best = d; nearest = p; }
      });

      const px = x(nearest.ts);
      const down = Number(nearest.down) || 0;
      const total = down + (Number(nearest.up) || 0);

      cross.setAttribute('x1', px.toFixed(1));
      cross.setAttribute('x2', px.toFixed(1));
      cross.setAttribute('visibility', 'visible');

      dots[0].setAttribute('cx', px.toFixed(1));
      dots[0].setAttribute('cy', y(total).toFixed(1));
      dots[0].setAttribute('visibility', 'visible');
      dots[1].setAttribute('cx', px.toFixed(1));
      dots[1].setAttribute('cy', y(down).toFixed(1));
      dots[1].setAttribute('visibility', 'visible');

      tooltip.hidden = false;
      tooltip.innerHTML =
        '<div class="pg-tip-time">' + esc(formatTimeFull(nearest.ts)) + '</div>' +
        '<div class="pg-tip-row"><i style="background:' + colors.up + '"></i>' + esc(labels.up) +
        '<strong>' + esc(formatBytes(nearest.up || 0)) + '</strong></div>' +
        '<div class="pg-tip-row"><i style="background:' + colors.down + '"></i>' + esc(labels.down) +
        '<strong>' + esc(formatBytes(nearest.down || 0)) + '</strong></div>' +
        '<div class="pg-tip-total">Total <strong>' + esc(formatBytes(total)) + '</strong></div>';

      const tipW = tooltip.offsetWidth || 170;
      const left = Math.min(width - tipW - 6, Math.max(6, px - tipW / 2));
      tooltip.style.left = left + 'px';
      tooltip.style.top = Math.max(4, y(total) - tooltip.offsetHeight - 12) + 'px';
    });

    svgEl.addEventListener('mouseleave', hide);
    svgEl.addEventListener('touchmove', function (e) {
      if (!e.touches.length) return;
      svgEl.dispatchEvent(new MouseEvent('mousemove', {
        clientX: e.touches[0].clientX, clientY: e.touches[0].clientY,
      }));
    }, { passive: true });
  }

  function reversePath(linePath) {
    // "M x,y L x,y ..." reversed -> "L x,y ..." walking back along the line
    const coords = linePath.match(/[ML]([\d.]+),([\d.]+)/g) || [];
    const reversed = coords.slice().reverse();
    return reversed.map(function (c, i) {
      return (i === 0 ? 'L' : 'L') + c.slice(1);
    }).join('');
  }

  global.pgChart = { area: area, formatBytes: formatBytes, formatRate: formatRate };
})(window);
