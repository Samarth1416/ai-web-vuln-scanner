/**
 * charts.js — CyberScan AI
 * Dashboard Chart.js initialisation
 */

Chart.defaults.color = '#4e6578';
Chart.defaults.borderColor = 'rgba(0,255,136,0.06)';

function initDashboardCharts(sevCounts, vulnCounts) {

  // ── Severity Doughnut ─────────────────────────
  const sevCtx = document.getElementById('sevChart');
  if (sevCtx) {
    const labels = Object.keys(sevCounts).filter(k => sevCounts[k] > 0);
    const data   = labels.map(k => sevCounts[k]);
    const colors = {
      Critical: '#ff4757',
      High:     '#ff9600',
      Medium:   '#ffd32a',
      Low:      '#00d4ff',
      Info:     '#4e6578',
    };

    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: labels.map(l => colors[l] + '99'),
          borderColor:     labels.map(l => colors[l]),
          borderWidth: 2,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { padding: 16, font: { size: 12 }, color: '#4e6578' }
          },
          tooltip: {
            callbacks: {
              label: ctx => ` ${ctx.label}: ${ctx.raw} finding(s)`
            }
          }
        }
      }
    });
  }

  // ── Vulnerability Bar Chart ───────────────────
  const vulnCtx = document.getElementById('vulnChart');
  if (vulnCtx) {
    const vLabels = Object.keys(vulnCounts);
    const vData   = vLabels.map(k => vulnCounts[k]);

    new Chart(vulnCtx, {
      type: 'bar',
      data: {
        labels: vLabels.map(l => l.length > 22 ? l.substring(0,22)+'…' : l),
        datasets: [{
          label: 'Findings',
          data: vData,
          backgroundColor: 'rgba(0,255,136,0.2)',
          borderColor:     '#00ff88',
          borderWidth: 2,
          borderRadius: 6,
          hoverBackgroundColor: 'rgba(0,255,136,0.4)',
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            ticks: { color: '#4e6578', font: { size: 11 }, maxRotation: 30 },
            grid:  { color: 'rgba(0,255,136,0.05)' }
          },
          y: {
            ticks: { color: '#4e6578', stepSize: 1 },
            grid:  { color: 'rgba(0,255,136,0.05)' },
            beginAtZero: true,
          }
        }
      }
    });
  }
}
