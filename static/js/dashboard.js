/**
 * Dashboard Visualizations powered by Chart.js
 * Cyber themed charts for Category Distribution, Activity Timeline, and Severity.
 */

let categoryChartInstance = null;
let timelineChartInstance = null;
let severityChartInstance = null;

function initDashboardCharts(catData, sevData, timelineData) {
  // Chart Colors
  const cyanAccent = "#00f2fe";
  const safeColor = "#00f5d4";
  const spamColor = "#ffb703";
  const phishColor = "#ff3366";
  const gridColor = "rgba(255, 255, 255, 0.06)";
  const textColor = "#a0aec0";

  // 1. Threat Category Distribution Doughnut Chart
  const ctxCat = document.getElementById("categoryChart");
  if (ctxCat) {
    if (categoryChartInstance) categoryChartInstance.destroy();

    categoryChartInstance = new Chart(ctxCat, {
      type: "doughnut",
      data: {
        labels: ["Safe / Legitimate", "Spam", "Phishing"],
        datasets: [
          {
            data: [catData.Safe || 0, catData.Spam || 0, catData.Phishing || 0],
            backgroundColor: [safeColor, spamColor, phishColor],
            borderColor: "transparent",
            borderWidth: 2,
            hoverOffset: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: textColor,
              boxWidth: 12,
              padding: 14,
              font: { size: 11, family: "Segoe UI" },
            },
          },
          tooltip: {
            backgroundColor: "#0d1b2a",
            titleColor: "#ffffff",
            bodyColor: "#a0aec0",
            borderColor: "rgba(0, 242, 254, 0.3)",
            borderWidth: 1,
            padding: 10,
          },
        },
        cutout: "68%",
      },
    });
  }

  // 2. 7-Day Activity Line Chart
  const ctxTimeline = document.getElementById("timelineChart");
  if (ctxTimeline) {
    if (timelineChartInstance) timelineChartInstance.destroy();

    const labels = (timelineData || []).map((item) => item.day.substring(5));
    const counts = (timelineData || []).map((item) => item.count);

    // Fallback if empty
    const finalLabels = labels.length > 0 ? labels : ["Day 1", "Day 2", "Day 3", "Day 4", "Day 5", "Day 6", "Today"];
    const finalCounts = counts.length > 0 ? counts : [1, 2, 1, 3, 2, 4, 2];

    timelineChartInstance = new Chart(ctxTimeline, {
      type: "line",
      data: {
        labels: finalLabels,
        datasets: [
          {
            label: "Detections",
            data: finalCounts,
            borderColor: cyanAccent,
            backgroundColor: "rgba(0, 242, 254, 0.12)",
            fill: true,
            tension: 0.35,
            borderWidth: 2,
            pointBackgroundColor: cyanAccent,
            pointBorderColor: "#ffffff",
            pointRadius: 4,
            pointHoverRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0d1b2a",
            borderColor: "rgba(0, 242, 254, 0.3)",
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            grid: { color: gridColor },
            ticks: { color: textColor, font: { size: 10 } },
          },
          y: {
            beginAtZero: true,
            grid: { color: gridColor },
            ticks: { color: textColor, stepSize: 1, font: { size: 10 } },
          },
        },
      },
    });
  }

  // 3. Risk Severity Bar Chart
  const ctxSev = document.getElementById("severityChart");
  if (ctxSev) {
    if (severityChartInstance) severityChartInstance.destroy();

    severityChartInstance = new Chart(ctxSev, {
      type: "bar",
      data: {
        labels: ["Low Risk", "Medium Risk", "High Risk"],
        datasets: [
          {
            label: "Messages",
            data: [sevData.Low || 0, sevData.Medium || 0, sevData.High || 0],
            backgroundColor: [
              "rgba(0, 245, 212, 0.65)",
              "rgba(255, 183, 3, 0.65)",
              "rgba(255, 51, 102, 0.65)",
            ],
            borderColor: [safeColor, spamColor, phishColor],
            borderWidth: 1,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#0d1b2a",
            borderColor: "rgba(0, 242, 254, 0.3)",
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: textColor, font: { size: 11 } },
          },
          y: {
            beginAtZero: true,
            grid: { color: gridColor },
            ticks: { color: textColor, stepSize: 1, font: { size: 10 } },
          },
        },
      },
    });
  }
}
