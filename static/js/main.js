/**
 * Main Application JavaScript: Theme Management, Space Starfield, Mobile Navigation, UI Helpers
 */

// Global function to toggle between 'light' and 'dark' themes
function setAppTheme(theme) {
  const chosenTheme = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", chosenTheme);
  localStorage.setItem("phishshield_theme", chosenTheme);

  const btnLight = document.getElementById("btnThemeLight");
  const btnDark = document.getElementById("btnThemeDark");

  if (btnLight && btnDark) {
    if (chosenTheme === "light") {
      btnLight.classList.add("active");
      btnDark.classList.remove("active");
    } else {
      btnDark.classList.add("active");
      btnLight.classList.remove("active");
    }
  }

  // Trigger custom event for dynamic components (like Chart.js and SpaceStarfield)
  window.dispatchEvent(new CustomEvent("themechange", { detail: { theme: chosenTheme } }));
}

// Attach globally
window.setAppTheme = setAppTheme;

// ============================================================
// SPACE BLACK STARFIELD & METEOR ENGINE
// ============================================================
class SpaceStarfield {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");
    this.stars = [];
    this.meteors = [];
    this.animId = null;
    this.isRunning = false;
    this.starCount = 180;
    this.lastMeteorTime = Date.now();
    this.nextMeteorDelay = 8000 + Math.random() * 8000;

    this.init();
  }

  init() {
    this.resize();
    window.addEventListener("resize", () => {
      this.resize();
      this.createStars();
    });
    this.createStars();

    // Hook into theme changes
    window.addEventListener("themechange", (e) => {
      if (e.detail && e.detail.theme === "dark") {
        this.start();
      } else {
        this.stop();
      }
    });

    // Check visibility to save GPU / battery
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        this.stop();
      } else {
        const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
        if (currentTheme === "dark") this.start();
      }
    });

    const activeTheme = document.documentElement.getAttribute("data-theme") || "dark";
    if (activeTheme === "dark") {
      this.start();
    }
  }

  resize() {
    if (!this.canvas) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.width = window.innerWidth;
    this.height = window.innerHeight;
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  createStars() {
    this.stars = [];
    const colors = [
      "rgba(255, 255, 255, ", // Brilliant white starlight
      "rgba(224, 242, 254, ", // Cool cyan starlight
      "rgba(186, 230, 253, ", // Soft sky blue starlight
      "rgba(254, 240, 138, "  // Warm pale gold starlight
    ];

    for (let i = 0; i < this.starCount; i++) {
      const colorPrefix = colors[Math.floor(Math.random() * colors.length)];
      this.stars.push({
        x: Math.random() * this.width,
        y: Math.random() * this.height,
        radius: Math.random() < 0.85 ? Math.random() * 1.1 + 0.35 : Math.random() * 1.5 + 1.2,
        baseAlpha: Math.random() * 0.6 + 0.25,
        twinkleSpeed: Math.random() * 0.03 + 0.008,
        twinklePhase: Math.random() * Math.PI * 2,
        colorPrefix: colorPrefix,
        hasCross: Math.random() < 0.08
      });
    }
  }

  spawnMeteor() {
    const startX = Math.random() * (this.width * 0.8) + (this.width * 0.1);
    const startY = Math.random() * (this.height * 0.35);
    const length = Math.random() * 85 + 65;
    const speed = Math.random() * 9 + 8;
    const angle = Math.PI / 4 + (Math.random() - 0.5) * 0.25;

    this.meteors.push({
      x: startX,
      y: startY,
      length: length,
      speed: speed,
      dx: Math.cos(angle) * speed,
      dy: Math.sin(angle) * speed,
      life: 1.0,
      decay: Math.random() * 0.02 + 0.015
    });
  }

  draw() {
    if (!this.isRunning) return;

    this.ctx.clearRect(0, 0, this.width, this.height);

    const now = Date.now();

    // Draw & twinkle stars
    for (let star of this.stars) {
      star.twinklePhase += star.twinkleSpeed;
      const alpha = Math.max(0.12, star.baseAlpha + Math.sin(star.twinklePhase) * 0.35);

      this.ctx.beginPath();
      this.ctx.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = star.colorPrefix + alpha + ")";
      this.ctx.fill();

      // Soft cosmic halo for brighter stars
      if (star.radius > 1.2) {
        this.ctx.beginPath();
        this.ctx.arc(star.x, star.y, star.radius * 2.2, 0, Math.PI * 2);
        this.ctx.fillStyle = star.colorPrefix + (alpha * 0.2) + ")";
        this.ctx.fill();

        if (star.hasCross && alpha > 0.55) {
          this.ctx.strokeStyle = "rgba(0, 242, 254, " + (alpha * 0.3) + ")";
          this.ctx.lineWidth = 0.6;
          this.ctx.beginPath();
          this.ctx.moveTo(star.x - star.radius * 3.5, star.y);
          this.ctx.lineTo(star.x + star.radius * 3.5, star.y);
          this.ctx.moveTo(star.x, star.y - star.radius * 3.5);
          this.ctx.lineTo(star.x, star.y + star.radius * 3.5);
          this.ctx.stroke();
        }
      }
    }

    // Handle meteors
    if (now - this.lastMeteorTime > this.nextMeteorDelay) {
      this.spawnMeteor();
      this.lastMeteorTime = now;
      this.nextMeteorDelay = 8000 + Math.random() * 9000;
    }

    for (let i = this.meteors.length - 1; i >= 0; i--) {
      const m = this.meteors[i];
      m.x += m.dx;
      m.y += m.dy;
      m.life -= m.decay;

      if (m.life <= 0 || m.x > this.width + 100 || m.y > this.height + 100) {
        this.meteors.splice(i, 1);
        continue;
      }

      const tailX = m.x - (m.dx / m.speed) * m.length;
      const tailY = m.y - (m.dy / m.speed) * m.length;

      const grad = this.ctx.createLinearGradient(tailX, tailY, m.x, m.y);
      grad.addColorStop(0, "rgba(0, 242, 254, 0)");
      grad.addColorStop(0.7, "rgba(0, 242, 254, " + (m.life * 0.4) + ")");
      grad.addColorStop(1, "rgba(255, 255, 255, " + (m.life * 0.95) + ")");

      this.ctx.beginPath();
      this.ctx.moveTo(tailX, tailY);
      this.ctx.lineTo(m.x, m.y);
      this.ctx.strokeStyle = grad;
      this.ctx.lineWidth = 1.5;
      this.ctx.stroke();

      // Shooting star head
      this.ctx.beginPath();
      this.ctx.arc(m.x, m.y, 1.3, 0, Math.PI * 2);
      this.ctx.fillStyle = "rgba(255, 255, 255, " + m.life + ")";
      this.ctx.fill();
    }

    this.animId = requestAnimationFrame(() => this.draw());
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.draw();
  }

  stop() {
    this.isRunning = false;
    if (this.animId) {
      cancelAnimationFrame(this.animId);
      this.animId = null;
    }
    if (this.ctx && this.width && this.height) {
      this.ctx.clearRect(0, 0, this.width, this.height);
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Theme from localStorage or default to 'dark'
  const savedTheme = localStorage.getItem("phishshield_theme") || "dark";
  setAppTheme(savedTheme);

  // 2. Initialize Space Black Starfield
  window.starfieldInstance = new SpaceStarfield("spaceStarsCanvas");

  // 3. Mobile Sidebar Toggle
  const sidebarToggle = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("appSidebar");
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });

    // Close when clicking outside on mobile
    document.addEventListener("click", (e) => {
      if (window.innerWidth <= 992 && sidebar.classList.contains("open")) {
        if (!sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
          sidebar.classList.remove("open");
        }
      }
    });
  }

  // 4. Auto-dismiss Flash Alerts after 6 seconds
  const alerts = document.querySelectorAll(".alert-dismissible");
  alerts.forEach((alert) => {
    setTimeout(() => {
      try {
        const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
        bsAlert.close();
      } catch (err) {}
    }, 6000);
  });
});
