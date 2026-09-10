document.documentElement.classList.add("js");
const navigationToggle = document.querySelector("[data-nav-toggle]");
const sidebar = document.getElementById("sidebar");
const narrowScreen = window.matchMedia("(max-width: 850px)");

function closeNavigation(restoreFocus = false) {
  document.body.classList.remove("nav-open");
  navigationToggle?.setAttribute("aria-expanded", "false");
  navigationToggle?.setAttribute("aria-label", "Open navigation");
  if (restoreFocus) navigationToggle?.focus();
}

function revealSection() {
  const section = window.location.hash.slice(1);
  if (!["overview", "inventory", "findings", "reports"].includes(section)) return;
  const target = document.getElementById(section);
  if (!target) return;
  sidebar?.querySelectorAll("[data-section]").forEach((link) => {
    if (link.dataset.section === section) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  });
  if (target.tagName === "DETAILS") target.open = true;
  target.scrollIntoView({ block: "start" });
  (target.querySelector("summary") || target).focus({ preventScroll: true });
}

window.addEventListener("hashchange", revealSection);
narrowScreen.addEventListener("change", () => closeNavigation());
revealSection();

document.addEventListener("focusin", (event) => {
  if (document.body.classList.contains("nav-open") &&
      !sidebar?.contains(event.target) && !navigationToggle?.contains(event.target)) {
    closeNavigation();
  }
});

document.addEventListener("click", async (event) => {
  if (event.target.closest("[data-nav-toggle]")) {
    if (document.body.classList.contains("nav-open")) closeNavigation(true);
    else {
      document.body.classList.add("nav-open");
      navigationToggle.setAttribute("aria-expanded", "true");
      navigationToggle.setAttribute("aria-label", "Close navigation");
      sidebar.querySelector("a.navitem").focus();
    }
    return;
  }
  if (event.target.closest("[data-nav-close]")) closeNavigation(true);
  const navigationLink = event.target.closest("a");
  if (sidebar?.contains(event.target) && navigationLink) {
    closeNavigation();
    if (navigationLink.hash && navigationLink.pathname === window.location.pathname) {
      event.preventDefault();
      if (window.location.hash === navigationLink.hash) revealSection();
      else window.location.hash = navigationLink.hash;
      return;
    }
  }
  document.querySelectorAll(".export-menu[open]").forEach((menu) => {
    if (!menu.contains(event.target)) menu.open = false;
  });
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const status = document.getElementById("copy-status");
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    status.textContent = "Finding key copied";
  } catch {
    status.textContent = "Copy unavailable in this browser";
  }
  status.hidden = false;
  window.setTimeout(() => { status.hidden = true; }, 2500);
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (document.body.classList.contains("nav-open")) closeNavigation(true);
  document.querySelectorAll(".export-menu[open]").forEach((menu) => {
    menu.open = false;
    menu.querySelector("summary").focus();
  });
});
