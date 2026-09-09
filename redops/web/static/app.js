document.addEventListener("click", async (event) => {
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
  document.querySelectorAll(".export-menu[open]").forEach((menu) => {
    menu.open = false;
    menu.querySelector("summary").focus();
  });
});
