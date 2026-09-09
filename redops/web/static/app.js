document.addEventListener("click", async (event) => {
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
