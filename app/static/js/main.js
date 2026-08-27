// Shared UI behaviors across pages

document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("navToggle");
  const links = document.getElementById("navLinks");
  if (toggle && links) {
    toggle.addEventListener("click", () => links.classList.toggle("open"));
  }

  // Auto-dismiss flash messages after 7s
  document.querySelectorAll(".flash").forEach((el) => {
    setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 7000);
  });

  // Generic file-drop widgets: any element with class "file-drop" wrapping an <input type=file>
  document.querySelectorAll(".file-drop").forEach((drop) => {
    const input = drop.querySelector("input[type=file]");
    const label = drop.querySelector(".file-drop-filename");
    if (!input) return;

    drop.addEventListener("click", () => input.click());
    ["dragenter", "dragover"].forEach((evt) =>
      drop.addEventListener(evt, (e) => { e.preventDefault(); drop.classList.add("dragover"); })
    );
    ["dragleave", "drop"].forEach((evt) =>
      drop.addEventListener(evt, (e) => { e.preventDefault(); drop.classList.remove("dragover"); })
    );
    drop.addEventListener("drop", (e) => {
      if (e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        input.dispatchEvent(new Event("change"));
      }
    });
    input.addEventListener("change", () => {
      if (input.files.length && label) {
        const f = input.files[0];
        label.textContent = `${f.name} (${formatBytes(f.size)})`;
      }
    });
  });
});

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`;
}
