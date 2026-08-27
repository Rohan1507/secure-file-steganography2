// Embed page: live capacity calculation + form submission progress

document.addEventListener("DOMContentLoaded", () => {
  const coverInput = document.getElementById("coverImageInput");
  const secretInput = document.getElementById("secretFileInput");
  const meterFill = document.getElementById("capacityMeterFill");
  const meterRow = document.getElementById("capacityMeterRow");
  const capacityBox = document.getElementById("capacityBox");
  const submitBtn = document.getElementById("embedSubmitBtn");
  const form = document.getElementById("embedForm");
  const progress = document.getElementById("embedProgress");
  const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

  let insufficientCapacity = false;

  async function updateCapacity() {
    if (!coverInput.files.length) {
      capacityBox.style.display = "none";
      return;
    }
    const fd = new FormData();
    fd.append("cover_image", coverInput.files[0]);
    fd.append("secret_size", secretInput.files.length ? secretInput.files[0].size : 0);

    try {
      const res = await fetch("/api/calculate-capacity", {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken },
        body: fd,
      });
      const data = await res.json();
      if (data.error) {
        capacityBox.style.display = "none";
        return;
      }

      capacityBox.style.display = "block";
      document.getElementById("imgDims").textContent = `${data.width} x ${data.height}`;
      document.getElementById("imgCapacity").textContent = formatBytes(data.usable_capacity_bytes);
      document.getElementById("secretSizeText").textContent = formatBytes(data.secret_size_bytes);
      document.getElementById("remainingText").textContent = formatBytes(Math.abs(data.remaining_bytes)) +
        (data.remaining_bytes < 0 ? " OVER CAPACITY" : " available");

      const pct = Math.min(100, (data.estimated_required_bytes / data.usable_capacity_bytes) * 100);
      meterFill.style.width = `${pct}%`;
      meterFill.classList.toggle("over", !data.sufficient);

      insufficientCapacity = !data.sufficient;
      submitBtn.disabled = insufficientCapacity || !secretInput.files.length;
    } catch (err) {
      capacityBox.style.display = "none";
    }
  }

  if (coverInput) coverInput.addEventListener("change", updateCapacity);
  if (secretInput) secretInput.addEventListener("change", updateCapacity);

  if (form) {
    form.addEventListener("submit", (e) => {
      if (insufficientCapacity) {
        e.preventDefault();
        alert("Secret file is too large for this cover image. Please select a larger image.");
        return;
      }
      progress.classList.add("active");
      submitBtn.disabled = true;
    });
  }
});
