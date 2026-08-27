// Extract page: submission progress indicator

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("extractForm");
  const progress = document.getElementById("extractProgress");
  const submitBtn = document.getElementById("extractSubmitBtn");

  if (form) {
    form.addEventListener("submit", () => {
      progress.classList.add("active");
      submitBtn.disabled = true;
    });
  }
});
