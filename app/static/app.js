// Small progressive-enhancement helpers. Kept out of inline attributes so the app can run
// under a strict Content-Security-Policy with no 'unsafe-inline' in script-src.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("select[data-autosubmit]").forEach((select) => {
    select.addEventListener("change", () => select.form && select.form.submit());
  });

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) {
        event.preventDefault();
      }
    });
  });
});
