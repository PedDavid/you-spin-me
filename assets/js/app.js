// Small behaviours for the server-rendered UI. No inline handlers, so the
// page works under a strict Content-Security-Policy (script-src 'self').
(() => {
  const setCookie = (name, value) => {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=31536000; samesite=lax`;
  };

  document.addEventListener('click', (event) => {
    const opener = event.target.closest('[data-dialog-open]');
    if (opener) {
      document.getElementById(opener.dataset.dialogOpen)?.showModal();
      return;
    }
    const closer = event.target.closest('[data-dialog-close]');
    if (closer) {
      closer.closest('dialog')?.close();
      return;
    }
    // A click on the backdrop lands on the <dialog> element itself.
    if (event.target instanceof HTMLDialogElement) {
      event.target.close();
      return;
    }
    if (event.target.closest('[data-theme-toggle]')) {
      const dark = document.documentElement.classList.toggle('dark');
      setCookie('ysm_theme', dark ? 'dark' : 'light');
    }
  });

  // After a successful rotation, clear the key from the form.
  document.addEventListener('rotation-complete', (event) => {
    event.target.closest('form')?.querySelectorAll('input[name="key"]').forEach((i) => { i.value = ''; });
  });

  // Closing a dialog clears any pasted key and previous results.
  document.addEventListener('close', (event) => {
    if (!(event.target instanceof HTMLDialogElement)) return;
    event.target.querySelectorAll('input[name="key"]').forEach((i) => { i.value = ''; });
    const result = event.target.querySelector('#rotate-result');
    if (result) result.replaceChildren();
  }, true);

  // Follow the OS preference until the user picks a theme.
  if (!document.cookie.includes('ysm_theme=') && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.classList.add('dark');
  }
})();
