// Small behaviours for the server-rendered UI. No inline handlers, so the
// page works under a strict Content-Security-Policy (script-src 'self').
(() => {
  const PALETTES = ['neutral', 'blue', 'green', 'orange', 'violet'];
  const root = document.documentElement;

  const setCookie = (name, value) => {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=31536000; samesite=lax`;
  };

  // --- Command palette (⌘K) ---
  const palette = () => document.getElementById('command-palette');
  const items = () => Array.from(palette()?.querySelectorAll('[role="menuitem"]') ?? []);

  const openPalette = () => {
    const dialog = palette();
    if (!dialog || dialog.open) return;
    dialog.showModal();
    const input = dialog.querySelector('input[name="q"]');
    input.value = '';
    input.focus();
    htmx.trigger(input, 'palette-open');
  };

  const setActive = (next) => {
    items().forEach((el) => el.classList.toggle('active', el === next));
    next?.scrollIntoView({ block: 'nearest' });
  };

  const move = (delta) => {
    const list = items();
    if (!list.length) return;
    const current = list.findIndex((el) => el.classList.contains('active'));
    setActive(list[(current + delta + list.length) % list.length]);
  };

  document.addEventListener('keydown', (event) => {
    const typing = event.target.closest('input, textarea, select, [contenteditable]');
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openPalette();
    } else if (event.key === '/' && !typing) {
      event.preventDefault();
      openPalette();
    } else if (palette()?.open) {
      if (event.key === 'ArrowDown') { event.preventDefault(); move(1); }
      if (event.key === 'ArrowUp') { event.preventDefault(); move(-1); }
      if (event.key === 'Enter') {
        const active = items().find((el) => el.classList.contains('active'));
        if (active) { event.preventDefault(); active.click(); }
      }
    }
  });

  document.addEventListener('mousemove', (event) => {
    const item = event.target.closest('#command-palette [role="menuitem"]');
    if (item && !item.classList.contains('active')) setActive(item);
  });

  document.addEventListener('click', (event) => {
    if (event.target.closest('[data-palette-open]')) {
      openPalette();
      return;
    }
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
      const dark = root.classList.toggle('dark');
      setCookie('ysm_theme', dark ? 'dark' : 'light');
      return;
    }
    if (event.target.closest('[data-palette-cycle]')) {
      const current = PALETTES.indexOf(root.dataset.palette || 'neutral');
      const next = PALETTES[(current + 1) % PALETTES.length];
      root.dataset.palette = next;
      setCookie('ysm_palette', next);
    }
  });

  // Audit clicks on an on-demand key's Create link. The link itself opens
  // the provider's page; the beacon records who opened it and when.
  const trackOpen = (event) => {
    const link = event.target.closest('a[data-track-open]');
    if (!link || (event.type === 'auxclick' && event.button !== 1)) return;
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content ?? '';
    navigator.sendBeacon(link.dataset.trackOpen, new URLSearchParams({ _csrf: csrf }));
  };
  document.addEventListener('click', trackOpen);
  document.addEventListener('auxclick', trackOpen);

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
    root.classList.add('dark');
  }
})();
