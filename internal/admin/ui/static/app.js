function copyText(text) {
  navigator.clipboard.writeText(text).then(() => {
    const el = document.createElement('div');
    el.className = 'alert alert-success';
    el.textContent = 'Скопировано в буфер обмена';
    el.style.position = 'fixed';
    el.style.top = '1rem';
    el.style.right = '1rem';
    el.style.zIndex = '9999';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 2000);
  });
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-copy]');
  if (btn) {
    copyText(btn.getAttribute('data-copy'));
  }
});
