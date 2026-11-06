// Progressive enhancement: all entries remain readable without JavaScript.
(() => {
  const filters = document.querySelector('.changelog-filters');
  if (!filters) return;
  const entries = [...document.querySelectorAll('.change-entry')];
  const sections = [...document.querySelectorAll('.change-section')];
  const count = document.querySelector('.changelog-count');
  const total = entries.filter(entry => entry.dataset.dated === 'true').length;
  filters.hidden = false;
  filters.addEventListener('click', event => {
    const button = event.target.closest('button[data-filter]');
    if (!button) return;
    const platform = button.dataset.filter;
    filters.querySelectorAll('button').forEach(item => {
      item.setAttribute('aria-pressed', String(item === button));
    });
    entries.forEach(entry => {
      entry.hidden = platform !== 'all' && !entry.dataset.platforms.split(' ').includes(platform);
    });
    sections.forEach(section => {
      section.hidden = [...section.querySelectorAll('.change-entry')].every(entry => entry.hidden);
    });
    const visible = entries.filter(entry => !entry.hidden && entry.dataset.dated === 'true').length;
    count.textContent = platform === 'all' ? `${total} dated updates` : `${visible} of ${total} dated updates apply to ${button.textContent}`;
    document.querySelectorAll('.changelog-years a').forEach(link => {
      link.hidden = document.getElementById(link.hash.slice(1)).hidden;
    });
  });
})();
