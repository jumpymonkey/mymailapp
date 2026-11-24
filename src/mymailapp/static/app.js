(() => {
  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }

    if (target.hasAttribute("data-expand-all")) {
      document.querySelectorAll("details.message-card").forEach((card) => {
        card.setAttribute("open", "");
      });
    } else if (target.hasAttribute("data-collapse-older")) {
      const cards = Array.from(document.querySelectorAll("details.message-card"));
      cards.forEach((card, idx) => {
        if (idx === cards.length - 1) {
          card.setAttribute("open", "");
        } else {
          card.removeAttribute("open");
        }
      });
    }
  });
})();
