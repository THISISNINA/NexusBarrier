/* Landing page behavior: theme toggle, lifecycle accordion, scroll reveal. */

function toggleNbTheme() {
  var root = document.documentElement;
  var isDark = root.getAttribute("data-theme") === "dark";
  if (isDark) {
    root.removeAttribute("data-theme");
    localStorage.setItem("nb-theme", "light");
  } else {
    root.setAttribute("data-theme", "dark");
    localStorage.setItem("nb-theme", "dark");
  }
}

/* Accordion: one stage open at a time. */
document.querySelectorAll(".lp-acc-header").forEach(function (header) {
  header.addEventListener("click", function () {
    var item = header.parentElement;
    var wasOpen = item.classList.contains("is-open");
    document.querySelectorAll(".lp-acc-item").forEach(function (other) {
      other.classList.remove("is-open");
      other.querySelector(".lp-acc-header").setAttribute("aria-expanded", "false");
    });
    if (!wasOpen) {
      item.classList.add("is-open");
      header.setAttribute("aria-expanded", "true");
    }
  });
});

/* Scroll reveal, with an always-visible fallback. */
var revealEls = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window) {
  var observer = new IntersectionObserver(
    function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );
  revealEls.forEach(function (el) {
    observer.observe(el);
  });
} else {
  revealEls.forEach(function (el) {
    el.classList.add("is-visible");
  });
}
