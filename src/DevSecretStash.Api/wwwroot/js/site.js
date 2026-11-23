// Dev Secret Stash: small progressive enhancements. The site works without this file.
(function () {
    document.documentElement.classList.remove("no-js");

    // Sticky nav border + mobile menu
    var nav = document.querySelector(".navbar");
    var toggle = document.querySelector(".mobile-toggle");
    var menu = document.querySelector(".nav-right");
    if (nav) {
        var onScroll = function () { nav.classList.toggle("stuck", window.scrollY > 8); };
        onScroll();
        window.addEventListener("scroll", onScroll, { passive: true });
    }
    if (toggle && menu) {
        toggle.addEventListener("click", function () {
            var open = menu.classList.toggle("open");
            toggle.setAttribute("aria-expanded", String(open));
        });
    }

    // Reveal on scroll
    var items = document.querySelectorAll(".reveal");
    if (!("IntersectionObserver" in window)) {
        items.forEach(function (el) { el.classList.add("in"); });
    } else {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) { entry.target.classList.add("in"); io.unobserve(entry.target); }
            });
        }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
        items.forEach(function (el, i) {
            el.style.transitionDelay = (i % 4) * 70 + "ms";
            io.observe(el);
        });
    }
})();
