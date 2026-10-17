/* Progressive enhancement for the opensecuritybot docs. No dependencies. */
(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  /* Mobile navigation ------------------------------------------------------ */
  const navToggle = $(".nav-toggle");
  const siteNav = $("#site-nav");
  if (navToggle && siteNav) {
    const label = $(".nav-toggle-label", navToggle);
    const setOpen = (open) => {
      navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      siteNav.classList.toggle("is-open", open);
      if (label) label.textContent = open ? "Close" : "Menu";
    };
    navToggle.addEventListener("click", () => {
      setOpen(navToggle.getAttribute("aria-expanded") !== "true");
    });
    siteNav.addEventListener("click", (event) => {
      if (event.target.closest("a")) setOpen(false);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") setOpen(false);
    });
  }

  /* Docs sidebar: keep the <details> usable when crossing the desktop break */
  const sidebar = $("details.sidebar");
  if (sidebar && typeof window.matchMedia === "function") {
    const wide = window.matchMedia("(min-width: 961px)");
    const onChange = (event) => {
      if (event.matches) sidebar.open = true;
    };
    if (wide.addEventListener) wide.addEventListener("change", onChange);
    else if (wide.addListener) wide.addListener(onChange);
  }

  /* Terminal-style code blocks --------------------------------------------- */
  const copyText = (text) => {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise((resolve, reject) => {
      const scratch = document.createElement("textarea");
      scratch.value = text;
      scratch.setAttribute("readonly", "");
      scratch.style.position = "fixed";
      scratch.style.top = "-1000px";
      document.body.appendChild(scratch);
      scratch.select();
      try {
        if (document.execCommand("copy")) resolve();
        else reject(new Error("copy rejected"));
      } catch (error) {
        reject(error);
      } finally {
        scratch.remove();
      }
    });
  };

  const languageOf = (pre) => {
    const code = pre.querySelector("code");
    const fromClass = code && (code.className.match(/language-([\w-]+)/) || [])[1];
    const raw = pre.getAttribute("data-lang") || (code && code.getAttribute("data-lang")) || fromClass || "";
    return (raw || "shell").toLowerCase();
  };

  $$("pre").forEach((pre) => {
    if (pre.closest(".terminal") || pre.closest(".code") || pre.hasAttribute("data-no-copy")) return;

    const wrap = document.createElement("div");
    wrap.className = "code";
    const head = document.createElement("div");
    head.className = "code-head";
    const lang = document.createElement("span");
    lang.className = "code-lang";
    lang.textContent = languageOf(pre);
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "copy-btn";
    copy.textContent = "Copy";
    copy.setAttribute("aria-label", "Copy code to clipboard");
    head.append(lang, copy);

    pre.replaceWith(wrap);
    wrap.append(head, pre);

    let reset;
    copy.addEventListener("click", () => {
      copyText(pre.textContent.replace(/\n$/, ""))
        .then(
          () => {
            copy.textContent = "Copied";
            copy.classList.add("is-copied");
          },
          () => {
            copy.textContent = "Copy failed";
            copy.classList.add("is-error");
          }
        )
        .finally(() => {
          clearTimeout(reset);
          reset = setTimeout(() => {
            copy.textContent = "Copy";
            copy.classList.remove("is-copied", "is-error");
          }, 1600);
        });
    });
  });

  /* TOC scrollspy ----------------------------------------------------------- */
  const toc = $(".toc");
  if (toc && "IntersectionObserver" in window) {
    const links = $$('a[href^="#"]', toc)
      .map((link) => {
        let id = link.hash.slice(1);
        try {
          id = decodeURIComponent(id);
        } catch {
          /* keep the raw fragment */
        }
        const heading = id ? document.getElementById(id) : null;
        return heading ? { link, heading } : null;
      })
      .filter(Boolean);

    if (links.length) {
      const visible = new Set();
      const mark = (target) => {
        for (const { link } of links) {
          const on = link === target;
          link.classList.toggle("is-active", on);
          if (on) link.setAttribute("aria-current", "location");
          else link.removeAttribute("aria-current");
        }
      };
      const observer = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting) visible.add(entry.target);
            else visible.delete(entry.target);
          }
          const shown = links.find(({ heading }) => visible.has(heading));
          if (shown) {
            mark(shown.link);
            return;
          }
          const passed = links.filter(({ heading }) => heading.getBoundingClientRect().top < 120);
          if (passed.length) mark(passed[passed.length - 1].link);
        },
        { rootMargin: "-88px 0px -70% 0px" }
      );
      for (const { heading } of links) observer.observe(heading);
    }
  }
})();
