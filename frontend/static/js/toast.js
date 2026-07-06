/* Toast helper -- one small file, exposes window.toast.show(message, opts).
 *
 * UI/UX polish (Phase B of the design-system work). The previous app had
 * every page reinventing inline <div class="error-message"> toggling from
 * its own JS, with no way to show a one-shot success/info notification.
 * This helper centralizes that pattern: any page can call
 *
 *   toast.show("Password updated", { type: "success" });
 *   toast.error("Could not save.");
 *   toast.info("Sending…");
 *
 * and get a top-right slide-in notification that auto-dismisses after 4s.
 *
 * XSS posture is unchanged: every text-bearing element is built with
 * createElement + textContent, never innerHTML, so a hostile `message`
 * is rendered as text. The VULN-3 closure (no reflection of attacker-
 * controllable strings) still holds -- this helper is the OPPOSITE
 * direction (app -> user), not user -> app.
 *
 * Accessibility:
 *   - The region is role="status" aria-live="polite" so screen readers
 *     announce new toasts without stealing focus.
 *   - Each toast has a real <button> dismiss control with aria-label.
 *   - prefers-reduced-motion: the slide-in is replaced with a simple
 *     fade and the progress bar is hidden.
 *
 * No dependencies; ~100 lines.
 */
(function () {
    "use strict";

    var DEFAULTS = {
        type: "info",          // "info" | "success" | "error"
        duration: 4000,        // ms; 0 = sticky (no auto-dismiss)
    };

    var ICON = {
        success: "✓",
        error:   "✕",
        info:    "ℹ",
    };

    // Detect prefers-reduced-motion once. The CSS also checks this media
    // query for the slide-in animation, but we read it here so we can
    // adjust behavior (e.g. skip the progress bar) without a flash.
    var reduceMotion = (function () {
        try {
            return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        } catch (e) {
            return false;
        }
    })();

    function getRegion() {
        var region = document.getElementById("toast-region");
        if (region) return region;
        region = document.createElement("div");
        region.id = "toast-region";
        region.setAttribute("role", "status");
        region.setAttribute("aria-live", "polite");
        region.setAttribute("aria-atomic", "false");
        // Append at the end of <body> so it sits above the page content
        // visually (the CSS uses position: fixed) but doesn't disturb the
        // existing layout flow.
        (document.body || document.documentElement).appendChild(region);
        return region;
    }

    function buildToast(message, opts) {
        var node = document.createElement("div");
        node.className = "toast is-" + opts.type;

        // Icon. The character is set via textContent, never innerHTML,
        // so a future change to the icon set can't introduce HTML parsing.
        var icon = document.createElement("span");
        icon.className = "toast-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = ICON[opts.type] || ICON.info;
        node.appendChild(icon);

        // Message body. textContent only -- XSS-safe even for hostile input.
        var body = document.createElement("span");
        body.className = "toast-message";
        body.textContent = message;
        node.appendChild(body);

        // Close button. Real <button> for keyboard + screen reader access.
        var close = document.createElement("button");
        close.type = "button";
        close.className = "toast-close";
        close.setAttribute("aria-label", "Dismiss notification");
        close.textContent = "✕";
        close.addEventListener("click", function () { dismiss(node); });
        node.appendChild(close);

        // Progress bar. A child div whose width animates from 100% -> 0%
        // over `duration`. The CSS transition is paused on hover (parent
        // :hover) so a user reading the message gets the full duration.
        if (opts.duration > 0 && !reduceMotion) {
            var bar = document.createElement("div");
            bar.className = "toast-progress";
            // Force a layout flush so the transition starts from 100% on
            // the next frame rather than animating from 0% (which would
            // happen if we set width and transition in the same tick).
            bar.style.width = "100%";
            node.appendChild(bar);
            // Start the countdown AFTER the element is in the DOM and has
            // had its initial width applied. rAF is fine here -- the actual
            // animation is CSS-driven.
            requestAnimationFrame(function () {
                bar.style.transition = "width " + opts.duration + "ms linear";
                bar.style.width = "0%";
            });
        }

        return node;
    }

    function dismiss(node) {
        if (!node || !node.parentNode) return;
        // Mark as leaving so the CSS can play the exit animation before
        // we remove the node from the DOM.
        node.classList.add("is-leaving");
        // The CSS handles the actual animation; the 200ms here matches
        // the .toast.is-leaving transition in toast.css. If the CSS
        // changes, this number will need to follow it -- acceptable for
        // a self-contained helper, and the alternative (CSS animation
        // events) is wider browser support but more code.
        setTimeout(function () {
            if (node.parentNode) node.parentNode.removeChild(node);
        }, 200);
    }

    function show(message, options) {
        var opts = Object.assign({}, DEFAULTS, options || {});
        if (typeof message !== "string") message = String(message);
        var region = getRegion();
        var node = buildToast(message, opts);
        region.appendChild(node);

        if (opts.duration > 0) {
            // Hover pauses: clearing the timeout + resuming the CSS
            // transition together is fiddly, so we use a simpler
            // approach -- the CSS rule for `.toast:hover .toast-progress`
            // sets `transition-play-state: paused`, which freezes the
            // visual progress without touching the timer. On mouseleave
            // the transition resumes. The setTimeout below still fires
            // on schedule, so the toast dismisses even while the user
            // hovers; if you want strict hover-to-extend, you can
            // listen for mouseenter/mouseleave here and clear/restart
            // the timer. For this lab's UX the simpler model is fine.
            setTimeout(function () { dismiss(node); }, opts.duration);
        }
        return node;
    }

    // Public API. Three named shortcuts on top of the generic show().
    window.toast = {
        show: show,
        success: function (msg, opts) { return show(msg, Object.assign({}, opts, { type: "success" })); },
        error:   function (msg, opts) { return show(msg, Object.assign({}, opts, { type: "error" })); },
        info:    function (msg, opts) { return show(msg, Object.assign({}, opts, { type: "info" })); },
    };
})();
