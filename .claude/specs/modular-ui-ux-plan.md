# Implementation Plan — Modular CSS Design System & UI/UX Polish

This document details the plan for refactoring stylesheets and applying premium UI/UX enhancements.

---

## 1. Sheet Decomposition

Rename and replace the monolithic `styles.css` file:
- Move global root declarations to `tokens.css`.
- Move HTML elements styling to `base.css`.
- Move body structure, `.container`, and `.header` to `layout.css`.
- Move `.btn`, `.form-group`, `.card`, and `.input` declarations to `components.css`.
- Move `.login-panel`, `.profile-card`, and page-specific elements to `pages.css`.
- Create `toast.css` for notifications.

---

## 2. proposed Changes

### `frontend/templates/` [MODIFY]
- Replace the link tag `<link rel="stylesheet" href="/static/css/styles.css">` with links to the new modular stylesheets inside `_header.html` or the global headers:
  ```html
  <link rel="stylesheet" href="/static/css/tokens.css">
  <link rel="stylesheet" href="/static/css/base.css">
  <link rel="stylesheet" href="/static/css/layout.css">
  <link rel="stylesheet" href="/static/css/components.css">
  <link rel="stylesheet" href="/static/css/pages.css">
  <link rel="stylesheet" href="/static/css/toast.css">
  ```

---

## 3. Verification Plan
- Load each page (login, signup, dashboard, profile, verify result) and ensure styling is consistent and visually complete.
- Verify dark/light toggle triggers variables changes instantly.
- Test responsive layout break-points on desktop and simulated mobile viewports.
