# Software Specification Document — Modular CSS Design System & UI/UX Polish

**Version:** 1.0.0
**Last Updated:** 2026-07-06
**Target Release Tag:** v2.0.3
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies the **Modular CSS Design System & Premium UI/UX Polish** enhancement. It is the post-v2.0.2 addition that refactored the application's monolithic styling into a modular, clean, and premium design system.

Previously, all styles were packed into a single unstructured `styles.css` file. The modular CSS design system separates tokens, layouts, global rules, pages, and components, allowing clean maintainability and standardizing high-end aesthetics (glassmorphism, micro-animations, dynamic hover states, and unified dark/light themes).

---

## 2. Technical Requirements & Structure

### 2.1 CSS Modularization Structure
The stylesheets are split under `frontend/static/css/` as follows:
- **`tokens.css`**: Defines all CSS variables (colors, fonts, borders, shadows, spacing, glassmorphic filters, and transitions). Supports automatic `@media (prefers-color-scheme: dark)` overrides.
- **`base.css`**: Resets and global HTML element defaults (typography, line heights, scrollbars, focus rings).
- **`layout.css`**: Structural containers, grids, flex layouts, header, footer, navigation bar, and main wrappers.
- **`components.css`**: Reusable component styles (buttons, card containers, inputs, forms, badge labels, table views).
- **`pages.css`**: Specific page styles (login panel alignment, profile page layout, active session grid, OTP code inputs).
- **`toast.css`**: Layout and animations for floating notification alerts.

### 2.2 Design System Tokens
- **Color Palettes**: Curated slate colors with vibrant purple/indigo accents (`--color-primary`, `--color-primary-hover`).
- **Glassmorphism**: Backdrop blur filters (`backdrop-filter: blur(12px)`) combined with semi-transparent borders and background colors.
- **Transitions**: Global ease-in-out transitions (`--transition-smooth: all 0.25s cubic-bezier(0.4, 0, 0.2, 1)`) for hover effects, buttons, and switches.
- **Dark Mode**: Uses CSS variables loaded via `data-theme="dark"` or system preferences, initialized instantly via a pre-render JS script to prevent theme flickering.
