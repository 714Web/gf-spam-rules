# AGENTS.md

## Project Overview

Gravity Forms Spam Rules Add-On is a WordPress plugin that extends Gravity Forms with advanced, configurable anti-spam features. It provides customizable blacklists, whitelists, pattern-based spam detection, rate limiting, and remote blacklist updates. The project is written in PHP and is structured as a standard WordPress plugin.

- **Primary language:** PHP
- **Framework:** Gravity Forms Add-On Framework
- **Test scripts:** Standalone PHP scripts in `/test`
- **Update mechanism:** [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker)

---

## Setup Commands

- **Clone the repository:**
  ```sh
  git clone https://github.com/jeremycaris/gf-spam-rules.git
  ```
- **Install dependencies:**
  - No package manager dependencies; all PHP files are included.
- **Activate plugin:**
  - From WordPress admin, activate "Gravity Forms Spam Rules Add-On".
- **Gravity Forms required:**
  - Ensure Gravity Forms is installed and activated.

---

## Development Workflow

- **Edit core logic:**
  - Main logic: `inc/core-functions.php`
  - Add-on bootstrap: `gfspamrules.php`
  - Settings UI: `class-gfspamrules.php`
- **Update blacklists:**
  - Remote blacklists are fetched automatically if enabled in settings.
- **Plugin update checker:**
  - Uses GitHub releases for updates.

---

## Testing Instructions

- **Test scripts location:** `/test` directory
- **Run all tests:**
  ```sh
  cd wp-content/plugins/gf-spam-rules
  for f in test/test-*.php; do php "$f"; done
  ```
- **Individual test:**
  ```sh
  php test/test-name-spam.php
  ```
- **Test coverage:**
  - Each major function has a corresponding test script.
  - Tests are standalone and mock WordPress/Gravity Forms functions as needed.

---

## Code Style Guidelines

- **Language:** PHP (WordPress standards)
- **Linting:** Not enforced by default; follow [WordPress PHP Coding Standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/php/)
- **File organization:**
  - Main plugin: `gfspamrules.php`
  - Core logic: `inc/core-functions.php`
  - Settings/admin: `class-gfspamrules.php`
  - Tests: `/test`
- **Naming conventions:**
  - Functions: `sofw_gform_*` for spam rules, `maybe_*` for updaters
  - Classes: `GFSpamRules*`

---

## Build and Deployment

- **Build process:** None required (pure PHP plugin)
- **Deployment:**
  - Copy plugin folder to `wp-content/plugins/` on target WordPress site
  - Activate via WordPress admin
- **Update mechanism:**
  - GitHub releases via Plugin Update Checker

---

## Security Considerations

- **Do not commit secrets or credentials.**
- **Blacklists and whitelists** are user-editable via the admin UI.
- **Remote blacklist updates** are fetched from trusted sources; review before enabling.
- **Rate limiting** is per-IP and uses WordPress transients.

---

## Pull Request Guidelines

- **Title format:** `[component] Brief description`
- **Required checks:**
  - All `/test` scripts must pass
  - Code should follow WordPress PHP standards
- **Review:**
  - Ensure new features are covered by a test script

---

## Debugging and Troubleshooting

- **Logs:**
  - Uses `GFCommon::log_debug()` for debug output (viewable in Gravity Forms logs)
- **Common issues:**
  - Plugin not loading: Ensure Gravity Forms is active
  - Tests fail: Check for missing mocks or test data
- **Performance:**
  - Blacklist checks are optimized for short lists; very large lists may impact performance

---

## Additional Notes

- `/test` is excluded from version control via `.gitignore`
- The plugin is designed to be robust but may block legitimate submissions if misconfigured—test thoroughly after changes
- For monorepo or multi-plugin setups, place an `AGENTS.md` in each plugin root
