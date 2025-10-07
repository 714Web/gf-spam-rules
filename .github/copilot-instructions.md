# Copilot Instructions for AI Coding Agents

## Project Architecture
- **Type:** WordPress plugin (PHP)
- **Purpose:** Extends Gravity Forms with advanced anti-spam features (blacklists, whitelists, pattern-based detection, rate limiting, remote blacklist updates).
- **Key files:**
  - `gfspamrules.php`: Plugin bootstrap and update checker
  - `class-gfspamrules.php`: Settings UI and admin integration
  - `inc/core-functions.php`: All core anti-spam logic (each function is documented with docblocks)
  - `/test/`: Standalone PHP scripts for each major function (mocking WP/Gravity Forms as needed)

## Developer Workflows
- **No build step:** Pure PHP, no transpilation or asset pipeline.
- **Testing:**
  - Run all tests: `for f in test/test-*.php; do php "$f"; done`
  - Each test script is standalone and mocks dependencies as needed.
- **Plugin updates:** Uses [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) for GitHub-based updates.
- **Blacklists/whitelists:** Configurable via admin UI; remote blacklists fetched if enabled.

## Project-Specific Patterns
- **Function naming:**
  - Spam rules: `sofw_gform_*`
  - Updaters: `maybe_*`
- **Class naming:**
  - All plugin classes prefixed with `GFSpamRules*`
- **Testing:**
  - Each core function has a corresponding `/test/test-*.php` script
  - Tests are not PHPUnit-based; they are simple PHP scripts with output assertions
- **Logging:**
  - Use `GFCommon::log_debug()` for debug output (viewable in Gravity Forms logs)
- **Rate limiting:**
  - Per-IP, uses WordPress transients for state
- **Remote blacklists:**
  - Fetched from trusted sources, merged with user-provided entries

## Integration Points
- **Gravity Forms:**
  - Plugin is a Gravity Forms Add-On; requires Gravity Forms to be active
  - Hooks into Gravity Forms via Add-On Framework
- **WordPress:**
  - Uses standard plugin structure and hooks
  - Settings and logs are managed via the WordPress admin

## Conventions & Gotchas
- `/test` is excluded from version control via `.gitignore`
- No Composer, npm, or other package manager dependencies
- All configuration is via the WordPress admin UI, not config files
- Large blacklists may impact performance; test thoroughly after changes

---

> For more details, see `README.md` (human-focused) and `AGENTS.md` (agent-focused, technical context).
