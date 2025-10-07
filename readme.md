
# Gravity Forms Spam Rules Add-On

A powerful, flexible anti-spam toolkit for Gravity Forms.

> **Note**
> This plugin is designed for WordPress sites using [Gravity Forms](https://www.gravityforms.com/). It provides advanced, configurable spam filtering and protection rules for your forms.

---

## Features

- **Customizable Spam Filters**: Block spam using blacklists, regex, suspicious TLDs, SQL/XSS/command injection patterns, and more.
- **Name, Email, and Content Blacklists**: Easily add or update blacklists for names, emails, and content.
- **Whitelist Support**: Prevent false positives for rare but legitimate names.
- **Rate Limiting**: Limit submissions per IP to prevent spam floods.
- **Honeypot Enforcement**: Enforce Gravity Forms' honeypot field for extra protection.
- **Remote Blacklist Updates**: Automatically fetch and update blacklists from trusted sources.
- **Granular Logging**: Debug and tune your spam rules with detailed logging.
- **Seamless Gravity Forms Integration**: Built as a Gravity Forms Add-On, with settings in the Gravity Forms admin UI.

---

## Getting Started

### 1. Installation

1. Download or clone this repository into your `wp-content/plugins/` directory:
	 ```sh
	 git clone https://github.com/jeremycaris/gf-spam-rules.git
	 ```
2. Activate **Gravity Forms Spam Rules Add-On** from your WordPress admin plugins page.
3. Ensure [Gravity Forms](https://www.gravityforms.com/) is installed and activated.

### 2. Configuration

- Go to **Forms > Settings > Spam Rules** in your WordPress admin.
- Configure blacklists, whitelists, rate limits, and other options as needed.
- Most features are enabled by toggling settings or adding entries to lists.

> **Tip**
> The plugin will automatically update its content and email blacklists from trusted remote sources if enabled.

---

## How It Works

- **Blacklists**: Block submissions containing blacklisted names, emails, or content. Blacklists can be extended with custom entries.
- **Regex & Pattern Filters**: Detect and block common spam, SQL injection, XSS, and suspicious URLs.
- **Rate Limiting**: Restrict the number of submissions per IP address within a configurable window.
- **Honeypot**: Enforce Gravity Forms' built-in honeypot field for bots.
- **Remote Updates**: Optionally fetch and merge blacklists from public sources.

---

## Example: Adding a Custom Name Blacklist

1. Go to **Forms > Settings > Spam Rules**.
2. Add names (one per line) to the **Name Blacklist** field.
3. Save settings. Submissions with those names will be flagged as spam.

---

## Development & Testing

- All core logic is in `inc/core-functions.php`.
- Each major function has a corresponding test script in `/test`.
- To run all tests:
	```sh
	cd wp-content/plugins/gf-spam-rules
	for f in test/test-*.php; do php "$f"; done
	```
- The plugin uses [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) for GitHub-based updates.

---

## Resources

- [Gravity Forms](https://www.gravityforms.com/)
- [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker)
- [Project on GitHub](https://github.com/jeremycaris/gf-spam-rules)

---

> **Caution**
> This plugin is powerful and may block legitimate submissions if not configured carefully. Always review logs and test thoroughly after changing rules.

