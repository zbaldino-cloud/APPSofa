# APPSofa

AppSOFA is an experimental macOS application-security feed and client inspired by the MacAdmins SOFA model.

The project is split into two parts:

- **Feed builder** — centrally gathers and normalizes application release/security data.
- **Client** — evaluates locally installed macOS applications against the published feed, with the long-term goal of integrating the decision model with Nudge and Jamf Pro.

## V0.5

The initial hosted-feed scaffold supports Google Chrome's live Stable version through Google's VersionHistory API. It intentionally leaves `MinimumSecureVersion` null until AppSOFA can establish a security floor from authoritative vendor security-release data. **Latest does not mean minimum secure.**

Build locally with `python3 feed/build.py`.

The generated feed is `public/v1/macos_apps_data_feed.json`.

GitHub Actions is configured to rebuild and deploy the static site/feed to GitHub Pages every six hours, on demand, and after relevant changes to `main`.

## Planned applications

Google Chrome, Mozilla Firefox, Zoom, and Microsoft Office for Mac.
