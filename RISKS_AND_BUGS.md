# Risks And Bugs

## Fix Plan
1. Remove public admin self-registration and keep admin creation behind an existing admin session.
2. Restrict system statistics and logs to admin-only access.
3. Escape all untrusted dashboard data before rendering it into HTML.
4. Replace the hard-coded secret fallback with an environment-based secret.
5. Disable always-on debug mode and keep it behind an explicit env flag.
6. Add a file size limit for uploads and keep CSRF hardening on the follow-up list.

## High Severity
- Public registration accepted the role field directly, which allowed a new user to self-register as admin through backend/app.py.
- The dashboard rendered database-backed values with innerHTML in frontend/dashboard.html, including file names, notes, and user names, which created a stored XSS risk.
- /api/admin/stats and /api/admin/logs were protected only by login_required, not admin-only checks, so any authenticated user could read system-wide stats and custody logs.

## Security Risks
- backend/app.py previously used a hard-coded fallback secret key when SECRET_KEY was not set.
- backend/app.py previously ran the Flask development server with debug=True and host=0.0.0.0, which was unsafe outside a local demo environment.
- CORS is enabled with supports_credentials=True, but there is still no CSRF protection on cookie-based POST routes.
- Evidence upload now has a size limit, but large-file handling and retention policy are still product decisions, not enforcement on the blockchain side.

## Reliability And UX Bugs
- frontend/dashboard.html deployContract() depended on the browser-global event object instead of receiving an event parameter, which was fragile and could break in some contexts.
- Some backend handlers assumed request.get_json() always returned an object; malformed or empty JSON bodies could trigger avoidable errors.
- The app mixes offline and on-chain states; if the blockchain is down, verification falls back to the database hash, which is useful for demo mode but weaker than on-chain verification.

## Notes On Impact
- The biggest functional risk is the admin registration flaw, because it can unlock all other admin-only actions.
- The biggest data-risk issue is stored XSS, because it can hijack sessions in the same origin and manipulate evidence views.
- The biggest operational risk is unrestricted uploads, because the app stores evidence locally without a quota or retention policy.