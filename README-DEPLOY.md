# CincyDose at cincydose.org — passwordless website

A standalone website for CincyDose with its own accounts, server and database. It doesn't depend on cincymapp.org or on a Claude account.

## How sign-in works (no passwords)
- **New users** choose **Create an account** and enter their name, email, institution, role and intended use. They confirm their email with a 6-digit code (or button) sent to them, and their request goes to the administrators.
- **You are emailed** each request with a **Review request** button. Approve or deny in one click; the person is emailed the decision.
- **Signing in**: the user types only their email and receives a one-time code and a sign-in button. The code works once and expires in 15 minutes.
- **Keep me signed in**: ticking this option keeps the device signed in for 30 days. Leave it unticked on shared computers; those sessions end after 30 minutes idle or 12 hours.
- **Admin page** (`/admin`):
  - review waiting requests
  - add a person directly
  - disable or re-enable accounts, make admins, delete accounts
  - read the activity log
- **The administrator** is `bhattbhagwat@gmail.com` (set in `.env`). It is created automatically and signs in with an emailed code.

No passwords are created or stored. The server keeps only account details. Patient values (covariates, doses, levels) are processed in the user's browser and never uploaded; the patient case is cleared when the tab closes.

Why a code rather than the email alone: if typing an email were enough, anyone could type the administrator's address and take over the site.

## Setup
1. **Domain**: buy **cincydose.org** at a registrar (about US$10–15 a year) and turn on auto-renew. If the site carries Cincinnati Children's name, check with CCHMC Communications and Information Services first.
2. **Server**: a small cloud server is enough (Ubuntu 24.04, 1 vCPU, 1–2 GB; US$6–12/month), or CCHMC hosting. Install Docker (`curl -fsSL https://get.docker.com | sh`) and copy this folder to `/opt/cincydose`.
3. **DNS**: at the registrar, add A records for `@` and `www` pointing to the server's IP address.
4. **Email** (required, because sign-in codes are sent by email):
   1. Create a free account at **resend.com**.
   2. Add **cincydose.org** under Domains and add the DNS records it shows until it says **Verified**.
   3. Create an API key.
   SendGrid, Postmark or SMTP also work; see `.env.example`.
5. **Start**:
   ```bash
   cd /opt/cincydose
   cp .env.example .env
   nano .env            # paste EMAIL_API_KEY; check INITIAL_ADMIN_EMAIL and ADMIN_EMAILS
   docker compose up -d
   ```
   Open https://cincydose.org, choose **Sign in**, enter `bhattbhagwat@gmail.com`, and use the code from your inbox.
6. **Test**: in a private window, create an account with another email, confirm it, approve it from your inbox, and sign in as that user.

## Day-to-day
- **Approving people**: use the button in the request email, or the admin page.
- **Approving a whole domain**: to approve every confirmed `@cchmc.org` address, set `AUTO_APPROVE_DOMAINS=cchmc.org` and run `docker compose up -d`.
- **Updating the app**: replace `app/index.html`, then run `docker compose up -d --build`.
- **Backups**: `./backup.sh /opt/cincydose-backups`, run nightly from cron.
- **Same server as cincymapp.org?** Possible, but only one program can use ports 80 and 443. Run each site on its own server, or ask for a combined proxy setup.

## Before clinical use
Have CCHMC review CincyDose first:
- **Information Security**: the deployment and privacy.
- **Pharmacy & Therapeutics**: the models, targets and dosing rules. Verify those marked "Textbook values · verify" or "Partly checked".
- **Regulatory Affairs**: dose-recommending software may fall under FDA oversight.
