# FixMate Pro (SOLUTIONS) - local services marketplace

Flask + SQLite. Customers find and pre-book workers, workers accept/complete jobs,
customers review workers, admins oversee the platform.

## Run
    pip install -r requirements.txt
    python app.py            # http://127.0.0.1:5000

Settings live in `.env` (Razorpay keys, admin accounts, fee, email). Nothing secret is in the source code.
`localpro.db` is migrated automatically on startup (old plain-text passwords are hashed, statuses normalised).

## Pages by role
| Role | Sidebar pages |
|---|---|
| Customer | Dashboard `/customer/dashboard` - Find Workers `/workers` - My Bookings `/customer/bookings` - My Reviews `/customer/reviews` - My Profile `/customer/profile` |
| Worker   | Dashboard `/worker/dashboard` - Job Requests `/worker/requests` - My Reviews `/worker/reviews` - My Profile `/worker/profile` - public page `/workers/<id>` |
| Admin    | Overview `/admin/` - Users `/admin/users` - Bookings `/admin/bookings` - Reviews `/admin/reviews` (sign in at `/admin/login`) |
| Guest    | Home `/`, `/workers`, `/workers/<id>`, `/login`, `/register/customer`, `/register/worker` |

Old URLs (`/available_workers`, `/worker_dashboard`, `/admin_report`, ...) redirect to the new ones.

## Booking life-cycle
Pending Payment -> (paid) Pre-Booked -> worker accepts -> Confirmed -> worker completes -> Completed -> customer reviews.
Decline / cancel before confirmation refunds the fee. A customer can review a booking once it is Completed,
or Confirmed with a date that has passed (one review per booking, editable).

## Before going live
* Set `ALLOW_DEMO_PAYMENTS=0` (demo mode fakes a payment when Razorpay is unreachable).
* Change the admin passwords in `.env`; rotate the Razorpay test secret (it was previously in source code).
* Set `SESSION_COOKIE_SECURE=1` when serving over HTTPS and run behind gunicorn/waitress, not `app.run`.
