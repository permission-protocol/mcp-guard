# Permission Deck Console — running it

A single self-contained file: `console/index.html`. No build step, no deps.
Plain HTML/CSS/vanilla JS. The backend sets permissive CORS, so a `file://`
open or any static server works.

## Live mode (against the backend)

1. Start the mcp-guard approval server so it listens on the base URL
   (`http://localhost:7700` — set `PP_APPROVAL_PORT` to match the contract).
2. Open the console:
   ```
   open console/index.html
   ```
   or serve it:
   ```
   python3 -m http.server 8080 --directory console
   # then visit http://localhost:8080/
   ```

On load the console:
- `GET /api/pending` once (so the deck is never blank), then
- subscribes to `GET /api/stream` (SSE, `event: queue`).
- If SSE never opens within ~3.5s, or drops, it falls back to polling
  `/api/pending` every 1s. The top-right pill shows the active transport:
  **live · SSE**, **live · polling**, or **backend offline**.

### Changing the backend URL
Edit the single const at the top of the `<script>` block in `index.html`:
```js
const BASE_URL = "http://localhost:7700";
```

## Mock mode (no backend — for screenshots)

Append `?mock=1`:
```
open "console/index.html?mock=1"
```
or `http://localhost:8080/?mock=1`.

Loads a hardcoded `QueueItem[]` — one card per lane:
- **Decide / irreversible** — `post_x` reply to @nicholascarlini. Red "hard
  stop" tag, no countdown. Approve / Deny only.
- **Decide / reversible** — `send_email` cold outreach. Green tag + a **live
  countdown** starting at 4:12 that ticks down once per second (clock text and
  progress bar both animate). Send now / Hold / Deny.
- **Unblock** — `reauth_instantly`. Human-only input affordance.
- **Verify** — `spend` "$49 → Instantly", confidence 68%, status
  `auto_released`. "already acted" tag; Looks right / Undo.

In mock mode card actions update optimistically only (no POST is made); the
connection pill reads **mock mode**. To watch the all-clear "You're clear"
state, clear all four cards.

## Contract mapping (field → UI)

| Contract field        | Where it shows |
|-----------------------|----------------|
| `lane`                | Routes the card into Decide / Unblock / Verify |
| `reversibility`       | Decide: irreversible → red hard-stop tag (no countdown); reversible → green tag + countdown |
| `countdown_remaining` | Live countdown clock + progress bar (reversible Decide); ticked locally between server pushes, reseeded from each server payload |
| `countdown_seconds`   | Denominator for the progress-bar fill |
| `confidence`          | Verify card "confidence N%" |
| `summary`             | One-line impact text on every card |
| `args_preview`        | The literal artifact block (email body / post text / "$49 → Instantly") |
| `tool_name`           | Cosmetic kind tag (Email / Post / Spend / …) |
| `status`              | Filters what stays on the deck; `auto_released`/`approved` verify items stay for post-hoc confirm |
| `created_at`          | "18 min" / "1 hr" relative timestamp |

## Card actions → endpoints

| Action                         | POST |
|--------------------------------|------|
| Approve / Send now / Looks right / Provide | `/api/approve/:id` |
| Hold (reversible Decide)       | `/api/hold/:id` (stops the countdown; card becomes a hard hold) |
| Deny                           | `/api/deny/:id` |
| Undo (Verify, within window)   | `/api/undo/:id` |

All actions update the UI optimistically; the authoritative state comes back on
the next SSE/poll push. If a POST fails, a red toast shows and the console
re-pulls `/api/pending` so the optimistic change never lies.
