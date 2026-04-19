# -*- coding: utf-8 -*-
# Burp Suite Extension: Turbo Replay
# Jython-compatible Python extension that monitors proxy traffic,
# collects unique endpoints, mutates requests, and replays them
# at high concurrency (Turbo Intruder-style).

from burp import IBurpExtender, IHttpListener, ITab, IScanIssue
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField,
    JTextArea, BorderFactory, SwingUtilities, JCheckBox,
    ListSelectionModel, BoxLayout, Box, JSplitPane
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Font, Color, Dimension, GridLayout
from java.lang import Runnable, String, Integer
from java.net import URL
from java.util.concurrent import Executors
import threading
from urlparse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_BODY = "GET /sandboxtest%xx HTTP/1.1\r\nX: x\r\n"

STATUS_PENDING = "Pending"
STATUS_RUNNING = "Running"
STATUS_COMPLETED = "Completed"
STATUS_ERROR = "Error"

DEFAULT_REPLAY_COUNT = 100
DEFAULT_THREAD_COUNT = 10


# ---------------------------------------------------------------------------
# Helper: normalize a URL path for deduplication
# ---------------------------------------------------------------------------
def normalize_path(raw_url):
    """Return the path portion only, stripped of query/fragment, with
    trailing slash removed (except for root '/')."""
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        parsed = urlparse(raw_url)
        path = parsed.path
    else:
        path = raw_url.split("?")[0].split("#")[0]

    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    return path if path else "/"


# ---------------------------------------------------------------------------
# Data model for one endpoint
# ---------------------------------------------------------------------------
class EndpointEntry(object):
    def __init__(self, path, host, method, replay_count, raw_request, http_service):
        self.path = path
        self.host = host
        self.method = method
        self.replay_count = replay_count
        self.status = STATUS_PENDING
        self.raw_request = raw_request
        self.http_service = http_service
        self.results = {}
        self.error_msg = ""
        self.baseline_code = None
        self.baseline_length = None


# ---------------------------------------------------------------------------
# Custom Burp scan issue for flagged anomalies
# ---------------------------------------------------------------------------
class TurboReplayIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000  # extension-generated

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service


# ---------------------------------------------------------------------------
# Swing table model
# ---------------------------------------------------------------------------
COLUMNS = ["Path", "Host", "Original Method", "Replay Count", "Status", "Baseline"]


class EndpointTableModel(AbstractTableModel):
    def __init__(self):
        self.entries = []
        self._lock = threading.Lock()

    def getRowCount(self):
        return len(self.entries)

    def getColumnCount(self):
        return len(COLUMNS)

    def getColumnName(self, col):
        return COLUMNS[col]

    def getValueAt(self, row, col):
        if row >= len(self.entries):
            return ""
        e = self.entries[row]
        if col == 0:
            return e.path
        elif col == 1:
            return e.host
        elif col == 2:
            return e.method
        elif col == 3:
            return Integer(e.replay_count)
        elif col == 4:
            return e.status
        elif col == 5:
            if e.baseline_code is not None:
                return "%d (%d bytes)" % (e.baseline_code, e.baseline_length)
            return ""
        return ""

    def setValueAt(self, value, row, col):
        if col == 3:
            try:
                v = int(str(value))
                if v < 1:
                    v = 1
                self.entries[row].replay_count = v
                self.fireTableCellUpdated(row, col)
            except (ValueError, TypeError):
                pass

    def isCellEditable(self, row, col):
        return col == 3

    def getColumnClass(self, col):
        if col == 3:
            return Integer
        return String

    def add_entry(self, entry):
        with self._lock:
            self.entries.append(entry)
            idx = len(self.entries) - 1
        self.fireTableRowsInserted(idx, idx)

    def clear(self):
        with self._lock:
            n = len(self.entries)
            self.entries = []
        if n > 0:
            self.fireTableRowsDeleted(0, n - 1)

    def update_status(self, row):
        self.fireTableRowsUpdated(row, row)


# ---------------------------------------------------------------------------
# Request builder: mutate an original request
# ---------------------------------------------------------------------------
def build_smuggle_request(helpers, raw_request, http_service, body_str):
    """Take the original raw request bytes and return a new byte[] with:
    - Method changed to POST
    - Expect: 100-Continue header added/replaced
    - Content-Length set to match body_str byte length
    - Body replaced with body_str
    """
    body_len = len(body_str.encode("ascii"))
    analyzed = helpers.analyzeRequest(http_service, raw_request)
    headers = list(analyzed.getHeaders())

    request_line = headers[0]
    parts = request_line.split(" ")
    parts[0] = "POST"
    headers[0] = " ".join(parts)

    new_headers = [headers[0]]
    has_expect = False
    has_cl = False
    for h in headers[1:]:
        lower = h.lower()
        if lower.startswith("expect:"):
            new_headers.append("Expect: 100-Continue")
            has_expect = True
        elif lower.startswith("content-length:"):
            new_headers.append("Content-Length: %d" % body_len)
            has_cl = True
        else:
            new_headers.append(h)

    if not has_expect:
        new_headers.append("Expect: 100-Continue")
    if not has_cl:
        new_headers.append("Content-Length: %d" % body_len)

    body_bytes = helpers.stringToBytes(body_str)
    return helpers.buildHttpMessage(new_headers, body_bytes)


# ---------------------------------------------------------------------------
# Replay worker (runs in a background thread)
# ---------------------------------------------------------------------------
class ReplayTask(object):
    def __init__(self, extender, entry, row_index):
        self.extender = extender
        self.entry = entry
        self.row = row_index

    def run(self):
        """Runs on a single worker thread. Sends all replay_count requests
        to this one endpoint sequentially, back-to-back. Multiple workers
        run different endpoints in parallel up to the global thread pool
        size, but within a single endpoint everything is serial on one
        thread for maximum per-host request rate (desync-friendly)."""
        entry = self.entry
        helpers = self.extender._helpers
        callbacks = self.extender._callbacks
        body_str = self.extender.get_exploit_body()
        flag_code = self.extender.get_flag_code()

        try:
            modified = build_smuggle_request(
                helpers, entry.raw_request, entry.http_service, body_str
            )
        except Exception as ex:
            entry.status = STATUS_ERROR
            entry.error_msg = "Build error: %s" % str(ex)
            self._update_ui()
            self._log_result()
            return

        entry.status = STATUS_RUNNING
        self._update_ui()

        # --- Baseline: first request establishes expected response ---
        try:
            baseline_resp = callbacks.makeHttpRequest(
                entry.http_service, modified
            )
            baseline_bytes = baseline_resp.getResponse()
            if baseline_bytes:
                analyzed_bl = helpers.analyzeResponse(baseline_bytes)
                entry.baseline_code = analyzed_bl.getStatusCode()
                body_offset = analyzed_bl.getBodyOffset()
                entry.baseline_length = len(baseline_bytes) - body_offset
            else:
                entry.baseline_code = 0
                entry.baseline_length = 0
        except Exception:
            entry.baseline_code = -1
            entry.baseline_length = 0

        self._update_ui()
        self.extender._log_on_edt(
            "[BASELINE] %s  |  Status: %s  |  Body length: %d bytes"
            % (entry.path, entry.baseline_code, entry.baseline_length)
        )

        # --- Sequential replay on THIS thread (no inner pool) ---
        remaining = entry.replay_count - 1
        results = {entry.baseline_code: 1}
        flagged_responses = []

        for _ in range(remaining):
            try:
                resp = callbacks.makeHttpRequest(entry.http_service, modified)
                resp_bytes = resp.getResponse()
                if resp_bytes:
                    analyzed_resp = helpers.analyzeResponse(resp_bytes)
                    code = analyzed_resp.getStatusCode()
                else:
                    code = 0
                results[code] = results.get(code, 0) + 1
                if (flag_code is not None
                        and code == flag_code
                        and code != entry.baseline_code):
                    flagged_responses.append(resp)
            except Exception:
                results[-1] = results.get(-1, 0) + 1

        entry.results = results
        entry.status = STATUS_COMPLETED
        self._update_ui()
        self._log_result()

        if flagged_responses:
            self._raise_scan_issue(entry, flag_code, flagged_responses)

    def _raise_scan_issue(self, entry, flag_code, flagged_responses):
        helpers = self.extender._helpers
        callbacks = self.extender._callbacks

        count = entry.results.get(flag_code, 0)
        protocol = str(entry.http_service.getProtocol())
        host = str(entry.http_service.getHost())
        port = entry.http_service.getPort()
        url = URL(protocol, host, port, entry.path)

        detail = (
            "<b>Turbo Replay - Anomalous Status Code Detected</b><br><br>"
            "Endpoint: <b>%s</b><br>"
            "Baseline response: <b>%d</b><br>"
            "Flagged status code <b>%d</b> appeared <b>%d</b> time(s) "
            "out of %d total replays.<br><br>"
            "This indicates the server responded differently under repeated "
            "requests with the smuggling payload, which may indicate a "
            "request smuggling or desync vulnerability.<br><br>"
            "Status code breakdown: %s"
            % (
                entry.path,
                entry.baseline_code,
                flag_code,
                count,
                entry.replay_count,
                ", ".join(
                    "%d: %d" % (c, n)
                    for c, n in sorted(entry.results.items())
                ),
            )
        )

        issue = TurboReplayIssue(
            http_service=entry.http_service,
            url=url,
            http_messages=flagged_responses,
            name="Turbo Replay: Anomalous %d on %s" % (flag_code, entry.path),
            detail=detail,
            severity="High",
        )
        callbacks.addScanIssue(issue)

        self.extender._log_on_edt(
            "** HIGH SEVERITY ISSUE RAISED ** %s  |  "
            "Flagged code %d appeared %d time(s) (baseline was %d)"
            % (entry.path, flag_code, count, entry.baseline_code)
        )

    def _update_ui(self):
        model = self.extender.table_model
        row = self.row

        class Updater(Runnable):
            def run(self_inner):
                model.update_status(row)

        SwingUtilities.invokeLater(Updater())

    def _log_result(self):
        entry = self.entry
        parts = []
        total = 0
        for code, cnt in sorted(entry.results.items()):
            label = str(code) if code > 0 else "Error/NoResp"
            parts.append("%s: %d" % (label, cnt))
            total += cnt

        summary = "[%s] %s  |  Total sent: %d  |  Baseline: %s  |  %s" % (
            entry.status,
            entry.path,
            total,
            entry.baseline_code,
            ", ".join(parts) if parts else "N/A",
        )
        if entry.error_msg:
            summary += "  |  " + entry.error_msg

        # Flag any codes that differ from baseline
        if entry.baseline_code is not None:
            anomalies = [
                (c, n) for c, n in entry.results.items()
                if c != entry.baseline_code
            ]
            if anomalies:
                flags = ", ".join("%sx%d" % (c, n) for c, n in anomalies)
                summary += "  ** ANOMALY (differs from baseline): " + flags

        self.extender._log_on_edt(summary)


# ---------------------------------------------------------------------------
# Main extension class
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Turbo Replay")

        self._seen_paths = {}
        self._seen_lock = threading.Lock()
        self.thread_count = DEFAULT_THREAD_COUNT
        self._pool = None
        self._pool_size = 0
        self._pool_lock = threading.Lock()

        # Tool flag constants from IBurpExtenderCallbacks
        self.TOOL_PROXY = callbacks.TOOL_PROXY
        self.TOOL_INTRUDER = callbacks.TOOL_INTRUDER

        self.table_model = EndpointTableModel()
        self._build_ui()

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Turbo Replay extension loaded.")

    # --- ITab ---
    def getTabCaption(self):
        return "Turbo Replay"

    def getUiComponent(self):
        return self._main_panel

    # --- Helpers for reading UI fields ---
    def get_exploit_body(self):
        text = self._body_area.getText()
        if not text or not text.strip():
            return DEFAULT_BODY
        # Convert literal \r\n in the text area to actual CR LF
        return text.replace("\\r\\n", "\r\n").replace("\\n", "\n")

    def get_flag_code(self):
        text = self._flag_code_field.getText().strip()
        if not text:
            return None
        try:
            return int(text)
        except (ValueError, TypeError):
            return None

    # --- IHttpListener ---
    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if not message_is_request:
            return

        # Filter by tool source based on UI checkboxes
        if tool_flag == self.TOOL_PROXY:
            if not self._proxy_cb.isSelected():
                return
        elif tool_flag == self.TOOL_INTRUDER:
            if not self._intruder_cb.isSelected():
                return
        else:
            return  # ignore other tools (repeater, scanner, etc.)

        request_bytes = message_info.getRequest()
        http_service = message_info.getHttpService()
        if http_service is None or request_bytes is None:
            return

        analyzed = self._helpers.analyzeRequest(http_service, request_bytes)
        url = analyzed.getUrl()
        method = analyzed.getMethod()

        path = normalize_path(str(url.getPath()))
        host = str(http_service.getHost())
        port = http_service.getPort()
        protocol = str(http_service.getProtocol())

        key = (host, port, path)
        with self._seen_lock:
            if key in self._seen_paths:
                return
            self._seen_paths[key] = True

        try:
            default_count = int(self._default_count_field.getText().strip())
            if default_count < 1:
                default_count = DEFAULT_REPLAY_COUNT
        except (ValueError, TypeError):
            default_count = DEFAULT_REPLAY_COUNT

        entry = EndpointEntry(
            path=path,
            host="%s://%s:%d" % (protocol, host, port) if port not in (80, 443) else "%s://%s" % (protocol, host),
            method=method,
            replay_count=default_count,
            raw_request=request_bytes,
            http_service=http_service,
        )

        extender = self
        model = self.table_model
        auto_run = self._autorun_cb.isSelected()

        class AddRow(Runnable):
            def run(self_inner):
                model.add_entry(entry)
                if auto_run:
                    row = len(model.entries) - 1
                    extender._read_thread_count()
                    extender._launch_replay(entry, row)

        SwingUtilities.invokeLater(AddRow())

    # --- UI construction ---
    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout(5, 5))
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # --- Top controls ---
        top = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))

        top.add(JLabel("Default Replay Count:"))
        self._default_count_field = JTextField(str(DEFAULT_REPLAY_COUNT), 6)
        top.add(self._default_count_field)

        top.add(JLabel("  Threads:"))
        self._thread_field = JTextField(str(DEFAULT_THREAD_COUNT), 4)
        self._thread_field.setToolTipText(
            "Number of endpoints processed in parallel. Each worker "
            "thread sends all N replay requests to one endpoint "
            "sequentially, back-to-back (desync-friendly)."
        )
        top.add(self._thread_field)

        top.add(JLabel("  Flag Code:"))
        self._flag_code_field = JTextField("", 5)
        self._flag_code_field.setToolTipText(
            "Status code to flag as High severity issue (e.g. 400). "
            "Leave blank to disable."
        )
        top.add(self._flag_code_field)

        top.add(Box.createHorizontalStrut(12))

        btn_start_all = JButton("Start All", actionPerformed=self._on_start_all)
        top.add(btn_start_all)

        btn_start_sel = JButton("Start Selected", actionPerformed=self._on_start_selected)
        top.add(btn_start_sel)

        btn_clear = JButton("Clear", actionPerformed=self._on_clear)
        top.add(btn_clear)

        # --- Second row: source checkboxes ---
        options = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2))

        self._proxy_cb = JCheckBox("Proxy traffic", True)
        self._proxy_cb.setToolTipText("Collect endpoints from Burp Proxy")
        options.add(self._proxy_cb)

        self._intruder_cb = JCheckBox("Intruder traffic", True)
        self._intruder_cb.setToolTipText("Collect endpoints from Burp Intruder")
        options.add(self._intruder_cb)

        options.add(Box.createHorizontalStrut(20))

        self._autorun_cb = JCheckBox("Auto-run on new endpoints", False)
        self._autorun_cb.setToolTipText(
            "Automatically replay each new endpoint as soon as it's discovered"
        )
        options.add(self._autorun_cb)

        top_wrapper = JPanel(BorderLayout())
        top_wrapper.add(top, BorderLayout.NORTH)
        top_wrapper.add(options, BorderLayout.SOUTH)
        self._main_panel.add(top_wrapper, BorderLayout.NORTH)

        # --- Center: table + body editor side by side above the log ---
        center = JPanel(BorderLayout(5, 5))

        # Table
        self._table = JTable(self.table_model)
        self._table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)

        col_model = self._table.getColumnModel()
        col_model.getColumn(0).setPreferredWidth(250)  # Path
        col_model.getColumn(1).setPreferredWidth(180)  # Host
        col_model.getColumn(2).setPreferredWidth(70)   # Method
        col_model.getColumn(3).setPreferredWidth(80)   # Replay Count
        col_model.getColumn(4).setPreferredWidth(80)   # Status
        col_model.getColumn(5).setPreferredWidth(120)  # Baseline

        class StatusRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self_inner, table, value, is_sel, has_focus, row, col):
                comp = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self_inner, table, value, is_sel, has_focus, row, col
                )
                if value == STATUS_COMPLETED:
                    comp.setForeground(Color(0, 128, 0))
                elif value == STATUS_RUNNING:
                    comp.setForeground(Color(0, 0, 200))
                elif value == STATUS_ERROR:
                    comp.setForeground(Color(200, 0, 0))
                else:
                    comp.setForeground(Color.DARK_GRAY)
                return comp

        col_model.getColumn(4).setCellRenderer(StatusRenderer())

        table_scroll = JScrollPane(self._table)
        table_scroll.setPreferredSize(Dimension(650, 300))

        # Exploit body editor
        body_panel = JPanel(BorderLayout(2, 2))
        body_panel.setBorder(BorderFactory.createTitledBorder("Exploit Body (editable)"))

        self._body_area = JTextArea(DEFAULT_BODY.replace("\r\n", "\\r\\n"))
        self._body_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._body_area.setLineWrap(True)
        self._body_area.setRows(8)

        body_hint = JLabel(
            "<html><i>Use \\r\\n for CRLF. Content-Length auto-calculated.</i></html>"
        )
        body_panel.add(body_hint, BorderLayout.NORTH)
        body_panel.add(JScrollPane(self._body_area), BorderLayout.CENTER)
        body_panel.setPreferredSize(Dimension(300, 300))

        # Horizontal split: table | body editor
        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, table_scroll, body_panel)
        top_split.setResizeWeight(0.7)

        # Log area
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        log_scroll = JScrollPane(self._log_area)
        log_scroll.setPreferredSize(Dimension(900, 200))
        log_scroll.setBorder(BorderFactory.createTitledBorder("Replay Results / Log"))

        # Vertical split: (table+body) / log
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, log_scroll)
        main_split.setResizeWeight(0.6)
        self._main_panel.add(main_split, BorderLayout.CENTER)

    # --- Button handlers ---
    def _read_thread_count(self):
        try:
            tc = int(self._thread_field.getText().strip())
            if tc < 1:
                tc = DEFAULT_THREAD_COUNT
        except (ValueError, TypeError):
            tc = DEFAULT_THREAD_COUNT
        self.thread_count = tc
        self._ensure_pool()

    def _ensure_pool(self):
        """Create the shared worker pool lazily, or replace it if the
        user changed the thread count. Each worker processes one whole
        endpoint at a time (all N requests sequentially on that thread)."""
        with self._pool_lock:
            if self._pool is None or self._pool_size != self.thread_count:
                old = self._pool
                self._pool = Executors.newFixedThreadPool(self.thread_count)
                self._pool_size = self.thread_count
                if old is not None:
                    # Let in-flight tasks finish on the old pool; no new submits
                    old.shutdown()

    def _on_start_all(self, event):
        self._read_thread_count()
        entries = self.table_model.entries
        for i, e in enumerate(entries):
            if e.status == STATUS_PENDING:
                self._launch_replay(e, i)

    def _on_start_selected(self, event):
        self._read_thread_count()
        rows = self._table.getSelectedRows()
        for r in rows:
            e = self.table_model.entries[r]
            if e.status == STATUS_PENDING:
                self._launch_replay(e, r)

    def _on_clear(self, event):
        with self._seen_lock:
            self._seen_paths.clear()
        self.table_model.clear()
        self._log_area.setText("")

    def _launch_replay(self, entry, row):
        """Submit this endpoint to the shared worker pool. One worker
        thread will handle ALL of its replay requests sequentially."""
        self._ensure_pool()
        task = ReplayTask(self, entry, row)

        class Worker(Runnable):
            def run(self_inner):
                task.run()

        self._pool.submit(Worker())

    def _log_on_edt(self, msg):
        log_area = self._log_area

        class Logger(Runnable):
            def run(self_inner):
                log_area.append(msg + "\n")
                log_area.setCaretPosition(log_area.getDocument().getLength())

        SwingUtilities.invokeLater(Logger())

    def log(self, msg):
        self._log_on_edt(msg)
