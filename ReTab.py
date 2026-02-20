#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ReTab —Adds a context menu to send requests to Repeater with auto-generated tab names.
"""
from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (
    JPanel, JCheckBox, JLabel, JTextField, JScrollPane,
    JMenuItem, BorderFactory, Box, BoxLayout, SwingUtilities
)
from java.awt import GridBagLayout, GridBagConstraints, Insets, Font, Color, Dimension
from java.util import ArrayList
from java.net import URLDecoder
import re


# ─── Precompiled Patterns ────────────────────────────────────────
_RE_GQL_OP = re.compile(r'(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)')
_RE_HASH   = re.compile(r':\s*"([a-fA-F0-9]+)"')
_RE_XML    = re.compile(r'<([a-zA-Z][\w.-]*:)?([a-zA-Z][\w.-]*)')
_RE_DIGITS = re.compile(r'^\d+$')
_RE_UUID   = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-')
_RE_HEX24  = re.compile(r'^[0-9a-fA-F]{24,}$')

_SOAP_SKIP = frozenset(["envelope", "header", "body", "xml"])
_BODY_MAX  = 65536
_CACHE_CAP = 5000


# ─── Extension ───────────────────────────────────────────────────

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._hl = callbacks.getHelpers()
        self._counts = {}

        self._opt_method  = True
        self._opt_query   = False
        self._opt_normid  = True
        self._opt_auth    = True
        self._opt_maxlen  = 60

        callbacks.setExtensionName("ReTab")
        callbacks.registerContextMenuFactory(self)
        SwingUtilities.invokeLater(self._init_ui)
        callbacks.printOutput("[+] ReTab loaded")

    # ─── ITab ─────────────────────────────────────────────────────

    def getTabCaption(self):
        return "ReTab"

    def getUiComponent(self):
        return self._ui_scroll

    # ─── IContextMenuFactory ─────────────────────────────────────

    def createMenuItems(self, ctx):
        if not ctx.getSelectedMessages():
            return None
        items = ArrayList()
        items.add(JMenuItem(
            "Send to Repeater (ReTab)",
            actionPerformed=lambda _: self._on_send(ctx)))
        return items

    # ─── Send Logic ───────────────────────────────────────────────

    def _on_send(self, ctx):
        self._sync_options()
        for msg in ctx.getSelectedMessages():
            req = msg.getRequest()
            svc = msg.getHttpService()
            if req is None or svc is None:
                continue
            try:
                name = self._dedupe(self._name_for(svc, req))
                self._cb.sendToRepeater(
                    svc.getHost(), svc.getPort(),
                    svc.getProtocol() == "https", req, name)
                self._cb.printOutput("[>] " + name)
            except Exception as e:
                self._cb.printError("[!] " + str(e))
                self._send_fallback(svc, req)

    def _send_fallback(self, svc, req):
        try:
            self._cb.sendToRepeater(
                svc.getHost(), svc.getPort(),
                svc.getProtocol() == "https", req, "request")
        except Exception:
            pass

    # ═════════════════════════════════════════════════════════════
    #  NAME GENERATION
    # ═════════════════════════════════════════════════════════════

    def _name_for(self, svc, req):
        try:
            info = self._hl.analyzeRequest(svc, req)
        except Exception:
            info = self._hl.analyzeRequest(req)

        hdrs    = info.getHeaders()
        method  = self._method(hdrs)
        path, q = self._path_query(info, hdrs)
        hdr_map = self._header_map(hdrs)
        body    = self._body(req, info.getBodyOffset())

        # Priority chain
        if hdr_map.get("upgrade", "").lower() == "websocket":
            return self._cap("WS-" + self._trim_path(path))

        if self._looks_graphql(path, q, hdr_map, body):
            return self._cap(self._gql_name(method, q, body))

        if "xml" in hdr_map.get("content-type", "").lower() and body:
            return self._cap(self._soap_name(body))

        return self._cap(self._rest_name(method, path, q, hdr_map))

    # ─── Path / Query Extraction ──────────────────────────────────

    def _path_query(self, info, hdrs):
        try:
            url = info.getUrl()
            if url is not None:
                return url.getPath() or "/", url.getQuery()
        except Exception:
            pass
        return self._path_query_from_line(hdrs)

    def _path_query_from_line(self, hdrs):
        try:
            if hdrs and hdrs.size() > 0:
                tokens = hdrs.get(0).split(" ")
                if len(tokens) >= 2:
                    raw = tokens[1]
                    sep = raw.find("?")
                    if sep >= 0:
                        return raw[:sep], raw[sep + 1:]
                    return raw, None
        except Exception:
            pass
        return "/", None

    # ─── GraphQL ──────────────────────────────────────────────────

    def _looks_graphql(self, path, q, hdr_map, body):
        if path and "graphql" in path.lower():
            return True
        if q and "query=" in q.lower():
            return True
        ct = hdr_map.get("content-type", "")
        return "application/json" in ct.lower() and body and '"query"' in body

    def _gql_name(self, method, q, body):
        op = self._gql_from_body(body) if body else None
        if not op and q:
            op = self._gql_from_qs(q)
        if op:
            return (method + "-" + op) if self._opt_method else op
        return "graphql"

    def _gql_from_body(self, body):
        op = _extract_json_str(body, "operationName")
        if op:
            return op
        raw = _extract_json_str(body, "query")
        if raw:
            m = _RE_GQL_OP.search(raw)
            if m:
                return m.group(1)
        h = self._persisted_hash(body)
        if h:
            return "gql-" + h[:6]
        return None

    def _gql_from_qs(self, q):
        val = _qs_value(q, "query")
        if val:
            m = _RE_GQL_OP.search(val)
            if m:
                return m.group(1)
        return None

    def _persisted_hash(self, body):
        idx = body.find("sha256Hash")
        if idx < 0:
            return None
        m = _RE_HASH.search(body, idx + 10, min(idx + 90, len(body)))
        return m.group(1) if m else None

    # ─── SOAP ─────────────────────────────────────────────────────

    def _soap_name(self, body):
        pos = 0
        for _ in range(8):
            m = _RE_XML.search(body, pos)
            if not m:
                break
            tag = m.group(2)
            if tag.lower() not in _SOAP_SKIP:
                return "SOAP-" + tag
            pos = m.end()
        return "SOAP-request"

    # ─── REST ─────────────────────────────────────────────────────

    def _rest_name(self, method, path, q, hdr_map):
        override = hdr_map.get("x-http-method-override", "")
        if override:
            method = override.upper()

        path = self._trim_path(path)
        if self._opt_normid:
            path = self._normalize_ids(path)

        parts = []
        if self._opt_method:
            parts.append(method)
            parts.append("-")
        parts.append(path or "/")

        ct = hdr_map.get("content-type", "").lower()
        if "multipart/form-data" in ct:
            parts.append("[multi]")
        elif "x-www-form-urlencoded" in ct:
            parts.append("[form]")

        if self._opt_query and q:
            parts.append("?")
            parts.append(q[:30])

        if self._opt_auth:
            hint = self._auth_tag(hdr_map)
            if hint:
                parts.append(hint)

        return "".join(parts)

    # ─── Auth Hint ────────────────────────────────────────────────

    def _auth_tag(self, hdr_map):
        val = hdr_map.get("authorization", "")
        if not val:
            return ""
        low = val.lower()
        try:
            if low.startswith("bearer "):
                tok = val[7:].strip()
                return "[.." + tok[-4:] + "]" if len(tok) >= 4 else "[bearer]"
            if low.startswith("basic "):
                from java.util import Base64 as JB64
                raw = JB64.getDecoder().decode(val[6:].strip())
                user = str(raw.tostring()).split(":")[0]
                return "[" + (user[:8] if len(user) > 8 else user) + "]"
        except Exception:
            pass
        return ""

    # ═════════════════════════════════════════════════════════════
    #  UTILITIES
    # ═════════════════════════════════════════════════════════════

    def _method(self, hdrs):
        try:
            return hdrs.get(0).split(" ", 2)[0] if hdrs and hdrs.size() > 0 else "GET"
        except Exception:
            return "GET"

    def _header_map(self, hdrs):
        out = {}
        if not hdrs:
            return out
        try:
            n = hdrs.size()
        except Exception:
            return out
        for i in range(1, n):
            try:
                line = hdrs.get(i)
                sep = line.find(":")
                if sep > 0:
                    out[line[:sep].strip().lower()] = line[sep + 1:].strip()
            except Exception:
                continue
        return out

    def _body(self, req, offset):
        try:
            chunk = req[offset:]
            if chunk and 0 < len(chunk) <= _BODY_MAX:
                return self._hl.bytesToString(chunk)
        except Exception:
            pass
        return ""

    def _trim_path(self, p):
        if not p:
            return "/"
        return p[:-1] if len(p) > 1 and p.endswith("/") else p

    def _normalize_ids(self, path):
        segs = path.split("/")
        out = []
        for s in segs:
            if not s:
                out.append(s)
            elif _RE_DIGITS.match(s) or _RE_UUID.match(s) or _RE_HEX24.match(s):
                out.append("{id}")
            else:
                out.append(s)
        return "/".join(out)

    def _cap(self, name):
        limit = self._opt_maxlen
        if len(name) <= limit:
            return name
        # Smart mid-truncation: keep prefix + last segment
        pivot = name.find("-/")
        if pivot >= 0:
            head = name[:pivot + 1]
            tail_src = name[pivot + 1:]
        else:
            head = ""
            tail_src = name
        slash = tail_src.rfind("/")
        if slash > 0 and slash < len(tail_src) - 1:
            tail = tail_src[slash:]
            budget = limit - len(head) - 4 - len(tail)   # 4 = "/..."
            if budget > 4:
                return head + tail_src[:budget] + "/..." + tail
        return name[:limit - 1] + "\xe2\x80\xa6"

    def _dedupe(self, name):
        n = self._counts.get(name, 0) + 1
        self._counts[name] = n
        if len(self._counts) > _CACHE_CAP:
            self._counts.clear()
            self._counts[name] = n
        return "%s (%d)" % (name, n) if n > 1 else name

    # ═════════════════════════════════════════════════════════════
    #  SETTINGS UI
    # ═════════════════════════════════════════════════════════════

    def _init_ui(self):
        root = JPanel()
        root.setLayout(BoxLayout(root, BoxLayout.Y_AXIS))
        root.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        root.add(self._label("ReTab", 16, True))
        root.add(Box.createVerticalStrut(4))
        root.add(self._label("Auto-generates meaningful Repeater tab names.", 12, False, Color(100, 100, 100)))
        root.add(Box.createVerticalStrut(18))

        root.add(self._section("Naming"))
        self._ui_method = self._checkbox(root, "Include HTTP method prefix", "POST-/api/users", self._opt_method)
        self._ui_query  = self._checkbox(root, "Append query string", "Truncated to 30 chars", self._opt_query)
        self._ui_normid = self._checkbox(root, "Normalize IDs", "/123 and UUIDs become /{id}", self._opt_normid)
        self._ui_auth   = self._checkbox(root, "Auth context hint", "Appends [..tok] or [user]", self._opt_auth)

        root.add(Box.createVerticalStrut(14))
        root.add(self._section("Limits"))
        row = JPanel()
        row.setLayout(BoxLayout(row, BoxLayout.X_AXIS))
        row.setAlignmentX(0.0)
        row.setMaximumSize(Dimension(340, 28))
        row.add(JLabel("Max name length  "))
        self._ui_maxlen = JTextField(str(self._opt_maxlen), 4)
        self._ui_maxlen.setMaximumSize(Dimension(50, 28))
        row.add(self._ui_maxlen)
        row.add(JLabel("  chars"))
        root.add(row)

        root.add(Box.createVerticalStrut(18))
        root.add(self._section("Priority Order"))
        for line in ["1  WebSocket   Upgrade: websocket",
                      "2  GraphQL     path / query / body",
                      "3  SOAP        Content-Type: xml",
                      "4  REST        method + path"]:
            lbl = JLabel("   " + line)
            lbl.setFont(Font("Monospaced", Font.PLAIN, 12))
            lbl.setAlignmentX(0.0)
            root.add(lbl)

        root.add(Box.createVerticalGlue())
        self._ui_scroll = JScrollPane(root)
        self._cb.addSuiteTab(self)

    def _sync_options(self):
        try: self._opt_method = self._ui_method.isSelected()
        except Exception: pass
        try: self._opt_query = self._ui_query.isSelected()
        except Exception: pass
        try: self._opt_normid = self._ui_normid.isSelected()
        except Exception: pass
        try: self._opt_auth = self._ui_auth.isSelected()
        except Exception: pass
        try:
            v = int(self._ui_maxlen.getText().strip())
            if 10 <= v <= 200:
                self._opt_maxlen = v
        except Exception:
            pass

    # ─── UI helpers ───────────────────────────────────────────────

    def _label(self, text, size, bold, color=None):
        lbl = JLabel(text)
        lbl.setFont(Font("SansSerif", Font.BOLD if bold else Font.PLAIN, size))
        lbl.setAlignmentX(0.0)
        if color:
            lbl.setForeground(color)
        return lbl

    def _section(self, text):
        lbl = JLabel(text)
        lbl.setFont(Font("SansSerif", Font.BOLD, 13))
        lbl.setAlignmentX(0.0)
        spacer = Box.createVerticalStrut(6)
        wrap = JPanel()
        wrap.setLayout(BoxLayout(wrap, BoxLayout.Y_AXIS))
        wrap.setAlignmentX(0.0)
        wrap.add(lbl)
        wrap.add(spacer)
        return wrap

    def _checkbox(self, parent, title, hint, default):
        cb = JCheckBox(title, default)
        cb.setAlignmentX(0.0)
        cb.setFont(Font("SansSerif", Font.PLAIN, 13))
        parent.add(cb)
        if hint:
            h = JLabel("     " + hint)
            h.setFont(Font("SansSerif", Font.PLAIN, 11))
            h.setForeground(Color(120, 120, 120))
            h.setAlignmentX(0.0)
            parent.add(h)
        parent.add(Box.createVerticalStrut(5))
        return cb


# ═════════════════════════════════════════════════════════════════
#  MODULE-LEVEL PURE FUNCTIONS  (no state, no side effects)
# ═════════════════════════════════════════════════════════════════

def _extract_json_str(text, key):
    """Fast extraction of a JSON string value by key. No json module."""
    tag = '"%s"' % key
    i = text.find(tag)
    if i < 0:
        return None
    rest = text[i + len(tag):]
    rest = rest.lstrip()
    if not rest or rest[0] != ':':
        return None
    rest = rest[1:].lstrip()
    if not rest:
        return None
    if rest[0] == '"':
        end = rest.find('"', 1)
        if end < 0:
            return None
        val = rest[1:end]
        return val if val != "null" else None
    return None


def _qs_value(qs, key):
    """Extract a single value from a query string without building a full dict."""
    search = key + "="
    i = qs.find(search)
    while i >= 0:
        if i == 0 or qs[i - 1] == '&':
            start = i + len(search)
            end = qs.find("&", start)
            raw = qs[start:] if end < 0 else qs[start:end]
            try:
                return URLDecoder.decode(raw, "UTF-8")
            except Exception:
                return raw
        i = qs.find(search, i + 1)
    return None
