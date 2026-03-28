#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ReTab — Adds a context menu to send requests to Repeater with auto-generated tab names.
"""
from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (
    JPanel, JCheckBox, JLabel, JTextField, JScrollPane,
    JMenuItem, BorderFactory, Box, BoxLayout, SwingUtilities,
    JTabbedPane                                                        
)
from java.awt import Font, Color, Dimension
from java.util import ArrayList
from java.net import URLDecoder
from collections import OrderedDict
import re


# ─── Precompiled Patterns (compiled once at module load) ─────────
_RE_GQL_OP = re.compile(r'(?:query|mutation|subscription)\s+([a-zA-Z0-9_]+)')
_RE_HASH   = re.compile(r':\s*"([a-fA-F0-9]+)"')
_RE_XML    = re.compile(r'<([a-zA-Z][\w.-]*:)?([a-zA-Z][\w.-]*)')
_RE_DIGITS = re.compile(r'^\d+$')
_RE_UUID   = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-')
_RE_HEX24  = re.compile(r'^[0-9a-fA-F]{24,}$')

# ─── Constants ───────────────────────────────────────────────────
_SOAP_SKIP = frozenset(["envelope", "header", "body", "xml"])
_BODY_MAX  = 65536
_SOAP_SCAN = 2048
_GQL_SCAN  = 200
_CACHE_CAP = 5000


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    # ═════════════════════════════════════════════════════════════
    #  LIFECYCLE
    # ═════════════════════════════════════════════════════════════

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._hl = callbacks.getHelpers()
        self._counts = OrderedDict()

        self._opt_method = True
        self._opt_query  = False
        self._opt_normid = True
        self._opt_auth   = True
        self._opt_host   = False
        self._opt_debug  = False
        self._opt_focus  = True                                        
        self._opt_maxlen = 60

        callbacks.setExtensionName("ReTab")
        callbacks.registerContextMenuFactory(self)
        SwingUtilities.invokeLater(self._init_ui)
        callbacks.printOutput("[+] ReTab loaded")

    # ═════════════════════════════════════════════════════════════
    #  ITab
    # ═════════════════════════════════════════════════════════════

    def getTabCaption(self):
        return "ReTab"

    def getUiComponent(self):
        return self._ui_scroll

    # ═════════════════════════════════════════════════════════════
    #  IContextMenuFactory
    # ═════════════════════════════════════════════════════════════

    def createMenuItems(self, ctx):
        if not ctx.getSelectedMessages():
            return None
        items = ArrayList()
        items.add(JMenuItem(
            "Send to Repeater (ReTab)",
            actionPerformed=lambda _: self._on_send(ctx)))
        return items

    # ═════════════════════════════════════════════════════════════
    #  SEND LOGIC
    # ═════════════════════════════════════════════════════════════

    def _on_send(self, ctx):
        self._sync_options()
        for msg in ctx.getSelectedMessages():
            req = msg.getRequest()
            svc = msg.getHttpService()
            if req is None or svc is None:
                continue
            try:
                is_https = svc.getProtocol().lower() == "https"
                name = self._dedupe(self._name_for(svc, req))
                self._cb.sendToRepeater(svc.getHost(), svc.getPort(), is_https, req, name)
                if self._opt_debug:
                    self._cb.printOutput("[>] " + name)
            except Exception as e:
                self._cb.printError("[!] " + str(e))
                self._send_fallback(svc, req)

        if self._opt_focus:                                            
            SwingUtilities.invokeLater(self._focus_repeater)           

    def _send_fallback(self, svc, req):
        try:
            is_https = svc.getProtocol().lower() == "https"
            self._cb.sendToRepeater(svc.getHost(), svc.getPort(), is_https, req, "request")
        except Exception:
            pass

    # ═════════════════════════════════════════════════════════════
    #  AUTO-SWITCH TO REPEATER TAB                        ← NEW
    # ═════════════════════════════════════════════════════════════

    def _focus_repeater(self):                                         
        """Walk Burp's Swing tree and select the top-level Repeater tab."""
        try:                                                           
            window = SwingUtilities.getWindowAncestor(self._ui_scroll) 
            self._select_tab(window, "Repeater")                       
        except Exception:                                              
            pass  # Silently fail — UI focus is non-critical           

    def _select_tab(self, container, title):                           
        """Recursively search for a JTabbedPane containing a tab with
        the given title and select it. Returns True on first match."""
        if isinstance(container, JTabbedPane):                         
            for i in range(container.getTabCount()):                   
                if container.getTitleAt(i) == title:                   
                    container.setSelectedIndex(i)                      
                    return True                                        
        for i in range(container.getComponentCount()):                 
            child = container.getComponent(i)                          
            if hasattr(child, "getComponentCount"):                    
                if self._select_tab(child, title):                     
                    return True                                        
        return False                                                   

    # ═════════════════════════════════════════════════════════════
    #  NAME GENERATION
    #
    #  Priority chain (order matters):
    #    1. WebSocket — checked first because a WS upgrade to /graphql
    #       should be named WS-/graphql, not by its GraphQL operation.
    #    2. GraphQL — single-endpoint APIs need operation-level naming;
    #       path alone is useless.
    #    3. SOAP/XML — action tag inside the body is more meaningful
    #       than the generic POST /service path.
    #    4. REST — fallback; method + path is always available.
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

        # 1. WebSocket
        if hdr_map.get("upgrade", "").lower() == "websocket":
            name = "WS-" + self._trim_path(path)

        # 2. GraphQL
        elif self._looks_graphql(path, q, hdr_map, body):
            name = self._gql_name(method, q, body)

        # 3. SOAP / XML
        elif "xml" in hdr_map.get("content-type", "").lower() and body:
            name = self._soap_name(body)

        # 4. REST
        else:
            name = self._rest_name(method, path, q, hdr_map)

        if self._opt_host:
            short = svc.getHost().split(".")[0]
            name = short + "-" + name

        return self._cap(name)

    # ─── Path / Query ────────────────────────────────────────────

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
                tokens = hdrs.get(0).split(" ", 2)
                if len(tokens) >= 2:
                    raw = tokens[1]
                    sep = raw.find("?")
                    if sep >= 0:
                        return raw[:sep], raw[sep + 1:]
                    return raw, None
        except Exception:
            pass
        return "/", None

    # ─── GraphQL ─────────────────────────────────────────────────

    def _looks_graphql(self, path, q, hdr_map, body):
        if path and "graphql" in path.lower():
            return True
        if q and "query=" in q.lower():
            return True
        ct = hdr_map.get("content-type", "").lower()
        if "application/graphql" in ct:
            return True
        if "application/json" in ct and body and '"query"' in body:
            return True
        return False

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
            m = _RE_GQL_OP.search(raw[:_GQL_SCAN])
            if m:
                return m.group(1)
        h = self._persisted_hash(body)
        if h:
            return "gql-" + h[:6]
        return None

    def _gql_from_qs(self, q):
        val = _qs_value(q, "query")
        if val:
            m = _RE_GQL_OP.search(val[:_GQL_SCAN])
            if m:
                return m.group(1)
        return None

    def _persisted_hash(self, body):
        idx = body.find("sha256Hash")
        if idx < 0:
            return None
        m = _RE_HASH.search(body, idx + 10, min(idx + 90, len(body)))
        return m.group(1) if m else None

    # ─── SOAP ────────────────────────────────────────────────────

    def _soap_name(self, body):
        scan = body[:_SOAP_SCAN]
        pos = 0
        for _ in range(8):
            m = _RE_XML.search(scan, pos)
            if not m:
                break
            tag = m.group(2)
            if tag.lower() not in _SOAP_SKIP:
                return "SOAP-" + tag
            pos = m.end()
        return "SOAP-request"

    # ─── REST ────────────────────────────────────────────────────

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
            tag = self._auth_tag(hdr_map)
            if tag:
                parts.append(tag)

        return "".join(parts)

    # ─── Auth Hint ───────────────────────────────────────────────

    def _auth_tag(self, hdr_map):
        val = hdr_map.get("authorization", "")
        if not val:
            return ""
        low = val.lower()
        try:
            if low.startswith("bearer "):
                tok = val[7:].strip()
                if len(tok) >= 8:
                    h = hash(tok[-8:]) % 0xFFFF
                    return "[#%04x]" % h
                return "[bearer]"
            if low.startswith("basic "):
                from java.util import Base64 as JB64
                raw = JB64.getDecoder().decode(val[6:].strip())
                user = self._hl.bytesToString(raw).split(":")[0]
                if len(user) > 8:
                    user = user[:8]
                return "[" + user + "]"
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
            chunk = req[offset:offset + _BODY_MAX]
            if chunk and len(chunk) > 0:
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
            budget = limit - len(head) - 4 - len(tail)
            if budget > 4:
                return head + tail_src[:budget] + "/..." + tail
        return name[:limit - 3] + "..."

    def _dedupe(self, name):
        if name in self._counts:
            self._counts[name] += 1
        else:
            self._counts[name] = 1
        n = self._counts[name]
        if len(self._counts) > _CACHE_CAP:
            self._counts.popitem(last=False)
        return "%s (%d)" % (name, n) if n > 1 else name

    # ═════════════════════════════════════════════════════════════
    #  SETTINGS UI
    # ═════════════════════════════════════════════════════════════

    def _init_ui(self):
        root = JPanel()
        root.setLayout(BoxLayout(root, BoxLayout.Y_AXIS))
        root.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        root.add(_ui_label("ReTab", 16, True))
        root.add(Box.createVerticalStrut(4))
        root.add(_ui_label("Auto-generates meaningful Repeater tab names.", 12, False, Color(100, 100, 100)))
        root.add(Box.createVerticalStrut(18))

        root.add(_ui_section("Naming"))
        self._ui_method = _ui_checkbox(root, "Include HTTP method prefix",    "POST-/api/users",              self._opt_method)
        self._ui_query  = _ui_checkbox(root, "Append query string",           "Truncated to 30 chars",        self._opt_query)
        self._ui_normid = _ui_checkbox(root, "Normalize IDs",                 "/123 and UUIDs become /{id}",  self._opt_normid)
        self._ui_auth   = _ui_checkbox(root, "Auth context hint",             "Appends [..tok] or [user]",    self._opt_auth)
        self._ui_host   = _ui_checkbox(root, "Include host prefix",           "api-POST-/users for multi-host testing", self._opt_host)

        root.add(Box.createVerticalStrut(14))
        root.add(_ui_section("Behavior"))                                                                      
        self._ui_focus = _ui_checkbox(root, "Auto-switch to Repeater tab",    "Jump to Repeater after send",  self._opt_focus)

        root.add(Box.createVerticalStrut(14))
        root.add(_ui_section("Limits"))
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

        root.add(Box.createVerticalStrut(14))
        root.add(_ui_section("Debug"))
        self._ui_debug = _ui_checkbox(root, "Enable debug logging", "Prints tab names to Extender output", self._opt_debug)

        root.add(Box.createVerticalStrut(14))
        root.add(_ui_section("Priority Order"))
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
        try: self._opt_host = self._ui_host.isSelected()
        except Exception: pass
        try: self._opt_focus = self._ui_focus.isSelected()             
        except Exception: pass
        try: self._opt_debug = self._ui_debug.isSelected()
        except Exception: pass
        try:
            v = int(self._ui_maxlen.getText().strip())
            if 10 <= v <= 200:
                self._opt_maxlen = v
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════
#  MODULE-LEVEL PURE FUNCTIONS
# ═════════════════════════════════════════════════════════════════

def _extract_json_str(text, key):
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
    if not qs:
        return None
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


# ─── UI Helpers (stateless) ──────────────────────────────────────

def _ui_label(text, size, bold, color=None):
    lbl = JLabel(text)
    lbl.setFont(Font("SansSerif", Font.BOLD if bold else Font.PLAIN, size))
    lbl.setAlignmentX(0.0)
    if color:
        lbl.setForeground(color)
    return lbl


def _ui_section(text):
    wrap = JPanel()
    wrap.setLayout(BoxLayout(wrap, BoxLayout.Y_AXIS))
    wrap.setAlignmentX(0.0)
    lbl = JLabel(text)
    lbl.setFont(Font("SansSerif", Font.BOLD, 13))
    lbl.setAlignmentX(0.0)
    wrap.add(lbl)
    wrap.add(Box.createVerticalStrut(6))
    return wrap


def _ui_checkbox(parent, title, hint, default):
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
