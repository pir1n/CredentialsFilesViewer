"""Credential Files View: a local Windows credential viewer."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from credential_api import Credential, PERSIST_NAMES, TYPE_NAMES, display_secret, read_current_credentials
from offline_artifacts import find_sid_directories, read_offline_credentials


def hex_dump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{value:02X}" for value in chunk).ljust(47)
        ascii_part = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
        lines.append(f"{offset:04X}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


class OfflineDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk) -> None:
        super().__init__(parent)
        self.title("Mở artifact Windows offline")
        self.geometry("790x330")
        self.transient(parent)
        self.grab_set()
        self.result: tuple[str, str, str, str | None, str | None] | None = None
        self.credentials = tk.StringVar(value=str(Path.home() / "AppData/Local/Microsoft/Credentials"))
        self.protect = tk.StringVar(value=str(Path.home() / "AppData/Roaming/Microsoft/Protect"))
        self.sid = tk.StringVar()
        self.password = tk.StringVar()
        self.masterkeys = tk.StringVar()
        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)
        rows = [
            ("Credentials:", self.credentials, self._pick_credentials),
            ("Protect:", self.protect, self._pick_protect),
            ("Masterkeys JSON (tùy chọn):", self.masterkeys, self._pick_masterkeys),
        ]
        for row, (label, variable, action) in enumerate(rows):
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=7)
            ttk.Entry(body, textvariable=variable).grid(row=row, column=1, sticky="ew", padx=8, pady=7)
            ttk.Button(body, text="Chọn...", command=action).grid(row=row, column=2, pady=7)
        ttk.Label(body, text="SID:").grid(row=3, column=0, sticky="w", pady=7)
        self.sid_box = ttk.Combobox(body, textvariable=self.sid)
        self.sid_box.grid(row=3, column=1, sticky="ew", padx=8, pady=7)
        ttk.Button(body, text="Tìm SID", command=self._find_sids).grid(row=3, column=2, pady=7)
        ttk.Label(body, text="Mật khẩu Windows:").grid(row=4, column=0, sticky="w", pady=7)
        ttk.Entry(body, textvariable=self.password, show="*").grid(row=4, column=1, sticky="ew", padx=8, pady=7)
        ttk.Label(body, text="Nhập mật khẩu Windows của SID này hoặc chọn file masterkeys JSON đã giải mã.", foreground="#555").grid(row=5, column=0, columnspan=3, sticky="w", pady=(9, 0))
        buttons = ttk.Frame(body)
        buttons.grid(row=6, column=0, columnspan=3, sticky="e", pady=(18, 0))
        ttk.Button(buttons, text="Hủy", command=self.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Giải mã", command=self._accept).pack(side="right")
        body.columnconfigure(1, weight=1)
        self._find_sids(show_error=False)

    def _pick_credentials(self) -> None:
        value = filedialog.askdirectory(parent=self, title="Chọn thư mục Microsoft\\Credentials")
        if value:
            self.credentials.set(value)

    def _pick_protect(self) -> None:
        value = filedialog.askdirectory(parent=self, title="Chọn thư mục Microsoft\\Protect hoặc thư mục SID")
        if value:
            self.protect.set(value)
            self._find_sids()

    def _pick_masterkeys(self) -> None:
        value = filedialog.askopenfilename(parent=self, title="Chọn masterkeys JSON đã giải mã", filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if value:
            self.masterkeys.set(value)

    def _find_sids(self, show_error: bool = True) -> None:
        try:
            sids = sorted(find_sid_directories(self.protect.get()))
        except ValueError as exc:
            sids = []
            if show_error:
                messagebox.showerror("Protect", str(exc), parent=self)
        self.sid_box["values"] = sids
        if sids and self.sid.get() not in sids:
            self.sid.set(sids[0])

    def _accept(self) -> None:
        if not self.sid.get():
            messagebox.showerror("Thiếu SID", "Chọn thư mục Protect chứa SID rồi bấm Tìm SID.", parent=self)
            return
        if not self.password.get() and not self.masterkeys.get():
            messagebox.showerror("Thiếu key", "Nhập mật khẩu Windows hoặc chọn masterkeys JSON.", parent=self)
            return
        self.result = (
            self.credentials.get(), self.protect.get(), self.sid.get(),
            self.password.get() or None, self.masterkeys.get() or None,
        )
        self.destroy()


class CredentialApp(tk.Tk):
    COLUMNS = ("target", "kind", "persist", "username", "modified", "size", "secret", "source")
    HEADINGS = {
        "target": ("Entry Name", 310),
        "kind": ("Entry Type", 130),
        "persist": ("Persist", 120),
        "username": ("User Name", 210),
        "modified": ("Modified Time (UTC)", 180),
        "size": ("Blob Size", 80),
        "secret": ("Password / Blob", 230),
        "source": ("Source", 190),
    }

    def __init__(self) -> None:
        super().__init__()
        self.title("Credential Files View")
        self.geometry("1320x760")
        self.minsize(900, 500)
        self.records: list[Credential] = []
        self.filtered: list[int] = []
        self.reveal = tk.BooleanVar(value=False)
        self.query = tk.StringVar()
        self.status = tk.StringVar(value="Sẵn sàng. Chọn Quét online hoặc mở artifact Windows offline.")
        self.mode = "Chưa mở"
        self._build()

    def _build(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Quét online", command=self.scan_online, accelerator="F5")
        file_menu.add_command(label="Mở artifact offline...", command=self.open_offline, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Thoát", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)
        view_menu = tk.Menu(menu, tearoff=False)
        view_menu.add_checkbutton(label="Hiện password / blob", variable=self.reveal, command=self._refresh)
        view_menu.add_command(label="Thuộc tính", command=self.show_properties, accelerator="Enter")
        menu.add_cascade(label="View", menu=view_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Giới thiệu", command=self._about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu)

        bar = ttk.Frame(self, padding=(8, 7))
        bar.pack(fill="x")
        ttk.Button(bar, text="⟳  Quét online", command=self.scan_online).pack(side="left", padx=(0, 5))
        ttk.Button(bar, text="📂  Mở offline", command=self.open_offline).pack(side="left", padx=5)
        ttk.Button(bar, text="Thuộc tính", command=self.show_properties).pack(side="left", padx=5)
        ttk.Checkbutton(bar, text="Hiện bí mật", variable=self.reveal, command=self._refresh).pack(side="left", padx=15)
        ttk.Label(bar, text="Tìm:").pack(side="left", padx=(14, 4))
        search = ttk.Entry(bar, textvariable=self.query, width=28)
        search.pack(side="left")
        self.query.trace_add("write", lambda *_: self._refresh())

        pane = ttk.PanedWindow(self, orient="vertical")
        pane.pack(fill="both", expand=True, padx=7, pady=(0, 5))

        table_frame = ttk.Frame(pane)
        self.table = ttk.Treeview(table_frame, columns=self.COLUMNS, show="headings", selectmode="browse")
        for column, (label, width) in self.HEADINGS.items():
            self.table.heading(column, text=label, command=lambda name=column: self._sort(name))
            self.table.column(column, width=width, minwidth=60, stretch=column in ("target", "username", "secret"))
        scroll_y = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        scroll_x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.table.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        pane.add(table_frame, weight=3)

        hex_frame = ttk.LabelFrame(pane, text="Credential blob (hex / ASCII)")
        self.hex_view = tk.Text(hex_frame, height=12, wrap="none", font=("Consolas", 10), state="disabled")
        hex_scroll = ttk.Scrollbar(hex_frame, orient="vertical", command=self.hex_view.yview)
        self.hex_view.configure(yscrollcommand=hex_scroll.set)
        self.hex_view.pack(side="left", fill="both", expand=True)
        hex_scroll.pack(side="right", fill="y")
        pane.add(hex_frame, weight=1)

        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=(7, 3)).pack(fill="x")
        self.table.bind("<<TreeviewSelect>>", lambda _: self._show_blob())
        self.table.bind("<Double-1>", lambda _: self.show_properties())
        self.bind("<F5>", lambda _: self.scan_online())
        self.bind("<Control-o>", lambda _: self.open_offline())
        self.table.bind("<Return>", lambda _: self.show_properties())
        self._sort_by = "target"
        self._descending = False

    def _selected(self) -> Credential | None:
        selected = self.table.selection()
        return self.records[int(selected[0])] if selected else None

    def _refresh(self) -> None:
        selected = self.table.selection()
        selected_id = selected[0] if selected else None
        self.table.delete(*self.table.get_children())
        term = self.query.get().casefold().strip()
        self.filtered = [
            index for index, item in enumerate(self.records)
            if not term or term in item.target.casefold() or term in item.username.casefold() or term in item.comment.casefold()
        ]
        def sort_key(index: int):
            item = self.records[index]
            if self._sort_by == "size":
                return len(item.blob)
            if self._sort_by == "kind":
                return TYPE_NAMES.get(item.kind, str(item.kind)).casefold()
            if self._sort_by == "persist":
                return PERSIST_NAMES.get(item.persistence, str(item.persistence)).casefold()
            if self._sort_by == "secret":
                return display_secret(item.blob).casefold()
            return str(getattr(item, self._sort_by, "")).casefold()
        self.filtered.sort(key=sort_key, reverse=self._descending)
        for index in self.filtered:
            item = self.records[index]
            secret = display_secret(item.blob) if self.reveal.get() else ("••••••" if item.blob or item.extra_blob else "")
            self.table.insert("", "end", iid=str(index), values=(
                item.target, TYPE_NAMES.get(item.kind, str(item.kind)),
                PERSIST_NAMES.get(item.persistence, str(item.persistence)),
                item.username, item.modified, len(item.blob), secret, item.source,
            ))
        if selected_id and self.table.exists(selected_id):
            self.table.selection_set(selected_id)
            self.table.see(selected_id)
        self._show_blob()
        self.status.set(f"{self.mode}  |  {len(self.filtered)}/{len(self.records)} credential(s)")

    def _sort(self, column: str) -> None:
        if self._sort_by == column:
            self._descending = not self._descending
        else:
            self._sort_by, self._descending = column, False
        self._refresh()

    def _show_blob(self) -> None:
        item = self._selected()
        if item and self.reveal.get():
            sections = []
            if item.blob:
                sections.append("Credential blob:\n" + hex_dump(item.blob))
            if item.extra_blob:
                sections.append("Additional blob:\n" + hex_dump(item.extra_blob))
            value = "\n\n".join(sections)
        else:
            value = "Bật ‘Hiện bí mật’ để xem dữ liệu blob." if item and (item.blob or item.extra_blob) else ""
        self.hex_view.configure(state="normal")
        self.hex_view.delete("1.0", "end")
        self.hex_view.insert("1.0", value)
        self.hex_view.configure(state="disabled")

    def scan_online(self) -> None:
        try:
            records = read_current_credentials()
        except Exception as exc:
            messagebox.showerror("Không thể quét", str(exc), parent=self)
            return
        self.records = records
        self.mode = "Online: tài khoản Windows hiện tại"
        self.reveal.set(False)
        self._refresh()

    def open_offline(self) -> None:
        dialog = OfflineDialog(self)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        credentials_dir, protect_dir, sid, password, masterkeys_json = dialog.result
        self.configure(cursor="watch")
        self.update_idletasks()
        try:
            result = read_offline_credentials(
                credentials_dir, protect_dir, sid,
                password=password, masterkeys_json=masterkeys_json,
            )
        except Exception as exc:
            messagebox.showerror("Không thể giải mã artifact", str(exc), parent=self)
            return
        finally:
            self.configure(cursor="")
        self.records = result.credentials
        self.mode = f"Offline: {credentials_dir}"
        self.reveal.set(False)
        self._refresh()
        message = f"Giải mã được {len(result.credentials)}/{result.file_count} file credential với {result.masterkey_count} master key."
        if result.failures:
            message += "\n\nFile chưa giải mã được:\n" + "\n".join(result.failures[:12])
            if len(result.failures) > 12:
                message += f"\n... và {len(result.failures) - 12} file khác."
        messagebox.showinfo("Kết quả DFIR", message, parent=self)

    def show_properties(self) -> None:
        item = self._selected()
        if item is None:
            return
        popup = tk.Toplevel(self)
        popup.title("Properties")
        popup.geometry("660x380")
        popup.transient(self)
        popup.grab_set()
        fields = [
            ("Entry Name", item.target), ("Entry Type", TYPE_NAMES.get(item.kind, str(item.kind))),
            ("Persist", PERSIST_NAMES.get(item.persistence, str(item.persistence))),
            ("User Name", item.username), ("Modified Time (UTC)", item.modified),
            ("Blob Size", str(len(item.blob))), ("Source", item.source),
            ("Comment", item.comment), ("Alias", item.alias),
        ]
        body = ttk.Frame(popup, padding=12)
        body.pack(fill="both", expand=True)
        for row, (label, value) in enumerate(fields):
            ttk.Label(body, text=label + ":").grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=3)
            entry = ttk.Entry(body)
            entry.insert(0, value)
            entry.configure(state="readonly")
            entry.grid(row=row, column=1, sticky="ew", pady=3)
        ttk.Label(body, text="Password / Blob:").grid(row=len(fields), column=0, sticky="nw", pady=3)
        secret = ttk.Entry(body)
        secret.insert(0, display_secret(item.blob) if self.reveal.get() else ("••••••" if item.blob else ""))
        secret.configure(state="readonly")
        secret.grid(row=len(fields), column=1, sticky="ew", pady=3)
        if item.extra_blob:
            ttk.Label(body, text="Additional Blob:").grid(row=len(fields) + 1, column=0, sticky="nw", pady=3)
            extra = ttk.Entry(body)
            extra.insert(0, display_secret(item.extra_blob) if self.reveal.get() else "••••••")
            extra.configure(state="readonly")
            extra.grid(row=len(fields) + 1, column=1, sticky="ew", pady=3)
        body.columnconfigure(1, weight=1)
        ttk.Button(body, text="OK", command=popup.destroy).grid(row=len(fields) + 2, column=1, sticky="e", pady=(12, 0))

    def _about(self) -> None:
        messagebox.showinfo("Credential Files View", "Online: Windows Credential Manager của phiên hiện tại. Offline: artifact Credentials + Protect và mật khẩu Windows hoặc DPAPI master key đã giải mã.", parent=self)


if __name__ == "__main__":
    CredentialApp().mainloop()
