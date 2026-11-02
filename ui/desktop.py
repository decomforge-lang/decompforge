"""
DecompForge Desktop — aplicacion de escritorio (Tkinter) que envuelve la CLI.

Menu superior:
  1. Decompilador  -> usa Ghidra (rea) sobre un binario.
  2. NameForge     -> la IA propone nombres sobre el proyecto descompilado.
  3. Compilador    -> aplica nombres/tipos/comentarios y recompila (placeholder).
  4. Switch        -> descompila un binario de Nintendo Switch y lo recompila
                     para Windows (placeholder, usa rea).

La logica de negocio vive en el nucleo Rust (decompforge.exe); esta app solo
orquesta comandos y muestra resultados.
"""

import json
import os
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

ROOT = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(ROOT)

def find_bin():
    if os.environ.get("DECOMPFORGE_BIN"):
        return os.environ["DECOMPFORGE_BIN"]
    candidates = [
        os.path.join(PARENT, "target", "release", "decompforge.exe"),
        os.path.join(PARENT, "target", "debug", "decompforge.exe"),
        os.path.join(PARENT, "target", "release", "decompforge"),
        os.path.join(PARENT, "target", "debug", "decompforge"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "decompforge"

BIN = find_bin()

def run_cli(args, cwd=None, on_done=None):
    def worker():
        try:
            proc = subprocess.run([BIN] + args, cwd=cwd or PARENT, capture_output=True, text=True)
            out = proc.stdout + (("\n[stderr]\n" + proc.stderr) if proc.stderr else "")
            code = proc.returncode
        except Exception as e:
            out = str(e); code = 127
        if on_done:
            on_done(code, out)
    threading.Thread(target=worker, daemon=True).start()

class DecompForgeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DecompForge")
        self.geometry("1080x720")
        self.minsize(900, 600)
        self.configure(bg="#0f1115")

        self.project = tk.StringVar(value="")
        self.binary = tk.StringVar(value="")
        self.platform = tk.StringVar(value="ps2")

        self._build_menu()
        self._build_layout()

    # ---------- menu superior ----------
    def _build_menu(self):
        menubar = tk.Menu(self, bg="#171a21", fg="#e6e8ee", activebackground="#5b8def")
        self.config(menu=menubar)

        m_dec = tk.Menu(menubar, tearoff=0, bg="#171a21", fg="#e6e8ee")
        m_dec.add_command(label="Abrir binario...", command=self.act_open_binary)
        m_dec.add_command(label="Cargar + analizar", command=self.act_load_analyze)
        m_dec.add_command(label="Re-analizar", command=self.act_reanalyze)
        m_dec.add_command(label="Info del proyecto", command=self.act_info)
        m_dec.add_separator()
        m_dec.add_command(label="Exportar re-json", command=self.act_export)
        menubar.add_cascade(label="1. Decompilador (Ghidra)", menu=m_dec)

        m_ia = tk.Menu(menubar, tearoff=0, bg="#171a21", fg="#e6e8ee")
        m_ia.add_command(label="NameForge por lotes", command=lambda: self.act_name(batch=True))
        m_ia.add_command(label="NameForge interactivo", command=lambda: self.act_name(batch=False))
        m_ia.add_command(label="Listar propuestas", command=self.act_name_list)
        m_ia.add_command(label="Aceptar propuesta...", command=self.act_name_accept)
        m_ia.add_command(label="Rechazar propuesta...", command=self.act_name_reject)
        m_ia.add_command(label="Generar config por defecto", command=self.act_name_config)
        menubar.add_cascade(label="2. IA (NameForge)", menu=m_ia)

        m_comp = tk.Menu(menubar, tearoff=0, bg="#171a21", fg="#e6e8ee")
        m_comp.add_command(label="Aplicar updates.json", command=self.act_apply)
        m_comp.add_command(label="Compilar (placeholder)", command=self.act_compile)
        menubar.add_cascade(label="3. Compilador", menu=m_comp)

        m_switch = tk.Menu(menubar, tearoff=0, bg="#171a21", fg="#e6e8ee")
        m_switch.add_command(label="Descompilar binario Switch...", command=self.act_switch_decompile)
        m_switch.add_command(label="Recompilar a Windows (placeholder)", command=self.act_switch_recompile)
        menubar.add_cascade(label="4. Switch → Windows", menu=m_switch)

        m_help = tk.Menu(menubar, tearoff=0, bg="#171a21", fg="#e6e8ee")
        m_help.add_command(label="Acerca de", command=lambda: messagebox.showinfo("DecompForge", "DecompForge — decompilar, verificar y portar.\nNucleo Rust + REA/Ghidra."))
        menubar.add_cascade(label="Ayuda", menu=m_help)

    # ---------- layout ----------
    def _build_layout(self):
        top = tk.Frame(self, bg="#171a21", padx=10, pady=8)
        top.pack(fill="x")
        tk.Label(top, text="Proyecto:", bg="#171a21", fg="#9aa3b2").pack(side="left")
        tk.Entry(top, textvariable=self.project, width=40, bg="#1e222b", fg="#e6e8ee", insertbackground="#e6e8ee", relief="flat").pack(side="left", padx=6)
        tk.Button(top, text="Abrir", command=self.act_open_project, bg="#5b8def", fg="white", relief="flat", padx=10).pack(side="left")
        tk.Label(top, text="Binario:", bg="#171a21", fg="#9aa3b2").pack(side="left", padx=(16,0))
        tk.Entry(top, textvariable=self.binary, width=46, bg="#1e222b", fg="#e6e8ee", insertbackground="#e6e8ee", relief="flat").pack(side="left", padx=6)
        tk.Button(top, text="Examinar", command=self.act_pick_binary, bg="#5b8def", fg="white", relief="flat", padx=10).pack(side="left")
        tk.Label(top, text="Plataforma:", bg="#171a21", fg="#9aa3b2").pack(side="left", padx=(16,0))
        ttk.Combobox(top, textvariable=self.platform, values=["ps2","ps3","switch","pc","gamecube"], width=10).pack(side="left", padx=6)

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=8)

        self.tab_log = scrolledtext.ScrolledText(self.tabs, bg="#0b0d12", fg="#e6e8ee", font=("Consolas", 10), insertbackground="#e6e8ee")
        self.tabs.add(self.tab_log, text="Salida")

        self.tab_props = scrolledtext.ScrolledText(self.tabs, bg="#0b0d12", fg="#e6e8ee", font=("Consolas", 10))
        self.tabs.add(self.tab_props, text="Propuestas")

        self.status = tk.Label(self, text="listo", bg="#171a21", fg="#9aa3b2", anchor="w", padx=10)
        self.status.pack(fill="x", side="bottom")

    def log(self, msg, tab="log"):
        w = self.tab_log if tab == "log" else self.tab_props
        w.insert("end", msg + "\n")
        w.see("end")
        self.update_idletasks()

    def set_status(self, msg):
        self.status.config(text=msg)
        self.update_idletasks()

    # ---------- helpers ----------
    def act_open_project(self):
        p = filedialog.askopenfilename(filetypes=[("Proyecto", "*.dfproj"), ("Todos", "*.*")])
        if p:
            self.project.set(p)

    def act_pick_binary(self):
        p = filedialog.askopenfilename(filetypes=[("Binario", "*.*")])
        if p:
            self.binary.set(p)

    def act_open_binary(self):
        self.act_pick_binary()

    # ---------- decompilador ----------
    def act_load_analyze(self):
        binp = self.binary.get().strip()
        proj = self.project.get().strip()
        if not binp or not proj:
            messagebox.showwarning("Faltan datos", "Indica binario y proyecto.")
            return
        self.set_status("cargando y analizando…")
        self.log(f"$ decompforge load {binp} --project {proj}")
        run_cli(["load", binp, "--project", proj], on_done=lambda c, o: self._on_load(c, o, binp, proj))

    def _on_load(self, code, out, binp, proj):
        self.log(out)
        if code == 0:
            self.set_status("analizado")
        else:
            self.set_status("error")

    def act_reanalyze(self):
        binp = self.binary.get().strip()
        proj = self.project.get().strip()
        if not binp or not proj:
            messagebox.showwarning("Faltan datos", "Indica binario y proyecto.")
            return
        self.set_status("re-analizando…")
        self.log(f"$ decompforge analyze {binp} --project {proj}")
        run_cli(["analyze", binp, "--project", proj], on_done=lambda c, o: (self.log(o), self.set_status("analizado" if c == 0 else "error")))

    def act_info(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("Faltan datos", "Indica proyecto.")
            return
        self.log(f"$ decompforge info --project {proj} --json")
        run_cli(["info", "--project", proj, "--json"], on_done=lambda c, o: (self.log(o), self.set_status("listo" if c == 0 else "error")))

    def act_export(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("Faltan datos", "Indica proyecto.")
            return
        outp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not outp:
            return
        fmt = "re-json"
        self.log(f"$ decompforge export --format {fmt} --project {proj} --output {outp}")
        run_cli(["export", "--format", fmt, "--project", proj, "--output", outp], on_done=lambda c, o: (self.log(o), self.set_status("exportado" if c == 0 else "error")))

    # ---------- IA ----------
    def act_name(self, batch=True):
        binp = self.binary.get().strip()
        proj = self.project.get().strip()
        if not binp or not proj:
            messagebox.showwarning("Faltan datos", "Indica binario y proyecto.")
            return
        args = ["name", binp, "--project", proj, "--json"]
        if batch:
            args.insert(2, "--batch")
        else:
            func = tk.simpledialog.askstring("Función", "Dirección (0x...):")
            if not func:
                return
            args += ["--function", func]
        self.log("$ " + " ".join(args))
        run_cli(args, on_done=lambda c, o: self._on_name(c, o))

    def _on_name(self, code, out):
        self.log(out, tab="props" if False else "log")
        try:
            data = json.loads(out)
            if isinstance(data, dict) and "records" in data:
                self.tab_props.delete("1.0", "end")
                for r in data["records"]:
                    self.tab_props.insert("end", f"{r['id']:>4}  0x{r['function']:08x}  {r['name']:<28} {r['confidence']:.2}  {r['reason']}\n")
                self.tab_props.see("end")
        except Exception:
            pass
        self.set_status("propuestas listas" if code == 0 else "error")

    def act_name_list(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("Faltan datos", "Indica proyecto.")
            return
        state = tk.simpledialog.askstring("Estado", "pending/accepted/rejected/all", initialvalue="pending") or "pending"
        self.log(f"$ decompforge name list --project {proj} --state {state} --json")
        run_cli(["name", "list", "--project", proj, "--state", state, "--json"], on_done=lambda c, o: self._on_name_list(c, o))

    def _on_name_list(self, code, out):
        self.log(out)
        try:
            data = json.loads(out)
            self.tab_props.delete("1.0", "end")
            for r in data:
                self.tab_props.insert("end", f"{r['id']:>4}  0x{r['function']:08x}  {r['name']:<28} {r['confidence']:.2}  {r['state']}  {r['reason']}\n")
        except Exception:
            pass
        self.set_status("listo" if code == 0 else "error")

    def act_name_accept(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("Faltan datos", "Indica proyecto.")
            return
        nid = tk.simpledialog.askinteger("Aceptar", "ID de la propuesta:")
        if nid is None:
            return
        force = messagebox.askyesno("Force", "¿Forzar si ya tiene nombre?")
        args = ["name", "accept", str(nid), "--project", proj]
        if force:
            args.append("--force")
        self.log("$ " + " ".join(args))
        run_cli(args, on_done=lambda c, o: (self.log(o), self.set_status("aceptada" if c == 0 else "error")))

    def act_name_reject(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("Faltan datos", "Indica proyecto.")
            return
        nid = tk.simpledialog.askinteger("Rechazar", "ID de la propuesta:")
        if nid is None:
            return
        self.log(f"$ decompforge name reject {nid} --project {proj}")
        run_cli(["name", "reject", str(nid), "--project", proj], on_done=lambda c, o: (self.log(o), self.set_status("rechazada" if c == 0 else "error")))

    def act_name_config(self):
        self.log("$ decompforge name config")
        run_cli(["name", "config"], on_done=lambda c, o: (self.log(o), self.set_status("config generada" if c == 0 else "error")))

    # ---------- compilador ----------
    def act_apply(self):
        proj = self.project.get().strip()
        if not proj:
            messagebox.showwarning("Faltan datos", "Indica proyecto.")
            return
        f = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not f:
            return
        self.log(f"$ decompforge apply {f} --project {proj}")
        run_cli(["apply", f, "--project", proj], on_done=lambda c, o: (self.log(o), self.set_status("aplicado" if c == 0 else "error")))

    def act_compile(self):
        messagebox.showinfo("Compilador", "Pendiente: integracion con toolchain fijado (Fase 4/5).")

    # ---------- switch ----------
    def act_switch_decompile(self):
        binp = self.binary.get().strip()
        proj = self.project.get().strip()
        if not binp or not proj:
            messagebox.showwarning("Faltan datos", "Indica binario y proyecto.")
            return
        self.platform.set("switch")
        self.log(f"$ decompforge load {binp} --project {proj}  (switch)")
        run_cli(["load", binp, "--project", proj], on_done=lambda c, o: (self.log(o), self.set_status("cargado" if c == 0 else "error")))

    def act_switch_recompile(self):
        messagebox.showinfo("Switch → Windows", "Pendiente: recompilacion estatica (Fase 5/6).")

if __name__ == "__main__":
    try:
        import tkinter.simpledialog  # noqa
    except Exception:
        pass
    app = DecompForgeApp()
    app.mainloop()