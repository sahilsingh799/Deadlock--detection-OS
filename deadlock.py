import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
from collections import defaultdict
from enum import Enum, auto
from typing import Dict, List, Set, Tuple
import json
from dataclasses import dataclass

class ResourceType(Enum):
    MUTEX = auto()
    SEMAPHORE = auto()
    FILE = auto()
    SOCKET = auto()
    SHARED_MEMORY = auto()
    PRINTER = auto()

    def __str__(self):
        return self.name.replace('_', ' ').title()

@dataclass
class Process:
    pid: str
    priority: int = 0
    status: str = "Ready"

@dataclass
class Resource:
    rid: str
    type: ResourceType
    instances: int = 1

class DeadlockDetector:
    def __init__(self):
        self.processes: Dict[str, Process] = {}
        self.resources: Dict[str, Resource] = {}
        self.request_graph: Dict[str, Set[str]] = defaultdict(set)
        self.allocation_graph: Dict[str, Set[str]] = defaultdict(set)
        self.history: List[str] = []
        self.lock = threading.RLock()
        self.detection_active = False
        self.detection_thread = None

    def add_process(self, pid: str, priority: int = 0) -> bool:
        with self.lock:
            if pid in self.processes:
                self._log(f"Process {pid} already exists", "WARNING")
                return False
            self.processes[pid] = Process(pid=pid, priority=priority)
            self._log(f"Added process {pid} (Priority: {priority})")
            return True

    def add_resource(self, rid: str, rtype: ResourceType, instances: int = 1) -> bool:
        with self.lock:
            if rid in self.resources:
                self._log(f"Resource {rid} already exists", "WARNING")
                return False
            self.resources[rid] = Resource(rid=rid, type=rtype, instances=instances)
            self._log(f"Added resource {rid} ({rtype})")
            return True

    def request_resource(self, pid: str, rid: str) -> bool:
        with self.lock:
            if pid not in self.processes:
                self._log(f"Process {pid} doesn't exist", "ERROR")
                return False
            if rid not in self.resources:
                self._log(f"Resource {rid} doesn't exist", "ERROR")
                return False
            
            self.request_graph[pid].add(rid)
            self.processes[pid].status = f"Waiting for {rid}"
            self._log(f"Process {pid} requested {rid}")
            return True

    def allocate_resource(self, pid: str, rid: str) -> bool:
        with self.lock:
            if pid not in self.processes:
                self._log(f"Process {pid} doesn't exist", "ERROR")
                return False
            if rid not in self.resources:
                self._log(f"Resource {rid} doesn't exist", "ERROR")
                return False
            
            self.request_graph[pid].discard(rid)
            self.allocation_graph[rid].add(pid)
            self.processes[pid].status = f"Holding {rid}"
            self._log(f"Allocated {rid} to {pid}")
            return True

    def release_resource(self, pid: str, rid: str) -> bool:
        with self.lock:
            if rid in self.allocation_graph and pid in self.allocation_graph[rid]:
                self.allocation_graph[rid].remove(pid)
                self.processes[pid].status = "Ready"
                self._log(f"Process {pid} released {rid}")
                return True
            self._log(f"Process {pid} doesn't hold {rid}", "WARNING")
            return False

    def detect_deadlock(self) -> Tuple[bool, List[List[str]]]:
        with self.lock:
            wait_graph = defaultdict(set)
            
            for pid, resources in self.request_graph.items():
                for rid in resources:
                    for holder in self.allocation_graph.get(rid, set()):
                        wait_graph[pid].add(holder)
            
            cycles = self._find_cycles(wait_graph)
            if cycles:
                self._log(f"Deadlock detected! Cycles: {cycles}", "CRITICAL")
            return (bool(cycles), cycles)

    def _find_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        cycles = []
        visited = set()
        
        def _dfs(node, path):
            visited.add(node)
            path.append(node)
            
            for neighbor in graph.get(node, set()):
                if neighbor in path:
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])
                elif neighbor not in visited:
                    _dfs(neighbor, path.copy())
            
            path.pop()

        for node in graph:
            if node not in visited:
                _dfs(node, [])
        
        return cycles

    def start_monitoring(self, interval: float = 2.0):
        if not self.detection_active:
            self.detection_active = True
            self.detection_thread = threading.Thread(
                target=self._monitor_loop,
                args=(interval,),
                daemon=True
            )
            self.detection_thread.start()
            self._log(f"Started monitoring (interval: {interval}s)")

    def stop_monitoring(self):
        if self.detection_active:
            self.detection_active = False
            if self.detection_thread:
                self.detection_thread.join()
            self._log("Monitoring stopped")

    def _monitor_loop(self, interval: float):
        while self.detection_active:
            self.detect_deadlock()
            time.sleep(interval)

    def _log(self, message: str, level: str = "INFO"):
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {level}: {message}"
        self.history.append(entry)
        if len(self.history) > 100:
            self.history.pop(0)

    def save_state(self, filename: str):
        with self.lock:
            state = {
                'processes': {pid: vars(p) for pid, p in self.processes.items()},
                'resources': {rid: vars(r) for rid, r in self.resources.items()},
                'requests': {pid: list(rids) for pid, rids in self.request_graph.items()},
                'allocations': {rid: list(pids) for rid, pids in self.allocation_graph.items()},
                'history': self.history
            }
            with open(filename, 'w') as f:
                json.dump(state, f, indent=2)
            self._log(f"Saved state to {filename}")

    def load_state(self, filename: str):
        with self.lock:
            with open(filename, 'r') as f:
                state = json.load(f)
            
            self.processes = {
                pid: Process(**data) for pid, data in state['processes'].items()
            }
            self.resources = {
                rid: Resource(
                    rid=data['rid'],
                    type=ResourceType[data['type']],
                    instances=data['instances']
                ) for rid, data in state['resources'].items()
            }
            self.request_graph = defaultdict(
                set, {pid: set(rids) for pid, rids in state['requests'].items()}
            )
            self.allocation_graph = defaultdict(
                set, {rid: set(pids) for rid, pids in state['allocations'].items()}
            )
            self.history = state.get('history', [])
            self._log(f"Loaded state from {filename}")

class DeadlockDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.detector = DeadlockDetector()
        self.title("Deadlock Detection Dashboard")
        self.geometry("1200x800")
        self.configure(bg="#f0f0f0")
        
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=('Arial', 10))
        self.style.configure("TButton", font=('Arial', 10))
        self.style.configure("Header.TLabel", font=('Arial', 12, 'bold'))
        self.style.configure("Critical.TLabel", foreground="red", font=('Arial', 10, 'bold'))
        self.style.configure("Warning.TLabel", foreground="orange")
        
        self._setup_ui()
        self._create_example_scenario()
        self.detector.start_monitoring()
        self.after(100, self._update_display)

    def _setup_ui(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        left_panel = ttk.Frame(main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status Frame
        status_frame = ttk.LabelFrame(left_panel, text="System Status")
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: OK", style="Header.TLabel")
        self.status_label.pack(pady=5)
        
        self.process_count_label = ttk.Label(status_frame, text="Processes: 0")
        self.process_count_label.pack()
        
        self.resource_count_label = ttk.Label(status_frame, text="Resources: 0")
        self.resource_count_label.pack()
        
        self.deadlock_label = ttk.Label(status_frame, text="Deadlocks: 0", style="Header.TLabel")
        self.deadlock_label.pack(pady=5)
        
        # Control Buttons
        control_frame = ttk.LabelFrame(left_panel, text="Controls")
        control_frame.pack(fill=tk.X, pady=5)
        
        buttons = [
            ("Add Process", self._add_process_dialog),
            ("Add Resource", self._add_resource_dialog),
            ("Request Resource", self._request_dialog),
            ("Allocate Resource", self._allocate_dialog),
            ("Release Resource", self._release_dialog),
            ("Detect Deadlock", self._manual_detect),
            ("Toggle Monitoring", self._toggle_monitoring)
        ]
        
        for text, command in buttons:
            ttk.Button(control_frame, text=text, command=command).pack(fill=tk.X, pady=2)
        
        # File Operations
        file_frame = ttk.LabelFrame(left_panel, text="File Operations")
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(file_frame, text="Save State", command=self._save_state).pack(fill=tk.X, pady=2)
        ttk.Button(file_frame, text="Load State", command=self._load_state).pack(fill=tk.X, pady=2)
        
        # Event Log
        log_frame = ttk.LabelFrame(left_panel, text="Event Log")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        
        # Right Panel - Tables and Graph
        tables_frame = ttk.Frame(right_panel)
        tables_frame.pack(fill=tk.X, pady=5)
        
        # Process Table
        process_frame = ttk.LabelFrame(tables_frame, text="Processes")
        process_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.process_tree = ttk.Treeview(process_frame, columns=('pid', 'priority', 'status'), show='headings')
        self.process_tree.heading('pid', text='PID')
        self.process_tree.heading('priority', text='Priority')
        self.process_tree.heading('status', text='Status')
        self.process_tree.column('pid', width=80)
        self.process_tree.column('priority', width=80)
        self.process_tree.column('status', width=200)
        self.process_tree.pack(fill=tk.BOTH, expand=True)
        
        # Resource Table
        resource_frame = ttk.LabelFrame(tables_frame, text="Resources")
        resource_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        self.resource_tree = ttk.Treeview(resource_frame, columns=('rid', 'type', 'instances'), show='headings')
        self.resource_tree.heading('rid', text='Resource ID')
        self.resource_tree.heading('type', text='Type')
        self.resource_tree.heading('instances', text='Instances')
        self.resource_tree.column('rid', width=100)
        self.resource_tree.column('type', width=120)
        self.resource_tree.column('instances', width=80)
        self.resource_tree.pack(fill=tk.BOTH, expand=True)
        
        # Graph Visualization
        graph_frame = ttk.LabelFrame(right_panel, text="Resource Allocation Graph")
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.graph_canvas = tk.Canvas(graph_frame, bg='white')
        self.graph_canvas.pack(fill=tk.BOTH, expand=True)
        
        self.cycle_text = tk.Text(graph_frame, height=4, wrap=tk.WORD)
        self.cycle_text.pack(fill=tk.X)
        self.cycle_text.config(state=tk.DISABLED)

    def _create_example_scenario(self):
        self.detector.add_process("P1", 1)
        self.detector.add_process("P2", 1)
        self.detector.add_resource("R1", ResourceType.MUTEX)
        self.detector.add_resource("R2", ResourceType.MUTEX)
        self.detector.allocate_resource("P1", "R1")
        self.detector.request_resource("P1", "R2")
        self.detector.allocate_resource("P2", "R2")
        self.detector.request_resource("P2", "R1")

    def _update_display(self):
        # Update process table
        self.process_tree.delete(*self.process_tree.get_children())
        for pid, process in self.detector.processes.items():
            self.process_tree.insert('', 'end', values=(pid, process.priority, process.status))
        
        # Update resource table
        self.resource_tree.delete(*self.resource_tree.get_children())
        for rid, resource in self.detector.resources.items():
            self.resource_tree.insert('', 'end', values=(rid, str(resource.type), resource.instances))
        
        # Update status labels
        self.process_count_label.config(text=f"Processes: {len(self.detector.processes)}")
        self.resource_count_label.config(text=f"Resources: {len(self.detector.resources)}")
        
        # Check for deadlocks
        deadlock, cycles = self.detector.detect_deadlock()
        if deadlock:
            self.status_label.config(text="Status: DEADLOCK DETECTED!", style="Critical.TLabel")
            self.deadlock_label.config(text=f"Deadlocks: {len(cycles)}", style="Critical.TLabel")
            
            # Display cycles
            self.cycle_text.config(state=tk.NORMAL)
            self.cycle_text.delete(1.0, tk.END)
            for i, cycle in enumerate(cycles, 1):
                self.cycle_text.insert(tk.END, f"Cycle {i}: {' → '.join(cycle)}\n")
            self.cycle_text.config(state=tk.DISABLED)
        else:
            self.status_label.config(text="Status: OK", style="TLabel")
            self.deadlock_label.config(text="Deadlocks: 0")
            self.cycle_text.config(state=tk.NORMAL)
            self.cycle_text.delete(1.0, tk.END)
            self.cycle_text.insert(tk.END, "No deadlocks detected")
            self.cycle_text.config(state=tk.DISABLED)
        
        # Update graph visualization
        self._draw_graph()
        
        # Update event log
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        for entry in self.detector.history[-10:]:
            if "CRITICAL" in entry:
                self.log_text.insert(tk.END, entry + "\n", "critical")
            elif "ERROR" in entry:
                self.log_text.insert(tk.END, entry + "\n", "error")
            elif "WARNING" in entry:
                self.log_text.insert(tk.END, entry + "\n", "warning")
            else:
                self.log_text.insert(tk.END, entry + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
        
        # Schedule next update
        self.after(500, self._update_display)

    def _draw_graph(self):
        self.graph_canvas.delete("all")
        width = self.graph_canvas.winfo_width()
        height = self.graph_canvas.winfo_height()
        
        if width < 10 or height < 10:
            return
        
        # Calculate positions
        process_nodes = list(self.detector.processes.keys())
        resource_nodes = list(self.detector.resources.keys())
        all_nodes = process_nodes + resource_nodes
        node_count = len(all_nodes)
        
        if node_count == 0:
            return
        
        # Draw nodes
        node_positions = {}
        radius = 30
        padding = 50
        
        # Process nodes on left
        for i, pid in enumerate(process_nodes):
            x = padding
            y = padding + i * (height - 2 * padding) / max(1, len(process_nodes) - 1)
            node_positions[pid] = (x, y)
            self.graph_canvas.create_oval(
                x - radius, y - radius, x + radius, y + radius,
                fill="lightblue", outline="black"
            )
            self.graph_canvas.create_text(x, y, text=pid)
        
        # Resource nodes on right
        for i, rid in enumerate(resource_nodes):
            x = width - padding
            y = padding + i * (height - 2 * padding) / max(1, len(resource_nodes) - 1)
            node_positions[rid] = (x, y)
            self.graph_canvas.create_rectangle(
                x - radius, y - radius, x + radius, y + radius,
                fill="lightgreen", outline="black"
            )
            self.graph_canvas.create_text(x, y, text=rid)
        
        # Draw request edges (process → resource)
        for pid, resources in self.detector.request_graph.items():
            if pid not in node_positions:
                continue
            x1, y1 = node_positions[pid]
            for rid in resources:
                if rid in node_positions:
                    x2, y2 = node_positions[rid]
                    self.graph_canvas.create_line(
                        x1 + radius, y1, x2 - radius, y2,
                        arrow=tk.LAST, fill="red", width=2
                    )
        
        # Draw allocation edges (resource → process)
        for rid, processes in self.detector.allocation_graph.items():
            if rid not in node_positions:
                continue
            x1, y1 = node_positions[rid]
            for pid in processes:
                if pid in node_positions:
                    x2, y2 = node_positions[pid]
                    self.graph_canvas.create_line(
                        x1 - radius, y1, x2 + radius, y2,
                        arrow=tk.LAST, fill="blue", width=2
                    )

    def _add_process_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add Process")
        dialog.grab_set()
        
        ttk.Label(dialog, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
        pid_entry = ttk.Entry(dialog)
        pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Priority (0-9):").grid(row=1, column=0, padx=5, pady=5)
        priority_entry = ttk.Entry(dialog)
        priority_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def on_ok():
            pid = pid_entry.get().strip()
            priority = priority_entry.get().strip()
            if not pid:
                messagebox.showerror("Error", "Process ID cannot be empty")
                return
            
            try:
                priority = int(priority) if priority else 0
                if not (0 <= priority <= 9):
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Priority must be between 0 and 9")
                return
            
            if self.detector.add_process(pid, priority):
                dialog.destroy()
        
        ttk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=1, sticky=tk.E, padx=5, pady=5)
        pid_entry.focus_set()

    def _add_resource_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add Resource")
        dialog.grab_set()
        
        ttk.Label(dialog, text="Resource ID:").grid(row=0, column=0, padx=5, pady=5)
        rid_entry = ttk.Entry(dialog)
        rid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Type:").grid(row=1, column=0, padx=5, pady=5)
        type_var = tk.StringVar()
        type_combobox = ttk.Combobox(dialog, textvariable=type_var, state="readonly")
        type_combobox['values'] = [str(t) for t in ResourceType]
        type_combobox.grid(row=1, column=1, padx=5, pady=5)
        type_combobox.current(0)
        
        ttk.Label(dialog, text="Instances:").grid(row=2, column=0, padx=5, pady=5)
        instances_entry = ttk.Entry(dialog)
        instances_entry.insert(0, "1")
        instances_entry.grid(row=2, column=1, padx=5, pady=5)
        
        def on_ok():
            rid = rid_entry.get().strip()
            if not rid:
                messagebox.showerror("Error", "Resource ID cannot be empty")
                return
            
            try:
                instances = int(instances_entry.get())
                if instances < 1:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Instances must be a positive integer")
                return
            
            try:
                rtype = ResourceType[type_var.get().replace(' ', '_').upper()]
            except KeyError:
                messagebox.showerror("Error", "Invalid resource type")
                return
            
            if self.detector.add_resource(rid, rtype, instances):
                dialog.destroy()
        
        ttk.Button(dialog, text="OK", command=on_ok).grid(row=3, column=1, sticky=tk.E, padx=5, pady=5)
        rid_entry.focus_set()

    def _request_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Request Resource")
        dialog.grab_set()
        
        ttk.Label(dialog, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
        pid_entry = ttk.Entry(dialog)
        pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Resource ID:").grid(row=1, column=0, padx=5, pady=5)
        rid_entry = ttk.Entry(dialog)
        rid_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def on_ok():
            pid = pid_entry.get().strip()
            rid = rid_entry.get().strip()
            if not pid or not rid:
                messagebox.showerror("Error", "Both fields are required")
                return
            
            if self.detector.request_resource(pid, rid):
                dialog.destroy()
        
        ttk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=1, sticky=tk.E, padx=5, pady=5)
        pid_entry.focus_set()

    def _allocate_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Allocate Resource")
        dialog.grab_set()
        
        ttk.Label(dialog, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
        pid_entry = ttk.Entry(dialog)
        pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Resource ID:").grid(row=1, column=0, padx=5, pady=5)
        rid_entry = ttk.Entry(dialog)
        rid_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def on_ok():
            pid = pid_entry.get().strip()
            rid = rid_entry.get().strip()
            if not pid or not rid:
                messagebox.showerror("Error", "Both fields are required")
                return
            
            if self.detector.allocate_resource(pid, rid):
                dialog.destroy()
        
        ttk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=1, sticky=tk.E, padx=5, pady=5)
        pid_entry.focus_set()

    def _release_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Release Resource")
        dialog.grab_set()
        
        ttk.Label(dialog, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
        pid_entry = ttk.Entry(dialog)
        pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Resource ID:").grid(row=1, column=0, padx=5, pady=5)
        rid_entry = ttk.Entry(dialog)
        rid_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def on_ok():
            pid = pid_entry.get().strip()
            rid = rid_entry.get().strip()
            if not pid or not rid:
                messagebox.showerror("Error", "Both fields are required")
                return
            
            if self.detector.release_resource(pid, rid):
                dialog.destroy()
        
        ttk.Button(dialog, text="OK", command=on_ok).grid(row=2, column=1, sticky=tk.E, padx=5, pady=5)
        pid_entry.focus_set()

    def _manual_detect(self):
        deadlock, cycles = self.detector.detect_deadlock()
        if deadlock:
            cycle_text = "\n".join(f"Cycle {i}: {' → '.join(cycle)}" 
                                for i, cycle in enumerate(cycles, 1))
            messagebox.showwarning(
                "Deadlock Detected",
                f"Found {len(cycles)} deadlock cycle(s):\n\n{cycle_text}"
            )
        else:
            messagebox.showinfo("No Deadlock", "No deadlocks detected in the system")

    def _toggle_monitoring(self):
        if self.detector.detection_active:
            self.detector.stop_monitoring()
            messagebox.showinfo("Monitoring", "Deadlock monitoring stopped")
        else:
            dialog = tk.Toplevel(self)
            dialog.title("Set Monitoring Interval")
            dialog.grab_set()
            
            ttk.Label(dialog, text="Scan interval (seconds):").grid(row=0, column=0, padx=5, pady=5)
            interval_entry = ttk.Entry(dialog)
            interval_entry.insert(0, "2.0")
            interval_entry.grid(row=0, column=1, padx=5, pady=5)
            
            def on_ok():
                try:
                    interval = float(interval_entry.get())
                    if interval <= 0:
                        raise ValueError
                    self.detector.start_monitoring(interval)
                    dialog.destroy()
                    messagebox.showinfo("Monitoring", f"Deadlock monitoring started (interval: {interval}s)")
                except ValueError:
                    messagebox.showerror("Error", "Please enter a positive number")
            
            ttk.Button(dialog, text="OK", command=on_ok).grid(row=1, column=1, sticky=tk.E, padx=5, pady=5)
            interval_entry.focus_set()

    def _save_state(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.detector.save_state(filename)

    def _load_state(self):
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.detector.load_state(filename)

if __name__ == "__main__":
    app = DeadlockDashboard()
    app.mainloop()
