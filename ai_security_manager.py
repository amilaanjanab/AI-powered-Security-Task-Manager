import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, Menu
import psutil
import google.generativeai as genai
import threading
import os
import sys
import json
import subprocess

# Configuration File Path
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

class AISecurityManager:
    def __init__(self, root):
        self.root = root
        self.root.title("AI-Powered Security Task Manager")
        self.root.geometry("1100x750")
        
        # Configure a modern style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("Treeview", rowheight=25, font=('Calibri', 10))
        self.style.configure("Treeview.Heading", font=('Calibri', 11, 'bold'))
        
        # Internal State
        self.api_key = None
        self.model = None
        self.api_initialized = False

        # Try to load API key quietly on startup
        self.load_stored_key()
        if self.api_key:
            self.setup_ai(self.api_key, quiet=True)

        # --- UI Layout ---
        
        # Top Frame: Toolbar
        toolbar = ttk.Frame(root, padding=10)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        
        # Main Toolbar Buttons
        ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_processes).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🤖 Analyze", command=self.start_analysis_thread).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="📂 Open Location", command=self.open_current_location).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="💀 Kill Process", command=self.kill_current_process).pack(side=tk.LEFT, padx=2)
        
        # Separator
        ttk.Frame(toolbar, width=20).pack(side=tk.LEFT)
        
        # Batch Scan
        self.btn_scan = ttk.Button(toolbar, text="🔍 Full System Scan", command=self.start_batch_scan_thread)
        self.btn_scan.pack(side=tk.LEFT, padx=2)

        # Separator
        ttk.Frame(toolbar, width=20).pack(side=tk.LEFT)

        # API Key Button
        self.btn_key = ttk.Button(toolbar, text="🔑 Set API Key", command=self.ask_api_key)
        self.btn_key.pack(side=tk.RIGHT, padx=5)

        # Middle Frame: Process List (Treeview)
        tree_frame = ttk.Frame(root, padding=10)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("pid", "name", "status", "path")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        
        # Define Headings
        self.tree.heading("pid", text="PID", command=lambda: self.sort_tree("pid", False))
        self.tree.heading("name", text="Process Name", command=lambda: self.sort_tree("name", False))
        self.tree.heading("status", text="Status", command=lambda: self.sort_tree("status", False))
        self.tree.heading("path", text="Executable Path", command=lambda: self.sort_tree("path", False))
        
        # Define Columns
        self.tree.column("pid", width=60, anchor="center")
        self.tree.column("name", width=150)
        self.tree.column("status", width=100)
        self.tree.column("path", width=450)
        
        # Scrollbar for Treeview
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bindings
        self.tree.bind("<Button-3>", self.show_context_menu) # Right-click menu

        # Bottom Frame: AI Insight
        insight_frame = ttk.LabelFrame(root, text="AI Security Insight", padding=10)
        insight_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.txt_insight = scrolledtext.ScrolledText(insight_frame, height=8, font=('Consolas', 10), state='disabled')
        self.txt_insight.pack(fill=tk.BOTH, expand=True)

        # Initial Load
        self.refresh_processes()

    # --- Configuration & Key Management ---

    def load_stored_key(self):
        """ Loads API Key from local .env file if it exists. """
        # First check actual environment variable
        env_key = os.getenv('GEMINI_API_KEY')
        if env_key:
            self.api_key = env_key
            return

        # Then check local .env file
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    for line in f:
                        if line.startswith("GEMINI_API_KEY="):
                            key = line.strip().split("=", 1)[1]
                            if key and key != "YOUR_API_KEY_HERE":
                                self.api_key = key
                                return
            except Exception:
                pass

    def save_stored_key(self, key):
        """ Saves API Key to local .env file. """
        try:
            with open(CONFIG_FILE, "w") as f:
                f.write(f"GEMINI_API_KEY={key}\n")
            self.api_key = key
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save API Key: {e}")

    def ask_api_key(self):
        """ Prompts the user to enter their API key. """
        key = simpledialog.askstring("API Key Required", "Please enter your Google Gemini API Key:\n(It will be saved locally in .env)")
        if key:
            self.save_stored_key(key)
            self.setup_ai(key)

    def ensure_ai_ready(self):
        """ Checks if AI is initialized. If not, prompts user for key. Returns True if ready. """
        if self.api_initialized:
            return True
        
        # Not initialized, prompt user
        response = messagebox.askyesno("AI Features", "This feature requires a Gemini API Key.\nWould you like to enter it now?")
        if response:
            self.ask_api_key()
            return self.api_initialized
        return False

    def setup_ai(self, key, quiet=False):
        """ Configures the Gemini API with the provided key. """
        try:
            genai.configure(api_key=key)
            # Find supported model
            available_models = []
            try:
                # Some environments fail listing models without valid key immediately
                for m in genai.list_models():
                    if 'generateContent' in m.supported_generation_methods:
                        available_models.append(m.name)
            except Exception:
                 if not quiet: messagebox.showerror("Error", "Invalid API Key or Network Error.")
                 return

            preferred_models = ['models/gemini-1.5-flash', 'models/gemini-pro', 'models/gemini-1.5-pro-latest']
            selected_model = next((m for m in preferred_models if m in available_models), available_models[0] if available_models else None)
            
            if selected_model:
                model_name = selected_model.replace('models/', '') if selected_model.startswith('models/') else selected_model
                self.model = genai.GenerativeModel(model_name)
                self.api_initialized = True
                if not quiet:
                    messagebox.showinfo("Success", f"AI Initialized successfully using model: {model_name}")
                print(f"AI Initialized: {model_name}")
            else:
                if not quiet:
                    messagebox.showerror("AI Error", "No suitable Gemini models found for your API key.")
        except Exception as e:
            if not quiet:
                messagebox.showerror("AI Error", f"Failed to configure AI: {e}")

    # --- UI Helpers ---

    def sort_tree(self, col, reverse):
        """ Sorts the treeview by column. """
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try:
            l.sort(key=lambda t: int(t[0]), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)

        self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = Menu(self.root, tearoff=0)
            menu.add_command(label="Analyze with AI", command=self.start_analysis_thread)
            menu.add_command(label="Open File Location", command=self.open_current_location)
            menu.add_separator()
            menu.add_command(label="End Process", command=self.kill_current_process)
            menu.post(event.x_root, event.y_root)

    # --- Core Functionality ---

    def refresh_processes(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            for proc in psutil.process_iter(['pid', 'name', 'status', 'exe']):
                try:
                    p_info = proc.as_dict(attrs=['pid', 'name', 'status', 'exe'], ad_value=None)
                    path = p_info['exe'] if p_info['exe'] else "N/A (Access Denied)"
                    self.tree.insert("", tk.END, values=(p_info['pid'], p_info['name'], p_info['status'], path))
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list processes: {e}")

    def get_selected_process_info(self, tree_widget=None):
        target_tree = tree_widget if tree_widget else self.tree
        selected = target_tree.selection()
        if not selected:
            return None, None, None
        item = target_tree.item(selected[0])
        return item['values'][0], item['values'][1], item['values'][3]

    def open_location(self, path):
        if not path or path == "N/A (Access Denied)" or not os.path.exists(path):
            messagebox.showerror("Error", f"Cannot open location. Path is invalid or inaccessible:\n{path}")
            return
        try:
            subprocess.run(['explorer', '/select,', os.path.normpath(path)])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open location: {e}")

    def open_current_location(self):
        _, _, path = self.get_selected_process_info()
        if path:
            self.open_location(path)
        else:
            messagebox.showinfo("Select Process", "Please select a process.")

    def kill_process_by_pid(self, pid, name):
        confirm = messagebox.askyesno("Confirm Kill", f"Are you sure you want to terminate '{name}' (PID: {pid})?")
        if confirm:
            try:
                proc = psutil.Process(int(pid))
                proc.terminate()
                return True
            except Exception as e:
                messagebox.showerror("Error", f"Could not kill process: {e}")
                return False
        return False

    def kill_current_process(self):
        pid, name, _ = self.get_selected_process_info()
        if pid:
            if self.kill_process_by_pid(pid, name):
                self.root.after(500, self.refresh_processes)
                messagebox.showinfo("Success", f"Process {name} terminated.")
        else:
            messagebox.showinfo("Select Process", "Please select a process.")

    # --- AI Analysis ---

    def start_analysis_thread(self):
        if not self.ensure_ai_ready():
            return
            
        pid, name, path = self.get_selected_process_info()
        if not name:
            messagebox.showinfo("Select Process", "Please select a process to analyze.")
            return
        
        self.update_insight_text(f"⏳ Analyzing '{name}'... please wait...")
        threading.Thread(target=self.run_analysis, args=(name, path), daemon=True).start()

    def run_analysis(self, name, path):
        try:
            prompt = (
                f"Analyze process: '{name}' from path: '{path}'. "
                "Context: Windows OS. "
                "1. Security Verdict: Safe, Suspicious, or Malware? "
                "2. Function: What does it do? "
                "3. Path Check: Is '{path}' normal for this process? "
                "Provide a short, clear summary."
            )
            response = self.model.generate_content(prompt)
            self.root.after(0, lambda: self.update_insight_text(response.text))
        except Exception as e:
            self.root.after(0, lambda: self.update_insight_text(f"AI Analysis Failed: {str(e)}"))

    def update_insight_text(self, text):
        self.txt_insight.config(state='normal')
        self.txt_insight.delete(1.0, tk.END)
        self.txt_insight.insert(tk.END, text)
        self.txt_insight.config(state='disabled')

    # --- Batch Scan & Results Window ---

    def start_batch_scan_thread(self):
        if not self.ensure_ai_ready():
            return

        self.update_insight_text("⏳ Gathering system processes for batch security scan...")
        processes = []
        for item in self.tree.get_children():
            vals = self.tree.item(item)['values']
            processes.append(f"{vals[0]},{vals[1]},{vals[3]}") 
            
        if not processes:
            self.update_insight_text("No processes found.")
            return

        self.update_insight_text(f"⏳ Sending {len(processes)} processes to Gemini for threat analysis...\nThis may take a moment.")
        threading.Thread(target=self.run_batch_scan, args=(processes,), daemon=True).start()

    def run_batch_scan(self, process_list):
        try:
            csv_data = "\n".join(process_list)
            prompt = (
                "Act as a cybersecurity expert. Analyze this list of Windows processes (PID, Name, Path). "
                "Identify any that are SUSPICIOUS (e.g., malware names, running from Temp/AppData/Downloads, mimicking system files). "
                "Ignore standard System32 paths unless the name is obviously wrong. "
                "\n\n"
                f"{csv_data}"
                "\n\n"
                "Return ONLY a JSON list of objects. Each object: "
                "{'pid': <int>, 'name': <str>, 'path': <str>, 'reason': <str>}. "
                "If path was missing in input, use 'N/A'. "
                "If no threats, return []. "
                "No markdown."
            )

            response = self.model.generate_content(prompt)
            text_response = response.text.strip().replace("```json", "").replace("```", "")
            
            try:
                suspicious_data = json.loads(text_response)
                self.root.after(0, lambda: self.show_suspicious_window(suspicious_data))
                self.root.after(0, lambda: self.update_insight_text("✅ Scan Complete. Check the results window."))
            except json.JSONDecodeError:
                 self.root.after(0, lambda: self.update_insight_text(f"⚠️ Scan Complete, but failed to parse JSON.\nRaw Output:\n{text_response}"))

        except Exception as e:
            self.root.after(0, lambda: self.update_insight_text(f"❌ Batch Scan Failed: {str(e)}"))

    def show_suspicious_window(self, data):
        if not data:
            messagebox.showinfo("Scan Complete", "No suspicious processes identified! 🎉")
            return

        win = tk.Toplevel(self.root)
        win.title(f"⚠️ Suspicious Processes Detected ({len(data)})")
        win.geometry("900x600")
        
        lbl = ttk.Label(win, text="Select a process below to see details and take action:", font=("Helvetica", 10))
        lbl.pack(pady=(10, 5))

        cols = ("pid", "name", "path") 
        tree = ttk.Treeview(win, columns=cols, show="headings", height=8)
        
        tree.heading("pid", text="PID")
        tree.heading("name", text="Process Name")
        tree.heading("path", text="Path")
        
        tree.column("pid", width=60, anchor="center")
        tree.column("name", width=150)
        tree.column("path", width=350)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10)

        data_map = {} 
        for item in data:
            pid = item.get('pid')
            data_map[str(pid)] = item
            tree.insert("", tk.END, values=(pid, item.get('name'), item.get('path')))

        reason_frame = ttk.LabelFrame(win, text="Reason for Suspicion", padding=10)
        reason_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        txt_reason = scrolledtext.ScrolledText(reason_frame, height=5, font=('Consolas', 10), state='disabled', wrap=tk.WORD)
        txt_reason.pack(fill=tk.BOTH, expand=True)

        def on_select(event):
            selected = tree.selection()
            if selected:
                item_vals = tree.item(selected[0])['values']
                pid_sel = str(item_vals[0])
                if pid_sel in data_map:
                    reason = data_map[pid_sel].get('reason', 'No reason provided.')
                    txt_reason.config(state='normal')
                    txt_reason.delete(1.0, tk.END)
                    txt_reason.insert(tk.END, reason)
                    txt_reason.config(state='disabled')

        tree.bind("<<TreeviewSelect>>", on_select)

        btn_frame = ttk.Frame(win, padding=10)
        btn_frame.pack(fill=tk.X, side=tk.BOTTOM)

        def kill_selected():
            selected = tree.selection()
            if selected:
                vals = tree.item(selected[0])['values']
                pid = vals[0]
                name = vals[1]
                if self.kill_process_by_pid(pid, name):
                    tree.delete(selected[0])
                    txt_reason.config(state='normal')
                    txt_reason.delete(1.0, tk.END)
                    txt_reason.config(state='disabled')
                    self.refresh_processes() 
            else:
                messagebox.showinfo("Select", "Please select a process from the list above.")

        def open_selected_loc():
            selected = tree.selection()
            if selected:
                vals = tree.item(selected[0])['values']
                path = vals[2]
                self.open_location(path)
            else:
                messagebox.showinfo("Select", "Please select a process from the list above.")

        def analyze_selected_suspicious():
            selected = tree.selection()
            if selected:
                vals = tree.item(selected[0])['values']
                name = vals[1]
                path = vals[2]
                
                txt_reason.config(state='normal')
                txt_reason.delete(1.0, tk.END)
                txt_reason.insert(tk.END, f"⏳ Performing deep analysis on '{name}'...\nLocation: {path}\nPLEASE WAIT...")
                txt_reason.config(state='disabled')
                
                threading.Thread(target=run_deep_analysis, args=(name, path), daemon=True).start()
            else:
                messagebox.showinfo("Select", "Please select a process from the list above.")

        def run_deep_analysis(name, path):
            try:
                prompt = (
                    f"Deep Security Analysis for process: '{name}'\n"
                    f"Executable Path: '{path}'\n"
                    "Context: Windows OS Security Check.\n\n"
                    "1. VERDICT: Is this specific path valid for this process name? (e.g. svchost.exe should NOT be in AppData)\n"
                    "2. RISK LEVEL: Safe, Suspicious, or Critical Malware?\n"
                    "3. DETAILS: What is the software? If unknown/random name, say so.\n"
                    "Provide a detailed but concise security report."
                )
                response = self.model.generate_content(prompt)
                result_text = response.text
                
                def update_ui():
                    txt_reason.config(state='normal')
                    txt_reason.delete(1.0, tk.END)
                    txt_reason.insert(tk.END, result_text)
                    txt_reason.config(state='disabled')
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                def show_error():
                    txt_reason.config(state='normal')
                    txt_reason.delete(1.0, tk.END)
                    txt_reason.insert(tk.END, f"Analysis Error: {str(e)}")
                    txt_reason.config(state='disabled')
                self.root.after(0, show_error)

        ttk.Button(btn_frame, text="🤖 Analyze Deeper", command=analyze_selected_suspicious).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame, text="💀 End Process", command=kill_selected).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame, text="📂 Open File Location", command=open_selected_loc).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(btn_frame, text="Close Window", command=win.destroy).pack(side=tk.RIGHT, padx=5)

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("Error: 'psutil' library is missing. Please install it using 'pip install psutil'")
        sys.exit(1)

    root = tk.Tk()
    app = AISecurityManager(root)
    root.mainloop()