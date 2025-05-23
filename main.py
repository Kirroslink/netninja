# -------------------------
# NetNinja - Upgraded All-in-One Version
# -------------------------


import customtkinter as ctk
import psutil
import subprocess
import socket
import json
import ctypes, sys
from datetime import datetime
from tkinter import filedialog

__version__ = "1.1.0"

# ----- Admin Elevation -----
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    sys.exit()

# ----- Adapter and IP Functions -----
def get_adapters():
    return [nic for nic in psutil.net_if_addrs().keys() if not nic.startswith("Loopback")] or ["No Adapters Found"]

def get_network_details(adapter):
    details = {"ip": "N/A", "subnet": "N/A", "gateway": "N/A"}
    addrs = psutil.net_if_addrs().get(adapter, [])
    for addr in addrs:
        if addr.family.name == "AF_INET":
            details["ip"] = addr.address
            details["subnet"] = addr.netmask
    try:
        route_output = subprocess.check_output("ipconfig", text=True)
        for block in route_output.split("\n\n"):
            if adapter in block:
                for line in block.splitlines():
                    if "Default Gateway" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            details["gateway"] = parts[1].strip()
    except:
        pass
    return details

# ----- Presets Storage -----
presets = {
    "Recon": {"ip": "192.168.12.10", "subnet": "255.255.255.0"},
    "Work Network": {"ip": "192.168.10.100", "subnet": "255.255.255.0", "gateway": "192.168.10.1"}
}

def get_presets():
    return presets

# ----- IP Configuration -----
def set_ip_config(adapter, ip, subnet, gateway):
    try:
        subprocess.run(["netsh", "interface", "ip", "set", "address", adapter,
                        "static", ip, subnet, gateway], capture_output=True, text=True)
        return f"IP configuration set for {adapter}"
    except Exception as e:
        return f"Failed to set IP: {e}"

def set_dhcp_config(adapter):
    try:
        subprocess.run(["netsh", "interface", "ip", "set", "address", adapter, "dhcp"], capture_output=True, text=True)
        return f"DHCP enabled for {adapter}"
    except Exception as e:
        return f"Failed to set DHCP: {e}"

# ----- Ping Tool -----
def ping_address(target):
    try:
        result = subprocess.run(["ping", "-n", "4", target], capture_output=True, text=True, timeout=5)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"

# ----- Execute Terminal Command -----
def run_terminal_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout or result.stderr
    except Exception as e:
        return str(e)
    
ctk.set_appearance_mode("Dark")  # Options: "Light", "Dark", "System"
ctk.set_default_color_theme("dark-blue")  # Options: "blue", "dark-blue", "green"

# ----- UI Class -----
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"NetNinja - v{__version__}")
        self.geometry("950x550")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.setup_ui()

    def setup_ui(self):
        # === Scrollable Sidebar ===
        self.left_frame = ctk.CTkScrollableFrame(self, width=250, label_text="Tools")
        self.left_frame.grid(row=0, column=0, rowspan=3, sticky="nsw", padx=2, pady=2)

        ctk.CTkLabel(self.left_frame, text="Select Adapter").pack(pady=(10,0))
        self.adapter_menu = ctk.CTkOptionMenu(self.left_frame, values=get_adapters(), command=self.update_network_info)
        self.adapter_menu.pack(pady=5)

        self.ip_label = ctk.CTkLabel(self.left_frame, text="IP: N/A")
        self.ip_label.pack()
        self.subnet_label = ctk.CTkLabel(self.left_frame, text="Subnet: N/A")
        self.subnet_label.pack()
        self.gateway_label = ctk.CTkLabel(self.left_frame, text="Gateway: N/A")
        self.gateway_label.pack()

#        self.scan_limit_entry = ctk.CTkEntry(self.left_frame, placeholder_text="Scan limit")
#        self.scan_limit_entry.pack(pady=5)

        self.scan_button = ctk.CTkButton(self.left_frame, text="Scan Network", command=self.start_network_scan)
        self.scan_button.pack(pady=(10, 5))

        ctk.CTkLabel(self.left_frame, text="Choose Preset").pack(pady=(10,0))
        self.preset_menu = ctk.CTkOptionMenu(self.left_frame, values=list(get_presets().keys()), command=self.load_preset)
        self.preset_menu.pack(pady=5)

        self.ip_entry = ctk.CTkEntry(self.left_frame, placeholder_text="IP Address")
        self.ip_entry.pack(pady=5)
        self.subnet_entry = ctk.CTkEntry(self.left_frame, placeholder_text="Subnet Mask")
        self.subnet_entry.pack(pady=5)
        self.gateway_entry = ctk.CTkEntry(self.left_frame, placeholder_text="Gateway")
        self.gateway_entry.pack(pady=5)

        self.set_ip_button = ctk.CTkButton(self.left_frame, text="Set IP", command=self.set_ip)
        self.set_ip_button.pack(pady=10)

        self.set_dhcp_button = ctk.CTkButton(self.left_frame, text="Set DHCP", command=self.set_dhcp)
        self.set_dhcp_button.pack(pady=5)

        self.preset_name_entry = ctk.CTkEntry(self.left_frame, placeholder_text="New Preset Name (or leave blank)")
        self.preset_name_entry.pack(pady=(10,5))
        self.save_preset_button = ctk.CTkButton(self.left_frame, text="Save Preset", command=self.save_preset)
        self.save_preset_button.pack()

        self.ping_entry = ctk.CTkEntry(self.left_frame, placeholder_text="Ping IP or Host")
        self.ping_entry.pack(pady=(20,5))
        self.ping_button = ctk.CTkButton(self.left_frame, text="Ping", command=self.run_ping)
        self.ping_button.pack()

        self.export_button = ctk.CTkButton(self.left_frame, text="⭳ Export Logs", command=self.export_logs)
        self.export_button.pack(pady=(5, 15))

        self.refresh_button = ctk.CTkButton(self.left_frame, text="↻ Refresh Network Info", command=self.refresh_network_info)
        self.refresh_button.pack(pady=5)

        # === Terminal UI ===
        self.terminal_output = ctk.CTkTextbox(self)
        self.terminal_output.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.terminal_output.insert("end", f"NetNinja v{__version__} Ready\n")

        self.terminal_input = ctk.CTkEntry(self, placeholder_text="Enter command here...")
        self.terminal_input.grid(row=1, column=1, sticky="ew", padx=10, pady=(0,10))
        self.terminal_input.bind("<Return>", self.run_terminal_command)

        self.clear_terminal_button = ctk.CTkButton(self, text="🧹 Clear Terminal", command=self.clear_terminal)
        self.clear_terminal_button.grid(row=2, column=1, sticky="e", padx=10, pady=(0, 10))


    def clear_terminal(self):
        self.terminal_output.delete("1.0", "end")

    def start_network_scan(self):
        adapter = self.adapter_menu.get()
        info = get_network_details(adapter)
        base_ip = ".".join(info["ip"].split(".")[:4])
        threading.Thread(target=scan_network, args=(base_ip, self.terminal_output), daemon=True).start()


    def refresh_network_info(self):
        adapters = get_adapters()
        self.adapter_menu.configure(values=adapters)
        if adapters:
            self.adapter_menu.set(adapters[1])
            self.update_network_info(adapters[1])
        else:
            self.update_network_info("")

    def update_network_info(self, adapter=None):
        adapter = adapter or self.adapter_menu.get()
        info = get_network_details(adapter)
        self.ip_label.configure(text=f"IP: {info['ip']}")
        self.subnet_label.configure(text=f"Subnet: {info['subnet']}")
        self.gateway_label.configure(text=f"Gateway: {info['gateway']}")

    def load_preset(self, preset_name):
        preset = get_presets().get(preset_name, {})
        self.ip_entry.delete(0, 'end')
        self.subnet_entry.delete(0, 'end')
        self.gateway_entry.delete(0, 'end')
        self.ip_entry.insert(0, preset.get('ip', ''))
        self.subnet_entry.insert(0, preset.get('subnet', ''))
        self.gateway_entry.insert(0, preset.get('gateway', ''))

    def set_ip(self):
        adapter = self.adapter_menu.get()
        ip = self.ip_entry.get()
        subnet = self.subnet_entry.get()
        gateway = self.gateway_entry.get()
        result = set_ip_config(adapter, ip, subnet, gateway)
        self.terminal_output.insert("end", result + "\n")
        self.update_network_info(adapter)

    def set_dhcp(self):
        adapter = self.adapter_menu.get()
        result = set_dhcp_config(adapter)
        self.terminal_output.insert("end", result + "\n")
        self.update_network_info(adapter)

    def save_preset(self):
        name = self.preset_name_entry.get().strip()
        if not name:
            name = datetime.now().strftime("Preset %Y-%m-%d %H-%M-%S")
        presets[name] = {
            "ip": self.ip_entry.get(),
            "subnet": self.subnet_entry.get(),
            "gateway": self.gateway_entry.get()
        }
        self.preset_menu.configure(values=list(presets.keys()))
        self.preset_menu.set(name)
        self.terminal_output.insert("end", f"Saved new preset: {name}\n")

    def run_ping(self):
        target = self.ping_entry.get()
        result = ping_address(target)
        self.terminal_output.insert("end", result + "\n")

    def run_terminal_command(self, event=None):
        cmd = self.terminal_input.get()
        self.terminal_input.delete(0, 'end')
        output = run_terminal_command(cmd)
        self.terminal_output.insert("end", f"> {cmd}\n{output}\n")

    def export_logs(self):
        log_text = self.terminal_output.get("1.0", "end").strip()
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(log_text)

import threading
import ipaddress
import time

def scan_ip(ip, results_box):
    try:
        socket.setdefaulttimeout(0.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, 80))  # Scan port 80 (HTTP)
        if result == 0:
            results_box.insert("end", f"[+] {ip} is active\n")
        s.close()
    except Exception as e:
        pass  # Silently ignore

def scan_network(base_ip, results_box, limit = 200):
    try:
        ip_net = ipaddress.IPv4Network(base_ip + "/24", strict=False)
        results_box.insert("end", f"Starting scan on {base_ip}...\n")
        count = 0
        for ip in ip_net.hosts():
            if count >= limit:
                results_box.insert("end", f"Scan limit ({limit}) reached. Stopping scan.\n")
                break
            threading.Thread(target=scan_ip, args=(str(ip), results_box), daemon=True).start()
            time.sleep(0.1)  # throttle slightly to avoid crash
            count += 1
    except Exception as e:
        results_box.insert("end", f"Scan Error: {e}\n")

# ----- Main Entry Point -----
if __name__ == "__main__":
    app = App()
    app.mainloop()
