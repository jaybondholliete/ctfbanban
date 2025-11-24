import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import re
from collections import defaultdict
from datetime import datetime
import json

class OSINTAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Zairee")
        self.root.geometry("1200x800")
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Zairee", 
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Input Tab
        self.create_input_tab()
        
        # Analysis Tabs
        self.create_ip_analysis_tab()
        self.create_user_analysis_tab()
        self.create_security_tab()
        self.create_timeline_tab()
        self.create_network_tab()
        self.create_export_tab()
        
        # Data storage
        self.analysis_data = {}
        
    def create_input_tab(self):
        input_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(input_frame, text="Input Data")
        
        # Configure grid
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(2, weight=1)
        
        # Buttons frame
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=0, column=0, pady=5, sticky=tk.W)
        
        ttk.Button(btn_frame, text="Load File", command=self.load_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_input).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Analyze", command=self.analyze_data).pack(side=tk.LEFT, padx=5)
        
        # Instructions
        inst_label = ttk.Label(input_frame, text="Paste or load target data (logs, text, etc.):")
        inst_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # Text input
        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=25)
        self.input_text.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
    def create_ip_analysis_tab(self):
        ip_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(ip_frame, text="IP Analysis")
        
        ip_frame.columnconfigure(0, weight=1)
        ip_frame.rowconfigure(0, weight=1)
        
        self.ip_text = scrolledtext.ScrolledText(ip_frame, wrap=tk.WORD)
        self.ip_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def create_user_analysis_tab(self):
        user_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(user_frame, text="Users & Accounts")
        
        user_frame.columnconfigure(0, weight=1)
        user_frame.rowconfigure(0, weight=1)
        
        self.user_text = scrolledtext.ScrolledText(user_frame, wrap=tk.WORD)
        self.user_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def create_security_tab(self):
        sec_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(sec_frame, text="Security Events")
        
        sec_frame.columnconfigure(0, weight=1)
        sec_frame.rowconfigure(0, weight=1)
        
        self.security_text = scrolledtext.ScrolledText(sec_frame, wrap=tk.WORD)
        self.security_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def create_timeline_tab(self):
        timeline_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(timeline_frame, text="Timeline")
        
        timeline_frame.columnconfigure(0, weight=1)
        timeline_frame.rowconfigure(0, weight=1)
        
        self.timeline_text = scrolledtext.ScrolledText(timeline_frame, wrap=tk.WORD)
        self.timeline_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def create_network_tab(self):
        network_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(network_frame, text="Network Info")
        
        network_frame.columnconfigure(0, weight=1)
        network_frame.rowconfigure(0, weight=1)
        
        self.network_text = scrolledtext.ScrolledText(network_frame, wrap=tk.WORD)
        self.network_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def create_export_tab(self):
        export_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(export_frame, text="Export")
        
        export_frame.columnconfigure(0, weight=1)
        export_frame.rowconfigure(1, weight=1)
        
        btn_frame = ttk.Frame(export_frame)
        btn_frame.grid(row=0, column=0, pady=10, sticky=tk.W)
        
        ttk.Button(btn_frame, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Export TXT", command=self.export_txt).pack(side=tk.LEFT, padx=5)
        
        self.export_text = scrolledtext.ScrolledText(export_frame, wrap=tk.WORD)
        self.export_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
    def load_file(self):
        filename = filedialog.askopenfilename(
            title="Select file",
            filetypes=(("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    self.input_text.delete(1.0, tk.END)
                    self.input_text.insert(1.0, content)
                messagebox.showinfo("Success", "File loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
                
    def clear_input(self):
        self.input_text.delete(1.0, tk.END)
        self.ip_text.delete(1.0, tk.END)
        self.user_text.delete(1.0, tk.END)
        self.security_text.delete(1.0, tk.END)
        self.timeline_text.delete(1.0, tk.END)
        self.network_text.delete(1.0, tk.END)
        self.export_text.delete(1.0, tk.END)
        self.analysis_data = {}
        
    def analyze_data(self):
        content = self.input_text.get(1.0, tk.END)
        
        if not content.strip():
            messagebox.showwarning("Warning", "Please input data to analyze")
            return
            
        # Clear previous results
        self.ip_text.delete(1.0, tk.END)
        self.user_text.delete(1.0, tk.END)
        self.security_text.delete(1.0, tk.END)
        self.timeline_text.delete(1.0, tk.END)
        self.network_text.delete(1.0, tk.END)
        self.export_text.delete(1.0, tk.END)
        
        # Analyze
        self.analysis_data = self.extract_information(content)
        
        # Display results
        self.display_ip_analysis()
        self.display_user_analysis()
        self.display_security_analysis()
        self.display_timeline()
        self.display_network_info()
        self.display_export_summary()
        
        messagebox.showinfo("Success", "Analysis complete!")
        
    def extract_information(self, content):
        data = {
            'ips': defaultdict(lambda: {'count': 0, 'events': []}),
            'users': defaultdict(lambda: {'count': 0, 'events': []}),
            'hostnames': set(),
            'ports': set(),
            'emails': set(),
            'urls': set(),
            'domains': set(),
            'hashes': set(),
            'ssh_events': [],
            'failed_logins': [],
            'successful_logins': [],
            'sudo_commands': [],
            'user_creations': [],
            'security_events': [],
            'timeline': [],
            'suspicious_ips': set(),
            'brute_force_attempts': defaultdict(int)
        }
        
        lines = content.split('\n')
        
        for line in lines:
            # Extract IPs
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            for ip in ips:
                if not ip.startswith('127.') and not ip.startswith('0.'):
                    data['ips'][ip]['count'] += 1
                    data['ips'][ip]['events'].append(line.strip())
            
            # Extract emails
            emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line)
            data['emails'].update(emails)
            
            # Extract URLs
            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', line)
            data['urls'].update(urls)
            
            # Extract domains from URLs
            for url in urls:
                domain = re.search(r'https?://([^/\s:]+)', url)
                if domain:
                    data['domains'].add(domain.group(1))
            
            # Extract hostnames
            hostnames = re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\b', line)
            data['hostnames'].update(hostnames)
            
            # Extract ports
            ports = re.findall(r'port\s+(\d+)', line, re.IGNORECASE)
            data['ports'].update(ports)
            
            # Extract hashes (MD5, SHA1, SHA256)
            hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', line)
            data['hashes'].update(hashes)
            
            # Extract users
            user_patterns = [
                r'user\s+([a-zA-Z0-9_-]+)',
                r'for\s+([a-zA-Z0-9_-]+)\s+from',
                r'USER=([a-zA-Z0-9_-]+)',
                r'name=([a-zA-Z0-9_-]+)',
            ]
            for pattern in user_patterns:
                users = re.findall(pattern, line, re.IGNORECASE)
                for user in users:
                    data['users'][user]['count'] += 1
                    data['users'][user]['events'].append(line.strip())
            
            # Security Events
            if 'failed' in line.lower() and 'password' in line.lower():
                data['failed_logins'].append(line.strip())
                data['security_events'].append(('Failed Login', line.strip()))
                # Track brute force
                for ip in ips:
                    data['brute_force_attempts'][ip] += 1
                    if data['brute_force_attempts'][ip] > 3:
                        data['suspicious_ips'].add(ip)
                        
            if 'accepted password' in line.lower():
                data['successful_logins'].append(line.strip())
                data['security_events'].append(('Successful Login', line.strip()))
                
            if 'sudo' in line.lower() and 'command' in line.lower():
                data['sudo_commands'].append(line.strip())
                data['security_events'].append(('Sudo Command', line.strip()))
                
            if 'useradd' in line.lower() or 'new user' in line.lower():
                data['user_creations'].append(line.strip())
                data['security_events'].append(('User Creation', line.strip()))
                
            if 'invalid user' in line.lower():
                data['security_events'].append(('Invalid User', line.strip()))
                
            if 'authentication failure' in line.lower():
                data['security_events'].append(('Auth Failure', line.strip()))
            
            # Timeline
            timestamp = re.search(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
            if timestamp:
                data['timeline'].append((timestamp.group(1), line.strip()))
        
        return data
    
    def display_ip_analysis(self):
        self.ip_text.insert(tk.END, "=" * 80 + "\n")
        self.ip_text.insert(tk.END, "IP ADDRESS ANALYSIS\n")
        self.ip_text.insert(tk.END, "=" * 80 + "\n\n")
        
        if self.analysis_data['ips']:
            sorted_ips = sorted(self.analysis_data['ips'].items(), 
                              key=lambda x: x[1]['count'], reverse=True)
            
            self.ip_text.insert(tk.END, f"Total Unique IPs: {len(sorted_ips)}\n\n")
            
            for ip, info in sorted_ips:
                status = " [SUSPICIOUS - Multiple Failed Attempts]" if ip in self.analysis_data['suspicious_ips'] else ""
                self.ip_text.insert(tk.END, f"IP: {ip} (Count: {info['count']}){status}\n")
                self.ip_text.insert(tk.END, "-" * 80 + "\n")
                
                # Show sample events (max 5)
                for event in info['events'][:5]:
                    self.ip_text.insert(tk.END, f"  {event}\n")
                
                if len(info['events']) > 5:
                    self.ip_text.insert(tk.END, f"  ... and {len(info['events']) - 5} more events\n")
                    
                self.ip_text.insert(tk.END, "\n")
        else:
            self.ip_text.insert(tk.END, "No IP addresses found.\n")
            
    def display_user_analysis(self):
        self.user_text.insert(tk.END, "=" * 80 + "\n")
        self.user_text.insert(tk.END, "USER & ACCOUNT ANALYSIS\n")
        self.user_text.insert(tk.END, "=" * 80 + "\n\n")
        
        if self.analysis_data['users']:
            sorted_users = sorted(self.analysis_data['users'].items(), 
                                key=lambda x: x[1]['count'], reverse=True)
            
            self.user_text.insert(tk.END, f"Total Unique Users: {len(sorted_users)}\n\n")
            
            for user, info in sorted_users:
                self.user_text.insert(tk.END, f"User: {user} (Mentions: {info['count']})\n")
                self.user_text.insert(tk.END, "-" * 80 + "\n")
                
                # Show sample events (max 3)
                for event in info['events'][:3]:
                    self.user_text.insert(tk.END, f"  {event}\n")
                
                if len(info['events']) > 3:
                    self.user_text.insert(tk.END, f"  ... and {len(info['events']) - 3} more events\n")
                    
                self.user_text.insert(tk.END, "\n")
        
        # User creation events
        if self.analysis_data['user_creations']:
            self.user_text.insert(tk.END, "\n" + "=" * 80 + "\n")
            self.user_text.insert(tk.END, "USER CREATION EVENTS\n")
            self.user_text.insert(tk.END, "=" * 80 + "\n\n")
            for event in self.analysis_data['user_creations']:
                self.user_text.insert(tk.END, f"  {event}\n")
                
    def display_security_analysis(self):
        self.security_text.insert(tk.END, "=" * 80 + "\n")
        self.security_text.insert(tk.END, "SECURITY EVENTS ANALYSIS\n")
        self.security_text.insert(tk.END, "=" * 80 + "\n\n")
        
        # Summary
        self.security_text.insert(tk.END, "SUMMARY:\n")
        self.security_text.insert(tk.END, f"  Failed Logins: {len(self.analysis_data['failed_logins'])}\n")
        self.security_text.insert(tk.END, f"  Successful Logins: {len(self.analysis_data['successful_logins'])}\n")
        self.security_text.insert(tk.END, f"  Sudo Commands: {len(self.analysis_data['sudo_commands'])}\n")
        self.security_text.insert(tk.END, f"  User Creations: {len(self.analysis_data['user_creations'])}\n")
        self.security_text.insert(tk.END, f"  Suspicious IPs: {len(self.analysis_data['suspicious_ips'])}\n\n")
        
        # Suspicious IPs
        if self.analysis_data['suspicious_ips']:
            self.security_text.insert(tk.END, "SUSPICIOUS IPs (Multiple Failed Attempts):\n")
            for ip in self.analysis_data['suspicious_ips']:
                attempts = self.analysis_data['brute_force_attempts'][ip]
                self.security_text.insert(tk.END, f"  {ip} - {attempts} failed attempts\n")
            self.security_text.insert(tk.END, "\n")
        
        # Failed Logins
        if self.analysis_data['failed_logins']:
            self.security_text.insert(tk.END, "FAILED LOGIN ATTEMPTS (Sample):\n")
            for event in self.analysis_data['failed_logins'][:10]:
                self.security_text.insert(tk.END, f"  {event}\n")
            if len(self.analysis_data['failed_logins']) > 10:
                self.security_text.insert(tk.END, f"  ... and {len(self.analysis_data['failed_logins']) - 10} more\n")
            self.security_text.insert(tk.END, "\n")
        
        # Successful Logins
        if self.analysis_data['successful_logins']:
            self.security_text.insert(tk.END, "SUCCESSFUL LOGINS:\n")
            for event in self.analysis_data['successful_logins']:
                self.security_text.insert(tk.END, f"  {event}\n")
            self.security_text.insert(tk.END, "\n")
        
        # Sudo Commands
        if self.analysis_data['sudo_commands']:
            self.security_text.insert(tk.END, "SUDO COMMANDS EXECUTED:\n")
            for event in self.analysis_data['sudo_commands']:
                self.security_text.insert(tk.END, f"  {event}\n")
            self.security_text.insert(tk.END, "\n")
            
    def display_timeline(self):
        self.timeline_text.insert(tk.END, "=" * 80 + "\n")
        self.timeline_text.insert(tk.END, "EVENT TIMELINE\n")
        self.timeline_text.insert(tk.END, "=" * 80 + "\n\n")
        
        if self.analysis_data['timeline']:
            for timestamp, event in self.analysis_data['timeline'][:100]:
                self.timeline_text.insert(tk.END, f"[{timestamp}] {event}\n")
            
            if len(self.analysis_data['timeline']) > 100:
                self.timeline_text.insert(tk.END, f"\n... and {len(self.analysis_data['timeline']) - 100} more events\n")
        else:
            self.timeline_text.insert(tk.END, "No timeline data found.\n")
            
    def display_network_info(self):
        self.network_text.insert(tk.END, "=" * 80 + "\n")
        self.network_text.insert(tk.END, "NETWORK INFORMATION\n")
        self.network_text.insert(tk.END, "=" * 80 + "\n\n")
        
        if self.analysis_data['hostnames']:
            self.network_text.insert(tk.END, f"HOSTNAMES ({len(self.analysis_data['hostnames'])}):\n")
            for hostname in sorted(self.analysis_data['hostnames']):
                self.network_text.insert(tk.END, f"  {hostname}\n")
            self.network_text.insert(tk.END, "\n")
        
        if self.analysis_data['domains']:
            self.network_text.insert(tk.END, f"DOMAINS ({len(self.analysis_data['domains'])}):\n")
            for domain in sorted(self.analysis_data['domains']):
                self.network_text.insert(tk.END, f"  {domain}\n")
            self.network_text.insert(tk.END, "\n")
        
        if self.analysis_data['urls']:
            self.network_text.insert(tk.END, f"URLs ({len(self.analysis_data['urls'])}):\n")
            for url in sorted(self.analysis_data['urls']):
                self.network_text.insert(tk.END, f"  {url}\n")
            self.network_text.insert(tk.END, "\n")
        
        if self.analysis_data['ports']:
            self.network_text.insert(tk.END, f"PORTS ({len(self.analysis_data['ports'])}):\n")
            for port in sorted(self.analysis_data['ports'], key=int):
                self.network_text.insert(tk.END, f"  {port}\n")
            self.network_text.insert(tk.END, "\n")
        
        if self.analysis_data['emails']:
            self.network_text.insert(tk.END, f"EMAIL ADDRESSES ({len(self.analysis_data['emails'])}):\n")
            for email in sorted(self.analysis_data['emails']):
                self.network_text.insert(tk.END, f"  {email}\n")
            self.network_text.insert(tk.END, "\n")
        
        if self.analysis_data['hashes']:
            self.network_text.insert(tk.END, f"HASHES ({len(self.analysis_data['hashes'])}):\n")
            for hash_val in sorted(self.analysis_data['hashes']):
                self.network_text.insert(tk.END, f"  {hash_val}\n")
            self.network_text.insert(tk.END, "\n")
            
    def display_export_summary(self):
        summary = f"""
OSINT ANALYSIS SUMMARY
{'=' * 80}

Total IPs Found: {len(self.analysis_data['ips'])}
Suspicious IPs: {len(self.analysis_data['suspicious_ips'])}
Total Users: {len(self.analysis_data['users'])}
Failed Logins: {len(self.analysis_data['failed_logins'])}
Successful Logins: {len(self.analysis_data['successful_logins'])}
Sudo Commands: {len(self.analysis_data['sudo_commands'])}
User Creations: {len(self.analysis_data['user_creations'])}
URLs Found: {len(self.analysis_data['urls'])}
Email Addresses: {len(self.analysis_data['emails'])}
Domains: {len(self.analysis_data['domains'])}
Ports: {len(self.analysis_data['ports'])}
Hashes: {len(self.analysis_data['hashes'])}
Timeline Events: {len(self.analysis_data['timeline'])}

Ready for export!
"""
        self.export_text.insert(tk.END, summary)
        
    def export_json(self):
        if not self.analysis_data:
            messagebox.showwarning("Warning", "No data to export. Run analysis first.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                # Convert sets to lists for JSON serialization
                export_data = {
                    'ips': dict(self.analysis_data['ips']),
                    'users': dict(self.analysis_data['users']),
                    'hostnames': list(self.analysis_data['hostnames']),
                    'ports': list(self.analysis_data['ports']),
                    'emails': list(self.analysis_data['emails']),
                    'urls': list(self.analysis_data['urls']),
                    'domains': list(self.analysis_data['domains']),
                    'hashes': list(self.analysis_data['hashes']),
                    'failed_logins': self.analysis_data['failed_logins'],
                    'successful_logins': self.analysis_data['successful_logins'],
                    'sudo_commands': self.analysis_data['sudo_commands'],
                    'user_creations': self.analysis_data['user_creations'],
                    'suspicious_ips': list(self.analysis_data['suspicious_ips']),
                    'brute_force_attempts': dict(self.analysis_data['brute_force_attempts'])
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                    
                messagebox.showinfo("Success", f"Data exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
                
    def export_txt(self):
        if not self.analysis_data:
            messagebox.showwarning("Warning", "No data to export. Run analysis first.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("OSINT ANALYSIS REPORT\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Write all sections
                    f.write(self.ip_text.get(1.0, tk.END))
                    f.write("\n\n")
                    f.write(self.user_text.get(1.0, tk.END))
                    f.write("\n\n")
                    f.write(self.security_text.get(1.0, tk.END))
                    f.write("\n\n")
                    f.write(self.network_text.get(1.0, tk.END))
                    
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

def main():
    root = tk.Tk()
    app = OSINTAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()