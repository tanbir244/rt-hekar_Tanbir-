import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox, filedialog
from random import randint, choice
import threading, time, math, csv, os

angle_offset = 0
log_history = []
client_messages = {}  # Client-wise message history

# ===============================
# Logging Function
# ===============================
def log_message(msg, tag, client_ip=None, save_history=True):
    output_area.insert(tk.END, msg + "\n", tag)
    output_area.see(tk.END)
    root.update()
    if save_history:
        log_history.append((msg, tag))
        if client_ip:
            if client_ip not in client_messages:
                client_messages[client_ip] = []
            client_messages[client_ip].append(msg)

# ===============================
# Circular Map Drawing
# ===============================
def draw_circular_map(highlight_ip=None, arrows=[], rotate=False):
    global angle_offset
    if rotate:
        angle_offset += 2
    canvas.delete("all")
    center_x, center_y = 700, 350
    radius = 300
    client_ips = [f"192.168.0.{i}" for i in range(2,8)]
    client_angles = [i*(360/len(client_ips)) + angle_offset for i in range(len(client_ips))]
    client_pos = [(center_x + radius*math.cos(math.radians(a)),
                   center_y + radius*math.sin(math.radians(a))) for a in client_angles]

    for i, pos in enumerate(client_pos):
        color = "yellow" if highlight_ip==client_ips[i] else "green"
        size = 30 if highlight_ip==client_ips[i] else 20
        canvas.create_oval(pos[0]-size,pos[1]-size,pos[0]+size,pos[1]+size,fill=color)
        canvas.create_text(pos[0], pos[1], text=client_ips[i], font=("Arial",10))

    # MITM Node
    mitm_pos = (center_x, center_y)
    canvas.create_oval(mitm_pos[0]-35,mitm_pos[1]-35,mitm_pos[0]+35,mitm_pos[1]+35,fill="orange")
    canvas.create_text(mitm_pos[0], mitm_pos[1], text="MITM", font=("Arial",12))

    # Server Node
    server_pos = (center_x, center_y - radius - 120)
    canvas.create_oval(server_pos[0]-40,server_pos[1]-40,server_pos[0]+40,server_pos[1]+40,fill="blue")
    canvas.create_text(server_pos[0], server_pos[1], text="Server", font=("Arial",12), fill="white")

    # Draw arrows
    for arrow in arrows:
        src, dst, color = arrow
        canvas.create_line(src[0], src[1], dst[0], dst[1], arrow=tk.LAST, fill=color, width=3)

    root.update()

# ===============================
# Hover Info
# ===============================
hover_label = None
def show_hover(ip):
    global hover_label
    recent = client_messages.get(ip, [])
    text = recent[-1] if recent else "No messages"
    hover_label = tk.Label(canvas, text=text, bg="white", fg="black", font=("Consolas",10))
    hover_label.place(x=600, y=10)

def hide_hover():
    global hover_label
    if hover_label:
        hover_label.destroy()
        hover_label = None

# ===============================
# Client Messages History Window
# ===============================
def show_client_history():
    ip = ip_field.get().strip()
    if ip=="":
        messagebox.showwarning("Input Error","Enter Client IP to view history")
        return
    history_window = tk.Toplevel(root)
    history_window.title(f"{ip} Message History")
    st = scrolledtext.ScrolledText(history_window, wrap=tk.WORD, font=("Consolas",12))
    st.pack(fill=tk.BOTH, expand=True)
    messages = client_messages.get(ip, [])
    for msg in messages:
        st.insert(tk.END, msg + "\n")
    st.see(tk.END)

# ===============================
# Server & MITM Simulation
# ===============================
def server(data, client_ip):
    client_name = f"Client_{client_ip}"
    log_message(f"[Server] Received from {client_name}: {data}", "server", client_ip)
    time.sleep(0.5)
    if "login" in data.lower():
        otp = f"OTP-{randint(100000,999999)}"
        log_message(f"[Server] Sending back to {client_name}: {otp}", "server", client_ip)
        return otp
    else:
        response = "OK"
        log_message(f"[Server] Sending back to {client_name}: {response}", "server", client_ip)
        return response

def mitm(client_data, client_ip, attack_type):
    client_name = f"Client_{client_ip}"
    log_message(f"[MITM] Intercepted from {client_name}: {client_data}", "mitm", client_ip)
    time.sleep(0.3)
    modified_data = client_data
    if attack_type=="Hide Password":
        modified_data = client_data.replace("password","*****")
        log_message(f"[MITM] Modified: {modified_data}", "mitm", client_ip)
    elif attack_type=="Modify Message":
        modified_data = client_data + " [MITM Modified]"
        log_message(f"[MITM] Modified: {modified_data}", "mitm", client_ip)
    elif attack_type=="Drop Message":
        log_message(f"[MITM] Dropped message from {client_name}", "mitm", client_ip)
        return "[MITM] Message dropped"
    elif attack_type=="Random Attack":
        choice_attack = choice(["Hide Password","Modify Message","Drop Message"])
        log_message(f"[MITM] Random Attack Chosen: {choice_attack}", "mitm", client_ip)
        return mitm(client_data, client_ip, choice_attack)

    server_response = server(modified_data, client_ip)
    time.sleep(0.3)
    log_message(f"[MITM] Intercepted response: {server_response}", "mitm", client_ip)
    return server_response

# ===============================
# Client Send Thread
# ===============================
def send_message_thread():
    ip = ip_field.get().strip()
    if ip=="":
        messagebox.showwarning("Input Error","Please enter Client IP.")
        return
    attack_type = attack_selector.get()
    client_input = input_field.get().strip()
    if client_input=="":
        messagebox.showwarning("Input Error","Please enter a message.")
        return
    input_field.delete(0, tk.END)

    client_ips = [f"192.168.0.{i}" for i in range(2,8)]
    center_x, center_y = 700, 350
    radius = 300
    client_angles = [i*(360/len(client_ips)) for i in range(len(client_ips))]
    client_pos = [(center_x + radius*math.cos(math.radians(a)),
                   center_y + radius*math.sin(math.radians(a))) for a in client_angles]
    mitm_pos = (center_x, center_y)
    server_pos = (center_x, center_y - radius - 120)

    if ip not in client_ips:
        messagebox.showwarning("Input Error","Client IP not in network!")
        return

    idx = client_ips.index(ip)
    arrows = [
        (client_pos[idx], mitm_pos, "green"),
        (mitm_pos, server_pos, "orange"),
        (server_pos, mitm_pos, "blue"),
        (mitm_pos, client_pos[idx], "orange")
    ]

    log_message(f"[Client_{ip}] Sending to Server: {client_input}", "client", ip)
    draw_circular_map(highlight_ip=ip, arrows=arrows)

    response = mitm(client_input, ip, attack_type)

    arrows = [
        (server_pos, mitm_pos, "blue"),
        (mitm_pos, client_pos[idx], "orange")
    ]
    draw_circular_map(highlight_ip=ip, arrows=arrows)

    log_message(f"[Client_{ip}] Received from Server: {response}", "client", ip)

def send_message():
    threading.Thread(target=send_message_thread).start()

# ===============================
# Auto Simulation
# ===============================
def auto_simulation():
    attacks = ["Hide Password","Modify Message","Drop Message","Random Attack"]
    messages = ["login:user,password123","check status","update info","send report","hello server"]
    client_ips = [f"192.168.0.{i}" for i in range(2,8)]
    center_x, center_y = 700, 350
    radius = 300
    client_angles = [i*(360/len(client_ips)) for i in range(len(client_ips))]
    client_pos = [(center_x + radius*math.cos(math.radians(a)),
                   center_y + radius*math.sin(math.radians(a))) for a in client_angles]
    mitm_pos = (center_x, center_y)
    server_pos = (center_x, center_y - radius - 120)

    for _ in range(5):  # Loop for auto messages
        for i, ip in enumerate(client_ips):
            msg = choice(messages)
            attack = choice(attacks)
            arrows = [
                (client_pos[i], mitm_pos, "green"),
                (mitm_pos, server_pos, "orange"),
                (server_pos, mitm_pos, "blue"),
                (mitm_pos, client_pos[i], "orange")
            ]
            log_message(f"[Client_{ip}] Auto Sending to Server: {msg}", "client", ip)
            draw_circular_map(highlight_ip=ip, arrows=arrows, rotate=True)
            mitm(msg, ip, attack)
            draw_circular_map(highlight_ip=ip, rotate=True)
            time.sleep(0.5)

def start_auto_simulation():
    threading.Thread(target=auto_simulation).start()

# ===============================
# Export Logs
# ===============================
def export_logs():
    if not log_history:
        messagebox.showwarning("No Logs", "No logs to export!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files","*.csv"),("Text Files","*.txt")])
    if not file_path:
        return
    _, ext = os.path.splitext(file_path)
    try:
        if ext.lower() == ".csv":
            with open(file_path, "w", newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Message","Tag"])
                for msg, tag in log_history:
                    writer.writerow([msg, tag])
        else:
            with open(file_path, "w", encoding='utf-8') as f:
                for msg, tag in log_history:
                    f.write(f"[{tag}] {msg}\n")
        messagebox.showinfo("Success", f"Logs exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export logs: {e}")

# ===============================
# GUI Setup
# ===============================
root = tk.Tk()
root.title("Dynamic Circular MITM Simulator v2.0")
root.geometry("1600x1000")

# Top Frame
top_frame = tk.Frame(root)
top_frame.pack(fill=tk.X, padx=10, pady=5)

ip_label = tk.Label(top_frame, text="Client IP:", font=("Consolas",12))
ip_label.pack(side=tk.LEFT, padx=(0,5))

ip_field = tk.Entry(top_frame, font=("Consolas",12))
ip_field.pack(side=tk.LEFT, padx=(0,10))
ip_field.insert(0,"Enter Client IP")

attack_selector = ttk.Combobox(top_frame, values=["Hide Password","Modify Message","Drop Message","Random Attack"], font=("Consolas",12), width=20)
attack_selector.current(0)
attack_selector.pack(side=tk.LEFT, padx=(0,10))

input_field = tk.Entry(top_frame, font=("Consolas",12))
input_field.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))

send_button = tk.Button(top_frame,text="Send",command=send_message,font=("Consolas",12))
send_button.pack(side=tk.LEFT,padx=(0,5))

auto_button = tk.Button(top_frame,text="Start Auto Simulation",command=start_auto_simulation,font=("Consolas",12))
auto_button.pack(side=tk.LEFT, padx=(5,0))

history_button = tk.Button(top_frame,text="Client History",command=show_client_history,font=("Consolas",12))
history_button.pack(side=tk.LEFT, padx=(5,0))

export_button = tk.Button(top_frame,text="Export Logs",command=export_logs,font=("Consolas",12))
export_button.pack(side=tk.LEFT, padx=(5,0))

clear_button = tk.Button(top_frame,text="Clear Output",command=lambda:[output_area.delete(1.0,tk.END),canvas.delete("all")],font=("Consolas",12))
clear_button.pack(side=tk.LEFT, padx=(5,0))

# Canvas
canvas = tk.Canvas(root, height=600, bg="white")
canvas.pack(fill=tk.X, padx=10, pady=5)

# Output Area
output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas",12))
output_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
output_area.tag_config("client", foreground="green")
output_area.tag_config("mitm", foreground="orange")
output_area.tag_config("server", foreground="blue")

# Instruction Label
instruction = tk.Label(root, text="Enter Client IP to highlight, select MITM attack, type message or start Auto Simulation.", font=("Consolas",12))
instruction.pack(pady=(0,5))

# ===============================
# Start Tkinter Mainloop
# ===============================
root.mainloop()