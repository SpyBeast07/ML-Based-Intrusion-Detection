import tkinter as tk
from tkinter import filedialog
from tkinter import *
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, UDP, TCP, DHCP
import threading

# --- GUI Setup ---
app = ttk.Window(themename="superhero")
app.title("Network Packet Analyzer and Attack Detection")
app.geometry("1000x700")

# --- Global Variables ---
selected_file = ""
df = pd.DataFrame()

# --- Frames ---
start_frame = ttk.Frame(app)
load_frame = ttk.Frame(app)

# --- Start Frame ---
start_label = ttk.Label(start_frame, text="Network Packet Analyzer and Attack Detection", font=("Helvetica", 22))
start_label.pack(pady=50)

start_btn = ttk.Button(start_frame, text="➤", bootstyle="primary-outline", width=20, command=lambda: switch_to_frame(load_frame))
start_btn.pack()

start_note = ttk.Label(start_frame, text="Click to Begin", font=("Helvetica", 12))
start_note.pack(pady=10)

# --- Load Frame ---
load_label = ttk.Label(load_frame, text="Load and Convert PCAP File to CSV", font=("Helvetica", 20))
load_label.pack(pady=20)

status_label = ttk.Label(load_frame, text="", font=("Helvetica", 12))
status_label.pack(pady=10)

progress = ttk.Meter(load_frame, bootstyle="info", subtext="Conversion Progress", interactive=False, textright="%")
progress.pack(pady=20)

# Treeview to show CSV preview
tree_frame = ttk.Frame(load_frame)
tree_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

tree_scroll_y = ttk.Scrollbar(tree_frame, orient=VERTICAL)
tree_scroll_x = ttk.Scrollbar(tree_frame, orient=HORIZONTAL)
tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
tree_scroll_y.config(command=tree.yview)
tree_scroll_x.config(command=tree.xview)
tree_scroll_y.pack(side=RIGHT, fill=Y)
tree_scroll_x.pack(side=BOTTOM, fill=X)
tree.pack(fill=BOTH, expand=True)

# --- Functions ---
def switch_to_frame(frame):
    start_frame.pack_forget()
    load_frame.pack(fill=BOTH, expand=True)

def load_pcap():
    global selected_file, df
    selected_file = filedialog.askopenfilename(filetypes=[("Supported files", "*.pcap *.pcapng *.csv")])
    
    if selected_file.endswith(".csv"):
        # If CSV selected, load directly into df
        df = pd.read_csv(selected_file)
        status_label.config(text=f"✔️ CSV File Loaded: {selected_file.split('/')[-1]}")
        show_csv_preview()
    elif selected_file.endswith(".pcap") or selected_file.endswith(".pcapng"):
        status_label.config(text=f"✔️ PCAP File Loaded: {selected_file.split('/')[-1]}")
    else:
        status_label.config(text="❌ Unsupported file type selected.")

def convert_pcap_to_csv():
    def task():
        global df
        progress.configure(amountused=10, subtext="Reading File...")
        packets = rdpcap(selected_file)

        data = []
        total = len(packets)
        for i, pkt in enumerate(packets):
            row = {
                "SYN_Packet": 0,
                "time": pkt.time,
                "src": None,
                "dst": None,
                "proto": None,
                "src_port": None,
                "dst_port": None,
                "length": len(pkt)
            }
            if pkt.haslayer(IP):
                row["src"] = pkt[IP].src
                row["dst"] = pkt[IP].dst
                proto_number = pkt[IP].proto
            elif pkt.haslayer(IPv6):
                row["src"] = pkt[IPv6].src
                row["dst"] = pkt[IPv6].dst
                proto_number = "UDP" if pkt.haslayer(UDP) else "Other"
            else:
                proto_number = None

            proto_mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
            row["proto"] = proto_mapping.get(proto_number, proto_number)

            if pkt.haslayer(UDP):
                row["src_port"] = pkt[UDP].sport
                row["dst_port"] = pkt[UDP].dport
            elif pkt.haslayer(TCP):
                row["src_port"] = pkt[TCP].sport
                row["dst_port"] = pkt[TCP].dport
                flags = int(pkt[TCP].flags)
                row["SYN_Packet"] = 1 if (flags & 0x02 and not (flags & 0x10)) else 0

            if pkt.haslayer(DHCP):
                for opt in pkt[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == "message-type":
                        dhcp_type = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}.get(opt[1], "DHCP")
                        row["proto"] = dhcp_type

            data.append(row)
            if i % (total // 50 + 1) == 0:
                progress.configure(amountused=(i / total) * 100)

        df = pd.DataFrame(data)
        df.to_csv("output.csv", index=False)
        progress.configure(amountused=100, subtext="Conversion Complete")
        status_label.config(text="✅ CSV File Saved as output.csv")
        show_csv_preview()

    threading.Thread(target=task).start()

def show_csv_preview():
    tree.delete(*tree.get_children())
    tree["columns"] = list(df.columns)
    tree["show"] = "headings"
    for col in df.columns:
        tree.heading(col, text=col)
        tree.column(col, width=120, anchor="center")

    for i, row in df.head(100).iterrows():
        tree.insert("", "end", values=list(row))

# --- Buttons ---
load_btn = ttk.Button(load_frame, text="Load PCAP File", command=load_pcap, bootstyle="primary")
load_btn.pack(pady=5)

convert_btn = ttk.Button(load_frame, text="Convert to CSV", command=convert_pcap_to_csv, bootstyle="success")
convert_btn.pack(pady=5)

# --- Cleaned Frame ---
cleaned_frame = ttk.Frame(app)

cleaned_label = ttk.Label(cleaned_frame, text="Cleaned CSV Preview (Dropped Columns)", font=("Helvetica", 20))
cleaned_label.pack(pady=20)

cleaned_status = ttk.Label(cleaned_frame, text="", font=("Helvetica", 12))
cleaned_status.pack(pady=10)

# Treeview for cleaned CSV
cleaned_tree_frame = ttk.Frame(cleaned_frame)
cleaned_tree_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

cleaned_scroll_y = ttk.Scrollbar(cleaned_tree_frame, orient=VERTICAL)
cleaned_scroll_x = ttk.Scrollbar(cleaned_tree_frame, orient=HORIZONTAL)
cleaned_tree = ttk.Treeview(cleaned_tree_frame, yscrollcommand=cleaned_scroll_y.set, xscrollcommand=cleaned_scroll_x.set)
cleaned_scroll_y.config(command=cleaned_tree.yview)
cleaned_scroll_x.config(command=cleaned_tree.xview)
cleaned_scroll_y.pack(side=RIGHT, fill=Y)
cleaned_scroll_x.pack(side=BOTTOM, fill=X)
cleaned_tree.pack(fill=BOTH, expand=True)

def go_to_cleaned_screen():
    load_frame.pack_forget()
    cleaned_frame.pack(fill=BOTH, expand=True)

def drop_columns():
    global df
    cols_to_drop = ["time", "src_port", "dst_port", "length"]
    df = df.drop(columns=cols_to_drop, errors="ignore")
    df.to_csv("output.csv", index=False)
    cleaned_status.config(text="✅ Columns Dropped and Saved to output.csv")
    update_cleaned_preview()

def update_cleaned_preview():
    cleaned_tree.delete(*cleaned_tree.get_children())
    cleaned_tree["columns"] = list(df.columns)
    cleaned_tree["show"] = "headings"
    for col in df.columns:
        cleaned_tree.heading(col, text=col)
        cleaned_tree.column(col, width=120, anchor="center")

    for i, row in df.head(100).iterrows():
        cleaned_tree.insert("", "end", values=list(row))

# Button to drop columns
drop_btn = ttk.Button(cleaned_frame, text="Drop Unwanted Columns", command=drop_columns, bootstyle="danger")
drop_btn.pack(pady=10)

# --- Add "Next" Button to Load Frame ---
next_btn = ttk.Button(load_frame, text="Next ➡️", command=go_to_cleaned_screen, bootstyle="info-outline")
next_btn.pack(pady=10)

# --- Count Frame ---
count_frame = ttk.Frame(app)

count_label = ttk.Label(count_frame, text="Add Count Column to Packets", font=("Helvetica", 20))
count_label.pack(pady=20)

count_status = ttk.Label(count_frame, text="", font=("Helvetica", 12))
count_status.pack(pady=10)

# Treeview for count preview
count_tree_frame = ttk.Frame(count_frame)
count_tree_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

count_scroll_y = ttk.Scrollbar(count_tree_frame, orient=VERTICAL)
count_scroll_x = ttk.Scrollbar(count_tree_frame, orient=HORIZONTAL)
count_tree = ttk.Treeview(count_tree_frame, yscrollcommand=count_scroll_y.set, xscrollcommand=count_scroll_x.set)
count_scroll_y.config(command=count_tree.yview)
count_scroll_x.config(command=count_tree.xview)
count_scroll_y.pack(side=RIGHT, fill=Y)
count_scroll_x.pack(side=BOTTOM, fill=X)
count_tree.pack(fill=BOTH, expand=True)

def go_to_count_screen():
    cleaned_frame.pack_forget()
    count_frame.pack(fill=BOTH, expand=True)

def apply_groupby_count():
    global df
    df = df.groupby(["SYN_Packet", "src", "dst", "proto"]).size().reset_index(name="count")
    df.to_csv("output.csv", index=False)
    count_status.config(text="✅ Packet Counts Added and Saved to output.csv")
    update_count_preview()

def update_count_preview():
    count_tree.delete(*count_tree.get_children())
    count_tree["columns"] = list(df.columns)
    count_tree["show"] = "headings"
    for col in df.columns:
        count_tree.heading(col, text=col)
        count_tree.column(col, width=120, anchor="center")

    for i, row in df.head(100).iterrows():
        count_tree.insert("", "end", values=list(row))

# Button to apply groupby and show results
groupby_btn = ttk.Button(count_frame, text="Add Count Column", command=apply_groupby_count, bootstyle="success")
groupby_btn.pack(pady=10)

# --- Add "Next" button to cleaned frame ---
next_to_count_btn = ttk.Button(cleaned_frame, text="Next ➡️", command=go_to_count_screen, bootstyle="info-outline")
next_to_count_btn.pack(pady=10)

# --- Attack Labeling and Encoding Frame ---
attack_frame = ttk.Frame(app)

attack_label = ttk.Label(attack_frame, text="Attack Labeling and Feature Encoding", font=("Helvetica", 20))
attack_label.pack(pady=20)

attack_status = ttk.Label(attack_frame, text="", font=("Helvetica", 12))
attack_status.pack(pady=10)

# Treeview for attack labeled and encoded data
attack_tree_frame = ttk.Frame(attack_frame)
attack_tree_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

attack_scroll_y = ttk.Scrollbar(attack_tree_frame, orient=VERTICAL)
attack_scroll_x = ttk.Scrollbar(attack_tree_frame, orient=HORIZONTAL)
attack_tree = ttk.Treeview(attack_tree_frame, yscrollcommand=attack_scroll_y.set, xscrollcommand=attack_scroll_x.set)
attack_scroll_y.config(command=attack_tree.yview)
attack_scroll_x.config(command=attack_tree.xview)
attack_scroll_y.pack(side=RIGHT, fill=Y)
attack_scroll_x.pack(side=BOTTOM, fill=X)
attack_tree.pack(fill=BOTH, expand=True)

def go_to_attack_screen():
    count_frame.pack_forget()
    attack_frame.pack(fill=BOTH, expand=True)

def apply_attack_label_and_encoding():
    global df
    # Ensure count column exists
    if 'count' not in df.columns:
        attack_status.config(text="❌ 'count' column missing. Please run previous step.")
        return

    # Calculate UDP mean
    udp_mean = df[df["proto"] == "UDP"]["count"].mean()

    def detect_attack(row):
        if row["proto"] == "DISCOVER" and row["count"] > 150:
            return 1
        if row["SYN_Packet"] == 1 and row["count"] > 100:
            return 1
        if row["proto"] == "ICMP" and row["count"] > 150:
            return 1
        if row["proto"] == "UDP" and row["count"] > udp_mean:
            return 1
        return 0

    df["attack"] = df.apply(detect_attack, axis=1)

    # Encoding
    proto_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'DISCOVER': 3, 'Other': 4}
    df.insert(df.columns.get_loc("proto") + 1, "proto_encoded", df["proto"].map(proto_map).astype(int))
    df.insert(df.columns.get_loc("src") + 1, "src_encoded", df["src"].astype('category').cat.codes.astype(int))
    df.insert(df.columns.get_loc("dst") + 1, "dst_encoded", df["dst"].astype('category').cat.codes.astype(int))

    # Save and show
    df.to_csv("output.csv", index=False)
    attack_status.config(text="✅ Attack labeled and encoded. Saved to output.csv")
    update_attack_preview()

def update_attack_preview():
    attack_tree.delete(*attack_tree.get_children())
    attack_tree["columns"] = list(df.columns)
    attack_tree["show"] = "headings"
    for col in df.columns:
        attack_tree.heading(col, text=col)
        attack_tree.column(col, width=120, anchor="center")

    for i, row in df.head(100).iterrows():
        attack_tree.insert("", "end", values=list(row))

# Button to apply attack detection and encoding
attack_btn = ttk.Button(attack_frame, text="Label Attack & Encode Features", command=apply_attack_label_and_encoding, bootstyle="warning")
attack_btn.pack(pady=10)

# --- Next button from Count Frame ---
next_to_attack_btn = ttk.Button(count_frame, text="Next ➡️", command=go_to_attack_screen, bootstyle="info-outline")
next_to_attack_btn.pack(pady=10)

# --- Naive Bayes Preprocessing Frame ---
nb_preprocess_frame = ttk.Frame(app)

nb_preprocess_label = ttk.Label(nb_preprocess_frame, text="Min-Max Scaling & Probabilities", font=("Helvetica", 20))
nb_preprocess_label.pack(pady=20)

nb_preprocess_text = tk.Text(nb_preprocess_frame, wrap="word", font=("Consolas", 11), height=25, width=120, bg="#0d1117", fg="white")
nb_preprocess_text.pack(padx=10, pady=10)

# --- Min-Max Scaling + Laplace Probabilities ---
def run_nb_preprocessing():
    global df, probabilities, count_probs, threshold, p_attack, p_normal
    output = ""

    # Step 1: Min-Max Scaling
    from sklearn.preprocessing import MinMaxScaler
    columns_to_normalize = ["SYN_Packet", "src_encoded", "dst_encoded", "proto_encoded", "count"]
    scaler = MinMaxScaler()
    df[columns_to_normalize] = scaler.fit_transform(df[columns_to_normalize])
    df.to_csv("normalized_output.csv", index=False)
    output += "✅ Normalized and saved to 'normalized_output.csv'\n\n"

    # Step 2: Min-Max Value Summary
    raw_df = pd.read_csv("output.csv")
    min_max_values = raw_df[columns_to_normalize + ["attack"]].agg(['min', 'max']).transpose().reset_index()
    min_max_values.columns = ['Feature', 'Min', 'Max']
    output += "🔍 Min-Max Scaling Summary (Before Normalization):\n"
    for _, row in min_max_values.iterrows():
        output += f"{row['Feature']}: Min = {row['Min']}, Max = {row['Max']}\n"

    # Step 3: Prior Probabilities
    total = len(df)
    attack_count = df[df["attack"] == 1].shape[0]
    normal_count = df[df["attack"] == 0].shape[0]
    p_attack = attack_count / total
    p_normal = normal_count / total
    output += f"\n🔹 Prior Probabilities:\nP(attack) = {attack_count}/{total} = {p_attack:.4f}\n"
    output += f"P(normal) = {normal_count}/{total} = {p_normal:.4f}\n"

    # Step 4: Laplace Smoothing for Features
    alpha = 1
    N = 2  # Binary values for SYN and count_flag
    def laplace_smoothing(feature, value, given):
        return (df[(df[feature] == value) & (df["attack"] == given)].shape[0] + alpha) / \
               (df[df["attack"] == given].shape[0] + alpha * df[feature].nunique())

    probabilities = {
        "P(SYN=1|attack)": laplace_smoothing("SYN_Packet", 1, 1),
        "P(SYN=0|attack)": laplace_smoothing("SYN_Packet", 0, 1),
        "P(SYN=1|normal)": laplace_smoothing("SYN_Packet", 1, 0),
        "P(SYN=0|normal)": laplace_smoothing("SYN_Packet", 0, 0),
    }
    output += "\n🔹 Laplace Probabilities (SYN):\n"
    for k, v in probabilities.items():
        output += f"{k} = {v:.4f}\n"

    proto_values = raw_df["proto_encoded"].unique()
    print(proto_values)
    for proto in proto_values:
        probabilities[f"P(proto={proto}|attack)"] = laplace_smoothing("proto_encoded", proto, 1)
        probabilities[f"P(proto={proto}|normal)"] = laplace_smoothing("proto_encoded", proto, 0)

    output += "\n🔹 Laplace Probabilities (proto_encoded):\n"
    for proto in proto_values:
        output += f"P(proto={proto}|attack) = {probabilities[f'P(proto={proto}|attack)']:.4f}\n"
        output += f"P(proto={proto}|normal) = {probabilities[f'P(proto={proto}|normal)']:.4f}\n"

    # Step 5: Count threshold probabilities
    attack_counts = raw_df[raw_df["attack"] == 1]["count"].tolist()
    normal_counts = raw_df[raw_df["attack"] == 0]["count"].tolist()
    threshold = max(normal_counts)
    df["count_flag"] = raw_df["count"].apply(lambda x: 1 if x > threshold else 0)

    def laplace_count(feature, value, given):
        return (df[(df[feature] == value) & (df["attack"] == given)].shape[0] + alpha) / \
               (df[df["attack"] == given].shape[0] + alpha * N)

    count_probs = {
        f"P(count>{threshold}|attack=1)": laplace_count("count_flag", 1, 1),
        f"P(count<={threshold}|attack=1)": laplace_count("count_flag", 0, 1),
        f"P(count>{threshold}|attack=0)": laplace_count("count_flag", 1, 0),
        f"P(count<={threshold}|attack=0)": laplace_count("count_flag", 0, 0)
    }

    output += f"\n🔹 Count Threshold = {threshold}\n"
    output += f"Attack = {attack_counts}\n"
    output += f"\nNormal = {normal_counts}\n"
    for k, v in count_probs.items():
        output += f"{k} = {v:.4f}\n"

    nb_preprocess_text.delete("1.0", tk.END)
    nb_preprocess_text.insert(tk.END, output)

# --- Run Button ---
run_nb_btn = ttk.Button(nb_preprocess_frame, text="Run Scaling & Smoothing", command=run_nb_preprocessing, bootstyle="success")
run_nb_btn.pack(pady=10)

# --- Add Next Button from Attack Frame ---
next_to_nb_pre_btn = ttk.Button(attack_frame, text="Next ➡️", command=lambda: [attack_frame.pack_forget(), nb_preprocess_frame.pack(fill=BOTH, expand=True)], bootstyle="info-outline")
next_to_nb_pre_btn.pack(pady=10)

# --- Naive Bayes Final Prediction Frame ---
nb_result_frame = ttk.Frame(app)

nb_result_label = ttk.Label(nb_result_frame, text="Final Naive Bayes Predictions", font=("Helvetica", 20))
nb_result_label.pack(pady=20)

nb_result_text = tk.Text(nb_result_frame, wrap="word", font=("Consolas", 11), height=25, width=120, bg="#0d1117", fg="white")
nb_result_text.pack(padx=10, pady=10)

# --- Final Naive Bayes Prediction Function ---
def run_nb_prediction():
    global probabilities, count_probs, threshold, p_attack, p_normal

    syn_value = 1
    count_feature = True  # count > threshold

    protocols = {
        'TCP': 0,
        'UDP': 1,
        'ICMP': 2,
        'DISCOVER': 3,
        'Other': 4
    }

    output = "\n🔍 Naive Bayes Protocol-wise Predictions:\n"
    with open("Naive_results.txt", "w") as f:
        for proto_name, proto_value in protocols.items():
            p_syn_given_attack = probabilities[f'P(SYN={syn_value}|attack)']
            p_proto_given_attack = probabilities[f'P(proto={proto_value}|attack)']
            p_count_given_attack = count_probs[f'P(count>{threshold}|attack=1)'] if count_feature else count_probs[f'P(count<={threshold}|attack=1)']

            p_syn_given_normal = probabilities[f'P(SYN={syn_value}|normal)']
            p_proto_given_normal = probabilities[f'P(proto={proto_value}|normal)']
            p_count_given_normal = count_probs[f'P(count>{threshold}|attack=0)'] if count_feature else count_probs[f'P(count<={threshold}|attack=0)']

            score_attack = p_attack * p_syn_given_attack * p_proto_given_attack * p_count_given_attack
            score_normal = p_normal * p_syn_given_normal * p_proto_given_normal * p_count_given_normal

            prediction = "🚨 ATTACK" if score_attack > score_normal else "✅ NORMAL"

            result = f"""
🔍 Protocol: {proto_name} ({proto_value})
🧮 Naive Bayes Scores:
P(Attack|F) = {score_attack:.10f}
P(Normal|F) = {score_normal:.10f}
{prediction}
"""
            output += result
            with open("Naive_results.txt", "w", encoding="utf-8") as f:
                f.write(result)

    nb_result_text.delete("1.0", tk.END)
    nb_result_text.insert(tk.END, output)
    print("✅ Naive Bayes results saved to 'Naive_results.txt'!")

# --- Run Button ---
nb_result_btn = ttk.Button(nb_result_frame, text="Generate Naive Bayes Results", command=run_nb_prediction, bootstyle="success")
nb_result_btn.pack(pady=10)

# --- Next Button from Previous Frame ---
next_to_nb_result_btn = ttk.Button(nb_preprocess_frame, text="Next ➡️", command=lambda: [nb_preprocess_frame.pack_forget(), nb_result_frame.pack(fill=BOTH, expand=True)], bootstyle="info-outline")
next_to_nb_result_btn.pack(pady=10)

# --- ID3 Decision Tree Frame ---
id3_frame = ttk.Frame(app)

id3_label = ttk.Label(id3_frame, text="ID3 Decision Tree & Predictions", font=("Helvetica", 20))
id3_label.pack(pady=20)

# Tree image display
id3_canvas = tk.Canvas(id3_frame, width=900, height=400, bg="white")
id3_canvas.pack(padx=10, pady=10)

# Output Text Area
id3_result_text = tk.Text(id3_frame, wrap="word", font=("Consolas", 11), height=10, width=120, bg="#0d1117", fg="white")
id3_result_text.pack(padx=10, pady=10)

from PIL import Image, ImageTk

# Function to run ID3 algorithm and show results
def run_id3():
    global df
    import matplotlib.pyplot as plt
    from sklearn.tree import DecisionTreeClassifier
    from sklearn import tree
    import matplotlib.image as mpimg

    raw_df = pd.read_csv("output.csv")

    def bin_count(value):
        if value <= 0.0005:
            return 'low'
        elif value <= 0.005:
            return 'medium'
        else:
            return 'high'

    raw_df['count_binned'] = raw_df['count'].apply(bin_count)
    raw_df['count_binned'] = raw_df['count_binned'].astype('category').cat.codes

    features = ['SYN_Packet', 'proto_encoded', 'count_binned']
    target = 'attack'
    X = raw_df[features]
    y = raw_df[target]

    clf = DecisionTreeClassifier(criterion='entropy', max_depth=4)
    clf.fit(X, y)

    plt.figure(figsize=(16, 8))
    tree.plot_tree(clf, feature_names=features, class_names=["Normal", "Attack"], filled=True)
    plt.savefig("id3_tree.png")
    plt.close()

    image = Image.open("id3_tree.png")
    resized_image = image.resize((900, 400))
    resized_image.save("id3_tree.png")

    img = tk.PhotoImage(file="id3_tree.png")
    id3_canvas.image = img
    id3_canvas.create_image(0, 0, anchor="nw", image=img)

    protocols = {
        'TCP': 0,
        'UDP': 1,
        'ICMP': 2,
        'DISCOVER': 3,
        'Other': 4
    }

    output = "🔍 Predictions for each protocol using ID3 Decision Tree\n\n"
    with open("ID3_results.txt", "w") as f:
        f.write(output)
        for proto_name, proto_code in protocols.items():
            sample = pd.DataFrame([[1, proto_code, 2]], columns=features)
            prediction = clf.predict(sample)[0]
            result = "🚨 ATTACK" if prediction == 1 else "✅ NORMAL"
            result_text = f"🔍 Protocol: {proto_name} ({proto_code}) → {result}\n"
            output += result_text
            f.write(result_text)

    id3_result_text.delete("1.0", tk.END)
    id3_result_text.insert(tk.END, output)
    print("✅ ID3 Decision Tree results saved to 'ID3_results.txt'!")

# Run Button
run_id3_btn = ttk.Button(id3_frame, text="Run ID3 Algorithm", command=run_id3, bootstyle="success")
run_id3_btn.pack(pady=10)

# Next Button from Naive Bayes to ID3
next_to_id3_btn = ttk.Button(nb_result_frame, text="Next ➡️", command=lambda: [nb_result_frame.pack_forget(), id3_frame.pack(fill=BOTH, expand=True)], bootstyle="info-outline")
next_to_id3_btn.pack(pady=10)

# --- Start Application ---
start_frame.pack(fill=BOTH, expand=True)
app.mainloop()