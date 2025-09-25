# Sniff, Learn, Detect: A Lightweight ML-Based Intrusion Detection Method Using Packet Features

[cite_start]**Project by: Harshita Kumawat & Kushagra Gupta** [cite: 2, 21]  
[cite_start]**Under the guidance of: Dr. Devika Kataria** [cite: 23]  
[cite_start]*A Minor Project for JK Lakshmipat University, April 2025* [cite: 19, 31]

---

### Overview

[cite_start]This project is a lightweight and efficient framework for real-time network threat detection using machine learning. [cite: 18, 44] [cite_start]In an era of increasing digitalization, traditional Intrusion Detection Systems (IDS) often fail to detect novel attack patterns. [cite: 63, 64] [cite_start]This tool leverages machine learning to analyze packet traffic, classify it as normal or malicious, and assess the severity of detected attacks. [cite: 51, 71]

### Features

* [cite_start]**PCAP to CSV Conversion**: Loads raw `.pcap` or `.pcapng` network capture files and converts them into a structured CSV format for analysis. [cite: 36, 84]
* [cite_start]**Feature Engineering**: Extracts and preprocesses key features from packets, including protocol type, SYN flags, and traffic counts. [cite: 37, 105, 107]
* [cite_start]**Naive Bayes Classification**: Classifies network packets as either normal or malicious using a Naive Bayes classifier with Laplace Smoothing to handle zero-probability issues. [cite: 38, 129]
* [cite_start]**ID3 Decision Tree Analysis**: Further analyzes malicious traffic to determine the severity of an attack (e.g., "Just Started," "In Progress," or "Critical") based on entropy and information gain. [cite: 42, 133]
* **Interactive GUI**: A user-friendly interface built with Tkinter and TTKBootstrap to guide the user through the analysis workflow.

### Methodology

The project employs a two-stage machine learning approach:

1.  [cite_start]**Naïve Bayes Classifier**: Used for the initial binary classification of packets (normal vs. malicious). [cite: 128] [cite_start]It calculates the probability of an attack based on features like `SYN_Packet`, `protocol_type`, and `count`. [cite: 128]
2.  [cite_start]**ID3 Decision Tree**: After a potential attack is flagged, a Decision Tree built with the ID3 algorithm classifies the threat level. [cite: 132] [cite_start]It uses entropy and information gain to split the data based on the most relevant features, providing clear and interpretable results. [cite: 133, 227]

### Repository Structure

```
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── data/
│   └── DHCP_starvaation.pcapng
├── reports/
│   ├── Abstract.pdf
│   └── Minor_Project_Report.pdf
└── src/
    ├── malware.ipynb
    └── newCode.py
```

### Setup and Usage

To run this project locally, follow these steps:

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourUsername/ML-Based-Intrusion-Detection.git](https://github.com/YourUsername/ML-Based-Intrusion-Detection.git)
    cd ML-Based-Intrusion-Detection
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the required libraries:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application:**
    ```bash
    python src/newCode.py
    ```
    The GUI will launch. Start by loading your `.pcap` file and follow the steps in the application.

### Results

The Naive Bayes model successfully identified attack patterns in UDP, ICMP, and DISCOVER traffic. [cite: 191, 192, 195] The Decision Tree provided a clear visualization of the classification logic, correctly flagging high-volume DISCOVER traffic as an attack while categorizing most other protocols as normal based on the training data. [cite: 203, 204]

![ID3 Decision Tree](./id3_tree.png)  
*(To show this image, you'll need to run the `newCode.py` script once to generate `id3_tree.png` and then move it to the root directory of your repository.)*

---
