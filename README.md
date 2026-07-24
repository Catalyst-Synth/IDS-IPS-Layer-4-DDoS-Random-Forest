# IDS/IPS Layer 4 DDoS Mitigation using Random Forest

This repository contains the source code, datasets, and machine learning pipeline for a final project focused on implementing an Intrusion Detection and Prevention System (IDPS) on a single-board computer. The system is designed to detect and mitigate Layer 4 Distributed Denial of Service (DDoS) attacks using a Random Forest classification algorithm.

The core scripts are optimized to run on an **Orange Pi R1 Plus LTS**, providing real-time network traffic monitoring and automated mitigation responses.

## 📁 Repository Structure

The project is structured into three main phases: Dataset Recording, Data Preprocessing & Modeling (Jupyter Notebooks), and Live Deployment.

### 1. Dataset Recorder on Orange Pi
Contains the tools used to capture and record network traffic directly from the Orange Pi interface.
* **`opi_dataset_recorder.py`**: The primary Python script used to sniff, extract Layer 4 features, and log network traffic into CSV format that run in Orange Pi.
* **`Dataset/`**: A collection of CSV files containing both normal traffic and various attack simulations (e.g., `attack_final.csv`, `dataset_balanced_final.csv`, `opi_builder_c_live_record.csv`, and testing splits `test1.csv` - `test4.csv`).

### 2. Machine Learning Pipeline (Jupyter Notebooks)
A sequential set of notebooks documenting the entire data science workflow, from raw data processing to model tuning:
* **`01_dataset_cek.ipynb`**: Initial data inspection and validation.
* **`02_gabungan_test.ipynb` & `03_combine_old_with_new_attack.ipynb`**: Merging historical and newly captured attack datasets.
* **`04_uji_coba_balance.ipynb` & `05_coba_traintest.ipynb`**: Handling class imbalances and splitting the data for training/testing.
* **`06_EDA.ipynb`**: Exploratory Data Analysis to visualize traffic patterns and feature distributions.
* **`07_baseline_model.ipynb` & `07_RF_tuning.ipynb`**: Training the baseline classifier and executing hyperparameter tuning for the Random Forest model to achieve optimal accuracy.
* **`08_feature_importance.ipynb`**: Analyzing which network features contribute most significantly to detecting DDoS patterns.

### 3. IDS-IPS Script on Orange Pi
The deployment phase of the project.
* **`idps_opi_v3.py`**: The finalized active monitoring script. It captures live packets, extracts the necessary features, passes them through the trained Random Forest model, and executes mitigation protocols (IPS) upon detecting malicious Layer 4 activity.

## ⚙️ Ignored Files (Local Only)
As defined in the `.gitignore`, the following directories are kept local to the development machine and are not tracked in this repository due to file size constraints and workspace configurations:
* `.vscode/` (Local IDE settings)
* `syn/` (Raw or oversized SYN flood capture files)
* `revisi (imbalance class)/` (Archived experimental revisions)

## 🚀 Getting Started

### Prerequisites
To run the live IDPS script, ensure the target environment (e.g., Orange Pi / Linux Debian-based OS) has the following installed:
* Python 3.9 for compatible orange pi
* Required Python libraries: `scikit-learn 1.2.1`, `Numpy 1.24.2` , `pandas`, `scapy`, `joblib`.
* Root/Sudo privileges are required for capturing live network packets and executing firewall iptables (IPS) rules.

### Running the IDPS
Navigate to the deployment folder and execute the script with root privileges

