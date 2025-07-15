# Network_Intrusion_Detection_System-
This project implements a machine learning-based Network Intrusion Detection System (NIDS) to automatically detect and classify different types of network attacks. It uses a large dataset, processes the data with feature selection, trains multiple models, and provides an interactive user interface built with Streamlit.
Key highlights:
Works with a large dataset (~2.5 million rows, 49 columns).
Performs data cleaning, one-hot encoding, and selects the top 50 important features.
Trains and evaluates Random Forest, XGBoost, and LightGBM models.
Provides comparison of accuracy, precision, F1 score, and training time.
Deploys an interactive Streamlit app to upload new data and see predictions.
Dataset used:
The dataset you used for this project is commonly known as the UNSW-NB15 dataset, which is widely available on Kaggle.
👉 Name:
UNSW-NB15 Network Intrusion Dataset
👉 Kaggle link (typical source):
https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
This dataset contains a mix of normal and malicious network traffic, with detailed labeling of attack categories such as Exploits, Fuzzers, Backdoor, DoS, Generic, Reconnaissance, Shellcode, and Worms. It is designed to simulate realistic network activities for intrusion detection research.
