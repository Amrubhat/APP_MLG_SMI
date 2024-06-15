import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, make_scorer, classification_report
from sklearn.impute import SimpleImputer

# Column names for the NSL-KDD dataset
col_names = ["duration", "protocol_type", "service", "flag", "src_bytes",
             "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
             "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
             "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
             "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
             "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
             "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

# Load the dataset with specified column names
file_path = 'NSL_KDD.csv'  # Path to the uploaded NSL-KDD dataset
data = pd.read_csv(file_path, names=col_names, low_memory=False)

# Define the mapping from detailed attack types to main categories
category_mapping = {
    'normal': 'normal',
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS', 'teardrop': 'DoS',
    'mailbomb': 'DoS', 'apache2': 'DoS', 'processtable': 'DoS', 'udpstorm': 'DoS',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L', 'spy': 'R2L',
    'warezclient': 'R2L', 'warezmaster': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L',
    'snmpguess': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L', 'worm': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R', 'httptunnel': 'U2R',
    'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe'
}

# Apply the mapping to the dataset
data['label'] = data['label'].map(category_mapping)

# Drop rows with unmapped labels (if any)
data = data.dropna(subset=['label'])

# Convert appropriate columns to numeric, using coercion to handle errors
for col in col_names[:-1]:  # Exclude the label column
    data[col] = pd.to_numeric(data[col], errors='coerce')

# Data preprocessing
# Separate features (X) and target (y)
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

# Impute missing values for numerical data
num_imputer = SimpleImputer(strategy='mean')
X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])] = num_imputer.fit_transform(
    X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])])

# Encode the target variable if it's categorical
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Identify categorical columns
categorical_features = ["protocol_type", "service", "flag"]

# Preprocessing for numerical and categorical features
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), [col for col in X.columns if col not in categorical_features]),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
    ])

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Creating a pipeline that includes preprocessing and the object for the random forest classifer
rf_clf = Pipeline(steps=[('preprocessor', preprocessor),
                         ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])

rf_clf.fit(X_train, y_train)
y_pred_rf = rf_clf.predict(X_test)
print("RandomForest")
print(f"Accuracy: {accuracy_score(y_test, y_pred_rf):.5f}")
print(f"Precision: {precision_score(y_test, y_pred_rf, average='macro',zero_division=1):.5f}")
print(f"Recall: {recall_score(y_test, y_pred_rf, average='macro'):.5f}")
print(f"F1 Score: {f1_score(y_test, y_pred_rf, average='macro'):.5f}")
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred_rf))
print()

report = classification_report(y_test, y_pred_rf)
print(report)

plt.figure(figsize=(10, 8))
sns.heatmap(confusion_matrix(y_test, y_pred_rf), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix Heatmap for Random Forest on NSL-KDD (5 Main Categories)")
plt.show()

def rf_new():
    ch = int(input("Enter protocol type: \n1. TCP\n2. UDP\n"))
    if ch == 1:
        protocol = 'tcp'
    elif ch == 2:
        protocol = 'udp'
    else:
        protocol = ''
    ch = int(input("Enter flag type: \n1. Safe connection (SF)\n2. Connection Initiated but no response (S0)\n3. Rejection Connection (REJ)\n4. Connection Rest (RSTO)\n"))
    if ch == 1:
        flag = 'SF'
    elif ch == 2:
        flag = 'S0'
    elif ch == 3:
        flag = 'REJ'
    elif ch == 4:
        flag = 'RSTO'
    else:
        flag = ''
    ch = int(input("Enter the destination network service used:\n1. Private\n2. HTTP\n3. FTP\n4. SMTP\n5. Telnet\n"))
    if ch == 1:
        service = 'private'
    elif ch == 2:
        service = 'http'
    elif ch == 3:
        service = 'ftp'
    elif ch == 4:
        service = 'smtp'
    elif ch == 5:
        service = 'telnet'
    else:
        service = ''
    count = input("Enter the number of connections to the same host as the current connection in the past two seconds (0 - 511)\n")
    hosts = input('Enter the number of connections having the same destination host IP address (0 - 255)\n')
    test = [0,protocol,service,flag,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,count,10,0,0,1,1,0.04,0.06,0,hosts,10,0.04,0.06,0,0,0,0,1,1]
    test_df = pd.DataFrame([test], columns=col_names[:41])
    y_new = rf_clf.predict(test_df)
    print(f"Predicted Category: {label_encoder.inverse_transform(y_new)[0]}")

n = int(input("1. Predict a new value\n2. Exit\n"))
if n == 1:
    rf_new()
elif n==2:
    pass
else:
    print("Invalid Input")