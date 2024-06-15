import pandas as pd
import streamlit as st
from datetime import datetime
import sqlite3
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, make_scorer, classification_report
from sklearn.impute import SimpleImputer
import joblib

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

# Read the dataset and handle potential issues
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

# Creating a pipeline that includes preprocessing and the object for the support vector machine classifer
svm_clf = Pipeline(steps=[('preprocessor', preprocessor),
                                ('classifier', SVC(kernel='linear', random_state=42))])

# Creating a pipeline that includes preprocessing and the object for the ensembling voter classifer
voting_clf = Pipeline(steps=[('preprocessor', preprocessor),
                                ('classifier', VotingClassifier(estimators=[('rf', rf_clf.named_steps['classifier']),
                                                                    ('svc', svm_clf.named_steps['classifier'])], voting='hard'))])

# Performing Principal Component Analysis to decompose the 41 existing features to only 20 features
n_components = 20  # Set the number of principal components

# Creating a pipeline that includes preprocessing, PCA, and the classifier
pca = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('pca', PCA(n_components=n_components)),
])
imputer = SimpleImputer(strategy='mean')
X = imputer.fit_transform(X)
pca = PCA(n_components=n_components)

# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train_P, X_test_P, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train_pca = pca.fit(X_train_P)
X_test_pca = pca.fit(X_test_P)
#X_pca.shape()

# Creating Database Connection Object and Cursor
conn = sqlite3.connect('predictions.db')
c = conn.cursor()


# Train and evaluate the Random Forest model
def RandomForest():
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

    # Save the Random Forest model
    joblib.dump(rf_clf, 'random_forest_model.pkl')


# Train and evaluate the Random Forest model after PCA decomposition
def RandomForestPCA():
    rf_clf.fit(X_train_pca, y_train)
    y_pred_rf_pca = pca.predict(X_test_pca)
    print("RandomForest with PCA")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_rf_pca):.5f}")
    print(f"Precision: {precision_score(y_test, y_pred_rf_pca, average='macro', zero_division=1):.5f}")
    print(f"Recall: {recall_score(y_test, y_pred_rf_pca, average='macro'):.5f}")
    print(f"F1 Score: {f1_score(y_test, y_pred_rf_pca, average='macro'):.5f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_rf_pca))
    print()

    report = classification_report(y_test, y_pred_rf_pca)
    print(report)

    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_matrix(y_test, y_pred_rf_pca), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix Heatmap for Random Forest with PCA on NSL-KDD (5 Main Categories)")
    plt.show()

    # Save the Random Forest model after PCA Decomposition
    joblib.dump(rf_clf, 'random_forest_pca_model.pkl')

# Train and evaluate the Support Vector Machine model
def SVM():
    svm_clf.fit(X_train, y_train)
    y_pred_svm = svm_clf.predict(X_test)
    print("Support Vector Machine")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_svm):.5f}")
    print(f"Precision: {precision_score(y_test, y_pred_svm, average='macro',zero_division=1):.5f}")
    print(f"Recall: {recall_score(y_test, y_pred_svm, average='macro',zero_division=1):.5f}")
    print(f"F1 Score: {f1_score(y_test, y_pred_svm, average='macro'):.5f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_svm))
    print()

    report = classification_report(y_test, y_pred_svm)
    print(report)

    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_matrix(y_test, y_pred_svm), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix Heatmap for Support Vector Machine on NSL-KDD (5 Main Categories)")
    plt.show()

    # Save the Support Vector Machine model
    joblib.dump(svm_clf, 'svm_model.pkl')

# Train and evaluate the Support Vector Machine model after PCA decomposition
def SVMPCA():
    svm_clf.fit(X_train_pca, y_train)
    y_pred_svm_pca = pca.predict(X_test_pca)
    print("RandomForest with PCA")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_svm_pca):.5f}")
    print(f"Precision: {precision_score(y_test, y_pred_svm_pca, average='macro', zero_division=1):.5f}")
    print(f"Recall: {recall_score(y_test, y_pred_svm_pca, average='macro'):.5f}")
    print(f"F1 Score: {f1_score(y_test, y_pred_svm_pca, average='macro'):.5f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_svm_pca))
    print()

    report = classification_report(y_test, y_pred_svm_pca)
    print(report)

    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_matrix(y_test, y_pred_svm_pca), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix Heatmap for Random Forest with PCA on NSL-KDD (5 Main Categories)")
    plt.show()

    # Save the Support Vector Machine after PCA decomposition
    joblib.dump(svm_clf, 'svm_pca_model.pkl')

# Train and evaluate the Ensembling Voting Classifier
def Ensembling():
    voting_clf.fit(X_train, y_train)
    y_pred_voting = voting_clf.predict(X_test)
    print("Voting Classifier (Ensembling):")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_voting):.5f}")
    print(f"Precision: {precision_score(y_test, y_pred_voting, average='macro',zero_division=1):.5f}")
    print(f"Recall: {recall_score(y_test, y_pred_voting, average='macro',zero_division=1):.5f}")
    print(f"F1 Score: {f1_score(y_test, y_pred_voting, average='macro'):.5f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_voting))
    print()

    report = classification_report(y_test, y_pred_voting)
    print(report)

    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_matrix(y_test, y_pred_voting), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix Heatmap for Voting Classifier Ensembling on NSL-KDD (5 Main Categories)")
    plt.show()


    # Save the Ensembling Voting Classifier
    joblib.dump(voting_clf, 'voting_classifier_model.pkl')

# Train and evaluate the Ensembling Voting Classifier model after PCA decomposition
def EnsemblingPCA():

    voting_clf.fit(X_train_pca, y_train)
    y_pred_voting_pca = pca.predict(X_test_pca)
    print("RandomForest with PCA")
    print(f"Accuracy: {accuracy_score(y_test, y_pred_voting_pca):.5f}")
    print(f"Precision: {precision_score(y_test, y_pred_voting_pca, average='macro', zero_division=1):.5f}")
    print(f"Recall: {recall_score(y_test, y_pred_voting_pca, average='macro'):.5f}")
    print(f"F1 Score: {f1_score(y_test, y_pred_voting_pca, average='macro'):.5f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_voting_pca))
    print()

    report = classification_report(y_test, y_pred_voting_pca)
    print(report)

    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_matrix(y_test, y_pred_voting_pca), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix Heatmap for Random Forest with PCA on NSL-KDD (5 Main Categories)")
    plt.show()

    # Save the Ensembling Voter Classifier after PCA decomposition
    joblib.dump(voting_clf, 'voting_classifier_pca_model.pkl')

n = int(input("Choose your Machine Learning Model:\n1. Random Forest Classifier\n2. Support Vector Machine\n3. Voting Classifier\n4. All Models\n"))
m = int(input("Which dataset:\n1. Original Dataset\n2. PCA Decomposed Dataset\n3. Both\n"))
if n == 1:
    if m == 1:
        RandomForest()
    elif m == 2:
        RandomForestPCA()
    elif m == 3:
        RandomForest()
        RandomForestPCA()
    else:
        print("Invalid Input")
elif n==2:
    if m == 1:
        SVM()
    elif m == 2:
        SVMPCA()
    elif m == 3:
        SVM()
        SVMPCA()
    else:
        print("Invalid Input")
elif n==3:
    if m == 1:
        Ensembling()
    elif m == 2:
        EnsemblingPCA()
    elif m == 3:
        Ensembling()
        EnsemblingPCA()
    else:
        print("Invalid Input")
elif n==4:
    if m == 1:
        RandomForest()
        SVM()
        Ensembling()
    elif m == 2:
        RandomForestPCA()
        SVMPCA()
        EnsemblingPCA()
    elif m == 3:
        RandomForest()
        RandomForestPCA()
        SVM()
        SVMPCA()
        Ensembling()
        EnsemblingPCA()
    else:
        print("Invalid Input")
else:
    print("Invalid Input")

def rf_new(test_df):
    y_new = rf_clf.predict(test_df)
    return label_encoder.inverse_transform(y_new)[0]

def svm_new(test_df):
    y_new = svm_clf.predict(test_df)
    return label_encoder.inverse_transform(y_new)[0]

def Ensembling_new(test_df):
    y_new = voting_clf.predict(test_df)
    return label_encoder.inverse_transform(y_new)[0]


n = int(input("1. Predict a new value\n2. Exit\n"))
if n == 1:
    c.execute('''CREATE TABLE IF NOT EXISTS predictions (date_time TEXT PRIMARY KEY, PROTOCOL TEXT, FLAG TEXT, SERVICE TEXT, COUNTS INT, HOSTS INT,  prediction TEXT)''')
    conn.commit()
    protocol = int(input("Enter protocol type: \n1. TCP\n2. UDP\n")) - 1
    protocol = ['tcp', 'udp'][protocol]

    flag = int(input("Enter flag type: \n1. SF\n2. S0\n3. REJ\n4. RSTO\n")) - 1
    flag = ['SF', 'S0', 'REJ', 'RSTO'][flag]

    service = int(input("Enter the destination network service used:\n1. Private\n2. HTTP\n3. FTP\n4. SMTP\n5. Telnet\n")) - 1
    service = ['private', 'http', 'ftp', 'smtp', 'telnet'][service]

    count = int(input("Enter the number of connections to the same host as the current connection in the past two seconds (0 - 511)\n"))
    hosts = int(input("Enter the number of connections having the same destination host IP address (0 - 255)\n"))

    test = [0, protocol, service, flag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count, 10, 0, 0, 1, 1, 0.04, 0.06, 0, hosts, 10, 0.04, 0.06, 0, 0, 0, 0, 1, 1]
    test_df = pd.DataFrame([test], columns=col_names[:-1])

    ch = int(input("Choose the model:\n1. Random Forest\n2. Support Vector Machine\n3. Ensembling"))
    if ch == 1:
        cat = rf_new(test_df)
        print("Predicted Category: ",cat)
        c.execute('INSERT INTO predictions VALUES (?, ?, ?, ?, ?, ?, ?)', (datetime.now(), protocol, flag, service, count, hosts, cat))
        conn.commit()
        print("Updated in SQLite")
    elif ch == 2:
        cat = svm_new(test_df)
        print("Predicted Category: ",cat)
        c.execute('INSERT INTO predictions VALUES (?, ?, ?, ?, ?, ?, ?)', (datetime.now(), protocol, flag, service, count, hosts, cat))
        conn.commit()
        print("Updated in SQLite")

    elif ch == 3:
        cat = Ensembling_new(test_df)
        print("Predicted Category: ",cat)
        c.execute('INSERT INTO predictions VALUES (?, ?, ?, ?, ?, ?, ?)', (datetime.now(), protocol, flag, service, count, hosts, cat))
        conn.commit()
        print("Updated in SQLite")
    conn.close()
    
elif n==2:
    pass
else:
    print("Invalid Input")