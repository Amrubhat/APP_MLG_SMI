import streamlit as st
import pandas as pd
import joblib
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
file_path = 'NSL_KDD.csv'
data = pd.read_csv(file_path, names=col_names, low_memory=False)

# Define the mapping from detailed attack types to main categories
category_mapping = {
    'normal': 'normal',
    'back': 'DoS',
    'land': 'DoS',
    'neptune': 'DoS',
    'pod': 'DoS',
    'smurf': 'DoS',
    'teardrop': 'DoS',
    'mailbomb': 'DoS',
    'apache2': 'DoS',
    'processtable': 'DoS',
    'udpstorm': 'DoS',
    'ftp_write': 'R2L',
    'guess_passwd': 'R2L',
    'imap': 'R2L',
    'multihop': 'R2L',
    'phf': 'R2L',
    'spy': 'R2L',
    'warezclient': 'R2L',
    'warezmaster': 'R2L',
    'sendmail': 'R2L',
    'named': 'R2L',
    'snmpgetattack': 'R2L',
    'snmpguess': 'R2L',
    'xlock': 'R2L',
    'xsnoop': 'R2L',
    'worm': 'R2L',
    'buffer_overflow': 'U2R',
    'loadmodule': 'U2R',
    'perl': 'U2R',
    'rootkit': 'U2R',
    'httptunnel': 'U2R',
    'ps': 'U2R',
    'sqlattack': 'U2R',
    'xterm': 'U2R',
    'ipsweep': 'Probe',
    'nmap': 'Probe',
    'portsweep': 'Probe',
    'satan': 'Probe',
    'mscan': 'Probe',
    'saint': 'Probe'
}

# Apply the mapping to the dataset
data['label'] = data['label'].map(category_mapping)

# Drop rows with unmapped labels (if any)
data = data.dropna(subset=['label'])

# Convert appropriate columns to numeric, using coercion to handle errors
for col in col_names[:-1]:
    data[col] = pd.to_numeric(data[col], errors='coerce')

# Data preprocessing
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

# Impute missing values for numerical data
num_imputer = SimpleImputer(strategy='mean')
X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])] = num_imputer.fit_transform(X.loc[:, X.columns.difference(['protocol_type', 'service', 'flag'])])

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
    ]
)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Creating a pipeline that includes preprocessing and the object for the random forest classifier
rf_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])

# Creating a pipeline that includes preprocessing and the object for the support vector machine classifier
svm_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', SVC(kernel='linear', random_state=42))])

# Creating a pipeline that includes preprocessing and the object for the ensembling voter classifier
voting_clf = Pipeline(steps=[('preprocessor', preprocessor), ('classifier', VotingClassifier(estimators=[('rf', rf_clf.named_steps['classifier']), ('svc', svm_clf.named_steps['classifier'])], voting='hard'))])

# Performing Principal Component Analysis to decompose the 41 existing features to only 20 features
n_components = 20

# Set the number of principal components
pca = PCA(n_components=n_components)

# Create a Streamlit app
st.title("NSL-KDD Classification Models")
st.header("Choose a Model")
model_choice = st.selectbox("Select a Model", ["Random Forest", "Support Vector Machine", "Ensembling Voting Classifier"], key="model_pred")

def rf_new(test_df):
    y_new = rf_clf.predict(test_df)
    st.write(f"Predicted Category: {label_encoder.inverse_transform(y_new)[0]}")

def svm_new(test_df):
    y_new = svm_clf.predict(test_df)
    st.write(f"Predicted Category: {label_encoder.inverse_transform(y_new)[0]}")

def Ensembling_new(test_df):
    y_new = voting_clf.predict(test_df)
    st.write(f"Predicted Category: {label_encoder.inverse_transform(y_new)[0]}")

# def new():
#     with st.form(key='predict_form'):
#         protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"], key = '1')
#         service = st.selectbox("Service", ["http", "smtp", "ftp", "ssh", "telnet"], key = '2')
#         flag = st.selectbox("Flag", ["SF", "S0", "REJ", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTR", "SH", "OTH"], key = '3')
#         count = st.number_input("Enter the number of connections to the same host as the current connection in the past two seconds (0 - 511)", min_value=0, max_value=511, step=1, key = '4')
#         hosts = st.number_input("Enter the number of connections having the same destination host IP address (0 - 255)", min_value=0, max_value=255, step=1, key = '5')
#         submit_button = st.form_submit_button(label='Enter')

#     if submit_button:
#         return protocol,service,flag,count,hosts

def input():
    with st.form(key='predict_form'):
        protocol = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"], key='protocol')
        service = st.selectbox("Service", ["http", "smtp", "ftp", "ssh", "telnet"], key='service')
        flag = st.selectbox("Flag", ["SF", "S0", "REJ", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTR", "SH", "OTH"], key='flag')
        count = st.number_input("Enter the number of connections to the same host as the current connection in the past two seconds (0 - 511)", min_value=0, max_value=511, step=1, key='count')
        hosts = st.number_input("Enter the number of connections having the same destination host IP address (0 - 255)", min_value=0, max_value=255, step=1, key='hosts')
        submit_button = st.form_submit_button(label='Enter')

        if submit_button:
            test = [0, protocol, service, flag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count, 10, 0, 0, 1, 1, 0.04, 0.06, 0, hosts, 10, 0.04, 0.06, 0, 0, 0, 0, 1, 1]
            test_df = pd.DataFrame([test], columns=col_names[:-1])
            st.write("Submitted")
            predict(test_df)

def predict(test_df):
    st.header("Choose a Model for Prediction")
    model_pred = st.selectbox("Select a Model", ["Random Forest", "Support Vector Machine", "Ensembling Voting Classifier"])
    if model_pred == "Random Forest":
        run_pred = st.button("Run Random Forest Prediction")
        if run_pred:
            rf_new(test_df)
    elif model_pred == "Support Vector Machine":
        run_pred = st.button("Run Support Vector Machine Prediction")
        if run_pred:
            svm_new(test_df)
    elif model_pred == "Ensembling Voting Classifier":
        run_pred = st.button("Run Ensembling Voting Classifier Prediction")
        if run_pred:
            Ensembling_new(test_df)
                
   

if model_choice == "Random Forest":
    run_button = st.button("Run Random Forest")
    if run_button:
        # Train and evaluate the Random Forest model
        rf_clf.fit(X_train, y_train)
        y_pred_rf = rf_clf.predict(X_test)
        st.write("Random Forest")
        st.write(f"Accuracy: {accuracy_score(y_test, y_pred_rf):.5f}")
        st.write(f"Precision: {precision_score(y_test, y_pred_rf, average='macro', zero_division=1):.5f}")
        st.write(f"Recall: {recall_score(y_test, y_pred_rf, average='macro'):.5f}")
        st.write(f"F1 Score: {f1_score(y_test, y_pred_rf, average='macro'):.5f}")
        st.write("Confusion Matrix:")
        st.write(confusion_matrix(y_test, y_pred_rf))
        st.write(classification_report(y_test, y_pred_rf))
        plt.figure(figsize=(10, 8))
        sns.heatmap(confusion_matrix(y_test, y_pred_rf), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.title("Confusion Matrix Heatmap for Random Forest on NSL-KDD (5 Main Categories)")
        # plt.show()
        plt.savefig('random_forest_confusion_matrix.png')
        st.image('random_forest_confusion_matrix.png', caption='Confusion Matrix Heatmap for Random Forest on NSL-KDD (5 Main Categories)')
        joblib.dump(rf_clf, 'random_forest_model.pkl')
        choice = st.radio("Predict a custom user input:", ["Yes", "No"])

        # Process the user's choice
        if choice == "Yes":
            input()
        else:
            st.write("End of Execution")

elif model_choice == "Support Vector Machine":
    run_button = st.button("Run Support Vector Machine")
    if run_button:
    # Train and evaluate the Support Vector Machine model
        svm_clf.fit(X_train, y_train)
        y_pred_svm = svm_clf.predict(X_test)
        st.write("Support Vector Machine")
        st.write(f"Accuracy: {accuracy_score(y_test, y_pred_svm):.5f}")
        st.write(f"Precision: {precision_score(y_test, y_pred_svm, average='macro', zero_division=1):.5f}")
        st.write(f"Recall: {recall_score(y_test, y_pred_svm, average='macro', zero_division=1):.5f}")
        st.write(f"F1 Score: {f1_score(y_test, y_pred_svm, average='macro'):.5f}")
        st.write("Confusion Matrix:")
        st.write(confusion_matrix(y_test, y_pred_svm))
        st.write(classification_report(y_test, y_pred_svm))
        plt.figure(figsize=(10, 8))
        sns.heatmap(confusion_matrix(y_test, y_pred_svm), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.title("Confusion Matrix Heatmap for Support Vector Machine on NSL-KDD (5 Main Categories)")
        # plt.show()
        plt.savefig('support_vector_machine_confusion_matrix.png')
        st.image('support_vector_machine_confusion_matrix.png', caption='Confusion Matrix Heatmap for Support Vector Machine on NSL-KDD (5 Main Categories)')
        joblib.dump(svm_clf, 'svm_model.pkl')
        choice = st.radio("Predict a custom user input:", ["Yes", "No"])

        # Process the user's choice
        if choice == "Yes":
            input()
        else:
            st.write("End of Execution")

elif model_choice == "Ensembling Voting Classifier":
    run_button = st.button("Run Ensembling Voting Classifier")
    if run_button:
    # Train and evaluate the Ensembling Voting Classifier model
        voting_clf.fit(X_train, y_train)
        y_pred_voting = voting_clf.predict(X_test)
        st.write("Voting Classifier (Ensembling):")
        st.write(f"Accuracy: {accuracy_score(y_test, y_pred_voting):.5f}")
        st.write(f"Precision: {precision_score(y_test, y_pred_voting, average='macro', zero_division=1):.5f}")
        st.write(f"Recall: {recall_score(y_test, y_pred_voting, average='macro', zero_division=1):.5f}")
        st.write(f"F1 Score: {f1_score(y_test, y_pred_voting, average='macro'):.5f}")
        st.write("Confusion Matrix:")
        st.write(confusion_matrix(y_test, y_pred_voting))
        st.write(classification_report(y_test, y_pred_voting))
        plt.figure(figsize=(10, 8))
        sns.heatmap(confusion_matrix(y_test, y_pred_voting), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.title("Confusion Matrix Heatmap for Voting Classifier Ensembling on NSL-KDD (5 Main Categories)")
        # plt.show()
        plt.savefig('ensembling_confusion_matrix.png')
        st.image('ensembling_confusion_matrix.png', caption='Confusion Matrix Heatmap for Ensembling Voting Classifier on NSL-KDD (5 Main Categories)')
        joblib.dump(voting_clf, 'voting_classifier_model.pkl')
        choice = st.radio("Predict a custom user input:", ["Yes", "No"])

        # Process the user's choice
        if choice == "Yes":
            input()
        else:
            st.write("End of Execution")

else:
    st.write("Invalid Model Choice")
