import pandas as pd
import sqlite3
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
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

# Encode the target variable
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Identify categorical columns
categorical_features = ["protocol_type", "service", "flag"]

# Preprocessing for numerical and categorical features
preprocessor = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), [col for col in X.columns if col not in categorical_features]),
        ('cat', OneHotEncoder(), categorical_features)
    ])

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Model Pipelines
def create_pipeline(model, use_pca=False, n_components=20):
    steps = [('preprocessor', preprocessor)]
    if use_pca:
        steps.append(('pca', PCA(n_components=n_components)))
    steps.append(('classifier', model))
    return Pipeline(steps=steps)

rf_clf = create_pipeline(RandomForestClassifier(n_estimators=100, random_state=42))
svm_clf = create_pipeline(SVC(kernel='linear', random_state=42))
voting_clf = create_pipeline(VotingClassifier(estimators=[
    ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
    ('svc', SVC(kernel='linear', random_state=42))
], voting='hard'))

# Evaluation Function
def evaluate_model(model, X_train, y_train, X_test, y_test, label_encoder):
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(model.named_steps['classifier'].__class__.__name__)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.5f}")
    print(f"Precision: {precision_score(y_test, y_pred, average='macro', zero_division=1):.5f}")
    print(f"Recall: {recall_score(y_test, y_pred, average='macro'):.5f}")
    print(f"F1 Score: {f1_score(y_test, y_pred, average='macro'):.5f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print()

    report = classification_report(y_test, y_pred)
    print(report)

    plt.figure(figsize=(10, 8))
    sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt="d", cmap="YlGnBu", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(f"Confusion Matrix Heatmap for {model.named_steps['classifier'].__class__.__name__} on NSL-KDD (5 Main Categories)")
    plt.show()

    # Save the model
    model_filename = model.named_steps['classifier'].__class__.__name__.lower() + ('_pca' if 'pca' in model.named_steps else '') + '_model.pkl'
    joblib.dump(model, model_filename)

# Model Selection and Evaluation
def main():
    n = int(input("Choose your Machine Learning Model:\n1. Random Forest Classifier\n2. Support Vector Machine\n3. Voting Classifier\n4. All Models\n"))
    m = int(input("Which dataset:\n1. Original Dataset\n2. PCA Decomposed Dataset\n3. Both\n"))

    if n == 1:
        if m == 1:
            evaluate_model(rf_clf, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 2:
            rf_clf_pca = create_pipeline(RandomForestClassifier(n_estimators=100, random_state=42), use_pca=True)
            evaluate_model(rf_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 3:
            evaluate_model(rf_clf, X_train, y_train, X_test, y_test, label_encoder)
            rf_clf_pca = create_pipeline(RandomForestClassifier(n_estimators=100, random_state=42), use_pca=True)
            evaluate_model(rf_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        else:
            print("Invalid Input")
    elif n == 2:
        if m == 1:
            evaluate_model(svm_clf, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 2:
            svm_clf_pca = create_pipeline(SVC(kernel='linear', random_state=42), use_pca=True)
            evaluate_model(svm_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 3:
            evaluate_model(svm_clf, X_train, y_train, X_test, y_test, label_encoder)
            svm_clf_pca = create_pipeline(SVC(kernel='linear', random_state=42), use_pca=True)
            evaluate_model(svm_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        else:
            print("Invalid Input")
    elif n == 3:
        if m == 1:
            evaluate_model(voting_clf, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 2:
            voting_clf_pca = create_pipeline(VotingClassifier(estimators=[
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('svc', SVC(kernel='linear', random_state=42))
            ], voting='hard'), use_pca=True)
            evaluate_model(voting_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 3:
            evaluate_model(voting_clf, X_train, y_train, X_test, y_test, label_encoder)
            voting_clf_pca = create_pipeline(VotingClassifier(estimators=[
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('svc', SVC(kernel='linear', random_state=42))
            ], voting='hard'), use_pca=True)
            evaluate_model(voting_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        else:
            print("Invalid Input")
    elif n == 4:
        if m == 1:
            evaluate_model(rf_clf, X_train, y_train, X_test, y_test, label_encoder)
            evaluate_model(svm_clf, X_train, y_train, X_test, y_test, label_encoder)
            evaluate_model(voting_clf, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 2:
            rf_clf_pca = create_pipeline(RandomForestClassifier(n_estimators=100, random_state=42), use_pca=True)
            svm_clf_pca = create_pipeline(SVC(kernel='linear', random_state=42), use_pca=True)
            voting_clf_pca = create_pipeline(VotingClassifier(estimators=[
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('svc', SVC(kernel='linear', random_state=42))
            ], voting='hard'), use_pca=True)
            evaluate_model(rf_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
            evaluate_model(svm_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
            evaluate_model(voting_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        elif m == 3:
            evaluate_model(rf_clf, X_train, y_train, X_test, y_test, label_encoder)
            rf_clf_pca = create_pipeline(RandomForestClassifier(n_estimators=100, random_state=42), use_pca=True)
            evaluate_model(rf_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
            evaluate_model(svm_clf, X_train, y_train, X_test, y_test, label_encoder)
            svm_clf_pca = create_pipeline(SVC(kernel='linear', random_state=42), use_pca=True)
            evaluate_model(svm_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
            evaluate_model(voting_clf, X_train, y_train, X_test, y_test, label_encoder)
            voting_clf_pca = create_pipeline(VotingClassifier(estimators=[
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('svc', SVC(kernel='linear', random_state=42))
            ], voting='hard'), use_pca=True)
            evaluate_model(voting_clf_pca, X_train, y_train, X_test, y_test, label_encoder)
        else:
            print("Invalid Input")
    else:
        print("Invalid Input")

if __name__ == "__main__":
    main()
