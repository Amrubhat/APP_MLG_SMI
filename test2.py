import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.decomposition import PCA
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
        ('cat', OneHotEncoder(), categorical_features)
    ])

# Create a pipeline that includes preprocessing, PCA, and the classifier
n_components = 20  # Set the number of principal components

rf_clf_pca = Pipeline(steps=[('preprocessor', preprocessor),
                             ('pca', PCA(n_components=n_components)),
                             ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])



# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(X.shape)

# Train and evaluate the RandomForest model with PCA
# Train and evaluate the RandomForest model with PCA
def RandomForestPCA():
    
    
    # Transform the training data to check the shape after PCA
    X_train_pca = rf_clf_pca.named_steps['pca'].transform(rf_clf_pca.named_steps['preprocessor'].transform(X_train))
    print(f"Shape of the dataset after PCA: {X_train_pca.shape}")

    rf_clf_pca.fit(X_train_pca, y_train) 

    X_test_pca = rf_clf_pca.named_steps['pca'].transform(rf_clf_pca.named_steps['preprocessor'].transform(X_test))
    y_pred_rf_pca = rf_clf_pca.predict(X_test_pca)
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

    # Save the RandomForest model with PCA
    joblib.dump(rf_clf_pca, 'random_forest_pca_model.pkl')

# Run the RandomForest with PCA function
RandomForestPCA()

# import pandas as pd
# from sklearn.preprocessing import StandardScaler, LabelEncoder
# from sklearn.decomposition import PCA
# import matplotlib.pyplot as plt

# # Step 1: Load the Dataset
# # Replace 'path_to_dataset' with the actual path to the NSL-KDD dataset file
# file_path = 'NSL_KDD.csv'
# df = pd.read_csv(file_path)

# # Step 2: Preprocess the Data
# # Check for missing values
# if df.isnull().sum().any():
#     df = df.dropna()

# # Encode categorical variables
# categorical_columns = df.select_dtypes(include=['object']).columns
# label_encoders = {}
# for col in categorical_columns:
#     label_encoders[col] = LabelEncoder()
#     df[col] = label_encoders[col].fit_transform(df[col])

# # Separate features and labels
# X = df.drop('label', axis=1)
# y = df['label']

# # Standardize the features
# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X)

# # Step 3: Apply PCA
# # Number of components to keep
# n_components = 2
# pca = PCA(n_components=n_components)
# X_pca = pca.fit_transform(X_scaled)

# # Step 4: Analyze the Results
# # Explained variance ratio
# explained_variance_ratio = pca.explained_variance_ratio_
# print('Explained variance ratio:', explained_variance_ratio)

# # Plot the first two principal components
# plt.figure(figsize=(8, 6))
# plt.scatter(X_pca[:, 0], X_pca[:, 1], c=y, cmap='viridis', edgecolor='k', s=40)
# plt.xlabel('First Principal Component')
# plt.ylabel('Second Principal Component')
# plt.title('PCA of NSL-KDD Dataset')
# plt.colorbar()
# plt.show()
