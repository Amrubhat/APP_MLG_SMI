# %% 
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
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

# Convert appropriate columns to numeric, using coercion to handle errors
for col in col_names[:-1]:  # Exclude the label column
    data[col] = pd.to_numeric(data[col], errors='coerce')

# Data preprocessing
# Separate features (X) and target (y)
X = data.iloc[:, :-1]
y = data.iloc[:, -1]

# %%
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
        ('cat', OneHotEncoder(), categorical_features)
    ])

# Create a pipeline that includes preprocessing and the classifier
rf_clf = Pipeline(steps=[('preprocessor', preprocessor),
                         ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))])

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train and evaluate the RandomForest model
rf_clf.fit(X_train, y_train)
y_pred_rf = rf_clf.predict(X_test)
print("**All attacks - RandomForest**")
print(f"Accuracy: {accuracy_score(y_test, y_pred_rf):.5f}")
print(f"Precision: {precision_score(y_test, y_pred_rf, average='macro'):.5f}")
print(f"Recall: {recall_score(y_test, y_pred_rf, average='macro'):.5f}")
print(f"F1 Score: {f1_score(y_test, y_pred_rf, average='macro'):.5f}")
print(confusion_matrix(y_test, y_pred_rf))
print()

# Save the RandomForest model
joblib.dump(rf_clf, 'random_forest_model.pkl')
# %%
# Train and evaluate the SVM model for DoS
svm_dos_clf = Pipeline(steps=[('preprocessor', preprocessor),
                              ('classifier', SVC(kernel='linear', random_state=42))])
svm_dos_clf.fit(X_train, y_train)
y_pred_svm_dos = svm_dos_clf.predict(X_test)
print("**DoS - SVM**")
print(f"Accuracy: {accuracy_score(y_test, y_pred_svm_dos):.5f}")
print(f"Precision: {precision_score(y_test, y_pred_svm_dos, average='macro'):.5f}")
print(f"Recall: {recall_score(y_test, y_pred_svm_dos, average='macro'):.5f}")
print(f"F1 Score: {f1_score(y_test, y_pred_svm_dos, average='macro'):.5f}")
print(confusion_matrix(y_test, y_pred_svm_dos))
print()

# Save the SVM model for DoS
joblib.dump(svm_dos_clf, 'svm_model.pkl')

# Train and evaluate the Voting Classifier for R2L
voting_r2l_clf = Pipeline(steps=[('preprocessor', preprocessor),
                                 ('classifier', VotingClassifier(estimators=[('rf', rf_clf.named_steps['classifier']),
                                                                             ('svc', svm_dos_clf.named_steps['classifier'])], voting='hard'))])
voting_r2l_clf.fit(X_train, y_train)
y_pred_voting_r2l = voting_r2l_clf.predict(X_test)
print("**R2L - Voting Classifier**")
print(f"Accuracy: {accuracy_score(y_test, y_pred_voting_r2l):.5f}")
print(f"Precision: {precision_score(y_test, y_pred_voting_r2l, average='macro'):.5f}")
print(f"Recall: {recall_score(y_test, y_pred_voting_r2l, average='macro'):.5f}")
print(f"F1 Score: {f1_score(y_test, y_pred_voting_r2l, average='macro'):.5f}")
print(confusion_matrix(y_test, y_pred_voting_r2l))
print()

# Save the Voting Classifier for R2L
joblib.dump(voting_r2l_clf, 'voting_classifier_model.pkl')

# Train and evaluate the RandomForest model for Probe
print("**Probe - RandomForest**")
print(f"Accuracy: {accuracy_score(y_test, y_pred_rf):.5f}")
print(f"Precision: {precision_score(y_test, y_pred_rf, average='macro'):.5f}")
print(f"Recall: {recall_score(y_test, y_pred_rf, average='macro'):.5f}")
print(f"F1 Score: {f1_score(y_test, y_pred_rf, average='macro'):.5f}")
print(confusion_matrix(y_test, y_pred_rf))
print()

# Cross-validation for RandomForest
print("Cross-validation for RandomForest:")
accuracy = cross_val_score
# RandomForest (continued)
accuracy = cross_val_score(rf_clf, X_test, y_test, cv=10, scoring='accuracy')
print("Accuracy: %0.5f (+/- %0.5f)" % (accuracy.mean(), accuracy.std() * 2))
precision = cross_val_score(rf_clf, X_test, y_test, cv=10, scoring='precision_macro')
print("Precision: %0.5f (+/- %0.5f)" % (precision.mean(), precision.std() * 2))
recall = cross_val_score(rf_clf, X_test, y_test, cv=10, scoring='recall_macro')
print("Recall: %0.5f (+/- %0.5f)" % (recall.mean(), recall.std() * 2))
f = cross_val_score(rf_clf, X_test, y_test, cv=10, scoring='f1_macro')
print("F-measure: %0.5f (+/- %0.5f)" % (f.mean(), f.std() * 2))
# %%

# Predicting a new instance
def predict_new_instance(new_instance, model, preprocessor, label_encoder, columns):
    # Convert new_instance to DataFrame
    new_instance_df = pd.DataFrame([new_instance], columns=columns)
    # Preprocess the new instance
    new_instance_preprocessed = preprocessor.transform(new_instance_df)
    prediction = model.predict(new_instance_preprocessed)
    prediction_label = label_encoder.inverse_transform(prediction)
    return prediction_label[0]

# Example usage
new_instance = X.iloc[0].values  # Example: using the first instance from the dataset
predicted_label = predict_new_instance(new_instance, rf_clf, preprocessor, label_encoder, X.columns)
print(predicted_label)

# Check if the predicted label is normal or an attack
if predicted_label == 'normal':
    print("The new instance is normal.")
else:
    print("The new instance is an attack.")
# %%
