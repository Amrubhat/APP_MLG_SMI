import pandas as pd
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import OneHotEncoder, StandardScaler
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.decomposition import PCA
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import accuracy_score

# # Load the dataset
# # df = pd.read_csv('NSL-KDD.csv')

# # For demonstration purposes, let's create a small dummy DataFrame
# data = {
#     'duration': [0, 0, 0, 0, 0],
#     'protocol_type': ['tcp', 'udp', 'tcp', 'udp', 'tcp'],
#     'service': ['http', 'domain_u', 'smtp', 'eco_i', 'ftp_data'],
#     'flag': ['SF', 'SF', 'REJ', 'SF', 'S0'],
#     'src_bytes': [491, 146, 0, 0, 491],
#     'dst_bytes': [0, 0, 0, 0, 0],
#     'land': [0, 0, 0, 0, 0],
#     'wrong_fragment': [0, 0, 0, 0, 0],
#     'urgent': [0, 0, 0, 0, 0],
#     'hot': [0, 0, 0, 0, 0],
#     # ... (more features) ...
#     'label': ['normal', 'anomaly', 'normal', 'anomaly', 'normal']
# }

# df = pd.DataFrame(data)

# # Separate features and target
# X = df.drop('label', axis=1)
# y = df['label']

# # Identify numeric and categorical columns
# numeric_features = X.select_dtypes(include=['int64', 'float64']).columns
# categorical_features = X.select_dtypes(include=['object']).columns

# # Create transformers for numeric and categorical data
# numeric_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='mean')),
#     ('scaler', StandardScaler())
# ])

# categorical_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='most_frequent')),
#     ('onehot', OneHotEncoder(handle_unknown='ignore'))
# ])

# # Create a preprocessor with column transformers
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', numeric_transformer, numeric_features),
#         ('cat', categorical_transformer, categorical_features)
#     ])

# # Create a pipeline that includes preprocessing and PCA
# # Use a valid n_components, smaller than the number of samples or featuresimport pandas as pd
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import OneHotEncoder, StandardScaler
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.decomposition import PCA
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import accuracy_score

# # Load the dataset
# # df = pd.read_csv('NSL-KDD.csv')

# # For demonstration purposes, let's create a small dummy DataFrame
# data = {
#     'duration': [0, 0, 0, 0, 0],
#     'protocol_type': ['tcp', 'udp', 'tcp', 'udp', 'tcp'],
#     'service': ['http', 'domain_u', 'smtp', 'eco_i', 'ftp_data'],
#     'flag': ['SF', 'SF', 'REJ', 'SF', 'S0'],
#     'src_bytes': [491, 146, 0, 0, 491],
#     'dst_bytes': [0, 0, 0, 0, 0],
#     'land': [0, 0, 0, 0, 0],
#     'wrong_fragment': [0, 0, 0, 0, 0],
#     'urgent': [0, 0, 0, 0, 0],
#     'hot': [0, 0, 0, 0, 0],
#     # ... (more features) ...
#     'label': ['normal', 'anomaly', 'normal', 'anomaly', 'normal']
# }

# df = pd.DataFrame(data)

# # Separate features and target
# X = df.drop('label', axis=1)
# y = df['label']

# # Identify numeric and categorical columns
# numeric_features = X.select_dtypes(include=['int64', 'float64']).columns
# categorical_features = X.select_dtypes(include=['object']).columns

# # Create transformers for numeric and categorical data
# numeric_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='mean')),
#     ('scaler', StandardScaler())
# ])

# categorical_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='most_frequent')),
#     ('onehot', OneHotEncoder(handle_unknown='ignore'))
# ])
# import pandas as pd
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import OneHotEncoder, StandardScaler
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.decomposition import PCA
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import accuracy_score

# # Load the dataset
# # df = pd.read_csv('NSL-KDD.csv')

# # For demonstration purposes, let's create a small dummy DataFrame
# data = {
#     'duration': [0, 0, 0, 0, 0],
#     'protocol_type': ['tcp', 'udp', 'tcp', 'udp', 'tcp'],
#     'service': ['http', 'domain_u', 'smtp', 'eco_i', 'ftp_data'],
#     'flag': ['SF', 'SF', 'REJ', 'SF', 'S0'],
#     'src_bytes': [491, 146, 0, 0, 491],
#     'dst_bytes': [0, 0, 0, 0, 0],
#     'land': [0, 0, 0, 0, 0],
#     'wrong_fragment': [0, 0, 0, 0, 0],
#     'urgent': [0, 0, 0, 0, 0],
#     'hot': [0, 0, 0, 0, 0],
#     # ... (more features) ...
#     'label': ['normal', 'anomaly', 'normal', 'anomaly', 'normal']
# }

# df = pd.DataFrame(data)

# # Separate features and target
# X = df.drop('label', axis=1)
# y = df['label']

# # Identify numeric and categorical columns
# numeric_features = X.select_dtypes(include=['int64', 'float64']).columns
# categorical_features = X.select_dtypes(include=['object']).columns

# # Create transformers for numeric and categorical data
# numeric_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='mean')),
#     ('scaler', StandardScaler())
# ])

# categorical_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='most_frequent')),
#     ('onehot', OneHotEncoder(handle_unknown='ignore'))
# ])

# # Create a preprocessor with column transformers
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', numeric_transformer, numeric_features),
#         ('cat', categorical_transformer, categorical_features)
#     ])

# # Create a pipeline that includes preprocessing and PCA
# # Use a valid n_components, smaller than the number of samples or features
# n_components = 2  # Adjust to a valid number considering the dataset

# pipeline = Pipeline(steps=[
#     ('preprocessor', preprocessor),
#     ('pca', PCA(n_components=n_components))import pandas as pd
# from sklearn.impute import SimpleImputer
# from sklearn.preprocessing import OneHotEncoder, StandardScaler
# from sklearn.compose import ColumnTransformer
# from sklearn.pipeline import Pipeline
# from sklearn.decomposition import PCA
# from sklearn.model_selection import train_test_split
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import accuracy_score

# # Load the dataset
# # df = pd.read_csv('NSL-KDD.csv')

# # For demonstration purposes, let's create a small dummy DataFrame
# data = {
#     'duration': [0, 0, 0, 0, 0],
#     'protocol_type': ['tcp', 'udp', 'tcp', 'udp', 'tcp'],
#     'service': ['http', 'domain_u', 'smtp', 'eco_i', 'ftp_data'],
#     'flag': ['SF', 'SF', 'REJ', 'SF', 'S0'],
#     'src_bytes': [491, 146, 0, 0, 491],
#     'dst_bytes': [0, 0, 0, 0, 0],
#     'land': [0, 0, 0, 0, 0],
#     'wrong_fragment': [0, 0, 0, 0, 0],
#     'urgent': [0, 0, 0, 0, 0],
#     'hot': [0, 0, 0, 0, 0],
#     # ... (more features) ...
#     'label': ['normal', 'anomaly', 'normal', 'anomaly', 'normal']
# }

# df = pd.DataFrame(data)

# # Separate features and target
# X = df.drop('label', axis=1)
# y = df['label']

# # Identify numeric and categorical columns
# numeric_features = X.select_dtypes(include=['int64', 'float64']).columns
# categorical_features = X.select_dtypes(include=['object']).columns

# # Create transformers for numeric and categorical data
# numeric_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='mean')),
#     ('scaler', StandardScaler())
# ])

# categorical_transformer = Pipeline(steps=[
#     ('imputer', SimpleImputer(strategy='most_frequent')),
#     ('onehot', OneHotEncoder(handle_unknown='ignore'))
# ])

# # Create a preprocessor with column transformers
# preprocessor = ColumnTransformer(
#     transformers=[
#         ('num', numeric_transformer, numeric_features),
#         ('cat', categorical_transformer, categorical_features)
#     ])

# # Create a pipeline that includes preprocessing and PCA
# # Use a valid n_components, smaller than the number of samples or features
# n_components = 2  # Adjust to a valid number considering the dataset

# pipeline = Pipeline(steps=[
#     ('preprocessor', preprocessor),
#     ('pca', PCA(n_components=n_components))
# ])

# # Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Debug: Check the shape of the training and test sets
# print(f'X_train shape: {X_train.shape}')
# print(f'X_test shape: {X_test.shape}')

# # Step 3: Apply PCA
# X_train_pca = pipeline.fit_transform(X_train)
# X_test_pca = pipeline.transform(X_test)

# # Debug: Check the shape of the PCA-transformed data
# print(f'X_train_pca shape: {X_train_pca.shape}')
# print(f'X_test_pca shape: {X_test_pca.shape}')

# # Optional: Train a classifier on the PCA-transformed data
# classifier = RandomForestClassifier(n_estimators=100, random_state=42)
# classifier.fit(X_train_pca, y_train)

# # Predict on the test data
# y_pred = classifier.predict(X_test_pca)

# # Debug: Check the first few predictions
# print(f'Predictions: {y_pred[:5]}')

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print(f'Accuracy: {accuracy:.2f}')

# # Optional: Print the explained variance ratio to see how much variance each component explains
# explained_variance_ratio = pipeline.named_steps['pca'].explained_variance_ratio_
# print(f'Explained variance ratio: {explained_variance_ratio}')

# # Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Debug: Check the shape of the training and test sets
# print(f'X_train shape: {X_train.shape}')
# print(f'X_test shape: {X_test.shape}')

# # Step 3: Apply PCA
# X_train_pca = pipeline.fit_transform(X_train)
# X_test_pca = pipeline.transform(X_test)

# # Debug: Check the shape of the PCA-transformed data
# print(f'X_train_pca shape: {X_train_pca.shape}')
# print(f'X_test_pca shape: {X_test_pca.shape}')

# # Optional: Train a classifier on the PCA-transformed data
# classifier = RandomForestClassifier(n_estimators=100, random_state=42)
# classifier.fit(X_train_pca, y_train)

# # Predict on the test data
# y_pred = classifier.predict(X_test_pca)

# # Debug: Check the first few predictions
# print(f'Predictions: {y_pred[:5]}')

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print(f'Accuracy: {accuracy:.2f}')

# # Optional: Print the explained variance ratio to see how much variance each component explains
# explained_variance_ratio = pipeline.named_steps['pca'].explained_variance_ratio_
# print(f'Explained variance ratio: {explained_variance_ratio}')

# # Create a pipeline that includes preprocessing and PCA
# # Use a valid n_components, smaller than the number of samples or features
# n_components = 2  # Adjust to a valid number considering the dataset

# pipeline = Pipeline(steps=[
#     ('preprocessor', preprocessor),
#     ('pca', PCA(n_components=n_components))
# ])

# # Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Debug: Check the shape of the training and test sets
# print(f'X_train shape: {X_train.shape}')
# print(f'X_test shape: {X_test.shape}')

# # Step 3: Apply PCA
# X_train_pca = pipeline.fit_transform(X_train)
# X_test_pca = pipeline.transform(X_test)

# # Debug: Check the shape of the PCA-transformed data
# print(f'X_train_pca shape: {X_train_pca.shape}')
# print(f'X_test_pca shape: {X_test_pca.shape}')

# # Optional: Train a classifier on the PCA-transformed data
# classifier = RandomForestClassifier(n_estimators=100, random_state=42)
# classifier.fit(X_train_pca, y_train)

# # Predict on the test data
# y_pred = classifier.predict(X_test_pca)

# # Debug: Check the first few predictions
# print(f'Predictions: {y_pred[:5]}')

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print(f'Accuracy: {accuracy:.2f}')

# # Optional: Print the explained variance ratio to see how much variance each component explains
# explained_variance_ratio = pipeline.named_steps['pca'].explained_variance_ratio_
# print(f'Explained variance ratio: {explained_variance_ratio}')

# n_components = 2  # Adjust to a valid number considering the dataset

# pipeline = Pipeline(steps=[
#     ('preprocessor', preprocessor),
#     ('pca', PCA(n_components=n_components))
# ])

# # Split the data into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# # Debug: Check the shape of the training and test sets
# print(f'X_train shape: {X_train.shape}')
# print(f'X_test shape: {X_test.shape}')

# # Step 3: Apply PCA
# X_train_pca = pipeline.fit_transform(X_train)
# X_test_pca = pipeline.transform(X_test)

# # Debug: Check the shape of the PCA-transformed data
# print(f'X_train_pca shape: {X_train_pca.shape}')
# print(f'X_test_pca shape: {X_test_pca.shape}')

# # Optional: Train a classifier on the PCA-transformed data
# classifier = RandomForestClassifier(n_estimators=100, random_state=42)
# classifier.fit(X_train_pca, y_train)

# # Predict on the test data
# y_pred = classifier.predict(X_test_pca)

# # Debug: Check the first few predictions
# print(f'Predictions: {y_pred[:5]}')

# # Evaluate the model
# accuracy = accuracy_score(y_test, y_pred)
# print(f'Accuracy: {accuracy:.2f}')

# # Optional: Print the explained variance ratio to see how much variance each component explains
# explained_variance_ratio = pipeline.named_steps['pca'].explained_variance_ratio_
# print(f'Explained variance ratio: {explained_variance_ratio}')

protocol = int(input("Enter protocol type: \n1. TCP\n2. UDP\n")) - 1
protocol = ['tcp', 'udp'][protocol]

flag = int(input("Enter flag type: \n1. SF\n2. S0\n3. REJ\n4. RSTO\n")) - 1
flag = ['SF', 'S0', 'REJ', 'RSTO'][flag]

service = int(input("Enter the destination network service used:\n1. Private\n2. HTTP\n3. FTP\n4. SMTP\n5. Telnet\n")) - 1
service = ['private', 'http', 'ftp', 'smtp', 'telnet'][service]

count = int(input("Enter the number of connections to the same host as the current connection in the past two seconds (0 - 511)\n"))
hosts = int(input("Enter the number of connections having the same destination host IP address (0 - 255)\n"))

test = [0, protocol, service, flag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, count, 10, 0, 0, 1, 1, 0.04, 0.06, 0, hosts, 10, 0.04, 0.06, 0, 0, 0, 0, 1, 1]
test_df = pd.DataFrame(test)
print(test_df.iloc[2])