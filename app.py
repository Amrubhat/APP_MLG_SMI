# import streamlit as st
# import numpy as np
# import joblib
# import os
# import sqlite3
# import pandas as pd

# # File paths for the models and data
# random_forest_model_path = r'C:\Users\amrut\OneDrive\Desktop\BMSCE\6th Sem\MLG Project\random_forest_model.pkl'
# svm_model_path = r'C:\Users\amrut\OneDrive\Desktop\BMSCE\6th Sem\MLG Project\svm_model.pkl'
# voting_classifier_model_path = r'C:\Users\amrut\OneDrive\Desktop\BMSCE\6th Sem\MLG Project\voting_classifier_model.pkl'

# data_path = 'NSL_KDD.csv'
# predictions_db = 'predictions.db'

# # Connect to the database
# conn = sqlite3.connect(predictions_db)
# c = conn.cursor()

# # Create a table to store predictions
# c.execute('''CREATE TABLE IF NOT EXISTS predictions
#              (id INTEGER PRIMARY KEY AUTOINCREMENT, 
#               feature_values TEXT, 
#               prediction TEXT)''')

# # Function to load the model
# def load_model(model_path, model_name):
#     if os.path.exists(model_path):
#         model = joblib.load(model_path)
#         st.sidebar.success(f"{model_name} loaded successfully")
#         return model
#     else:
#         st.sidebar.error(f"{model_name} file not found at {model_path}")
#         return None

# # Load the models at startup
# random_forest_model = load_model(random_forest_model_path, "Random Forest model")
# svm_model = load_model(svm_model_path, "SVM model")
# voting_classifier_model = load_model(voting_classifier_model_path, "Voting Classifier model")

# # Load and preprocess data
# data = pd.read_csv(data_path)
# feature_columns = data.columns[:-1]  # Exclude the label column

# # Streamlit app
# st.markdown("""
#     <style>
#         .main, .stApp {
#             background-color: #000000;
#         }
#         .stAlert, .css-1vz0t63 {
#         }
#         .st-bv, .css-1t1gfbh {
#         }
#         .css-145kmo2, .css-1q8dd3e, .css-16huue1 {
#         }
#         .st-dw {
#         }
#     </style>
# """, unsafe_allow_html=True)

# st.title('Network Intrusion Detection System')
# st.header('Enter Input Features')

# # Setting default values for inputs
# default_values = {
#     'duration': 0.0,
#     'protocol_type': 'tcp',
#     'src_bytes': 0,
#     'dst_bytes': 0,
#     'flag': 'SF'
# }

# with st.form(key='predict_form'):
#     feature_values = {}
#     for column in feature_columns:
#         if column in default_values:
#             if column == 'protocol_type' or column == 'flag':
#                 feature_values[column] = st.selectbox(f'{column}', options=data[column].unique(), index=list(data[column].unique()).index(default_values[column]))
#             else:
#                 feature_values[column] = st.number_input(f'{column}', value=default_values[column], step=0.01)
#         else:
#             feature_values[column] = st.number_input(f'{column}', value=0.0, step=0.01)
    
#     submit_button = st.form_submit_button(label='Predict')

# if submit_button:
#     if random_forest_model is None or svm_model is None or voting_classifier_model is None:
#         st.error("One or more models are not loaded properly.")
#     else:
#         try:
#             # Prepare feature list
#             feature_list = [feature_values[col] for col in feature_columns]
#             single_pred = np.array(feature_list).reshape(1, -1)

#             # Make predictions using each model
#             rf_prediction = random_forest_model.predict(single_pred)
#             svm_prediction = svm_model.predict(single_pred)
#             voting_prediction = voting_classifier_model.predict(single_pred)

#             st.success(f'Random Forest prediction: **{rf_prediction[0]}**')
#             st.success(f'SVM prediction: **{svm_prediction[0]}**')
#             st.success(f'Voting Classifier prediction: **{voting_prediction[0]}**')

#             # Insert predictions into the database
#             c.execute("INSERT INTO predictions (feature_values, prediction) VALUES (?, ?)",
#                       (str(feature_values), f'RF: {rf_prediction[0]}, SVM: {svm_prediction[0]}, Voting: {voting_prediction[0]}'))
#             conn.commit()

#         except Exception as e:
#             st.error(f"Error during prediction: {e}")

# st.header("Stored Predictions")
# try:
#     df = pd.read_sql_query("SELECT * FROM predictions ", conn)
#     if not df.empty:
#         st.dataframe(df)
#     else:
#         st.info("No previous predictions found.")
# except Exception as e:
#     st.error(f"Error retrieving stored predictions: {e}")

# # Close the database connection at the end
# conn.close()

import streamlit as st
import numpy as np
import joblib
import os
import sqlite3
import pandas as pd

# File paths for the models and data
random_forest_model_path = r'C:\Users\amrut\OneDrive\Desktop\BMSCE\6th Sem\MLG Project\random_forest_model.pkl'
svm_model_path = r'C:\Users\amrut\OneDrive\Desktop\BMSCE\6th Sem\MLG Project\svm_model.pkl'
voting_classifier_model_path = r'C:\Users\amrut\OneDrive\Desktop\BMSCE\6th Sem\MLG Project\voting_classifier_model.pkl'

data_path = 'NSL_KDD.csv'
predictions_db = 'predictions.db'

# Connect to the database
conn = sqlite3.connect(predictions_db)
c = conn.cursor()

# Create a table to store predictions
c.execute('''CREATE TABLE IF NOT EXISTS predictions
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              feature_values TEXT, 
              prediction TEXT)''')

# Function to load the model
def load_model(model_path, model_name):
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        st.sidebar.success(f"{model_name} loaded successfully")
        return model
    else:
        st.sidebar.error(f"{model_name} file not found at {model_path}")
        return None

# Load the models at startup
random_forest_model = load_model(random_forest_model_path, "Random Forest model")
svm_model = load_model(svm_model_path, "SVM model")
voting_classifier_model = load_model(voting_classifier_model_path, "Voting Classifier model")

# Load and preprocess data
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

data = pd.read_csv(data_path, names=col_names)
feature_columns = data.columns[:-1]  # Exclude the label column

# Streamlit app
st.markdown("""
    <style>
        .main, .stApp {
            background-color: #000000;
        }
        .stAlert, .css-1vz0t63 {
        }
        .st-bv, .css-1t1gfbh {
        }
        .css-145kmo2, .css-1q8dd3e, .css-16huue1 {
        }
        .st-dw {
        }
    </style>
""", unsafe_allow_html=True)

st.title('Network Intrusion Detection System')
st.header('Enter Input Features')

# Setting default values for inputs
default_values = {
    'duration': 0.0,
    'protocol_type': 'tcp',
    'service': 'http',
    'flag': 'SF',
    'src_bytes': 0,
    'dst_bytes': 0,
    'land': 0,
    'wrong_fragment': 0,
    'urgent': 0,
    'hot': 0,
    'num_failed_logins': 0,
    'logged_in': 0,
    'num_compromised': 0,
    'root_shell': 0,
    'su_attempted': 0,
    'num_root': 0,
    'num_file_creations': 0,
    'num_shells': 0,
    'num_access_files': 0,
    'num_outbound_cmds': 0,
    'is_host_login': 0,
    'is_guest_login': 0,
    'count': 0,
    'srv_count': 0,
    'serror_rate': 0.0,
    'srv_serror_rate': 0.0,
    'rerror_rate': 0.0,
    'srv_rerror_rate': 0.0,
    'same_srv_rate': 0.0,
    'diff_srv_rate': 0.0,
    'srv_diff_host_rate': 0.0,
    'dst_host_count': 0,
    'dst_host_srv_count': 0,
    'dst_host_same_srv_rate': 0.0,
    'dst_host_diff_srv_rate': 0.0,
    'dst_host_same_src_port_rate': 0.0,
    'dst_host_srv_diff_host_rate': 0.0,
    'dst_host_serror_rate': 0.0,
    'dst_host_srv_serror_rate': 0.0,
    'dst_host_rerror_rate': 0.0,
    'dst_host_srv_rerror_rate': 0.0
}

# Take 8 inputs from the user
user_inputs = {}
for i in range(8):
    key = st.selectbox(f'Input {i+1}', feature_columns)
    slider_key = f"{key}_{i}"  # Generate a unique key for each slider
    value = st.slider(f'Select value for {key}', min_value=0.0, max_value=1000.0, value=default_values[key], step=0.01, key=slider_key)
    user_inputs[key] = value

# Set default values for remaining features
for key, value in default_values.items():
    if key not in user_inputs:
        user_inputs[key] = value

# Convert user inputs into a single row DataFrame
user_input_df = pd.DataFrame([user_inputs])

# Predict upon button press
if st.button('Predict'):
    try:
        # Make predictions using each model
        rf_prediction = random_forest_model.predict(user_input_df)
        svm_prediction = svm_model.predict(user_input_df)
        voting_prediction = voting_classifier_model.predict(user_input_df)

        st.success(f'Random Forest prediction: **{rf_prediction[0]}**')
        st.success(f'SVM prediction: **{svm_prediction[0]}**')
        st.success(f'Voting Classifier prediction: **{voting_prediction[0]}**')

        # Insert predictions into the database
        c.execute("INSERT INTO predictions (feature_values, prediction) VALUES (?, ?)",
                  (str(user_inputs), f'RF: {rf_prediction[0]}, SVM: {svm_prediction[0]}, Voting: {voting_prediction[0]}'))
        conn.commit()

    except Exception as e:
        st.error(f"Error during prediction: {e}")

st.header("Stored Predictions")
try:
    df = pd.read_sql_query("SELECT * FROM predictions", conn)
    if not df.empty:
        st.dataframe(df)
    else:
        st.info("No previous predictions found.")
except Exception as e:
    st.error(f"Error retrieving stored predictions: {e}")

# Close the database connection at the end
conn.close()
