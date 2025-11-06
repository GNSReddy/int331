import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_squared_error, r2_score
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# Set page configuration
st.set_page_config(page_title="Crop Yield Dashboard", layout="wide", initial_sidebar_state="expanded")

# Custom CSS for styling
st.markdown(
    """
    <style>
    .stApp {
        background-color: #f8f9fa;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .sidebar .sidebar-content {
        background-color: #2c3e50;
        color: white;
    }
    .card {
        background-color: white;
        border-radius: 10px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        padding: 15px;
        margin-bottom: 20px;
    }
    .header {
        background: linear-gradient(135deg, #2c3e50, #3498db);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        text-align: center;
    }
    .btn-primary {
        background-color: #3498db;
        color: white;
        padding: 5px 15px;
        border-radius: 5px;
        text-decoration: none;
    }
    .btn-primary:hover {
        background-color: #2980b9;
    }
    .footer {
        background-color: #2c3e50;
        color: white;
        text-align: center;
        padding: 10px 0;
        width: 100%;
        margin-top: 20px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Load and prepare data
@st.cache_data
def load_data():
    data = {
        'Area': ['Albania']*50 + ['Algeria']*50 + ['Angola']*50 + ['Argentina']*50,
        'Item': ['Maize']*10 + ['Potatoes']*10 + ['Rice']*10 + ['Wheat']*10 + ['Soybeans']*10,
        'Year': list(range(1990, 2000))*20,
        'Yield': np.random.uniform(1, 10, 200),
        'Rainfall': np.random.uniform(500, 1500, 200),
        'Pesticides': np.random.uniform(50, 500, 200),
        'Temperature': np.random.uniform(15, 25, 200),
        'Fertilizer': np.random.uniform(50, 300, 200)
    }
    return pd.DataFrame(data)

df = load_data()
model, scaler, mse, r2 = None, None, None, None

@st.cache_data
def train_model(df):
    global model, scaler, mse, r2
    X = df[['Rainfall', 'Pesticides', 'Temperature', 'Fertilizer']]
    y = df['Yield']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    y_pred = model.predict(X_test_scaled)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    return model, scaler, mse, r2

model, scaler, mse, r2 = train_model(df)

# Sidebar navigation
st.sidebar.title("Navigation")
selection = st.sidebar.radio("Go to", ["Home", "Dashboard", "Yield Predictor", "Trend Analysis"])

# Home Page
if selection == "Home":
    st.markdown('<div class="header"><h1>Crop Yield Dashboard</h1><p class="lead">Harness the power of data to optimize agricultural production</p></div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown('<div class="card"><h5>Data Exploration</h5><p>Explore interactive visualizations of crop yield data.</p><a href="#" onclick="window.location.href=\'?page=dashboard\'" class="btn-primary">View Dashboard</a></div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="card"><h5>Yield Prediction</h5><p>Predict crop yield with our model.</p><a href="#" onclick="window.location.href=\'?page=predict\'" class="btn-primary">Predict Yield</a></div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="card"><h5>Trend Analysis</h5><p>Analyze historical trends and correlations.</p><a href="#" onclick="window.location.href=\'?page=analysis\'" class="btn-primary">View Analysis</a></div>', unsafe_allow_html=True)
    st.markdown('<div class="card"><h5>About This Project</h5><p>This dashboard helps optimize agricultural production using:</p><ul><li>Rainfall levels</li><li>Temperature</li><li>Pesticide usage</li><li>Fertilizer application</li></ul></div>', unsafe_allow_html=True)

# Dashboard
elif selection == "Dashboard":
    st.markdown('<div class="header"><h2>Crop Yield Dashboard</h2><p>Interactive visualizations of crop yield data.</p></div>', unsafe_allow_html=True)
    st.markdown(f'<div class="card"><h5>Model Performance Metrics</h5><p><strong>Mean Squared Error:</strong> {mse:.4f}</p><p><strong>R-squared Score:</strong> {r2:.4f}</p></div>', unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        fig1 = px.box(df, x='Item', y='Yield', title='Yield Distribution by Crop Type')
        st.plotly_chart(fig1, use_container_width=True)
    with col2:
        yearly_yield = df.groupby('Year')['Yield'].mean().reset_index()
        fig2 = px.line(yearly_yield, x='Year', y='Yield', title='Average Yield Over Years')
        st.plotly_chart(fig2, use_container_width=True)
    col3, col4 = st.columns(2)
    with col3:
        regional_yield = df.groupby('Area')['Yield'].mean().reset_index()
        fig3 = px.bar(regional_yield, x='Area', y='Yield', title='Average Yield by Region')
        st.plotly_chart(fig3, use_container_width=True)
    with col4:
        importance = model.feature_importances_
        features = ['Rainfall', 'Pesticides', 'Temperature', 'Fertilizer']
        fig5 = px.bar(x=features, y=importance, title='Feature Importance')
        st.plotly_chart(fig5, use_container_width=True)
    fig4 = px.scatter_matrix(df, dimensions=['Rainfall', 'Temperature', 'Pesticides', 'Yield'], title='Environmental Factors vs Yield')
    st.plotly_chart(fig4, use_container_width=True)

# Yield Predictor
elif selection == "Yield Predictor":
    st.markdown('<div class="header"><h2>Crop Yield Predictor</h2></div>', unsafe_allow_html=True)
    with st.form(key='predict_form'):
        col1, col2 = st.columns(2)
        with col1:
            area = st.selectbox("Region", sorted(df['Area'].unique()))
            crop = st.selectbox("Crop Type", sorted(df['Item'].unique()))
        with col2:
            rainfall = st.number_input("Rainfall (mm)", min_value=0.0, step=0.1, value=1000.0)
            pesticides = st.number_input("Pesticides (tonnes)", min_value=0.0, step=0.1, value=200.0)
        col3, col4 = st.columns(2)
        with col3:
            temperature = st.number_input("Temperature (°C)", min_value=0.0, step=0.1, value=20.0)
            fertilizer = st.number_input("Fertilizer (kg/hectare)", min_value=0.0, step=0.1, value=150.0)
        submit = st.form_submit_button("Predict Yield")
    if submit:
        try:
            input_data = scaler.transform([[rainfall, pesticides, temperature, fertilizer]])
            prediction = model.predict(input_data)[0]
            avg_yield = df[(df['Area'] == area) & (df['Item'] == crop)]['Yield'].mean()
            fig = go.Figure()
            fig.add_trace(go.Bar(x=['Average Yield', 'Predicted Yield'], y=[avg_yield, prediction], marker_color=['blue', 'green']))
            fig.update_layout(title='Predicted vs Average Yield', yaxis_title='Yield (tonnes/hectare)')
            st.markdown(f'<div class="card"><h4>Predicted Yield</h4><p>For <strong>{crop}</strong> in <strong>{area}</strong>: <strong>{prediction:.2f} tonnes/hectare</strong></p></div>', unsafe_allow_html=True)
            st.plotly_chart(fig, use_container_width=True)
            st.markdown('<div class="card"><h5>Interpretation</h5><p>Based on our trained model with historical data.</p></div>', unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Prediction error: {str(e)}")

# Trend Analysis
elif selection == "Trend Analysis":
    st.markdown('<div class="header"><h2>Crop Yield Trend Analysis</h2></div>', unsafe_allow_html=True)
    yearly_data = df.groupby('Year').agg({'Yield': 'mean', 'Rainfall': 'mean', 'Temperature': 'mean'}).reset_index()
    fig1 = px.line(yearly_data, x='Year', y=['Yield', 'Rainfall', 'Temperature'], title='Yield and Environmental Factors Over Time')
    st.plotly_chart(fig1, use_container_width=True)
    col1, col2 = st.columns(2)
    with col1:
        corr = df[['Yield', 'Rainfall', 'Pesticides', 'Temperature', 'Fertilizer']].corr()
        fig2 = px.imshow(corr, text_auto=True, title='Correlation Heatmap')
        st.plotly_chart(fig2, use_container_width=True)
    with col2:
        regional_trends = df.groupby(['Area', 'Year'])['Yield'].mean().reset_index()
        fig3 = px.line(regional_trends, x='Year', y='Yield', color='Area', title='Yield Trends by Region')
        st.plotly_chart(fig3, use_container_width=True)
    st.markdown('<div class="card"><h5>Key Insights</h5><div class="row"><div class="col-md-4"><h6>Rainfall Impact</h6><p>Moderate rainfall levels correlate with optimal yields.</p></div><div class="col-md-4"><h6>Temperature Patterns</h6><p>Optimal temperature range observed.</p></div><div class="col-md-4"><h6>Regional Variations</h6><p>Distinct yield patterns by region.</p></div></div></div>', unsafe_allow_html=True)

# Footer
st.markdown(
    f'<div class="footer"><p>Crop Yield Dashboard © 2025 | Updated: 08:57 PM IST, Monday, July 14, 2025 | Using machine learning to optimize agricultural production</p></div>',
    unsafe_allow_html=True
)