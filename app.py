import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
from typing import Dict, List, Any
import os
from agent import CyberSecuritySystem, ThreatInputHandler, create_production_system
from dotenv import load_dotenv

load_dotenv()

# Page configuration
st.set_page_config(
    page_title="CyberGuard AI - Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .threat-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #007bff;
        margin: 1rem 0;
    }
    .emergency-card {
        background: #ffebee;
        border-left: 4px solid #f44336;
    }
    .urgent-card {
        background: #fff3e0;
        border-left: 4px solid #ff9800;
    }
    .alert-card {
        background: #f3e5f5;
        border-left: 4px solid #9c27b0;
    }
    .routine-card {
        background: #e8f5e8;
        border-left: 4px solid #4caf50;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
    }
    .status-indicator {
        width: 20px;
        height: 20px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 10px;
    }
    .status-online { background-color: #4caf50; }
    .status-warning { background-color: #ff9800; }
    .status-offline { background-color: #f44336; }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'cyber_system' not in st.session_state:
    st.session_state.cyber_system = None
if 'threat_history' not in st.session_state:
    st.session_state.threat_history = []
if 'active_threats' not in st.session_state:
    st.session_state.active_threats = []
if 'system_status' not in st.session_state:
    st.session_state.system_status = {
        'ai_agent': 'Online',
        'vector_db': 'Online',
        'threat_intel': 'Online',
        'monitoring': 'Online'
    }

def initialize_system():
    """Initialize the cybersecurity system"""
    try:
        if st.session_state.cyber_system is None:
            with st.spinner("Initializing CyberGuard AI System..."):
                st.session_state.cyber_system = create_production_system()
            st.success("✅ System initialized successfully!")
        return True
    except Exception as e:
        st.error(f"❌ System initialization failed: {str(e)}")
        return False

def get_threat_color(classification):
    """Get color based on threat classification"""
    colors = {
        'EMERGENCY': '#f44336',
        'URGENT': '#ff9800',
        'ALERT': '#9c27b0',
        'ROUTINE': '#4caf50'
    }
    return colors.get(classification, '#666666')

def create_threat_metrics():
    """Create threat metrics dashboard"""
    threats = st.session_state.threat_history
    
    if not threats:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Threats", "0")
        with col2:
            st.metric("Active Threats", "0")
        with col3:
            st.metric("Resolved", "0")
        with col4:
            st.metric("Avg Response Time", "0s")
        return
    
    # Calculate metrics
    total_threats = len(threats)
    active_threats = len([t for t in threats if t.get('final_action') == 'PENDING_HUMAN_REVIEW'])
    resolved_threats = len([t for t in threats if t.get('final_action') != 'PENDING_HUMAN_REVIEW'])
    
    # Classification breakdown
    emergency = len([t for t in threats if t.get('classification') == 'EMERGENCY'])
    urgent = len([t for t in threats if t.get('classification') == 'URGENT'])
    alert = len([t for t in threats if t.get('classification') == 'ALERT'])
    routine = len([t for t in threats if t.get('classification') == 'ROUTINE'])
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Threats", 
            total_threats,
            delta=f"+{len([t for t in threats[-5:]])} recent" if len(threats) >= 5 else None
        )
    
    with col2:
        st.metric(
            "Active Threats", 
            active_threats,
            delta=f"{active_threats - resolved_threats}" if active_threats > resolved_threats else None
        )
    
    with col3:
        st.metric(
            "Resolved", 
            resolved_threats,
            delta=f"+{resolved_threats}" if resolved_threats > 0 else None
        )
    
    with col4:
        avg_confidence = sum([t.get('confidence_score', 0) for t in threats]) / len(threats) if threats else 0
        st.metric(
            "Avg Confidence", 
            f"{avg_confidence:.1%}",
            delta=f"{avg_confidence:.1%}" if avg_confidence > 0.8 else None
        )

def create_threat_timeline():
    """Create threat timeline visualization"""
    threats = st.session_state.threat_history
    
    if not threats:
        st.info("No threat data available for timeline.")
        return
    
    # Prepare data for timeline
    timeline_data = []
    for i, threat in enumerate(threats):
        timeline_data.append({
            'Timestamp': threat.get('timestamp', datetime.now().isoformat()),
            'Classification': threat.get('classification', 'UNKNOWN'),
            'Alert': threat.get('sensor_alert', 'Unknown Alert')[:50] + '...',
            'Confidence': threat.get('confidence_score', 0),
            'Status': threat.get('final_action', 'PENDING')
        })
    
    df = pd.DataFrame(timeline_data)
    
    if not df.empty:
        # Convert timestamp to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Create timeline chart
        fig = px.timeline(
            df, 
            x_start='Timestamp', 
            x_end='Timestamp',
            y='Classification',
            color='Classification',
            title="Threat Detection Timeline",
            color_discrete_map={
                'EMERGENCY': '#f44336',
                'URGENT': '#ff9800', 
                'ALERT': '#9c27b0',
                'ROUTINE': '#4caf50'
            }
        )
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def create_system_status():
    """Create system status dashboard"""
    st.markdown("### 🔧 System Status")
    
    status_data = st.session_state.system_status
    
    col1, col2 = st.columns(2)
    
    with col1:
        for component, status in list(status_data.items())[:2]:
            status_class = "status-online" if status == "Online" else "status-offline" 
            st.markdown(f"""
            <div style="display: flex; align-items: center; margin: 10px 0;">
                <span class="status-indicator {status_class}"></span>
                <strong>{component.replace('_', ' ').title()}:</strong> {status}
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        for component, status in list(status_data.items())[2:]:
            status_class = "status-online" if status == "Online" else "status-offline"
            st.markdown(f"""
            <div style="display: flex; align-items: center; margin: 10px 0;">
                <span class="status-indicator {status_class}"></span>
                <strong>{component.replace('_', ' ').title()}:</strong> {status}
            </div>
            """, unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ CyberGuard AI - Security Operations Center</h1>
        <p>Advanced AI-Powered Threat Detection & Response System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## 🎛️ Control Panel")
        
        # System initialization
        if st.button("🚀 Initialize System", type="primary"):
            initialize_system()
        
        st.markdown("---")
        
        # Navigation
        page = st.selectbox(
            "📍 Navigation",
            ["🏠 Dashboard", "⚠️ Threat Analysis", "📊 Analytics", "⚙️ Settings", "📋 Incident Response"]
        )
        
        st.markdown("---")
        
        # Quick actions
        st.markdown("### ⚡ Quick Actions")
        if st.button("🔔 Test Alert"):
            test_alerts = [
                "Unauthorized access detected at Gate 7 security checkpoint",
                "Network intrusion attempt from IP 192.168.1.100",
                "Malware detected on workstation WS-0045",
                "Sensor tampering detected in Zone A-12",
                "Failed login attempts detected from external IP"
            ]
            import random
            test_alert = random.choice(test_alerts)
            if st.session_state.cyber_system:
                with st.spinner("Processing test alert..."):
                    result = st.session_state.cyber_system.process_threat(test_alert)
                    st.session_state.threat_history.append(result)
                st.success("Test alert processed!")
                st.rerun()
        
        if st.button("🧹 Clear History"):
            st.session_state.threat_history = []
            st.session_state.active_threats = []
            st.success("History cleared!")
            st.rerun()
    
    # Main content based on selected page
    if page == "🏠 Dashboard":
        show_dashboard()
    elif page == "⚠️ Threat Analysis":
        show_threat_analysis()
    elif page == "📊 Analytics":
        show_analytics()
    elif page == "⚙️ Settings":
        show_settings()
    elif page == "📋 Incident Response":
        show_incident_response()

def show_dashboard():
    """Show main dashboard"""
    
    # Check if system is initialized
    if st.session_state.cyber_system is None:
        st.warning("⚠️ System not initialized. Please click 'Initialize System' in the sidebar.")
        return
    
    # Metrics row
    create_threat_metrics()
    
    st.markdown("---")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📈 Threat Activity Timeline")
        create_threat_timeline()
        
        # Recent threats
        st.markdown("### 🚨 Recent Threats")
        recent_threats = st.session_state.threat_history[-5:] if st.session_state.threat_history else []
        
        if recent_threats:
            for threat in reversed(recent_threats):
                classification = threat.get('classification', 'UNKNOWN')
                confidence = threat.get('confidence_score', 0)
                timestamp = threat.get('timestamp', '')
                alert = threat.get('sensor_alert', 'Unknown alert')
                
                card_class = f"{classification.lower()}-card"
                
                st.markdown(f"""
                <div class="threat-card {card_class}">
                    <strong>🚨 {classification}</strong> 
                    <span style="float: right;">Confidence: {confidence:.1%}</span><br>
                    <small>{timestamp}</small><br>
                    <em>{alert[:100]}...</em>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No recent threats detected.")
    
    with col2:
        create_system_status()
        
        # Classification breakdown
        st.markdown("### 📊 Threat Breakdown")
        threats = st.session_state.threat_history
        
        if threats:
            classification_counts = {}
            for threat in threats:
                classification = threat.get('classification', 'UNKNOWN')
                classification_counts[classification] = classification_counts.get(classification, 0) + 1
            
            # Create pie chart
            labels = list(classification_counts.keys())
            values = list(classification_counts.values())
            colors = [get_threat_color(label) for label in labels]
            
            fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3)])
            fig.update_traces(
                marker=dict(colors=colors),
                textposition='inside',
                textinfo='percent+label'
            )
            fig.update_layout(height=300, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data available.")

def show_threat_analysis():
    """Show threat analysis interface"""
    st.markdown("## ⚠️ Threat Analysis & Detection")
    
    if st.session_state.cyber_system is None:
        st.warning("⚠️ System not initialized. Please initialize the system first.")
        return
    
    # Input methods
    tab1, tab2, tab3 = st.tabs(["📝 Manual Alert", "🌐 Network Event", "🔑 Access Control"])
    
    with tab1:
        st.markdown("### 📝 Manual Security Alert")
        
        alert_text = st.text_area(
            "Enter security alert description:",
            height=150,
            placeholder="Describe the security incident, including location, system affected, and observed behavior..."
        )
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            if st.button("🔍 Analyze Threat", type="primary"):
                if alert_text.strip():
                    with st.spinner("Processing threat..."):
                        result = st.session_state.cyber_system.process_threat(alert_text)
                        st.session_state.threat_history.append(result)
                    
                    st.success("✅ Threat analysis completed!")
                    show_threat_result(result)
                else:
                    st.error("Please enter an alert description.")
    
    with tab2:
        st.markdown("### 🌐 Network Security Event")
        
        col1, col2 = st.columns(2)
        
        with col1:
            event_type = st.selectbox("Event Type", [
                "Intrusion Attempt", "DDoS Attack", "Port Scan", 
                "Malware Communication", "Data Exfiltration"
            ])
            source_ip = st.text_input("Source IP Address", placeholder="192.168.1.100")
            target = st.text_input("Target System", placeholder="Web Server, Database, etc.")
        
        with col2:
            detector = st.text_input("Detection System", placeholder="Firewall, IDS, etc.")
            severity = st.selectbox("Reported Severity", ["Low", "Medium", "High", "Critical"])
            
        if st.button("🔍 Analyze Network Event", type="primary"):
            if source_ip and target:
                handler = ThreatInputHandler(st.session_state.cyber_system)
                network_event = {
                    "event_type": event_type,
                    "source_ip": source_ip,
                    "target": target,
                    "detector": detector,
                    "severity": severity
                }
                
                with st.spinner("Processing network event..."):
                    result = handler.handle_network_alert(network_event)
                    st.session_state.threat_history.append(result)
                
                st.success("✅ Network event analysis completed!")
                show_threat_result(result)
            else:
                st.error("Please fill in required fields (Source IP and Target).")
    
    with tab3:
        st.markdown("### 🔑 Access Control Event")
        
        col1, col2 = st.columns(2)
        
        with col1:
            event_type = st.selectbox("Access Event", [
                "Unauthorized Access", "Failed Authentication", "Privilege Escalation",
                "After Hours Access", "Multiple Failed Attempts"
            ])
            user_id = st.text_input("User ID", placeholder="user123, unknown, etc.")
            location = st.text_input("Location", placeholder="Gate 7, Building A, etc.")
        
        with col2:
            access_method = st.selectbox("Access Method", [
                "Biometric", "Card Reader", "PIN Entry", "Mobile App", "Unknown"
            ])
            
        if st.button("🔍 Analyze Access Event", type="primary"):
            if user_id and location:
                handler = ThreatInputHandler(st.session_state.cyber_system)
                access_event = {
                    "event_type": event_type,
                    "user_id": user_id,
                    "location": location,
                    "access_method": access_method
                }
                
                with st.spinner("Processing access control event..."):
                    result = handler.handle_access_control_event(access_event)
                    st.session_state.threat_history.append(result)
                
                st.success("✅ Access control event analysis completed!")
                show_threat_result(result)
            else:
                st.error("Please fill in required fields (User ID and Location).")

def show_threat_result(result):
    """Display threat analysis result"""
    st.markdown("---")
    st.markdown("## 📋 Analysis Results")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        classification = result.get('classification', 'UNKNOWN')
        color = get_threat_color(classification)
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid {color};">
            <h3 style="color: {color}; margin: 0;">{classification}</h3>
            <p>Threat Level</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        confidence = result.get('confidence_score', 0)
        confidence_color = "#4caf50" if confidence > 0.8 else "#ff9800" if confidence > 0.6 else "#f44336"
        st.markdown(f"""
        <div class="metric-card" style="border-left: 4px solid {confidence_color};">
            <h3 style="color: {confidence_color}; margin: 0;">{confidence:.1%}</h3>
            <p>Confidence Score</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        location = result.get('threat_metadata', {}).get('location', 'Unknown')
        st.markdown(f"""
        <div class="metric-card">
            <h3 style="margin: 0;">📍 {location}</h3>
            <p>Location</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        timestamp = result.get('timestamp', '')
        formatted_time = timestamp.split('T')[1][:8] if 'T' in timestamp else timestamp
        st.markdown(f"""
        <div class="metric-card">
            <h3 style="margin: 0;">⏰ {formatted_time}</h3>
            <p>Detection Time</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Detailed results
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 🤖 AI Response Plan")
        ai_response = result.get('ai_response', 'No response generated')
        st.markdown(f"```\n{ai_response}\n```")
        
        # Human decision interface
        st.markdown("### 👤 Human Decision Required")
        
        decision_col1, decision_col2 = st.columns([3, 1])
        
        with decision_col1:
            human_decision = st.selectbox(
                "Select Action:",
                ["APPROVE", "OVERRIDE", "ESCALATE", "MODIFY"],
                help="Choose how to proceed with the AI recommendation"
            )
        
        with decision_col2:
            if st.button("✅ Submit Decision", type="primary"):
                # Update the result with human decision
                updated_result = st.session_state.cyber_system.process_threat(
                    result['sensor_alert'], 
                    human_decision
                )
                
                # Update in history
                for i, threat in enumerate(st.session_state.threat_history):
                    if threat.get('timestamp') == result.get('timestamp'):
                        st.session_state.threat_history[i] = updated_result
                        break
                
                st.success(f"Decision '{human_decision}' recorded!")
                st.rerun()
    
    with col2:
        st.markdown("### 📊 Threat Metadata")
        metadata = result.get('threat_metadata', {})
        
        for key, value in metadata.items():
            if key not in ['llm_analysis']:
                st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")
        
        st.markdown("### 📚 Retrieved Protocols")
        retrieved_docs = result.get('retrieved_docs', [])
        
        for i, doc in enumerate(retrieved_docs[:2]):
            relevance = doc.get('relevance_score', 0)
            doc_type = doc.get('metadata', {}).get('threat_type', 'general')
            
            with st.expander(f"Protocol {i+1}: {doc_type} ({relevance:.1%} relevant)"):
                st.markdown(doc.get('content', 'No content available')[:500] + "...")

def show_analytics():
    """Show analytics dashboard"""
    st.markdown("## 📊 Security Analytics")
    
    threats = st.session_state.threat_history
    
    if not threats:
        st.info("No threat data available for analytics. Process some threats first.")
        return
    
    # Time-based analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📅 Threats Over Time")
        
        # Prepare time data
        time_data = {}
        for threat in threats:
            timestamp = threat.get('timestamp', '')
            if timestamp:
                date = timestamp.split('T')[0]
                time_data[date] = time_data.get(date, 0) + 1
        
        if time_data:
            df_time = pd.DataFrame(list(time_data.items()), columns=['Date', 'Count'])
            df_time['Date'] = pd.to_datetime(df_time['Date'])
            
            fig = px.line(df_time, x='Date', y='Count', title="Daily Threat Count")
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 🎯 Classification Distribution")
        
        classification_data = {}
        for threat in threats:
            classification = threat.get('classification', 'UNKNOWN')
            classification_data[classification] = classification_data.get(classification, 0) + 1
        
        if classification_data:
            fig = px.bar(
                x=list(classification_data.keys()), 
                y=list(classification_data.values()),
                title="Threat Classifications",
                color=list(classification_data.keys()),
                color_discrete_map={
                    'EMERGENCY': '#f44336',
                    'URGENT': '#ff9800',
                    'ALERT': '#9c27b0',
                    'ROUTINE': '#4caf50'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Confidence analysis
    st.markdown("### 🎯 Confidence Score Analysis")
    
    confidence_scores = [threat.get('confidence_score', 0) for threat in threats]
    
    if confidence_scores:
        fig = px.histogram(
            x=confidence_scores, 
            nbins=10, 
            title="Distribution of Confidence Scores",
            labels={'x': 'Confidence Score', 'y': 'Frequency'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Alert type analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔍 Alert Types")
        
        alert_types = {}
        for threat in threats:
            alert_type = threat.get('threat_metadata', {}).get('alert_type', 'unknown')
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        if alert_types:
            df_alerts = pd.DataFrame(list(alert_types.items()), columns=['Type', 'Count'])
            st.dataframe(df_alerts, use_container_width=True)
    
    with col2:
        st.markdown("### 📍 Location Analysis")
        
        locations = {}
        for threat in threats:
            location = threat.get('threat_metadata', {}).get('location', 'Unknown')
            locations[location] = locations.get(location, 0) + 1
        
        if locations:
            df_locations = pd.DataFrame(list(locations.items()), columns=['Location', 'Count'])
            st.dataframe(df_locations, use_container_width=True)

def show_settings():
    """Show settings page"""
    st.markdown("## ⚙️ System Settings")
    
    # API Configuration
    st.markdown("### 🔑 API Configuration")
    
    with st.expander("Environment Variables", expanded=False):
        cerebras_key = st.text_input("Cerebras API Key", value="", type="password")
        pinecone_key = st.text_input("Pinecone API Key", value="", type="password")
        
        if st.button("💾 Save API Keys"):
            st.success("API keys would be saved (demo mode)")
    
    # System Configuration
    st.markdown("### 🎛️ System Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        confidence_threshold = st.slider("Confidence Threshold", 0.0, 1.0, 0.8, 0.1)
        auto_response = st.checkbox("Enable Auto-Response", False)
        notification_email = st.text_input("Notification Email", placeholder="admin@company.com")
    
    with col2:
        alert_retention = st.selectbox("Alert Retention Period", ["7 days", "30 days", "90 days", "1 year"])
        escalation_timeout = st.number_input("Escalation Timeout (minutes)", 1, 60, 15)
        
    # Threat Intelligence Sources
    st.markdown("### 🔍 Threat Intelligence Sources")
    
    intel_sources = [
        {"name": "Internal Knowledge Base", "status": "Active", "last_update": "2 hours ago"},
        {"name": "Pinecone Vector DB", "status": "Active", "last_update": "Real-time"},
        {"name": "Security Protocols", "status": "Active", "last_update": "1 day ago"},
    ]
    
    df_intel = pd.DataFrame(intel_sources)
    st.dataframe(df_intel, use_container_width=True)
    
    if st.button("💾 Save Settings"):
        st.success("Settings saved successfully!")

def show_incident_response():
    """Show incident response interface"""
    st.markdown("## 📋 Incident Response Center")
    
    # Active incidents
    st.markdown("### 🚨 Active Incidents")
    
    active_incidents = [
        threat for threat in st.session_state.threat_history 
        if threat.get('final_action') == 'PENDING_HUMAN_REVIEW'
    ]
    
    if active_incidents:
        for i, incident in enumerate(active_incidents):
            classification = incident.get('classification', 'UNKNOWN')
            color = get_threat_color(classification)
            
            with st.expander(f"Incident #{i+1} - {classification}", expanded=True):
                col1, col2, col3 = st.columns([2, 2, 1])
                
                with col1:
                    st.markdown(f"**Alert:** {incident.get('sensor_alert', 'N/A')}")
                    st.markdown(f"**Location:** {incident.get('threat_metadata', {}).get('location', 'Unknown')}")
                    st.markdown(f"**Time:** {incident.get('timestamp', 'Unknown')}")
                
                with col2:
                    st.markdown(f"**Classification:** {classification}")
                    st.markdown(f"**Confidence:** {incident.get('confidence_score', 0):.1%}")
                    st.markdown(f"**Status:** {incident.get('final_action', 'Unknown')}")
                
                with col3:
                    if st.button(f"Resolve #{i+1}", key=f"resolve_{i}"):
                        st.success("Incident marked as resolved!")
    else:
        st.info("No active incidents requiring attention.")
    
    # Response templates
    st.markdown("### 📝 Response Templates")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔴 Emergency Procedures")
        emergency_templates = [
            "Immediate system isolation and containment",
            "Emergency response team activation",
            "Executive notification protocol",
            "Business continuity activation"
        ]
        
        for template in emergency_templates:
            if st.button(f"📋 {template}", key=f"emergency_{template}"):
                st.info(f"Template '{template}' loaded")
    
    with col2:
        st.markdown("#### 🟡 Standard Procedures")
        standard_templates = [
            "Standard investigation protocol",
            "User access review procedure",
            "System maintenance notification",
            "Routine security assessment"
        ]
        
        for template in standard_templates:
            if st.button(f"📋 {template}", key=f"standard_{template}"):
                st.info(f"Template '{template}' loaded")
    
    # Response documentation
    st.markdown("### 📄 Response Documentation")
    
    response_notes = st.text_area(
        "Response Notes:",
        height=150,
        placeholder="Document actions taken, observations, and next steps..."
    )
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("💾 Save Notes"):
            st.success("Response notes saved!")
    
    with col2:
        if st.button("📧 Send Report"):
            st.success("Incident report sent!")
    
    with col3:
        if st.button("🔄 Update Status"):
            st.success("Incident status updated!")

if __name__ == "__main__":
    main()