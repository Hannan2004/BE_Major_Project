import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import datetime
import time
import random
from typing import Dict, List, Any
import asyncio
from kafka import KafkaConsumer
import threading
import queue

# Import your DDoS detection system
# from ddos_detection_system import create_ddos_detection_system

# Mock DDoS Detection System for demo (replace with actual import)
class MockDDoSDetectionSystem:
    def process_ddos_threat(self, alert, human_decision="PENDING"):
        # Simulate processing time
        time.sleep(2)
        
        classifications = ["NORMAL", "SUSPICIOUS", "MODERATE", "SEVERE", "CRITICAL"]
        classification = random.choice(classifications[1:])  # Exclude NORMAL for demo
        
        action_plan = f"""
## PHASE 1 - IMMEDIATE ACTIONS (0-5 minutes)
1. **Activate Rate Limiting**: `iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT`
2. **Enable DDoS Protection**: Contact upstream ISP for traffic filtering
3. **Scale Infrastructure**: Auto-scale web servers and load balancers
4. **Alert Security Team**: Notify SOC via PagerDuty

## PHASE 2 - SHORT TERM RESPONSE (5-30 minutes)  
1. **Deploy CDN Protection**: Route traffic through Cloudflare/AWS Shield
2. **Implement GeoBlocking**: Block traffic from attack source countries
3. **Database Protection**: Enable read replicas and connection pooling
4. **Stakeholder Communication**: Notify customers of potential service impact

## PHASE 3 - SUSTAINED DEFENSE (30+ minutes)
1. **Monitor Attack Patterns**: Set up enhanced logging and alerting
2. **Capacity Planning**: Evaluate infrastructure scaling needs
3. **Forensic Analysis**: Collect attack samples for threat intelligence
4. **Recovery Planning**: Prepare service restoration procedures

## ROLLBACK PLAN
- Disable rate limiting if false positive detected
- Contact ISP to remove upstream filtering
- Scale down infrastructure after attack subsides
"""
        
        return {
            "classification": classification,
            "confidence_score": random.uniform(0.7, 0.95),
            "action_plan": action_plan,
            "final_action": f"PLAN_READY_FOR_{human_decision}",
            "timestamp": datetime.datetime.now().isoformat(),
            "threat_metadata": {
                "total_packets": random.randint(10000, 100000),
                "unique_sources": random.randint(50, 500),
                "risk_level": classification
            }
        }

def generate_mock_kafka_logs():
    """Generate realistic network logs that simulate DDoS patterns"""
    
    # Simulate different attack patterns
    attack_patterns = [
        {"type": "volumetric", "multiplier": 10, "ports": [80, 443]},
        {"type": "protocol", "multiplier": 5, "ports": [53, 123]},  
        {"type": "application", "multiplier": 3, "ports": [80, 443, 8080]}
    ]
    
    pattern = random.choice(attack_patterns)
    base_ips = ["192.168.1.", "10.0.0.", "172.16.1.", "203.0.113."]
    target_ips = ["10.0.0.1", "10.0.0.2", "192.168.100.1"]
    
    logs = []
    timestamp = datetime.datetime.now()
    
    for i in range(20):
        # Generate source IPs (some repeated for botnet simulation)
        if random.random() < 0.3:  # 30% chance of repeated IP (botnet)
            src_ip = f"{random.choice(base_ips)}{random.randint(100, 120)}"
        else:
            src_ip = f"{random.choice(base_ips)}{random.randint(1, 255)}"
            
        log = {
            "timestamp": (timestamp - datetime.timedelta(seconds=i*2)).isoformat(),
            "src_ip": src_ip,
            "dst_ip": random.choice(target_ips),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "port": random.choice(pattern["ports"]),
            "packets": random.randint(100, 1000) * pattern["multiplier"],
            "bytes": random.randint(1000, 50000) * pattern["multiplier"],
            "flags": random.choice(["SYN", "ACK", "FIN", "RST", "SYN_FLOOD"]),
            "attack_indicator": pattern["type"]
        }
        logs.append(log)
    
    return logs

def create_network_traffic_chart(logs_df):
    """Create real-time network traffic visualization"""
    
    # Traffic over time
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Traffic Volume Over Time', 'Top Source IPs', 
                       'Protocol Distribution', 'Attack Pattern Analysis'),
        specs=[[{"secondary_y": True}, {"type": "bar"}],
               [{"type": "pie"}, {"type": "scatter"}]]
    )
    
    # Traffic volume over time
    traffic_over_time = logs_df.groupby('timestamp').agg({
        'packets': 'sum',
        'bytes': 'sum'
    }).reset_index()
    
    fig.add_trace(
        go.Scatter(x=traffic_over_time['timestamp'], y=traffic_over_time['packets'],
                  name='Packets/sec', line=dict(color='red')),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(x=traffic_over_time['timestamp'], y=traffic_over_time['bytes'],
                  name='Bytes/sec', line=dict(color='blue'), yaxis='y2'),
        row=1, col=1, secondary_y=True
    )
    
    # Top source IPs
    top_sources = logs_df.groupby('src_ip')['packets'].sum().nlargest(10)
    fig.add_trace(
        go.Bar(x=top_sources.values, y=top_sources.index, 
               name='Packets', orientation='h', marker_color='orange'),
        row=1, col=2
    )
    
    # Protocol distribution
    protocol_dist = logs_df['protocol'].value_counts()
    fig.add_trace(
        go.Pie(labels=protocol_dist.index, values=protocol_dist.values, 
               name="Protocol Distribution"),
        row=2, col=1
    )
    
    # Attack pattern analysis
    attack_analysis = logs_df.groupby(['src_ip', 'attack_indicator']).size().reset_index(name='count')
    fig.add_trace(
        go.Scatter(x=attack_analysis['src_ip'], y=attack_analysis['count'],
                  mode='markers', marker=dict(size=attack_analysis['count'], 
                  color=attack_analysis['count'], colorscale='Reds'),
                  text=attack_analysis['attack_indicator'], name='Attack Patterns'),
        row=2, col=2
    )
    
    fig.update_layout(height=800, showlegend=True, 
                     title_text="🔍 Real-Time DDoS Detection Dashboard")
    
    return fig

def create_threat_intelligence_map(logs_df):
    """Create an interactive threat map showing attack sources"""
    
    # Mock geographical data for demo
    countries = ['United States', 'Russia', 'China', 'Brazil', 'Germany', 'India']
    
    # Aggregate attack data by mock countries
    geo_data = []
    for country in countries:
        attack_count = random.randint(10, 1000)
        severity = random.choice(['Low', 'Medium', 'High', 'Critical'])
        
        geo_data.append({
            'country': country,
            'attacks': attack_count,
            'severity': severity,
            'lat': random.uniform(-60, 70),
            'lon': random.uniform(-180, 180)
        })
    
    geo_df = pd.DataFrame(geo_data)
    
    # Create world map with attack sources
    fig = px.scatter_geo(geo_df,
                        lat='lat', lon='lon',
                        size='attacks',
                        color='severity',
                        color_discrete_map={
                            'Low': 'green',
                            'Medium': 'yellow', 
                            'High': 'orange',
                            'Critical': 'red'
                        },
                        hover_name='country',
                        hover_data=['attacks'],
                        title='🌍 Global DDoS Attack Sources')
    
    fig.update_geos(projection_type="orthographic")
    fig.update_layout(height=500)
    
    return fig

# Initialize session state
if 'ddos_system' not in st.session_state:
    st.session_state.ddos_system = MockDDoSDetectionSystem()
if 'kafka_logs' not in st.session_state:
    st.session_state.kafka_logs = []
if 'current_plan' not in st.session_state:
    st.session_state.current_plan = ""
if 'threat_level' not in st.session_state:
    st.session_state.threat_level = "NORMAL"

# Streamlit UI
st.set_page_config(
    page_title="DDoS Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Header
st.title("🛡️ AI-Powered DDoS Detection & Mitigation System")
st.markdown("---")

# Sidebar for controls
with st.sidebar:
    st.header("🎛️ Control Panel")
    
    # Simulation controls
    st.subheader("Simulation Controls")
    if st.button("🔄 Refresh Kafka Logs", type="primary"):
        st.session_state.kafka_logs = generate_mock_kafka_logs()
        st.success("Kafka logs refreshed!")
    
    if st.button("⚠️ Simulate DDoS Attack"):
        attack_alert = "High volume DDoS attack detected from multiple sources"
        with st.spinner("Processing DDoS threat..."):
            result = st.session_state.ddos_system.process_ddos_threat(attack_alert)
            st.session_state.current_plan = result['action_plan']
            st.session_state.threat_level = result['classification']
        st.success(f"DDoS threat processed! Level: {result['classification']}")
    
    # System status
    st.subheader("🔍 System Status")
    status_color = {"NORMAL": "🟢", "SUSPICIOUS": "🟡", "MODERATE": "🟠", 
                   "SEVERE": "🔴", "CRITICAL": "⚫"}
    st.markdown(f"**Threat Level:** {status_color.get(st.session_state.threat_level, '🟢')} {st.session_state.threat_level}")
    
    # Auto-refresh toggle
    auto_refresh = st.checkbox("🔄 Auto-refresh (5s)", value=True)

# Main dashboard
col1, col2 = st.columns([2, 1])

with col1:
    # Kafka Logs Section
    st.header("📊 Kafka Network Logs")
    
    # Auto-refresh logs if enabled
    if auto_refresh:
        if len(st.session_state.kafka_logs) == 0 or random.random() < 0.3:
            st.session_state.kafka_logs = generate_mock_kafka_logs()
    
    if st.session_state.kafka_logs:
        logs_df = pd.DataFrame(st.session_state.kafka_logs)
        
        # Display recent logs table
        st.subheader("Recent Network Events")
        st.dataframe(
            logs_df[['timestamp', 'src_ip', 'dst_ip', 'protocol', 'port', 'packets', 'flags']].head(10),
            use_container_width=True
        )
        
        # Network traffic visualization
        st.subheader("Real-Time Traffic Analysis")
        chart = create_network_traffic_chart(logs_df)
        st.plotly_chart(chart, use_container_width=True)
        
    else:
        st.info("No Kafka logs available. Click 'Refresh Kafka logs' to load data.")

with col2:
    # Current Mitigation Plan
    st.header("📋 Current Mitigation Plan")
    
    if st.session_state.current_plan:
        # Plan status indicator
        if st.session_state.threat_level in ['SEVERE', 'CRITICAL']:
            st.error(f"🚨 {st.session_state.threat_level} THREAT DETECTED")
        elif st.session_state.threat_level in ['MODERATE', 'SUSPICIOUS']:
            st.warning(f"⚠️ {st.session_state.threat_level} THREAT DETECTED")
        else:
            st.success("✅ System Normal")
        
        # Display plan
        st.markdown(st.session_state.current_plan)
        
        # Human decision buttons
        st.subheader("🧑‍💼 Human Decision Required")
        
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("✅ Execute Plan", type="primary"):
                st.success("🚀 Plan execution initiated!")
                st.balloons()
        
        with col_btn2:
            if st.button("🔧 Modify & Execute"):
                st.info("🛠️ Plan modifications requested")
        
        if st.button("❌ Reject Plan", type="secondary"):
            st.warning("⚠️ Plan rejected - Manual override activated")
            
    else:
        st.info("No active mitigation plan. Simulate a DDoS attack to generate one.")

# Enhanced Feature: Global Threat Intelligence Map
st.header("🌍 Enhanced Feature: Global Threat Intelligence Map")
st.markdown("**Real-time visualization of DDoS attack sources worldwide**")

if st.session_state.kafka_logs:
    logs_df = pd.DataFrame(st.session_state.kafka_logs)
    threat_map = create_threat_intelligence_map(logs_df)
    st.plotly_chart(threat_map, use_container_width=True)
else:
    st.info("Load Kafka logs to view global threat intelligence.")

# Performance Metrics Footer
st.markdown("---")
col_metric1, col_metric2, col_metric3, col_metric4 = st.columns(4)

if st.session_state.kafka_logs:
    logs_df = pd.DataFrame(st.session_state.kafka_logs)
    
    with col_metric1:
        total_packets = logs_df['packets'].sum()
        st.metric("Total Packets", f"{total_packets:,}")
    
    with col_metric2:
        unique_sources = logs_df['src_ip'].nunique()
        st.metric("Unique Sources", unique_sources)
    
    with col_metric3:
        avg_packet_size = logs_df['bytes'].mean() / logs_df['packets'].mean() if logs_df['packets'].mean() > 0 else 0
        st.metric("Avg Packet Size", f"{avg_packet_size:.0f} bytes")
    
    with col_metric4:
        attack_score = min(100, (total_packets / 1000) + (unique_sources * 2))
        st.metric("Attack Risk Score", f"{attack_score:.0f}/100")

# Auto-refresh mechanism
if auto_refresh:
    time.sleep(5)
    st.rerun()