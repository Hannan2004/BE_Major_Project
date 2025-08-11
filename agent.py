import os
from typing import Dict, List, Any, TypedDict, Annotated
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_cerebras import ChatCerebras
from langchain.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone, ServerlessSpec
from langchain.schema import Document
import json
import datetime
from dotenv import load_dotenv
import time

load_dotenv()

class CyberThreatState(TypedDict):
    """State object that gets passed between agents"""
    sensor_alert: str
    messages: Annotated[list, add_messages]
    classification: str
    threat_metadata: Dict[str, Any]
    retrieved_docs: List[Dict]
    ai_response: str
    human_decision: str
    final_action: str
    timestamp: str
    confidence_score: float

class CyberSecuritySystem:
    """Real implementation using LangGraph with ChatGroq and Pinecone"""

    def __init__(self):

        self.llm = ChatCerebras(
            api_key=os.getenv("CEREBRAS_API_KEY"),
            model="qwen-3-32b",
        )

        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )

        self.pinecone_api_key = os.getenv("PINECONE_API_KEY")
        self.index_name = "cybersecurity-threats"

        self.vector_store = self._setup_vector_store()

        self.app = self._create_graph()

    def _setup_vector_store(self) -> PineconeVectorStore:
        "Set up Pinecone vector store"

        pc = Pinecone(api_key=self.pinecone_api_key)
        
        try:
            existing_indexes = pc.list_indexes().names()

            if self.index_name not in existing_indexes:
                pc.create_index(
                    name=self.index_name,
                    dimension=384,
                    metric='cosine',
                    spec=ServerlessSpec(
                        cloud='aws',
                        region='us-east-1'
                    )
                )
                time.sleep(10)

            index = pc.Index(self.index_name)

            stats = index.describe_index_stats()
            if stats.total_vector_count > 0:
                return PineconeVectorStore(
                    index=index,
                    embedding=self.embeddings
                )

            file_path = r"DDoS_Book.pdf" 
            loader = PyPDFLoader(file_path)
            documents = loader.load()

            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=20
            )
            docs = text_splitter.split_documents(documents)

            vector_store = PineconeVectorStore.from_documents(
                documents=docs,
                embedding=self.embeddings,
                index_name=self.index_name
            )

            return vector_store

        except Exception as e:
            print(f"Error setting up Pinecone vector store: {e}")
            return None

    def _create_graph(self) -> StateGraph:
        """Create the LangGraph workflow"""

        workflow = StateGraph(CyberThreatState)

        workflow.add_node("data_ingestion", self.data_ingestion_agent)
        workflow.add_node("classify_event", self.event_classification_agent)
        workflow.add_node("retrieve_intel", self.rag_agent)
        workflow.add_node("reasoning", self.reasoning_agent)
        workflow.add_node("planning", self.planning_agent)
        workflow.add_node("plan_reflector", self.plan_reflector_agent)
        workflow.add_node("human_review", self.human_interaction_agent)
        
        workflow.set_entry_point("data_ingestion")
        workflow.add_edge("data_ingestion", "classify_event")
        workflow.add_edge("classify_event", "retrieve_intel")
        workflow.add_edge("retrieve_intel", "reasoning")
        workflow.add_edge("reasoning", "planning")
        workflow.add_edge("planning", "plan_reflector")
        workflow.add_conditional_edge("plan_reflector", decision, {"human_review": "human_review", "planning": "planning"})
        workflow.add_conditional_edge("human_review", human_decision, {"approved": END, "not_approved": "planning"})
        workflow.add_edge("planning", END)

        return workflow.compile()

  
    def data_ingestion_agent(self, state: CyberThreatState) -> CyberThreatState:
        """Agent 1: Data Ingestion and Preprocessing from Kafka"""

        timestamp = datetime.datetime.now().isoformat()

        try:
            consumer = KafkaConsumer(
                'network-logs',
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                consumer_timeout_ms=5000
            )

            network_logs = []
            for message in consumer:
                network_logs.append(message.value)
                if len(network_logs) >= 10:
                    break
            
            consumer.close()

            if not network_logs:
                state["threat_metadata"] = {
                    "timestamp": timestamp,
                    "error": "No network logs found",
                    "processed_by": "data_ingestion_agent"
                }
                return state
            
            logs_text = "\n".join([str(log) for log in network_logs])

            summary_prompt = f"""
            Analyze and summarize these network logs for potential security threats:
        
            Network Logs:
            {logs_text}
        
            Provide a structured summary including:
            - Total Events: Number of log entries processed
            - Suspicious Activities: Any anomalous patterns or behaviors
            - Source IPs: Key source IP addresses
            - Destination IPs: Key destination IP addresses
            - Protocols: Network protocols observed
            - Risk Assessment: Low, Medium, High, or Critical
            - Key Findings: Brief description of notable events
 
            Keep your response concise and focused on security relevance.
            """

            response = self.llm.invoke(summary_prompt)

            metadata = {
            "timestamp": timestamp,
            "raw_logs_count": len(network_logs),
            "processed_by": "data_ingestion_agent",
            "source_system": "Kafka Network Logs",
            "log_summary": response.content,
            "sample_logs": network_logs[:3],  # Keep first 3 logs as samples
            "risk_level": self._extract_risk_level(response.content),
            "source_ips": self._extract_source_ips(network_logs),
            "destination_ips": self._extract_destination_ips(network_logs)
            }
        
        except Exception as e:
            metadata = {
                "timestamp": timestamp,
                "error": str(e),
                "processed_by": "data_ingestion_agent",
                "source_system": "Kafka Network Logs",
                "risk_level": "Unknown"
            }
        
        state["threat_metadata"] = metadata
        state["timestamp"] = timestamp
        state["network_logs_summary"] = metadata.get("log_summary", "No summary available")
        state["messages"] = [{"role": "system", "content": f"Network logs processed: {len(network_logs)} entries analyzed"}]
        
        return state
    
    def event_classification_agent(self, state: CyberThreatState) -> CyberThreatState:
        """Agent 2: Event Classification using Groq LLM"""
        
        alert = state["sensor_alert"]
        metadata = state["threat_metadata"]
        
        classification_prompt = f"""
        You are a cybersecurity expert. Classify this security event based on severity and required response.
        
        Alert: {alert}
        Location: {metadata.get('location', 'Unknown')}
        Source System: {metadata.get('source_system', 'Unknown')}
        
        Classify the threat level as exactly one of:
        - ROUTINE: Normal operational events, low priority, can wait for regular business hours
        - ALERT: Suspicious activity requiring attention within hours
        - URGENT: Significant threats requiring immediate response within minutes
        - EMERGENCY: Critical threats requiring immediate response within seconds
        
        Also provide a confidence score between 0.0 and 1.0 based on the clarity and severity of the threat.
        
        Respond in this exact format:
        Classification: [ROUTINE/ALERT/URGENT/EMERGENCY]
        Confidence: [0.0-1.0]
        Reasoning: [Brief explanation]
        """
        
        try:
            response = self.llm.invoke(classification_prompt)
            response_text = response.content.upper()
            
            if "EMERGENCY" in response_text:
                classification = "EMERGENCY"
                confidence = 0.95
            elif "URGENT" in response_text:
                classification = "URGENT"
                confidence = 0.90
            elif "ALERT" in response_text:
                classification = "ALERT"
                confidence = 0.85
            elif "ROUTINE" in response_text:
                classification = "ROUTINE"
                confidence = 0.80
            else:
                classification = "ALERT"  
                confidence = 0.70
                
            try:
                import re
                conf_match = re.search(r'confidence:\s*([0-9.]+)', response.content.lower())
                if conf_match:
                    confidence = float(conf_match.group(1))
            except:
                pass
                
        except Exception as e:
            classification = "ALERT"
            confidence = 0.5
        
        state["classification"] = classification
        state["confidence_score"] = confidence
        state["messages"].append({
            "role": "assistant", 
            "content": f"Event classified as {classification} with {confidence:.1%} confidence"
        })
        
        return state
    
    def rag_agent(self, state: CyberThreatState) -> CyberThreatState:
        """Agent 3: RAG-based Threat Intelligence Retrieval using Pinecone"""
        
        alert = state["sensor_alert"]
        classification = state["classification"]
        alert_type = state["threat_metadata"].get("alert_type", "")
        
        search_query = f"{alert} {classification} {alert_type} protocol response"
        
        try:
            if self.vector_store:
                docs = self.vector_store.similarity_search(search_query, k=3)
                
                retrieved_docs = []
                for i, doc in enumerate(docs):
                    retrieved_docs.append({
                        "content": doc.page_content,
                        "metadata": doc.metadata,
                        "relevance_score": 0.9 - (i * 0.1)  # Simple scoring
                    })
            else:
                retrieved_docs = [{
                    "content": "GENERIC SECURITY RESPONSE: 1. Assess the situation 2. Contain the threat 3. Notify stakeholders 4. Document incident",
                    "metadata": {"threat_type": "generic", "severity": classification},
                    "relevance_score": 0.6
                }]
                
        except Exception as e:
            retrieved_docs = [{
                "content": f"Error retrieving threat intelligence: {str(e)}",
                "metadata": {"error": str(e)},
                "relevance_score": 0.0
            }]
        
        state["retrieved_docs"] = retrieved_docs
        state["messages"].append({
            "role": "assistant",
            "content": f"Retrieved {len(retrieved_docs)} relevant threat intelligence documents from Pinecone"
        })
        
        return state
    
    def reasoning_agent(self, state: CyberThreatState) -> CyberThreatState:
        """Agent 4: GenAI Response Generation using Groq"""
        
        alert = state["sensor_alert"]
        classification = state["classification"]
        docs = state["retrieved_docs"]
        metadata = state["threat_metadata"]
        
        doc_context = "\n\n".join([
            f"Protocol Document {i+1}:\n{doc['content']}" 
            for i, doc in enumerate(docs) if doc['relevance_score'] > 0.5
        ])
        
        response_prompt = f"""
        You are a cybersecurity incident response expert. Generate a detailed, actionable response plan.
        
        INCIDENT DETAILS:
        - Alert: {alert}
        - Classification: {classification}
        - Location: {metadata.get('location', 'Unknown')}
        - Timestamp: {metadata.get('timestamp', 'Unknown')}
        - Alert Type: {metadata.get('alert_type', 'Unknown')}
        
        RELEVANT PROTOCOLS:
        {doc_context}
        
        Generate a comprehensive incident response plan with:
        1. IMMEDIATE ACTIONS (next 5 minutes)
        2. PERSONNEL TO NOTIFY (specific roles/departments)
        3. SYSTEMS TO CHECK/ISOLATE (technical steps)
        4. FOLLOW-UP PROCEDURES (next 24 hours)
        5. ESCALATION PATH (if situation worsens)
        
        Be specific, actionable, and consider the {classification} classification level.
        Format your response clearly with numbered steps under each section.
        """
        
        try:
            response = self.llm.invoke(response_prompt)
            ai_response = response.content
        except Exception as e:
            ai_response = f"Error generating response: {str(e)}\n\nFallback response: Please manually assess the {classification} level incident: {alert}"
        
        state["ai_response"] = ai_response
        state["messages"].append({
            "role": "assistant",
            "content": "Generated comprehensive incident response plan using Groq LLM"
        })
        
        return state
    
    def human_interaction_agent(self, state: CyberThreatState) -> CyberThreatState:
        """Agent 5: Human-in-the-loop Interaction"""
        
        human_decision = state.get("human_decision", "PENDING")
        
        if human_decision == "APPROVE":
            final_action = "EXECUTE_AI_RECOMMENDATION"
            action_status = "AI recommendation approved and queued for execution"
        elif human_decision == "OVERRIDE":
            final_action = "AWAIT_MANUAL_INSTRUCTIONS"
            action_status = "Manual override activated, awaiting human instructions"
        elif human_decision == "ESCALATE":
            final_action = "ESCALATE_TO_SUPERVISOR"
            action_status = "Incident escalated to supervisor for review"
        elif human_decision == "MODIFY":
            final_action = "REQUEST_MODIFICATIONS"
            action_status = "Requesting modifications to AI recommendation"
        else:
            final_action = "PENDING_HUMAN_REVIEW"
            action_status = "Awaiting human operator decision"
        
        state["final_action"] = final_action
        state["messages"].append({
            "role": "system",
            "content": action_status
        })
        
        return state
    
    def _extract_location(self, alert: str) -> str:
        """Extract location from alert text"""
        import re
        
        location_patterns = [
            r"zone\s+([A-Z]\d*)",
            r"gate\s+(\d+)",
            r"terminal\s+([A-Z]\d*)",
            r"sector\s+(\d+)",
            r"area\s+(\d+)",
            r"floor\s+(\d+)",
            r"building\s+([A-Z]\d*)",
            r"room\s+(\d+)"
        ]
        
        for pattern in location_patterns:
            match = re.search(pattern, alert, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return "Unknown Location"
    
    def _extract_alert_type(self, alert: str) -> str:
        """Extract alert type from description"""
        alert_lower = alert.lower()
        
        if any(word in alert_lower for word in ["unauthorized", "access", "breach", "intrusion"]):
            return "unauthorized_access"
        elif any(word in alert_lower for word in ["sensor", "spoofing", "manipulation", "tamper"]):
            return "sensor_spoofing"
        elif any(word in alert_lower for word in ["network", "cyber", "ddos", "attack"]):
            return "network_intrusion"
        elif any(word in alert_lower for word in ["light", "lighting", "illumination"]):
            return "lighting_anomaly"
        elif any(word in alert_lower for word in ["malware", "virus", "trojan", "ransomware"]):
            return "malware"
        elif any(word in alert_lower for word in ["fire", "smoke", "temperature", "heat"]):
            return "environmental_threat"
        else:
            return "generic_security_event"
    
    def _extract_system_info(self, llm_response: str) -> str:
        """Extract system information from LLM response"""
        response_lower = llm_response.lower()
        
        if "iot" in response_lower or "sensor" in response_lower:
            return "IoT Sensor Network"
        elif "network" in response_lower:
            return "Network Security System"
        elif "access" in response_lower or "door" in response_lower:
            return "Access Control System"
        elif "camera" in response_lower or "surveillance" in response_lower:
            return "Video Surveillance System"
        else:
            return "Security Monitoring System"
    
    def process_threat(self, sensor_alert: str, human_decision: str = "PENDING") -> Dict[str, Any]:
        """Process a threat through the complete agent pipeline"""
        
        initial_state = CyberThreatState(
            sensor_alert=sensor_alert,
            messages=[],
            classification="",
            threat_metadata={},
            retrieved_docs=[],
            ai_response="",
            human_decision=human_decision,
            final_action="",
            timestamp="",
            confidence_score=0.0
        )
        
        try:
            result = self.app.invoke(initial_state)
            return result
        except Exception as e:
            return {
                "error": f"Pipeline execution failed: {str(e)}",
                "sensor_alert": sensor_alert,
                "classification": "ERROR",
                "final_action": "SYSTEM_ERROR",
                "ai_response": f"System error occurred: {str(e)}",
                "confidence_score": 0.0,
                "timestamp": datetime.datetime.now().isoformat()
            }

def create_production_system():
    """
    Example of how to set up the production system
    """
    
    required_env_vars = [
        "CEREBRAS_API_KEY",
        "PINECONE_API_KEY"
    ]
    
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Warning: Missing environment variables: {missing_vars}")
        print("System will run with limited functionality.")
    
    # Initialize system
    cyber_system = CyberSecuritySystem()
    
    return cyber_system

# Threat Input Handler
class ThreatInputHandler:
    """Handles different types of threat inputs"""
    
    def __init__(self, cyber_system: CyberSecuritySystem):
        self.cyber_system = cyber_system
    
    def handle_sensor_input(self, sensor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle input from IoT sensors"""
        
        alert = f"Sensor anomaly detected: {sensor_data.get('type', 'Unknown')} " \
                f"at {sensor_data.get('location', 'Unknown location')} " \
                f"with value {sensor_data.get('value', 'N/A')} " \
                f"(threshold: {sensor_data.get('threshold', 'N/A')})"
        
        return self.cyber_system.process_threat(alert)
    
    def handle_network_alert(self, network_event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle network security alerts"""
        
        alert = f"Network security event: {network_event.get('event_type', 'Unknown')} " \
                f"from IP {network_event.get('source_ip', 'Unknown')} " \
                f"targeting {network_event.get('target', 'Unknown system')} " \
                f"detected by {network_event.get('detector', 'security system')}"
        
        return self.cyber_system.process_threat(alert)
    
    def handle_access_control_event(self, access_event: Dict[str, Any]) -> Dict[str, Any]:
        """Handle access control system events"""
        
        alert = f"Access control event: {access_event.get('event_type', 'Unknown')} " \
                f"by user {access_event.get('user_id', 'Unknown')} " \
                f"at {access_event.get('location', 'Unknown location')} " \
                f"using {access_event.get('access_method', 'unknown method')}"
        
        return self.cyber_system.process_threat(alert)

if __name__ == "__main__":
    try:
        system = create_production_system()
        
        test_alert = "Unauthorized access detected at Gate 7 security checkpoint with failed biometric authentication"
        result = system.process_threat(test_alert)
        
        print("Threat Processing Result:")
        print(f"Classification: {result['classification']}")
        print(f"Confidence: {result['confidence_score']:.2%}")
        print(f"Final Action: {result['final_action']}")
        print(f"\nAI Response:\n{result['ai_response']}")
        
    except Exception as e:
        print(f"System initialization failed: {e}")
        print("Please ensure all required environment variables are set:")
        print("- CEREBRAS_API_KEY")
        print("- PINECONE_API_KEY")   
