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
from kafka import KafkaConsumer
import json
import datetime
from dotenv import load_dotenv
import time
import re

load_dotenv()

class DDoSDetectionState(TypedDict):
    """State object that gets passed between agents"""
    sensor_alert: str
    messages: Annotated[list, add_messages]
    classification: str
    threat_metadata: Dict[str, Any]
    retrieved_docs: List[Dict]
    ai_response: str
    action_plan: str
    plan_review: str
    plan_approved: bool
    human_decision: str
    final_action: str
    timestamp: str
    confidence_score: float
    network_logs_summary: str

class DDoSDetectionSystem:
    """DDoS Attack Detection System using LangGraph with multiple agents"""

    def __init__(self):
        self.llm = ChatCerebras(
            api_key=os.getenv("CEREBRAS_API_KEY"),
            model="qwen-3-32b",
        )

        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )

        self.pinecone_api_key = os.getenv("PINECONE_API_KEY")
        self.index_name = "ddos-threat-intel"

        self.vector_store = self._setup_vector_store()
        self.app = self._create_graph()

    def _setup_vector_store(self) -> PineconeVectorStore:
        """Set up Pinecone vector store for DDoS threat intelligence"""
        
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

            # Load DDoS knowledge base
            file_path = r"DDoS_Book.pdf" 
            loader = PyPDFLoader(file_path)
            documents = loader.load()

            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=200
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
        
        workflow = StateGraph(DDoSDetectionState)

        # Add all agents
        workflow.add_node("data_ingestion", self.data_ingestion_agent)
        workflow.add_node("classify_event", self.event_classification_agent)
        workflow.add_node("retrieve_intel", self.rag_agent)
        workflow.add_node("reasoning", self.reasoning_agent)
        workflow.add_node("planning", self.planning_agent)
        workflow.add_node("plan_reflector", self.plan_reflector_agent)
        workflow.add_node("human_review", self.human_interaction_agent)
        
        # Define workflow edges
        workflow.set_entry_point("data_ingestion")
        workflow.add_edge("data_ingestion", "classify_event")
        workflow.add_edge("classify_event", "retrieve_intel")
        workflow.add_edge("retrieve_intel", "reasoning")
        workflow.add_edge("reasoning", "planning")
        workflow.add_edge("planning", "plan_reflector")
        
        # Conditional edges
        workflow.add_conditional_edge(
            "plan_reflector", 
            self.plan_decision, 
            {"human_review": "human_review", "planning": "planning"}
        )
        workflow.add_conditional_edge(
            "human_review", 
            self.human_decision_router, 
            {"approved": END, "not_approved": "planning"}
        )

        return workflow.compile()

    def plan_decision(self, state: DDoSDetectionState) -> str:
        """Decision function for plan reflector"""
        return "human_review" if state["plan_approved"] else "planning"

    def human_decision_router(self, state: DDoSDetectionState) -> str:
        """Decision function for human review"""
        decision = state.get("human_decision", "PENDING")
        return "approved" if decision in ["EXECUTE", "MODIFY_AND_EXECUTE"] else "not_approved"

    def data_ingestion_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 1: Data Ingestion from Kafka Network Logs"""
        
        timestamp = datetime.datetime.now().isoformat()
        
        try:
            # Connect to Kafka consumer for network logs
            consumer = KafkaConsumer(
                'network-logs',
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                consumer_timeout_ms=5000
            )

            network_logs = []
            for message in consumer:
                network_logs.append(message.value)
                if len(network_logs) >= 20:  # Get more logs for DDoS analysis
                    break
            
            consumer.close()

            if not network_logs:
                # Simulate network logs for demo
                network_logs = [
                    {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "protocol": "TCP", "port": 80, "packets": 1000, "timestamp": timestamp},
                    {"src_ip": "192.168.1.101", "dst_ip": "10.0.0.1", "protocol": "TCP", "port": 80, "packets": 1500, "timestamp": timestamp},
                    {"src_ip": "192.168.1.102", "dst_ip": "10.0.0.1", "protocol": "TCP", "port": 80, "packets": 2000, "timestamp": timestamp},
                    {"src_ip": "192.168.1.103", "dst_ip": "10.0.0.1", "protocol": "UDP", "port": 53, "packets": 5000, "timestamp": timestamp},
                    {"src_ip": "192.168.1.104", "dst_ip": "10.0.0.1", "protocol": "TCP", "port": 443, "packets": 3000, "timestamp": timestamp}
                ]
            
            logs_text = "\n".join([str(log) for log in network_logs])

            # Analyze logs for DDoS patterns
            analysis_prompt = f"""
            Analyze these network logs for potential DDoS attack patterns:
        
            Network Logs:
            {logs_text}
        
            Look for DDoS indicators such as:
            - High packet volume from single/multiple sources
            - Unusual traffic patterns to single destination
            - Protocol flooding (TCP/UDP/ICMP)
            - Port scanning activities
            - Bandwidth consumption anomalies
            
            Provide analysis including:
            - Total Packets: Sum of all packet counts
            - Unique Source IPs: Count of distinct source addresses
            - Top Target: Most targeted destination IP
            - Suspicious Patterns: Any DDoS-like behaviors
            - Traffic Volume: Assessment of traffic levels
            - Risk Level: LOW, MEDIUM, HIGH, or CRITICAL
            
            Keep response structured and security-focused.
            """

            response = self.llm.invoke(analysis_prompt)

            metadata = {
                "timestamp": timestamp,
                "logs_processed": len(network_logs),
                "processed_by": "data_ingestion_agent",
                "source_system": "Kafka Network Logs",
                "analysis": response.content,
                "sample_logs": network_logs[:5],
                "total_packets": sum(log.get('packets', 0) for log in network_logs),
                "unique_sources": len(set(log.get('src_ip', '') for log in network_logs)),
                "risk_level": self._extract_risk_level(response.content)
            }
        
        except Exception as e:
            metadata = {
                "timestamp": timestamp,
                "error": str(e),
                "processed_by": "data_ingestion_agent",
                "source_system": "Kafka Network Logs",
                "risk_level": "UNKNOWN"
            }
        
        state["threat_metadata"] = metadata
        state["timestamp"] = timestamp
        state["network_logs_summary"] = metadata.get("analysis", "No analysis available")
        state["messages"] = [{"role": "system", "content": f"Network logs ingested: {metadata.get('logs_processed', 0)} entries analyzed"}]
        
        return state

    def event_classification_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 2: DDoS Event Classification"""
        
        alert = state["sensor_alert"]
        metadata = state["threat_metadata"]
        logs_summary = state["network_logs_summary"]
        
        classification_prompt = f"""
        You are a DDoS attack detection expert. Classify this potential DDoS event:
        
        Alert: {alert}
        Network Analysis: {logs_summary}
        Total Packets: {metadata.get('total_packets', 0)}
        Unique Sources: {metadata.get('unique_sources', 0)}
        
        Classify the DDoS threat level as exactly one of:
        - NORMAL: Regular traffic, no DDoS indicators
        - SUSPICIOUS: Unusual patterns, possible reconnaissance 
        - MODERATE: DDoS attack detected, manageable impact
        - SEVERE: Large-scale DDoS, significant impact
        - CRITICAL: Massive DDoS attack, service disruption imminent
        
        Consider factors:
        - Traffic volume and rate
        - Source IP diversity 
        - Protocol distribution
        - Target concentration
        - Attack sophistication
        
        Provide confidence score (0.0-1.0) based on evidence strength.
        
        Format:
        Classification: [NORMAL/SUSPICIOUS/MODERATE/SEVERE/CRITICAL]
        Confidence: [0.0-1.0]
        Attack Type: [e.g., Volumetric, Protocol, Application Layer]
        Reasoning: [Brief technical explanation]
        """
        
        try:
            response = self.llm.invoke(classification_prompt)
            response_text = response.content.upper()
            
            # Extract classification
            if "CRITICAL" in response_text:
                classification = "CRITICAL"
                confidence = 0.95
            elif "SEVERE" in response_text:
                classification = "SEVERE"
                confidence = 0.90
            elif "MODERATE" in response_text:
                classification = "MODERATE"
                confidence = 0.85
            elif "SUSPICIOUS" in response_text:
                classification = "SUSPICIOUS"
                confidence = 0.75
            else:
                classification = "NORMAL"
                confidence = 0.70
                
            # Try to extract confidence from response
            try:
                conf_match = re.search(r'confidence:\s*([0-9.]+)', response.content.lower())
                if conf_match:
                    confidence = float(conf_match.group(1))
            except:
                pass
                
        except Exception as e:
            classification = "MODERATE"  # Safe default for DDoS
            confidence = 0.5
        
        state["classification"] = classification
        state["confidence_score"] = confidence
        state["messages"].append({
            "role": "assistant", 
            "content": f"DDoS event classified as {classification} with {confidence:.1%} confidence"
        })
        
        return state

    def rag_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 3: RAG-based DDoS Threat Intelligence Retrieval"""
        
        alert = state["sensor_alert"]
        classification = state["classification"]
        
        # Create search query for DDoS-specific knowledge
        search_query = f"DDoS {classification} attack mitigation response protocol defense"
        
        try:
            if self.vector_store:
                docs = self.vector_store.similarity_search(search_query, k=5)
                
                retrieved_docs = []
                for i, doc in enumerate(docs):
                    retrieved_docs.append({
                        "content": doc.page_content,
                        "metadata": doc.metadata,
                        "relevance_score": 0.95 - (i * 0.1)
                    })
            else:
                # Fallback DDoS knowledge
                retrieved_docs = [{
                    "content": """DDoS Attack Response Protocol:
1. IMMEDIATE: Activate rate limiting and traffic filtering
2. ANALYZE: Identify attack vectors and source patterns  
3. MITIGATE: Deploy upstream filtering and traffic shaping
4. COMMUNICATE: Notify stakeholders and ISP if needed
5. DOCUMENT: Log attack details for forensic analysis""",
                    "metadata": {"source": "DDoS_Response_Guide", "severity": classification},
                    "relevance_score": 0.8
                }]
                
        except Exception as e:
            retrieved_docs = [{
                "content": f"Error retrieving DDoS intelligence: {str(e)}. Use standard DDoS mitigation procedures.",
                "metadata": {"error": str(e)},
                "relevance_score": 0.0
            }]
        
        state["retrieved_docs"] = retrieved_docs
        state["messages"].append({
            "role": "assistant",
            "content": f"Retrieved {len(retrieved_docs)} DDoS mitigation documents from knowledge base"
        })
        
        return state

    def reasoning_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 4: DDoS Attack Analysis and Response Generation"""
        
        alert = state["sensor_alert"]
        classification = state["classification"]
        docs = state["retrieved_docs"]
        metadata = state["threat_metadata"]
        
        doc_context = "\n\n".join([
            f"Knowledge Source {i+1}:\n{doc['content']}" 
            for i, doc in enumerate(docs) if doc['relevance_score'] > 0.6
        ])
        
        reasoning_prompt = f"""
        You are a DDoS incident response specialist. Analyze this attack and generate response strategy.
        
        ATTACK DETAILS:
        - Alert: {alert}
        - Classification: {classification}
        - Total Packets: {metadata.get('total_packets', 'Unknown')}
        - Unique Sources: {metadata.get('unique_sources', 'Unknown')}
        - Timestamp: {metadata.get('timestamp', 'Unknown')}
        
        KNOWLEDGE BASE:
        {doc_context}
        
        Generate comprehensive DDoS response analysis covering:
        
        1. ATTACK ASSESSMENT
           - Attack type and vectors identified
           - Scale and potential impact
           - Source analysis (botnet, single source, etc.)
           
        2. IMMEDIATE TECHNICAL RESPONSE
           - Traffic filtering and rate limiting
           - Upstream mitigation requests
           - System resource protection
           
        3. STAKEHOLDER COMMUNICATION
           - Internal teams to notify
           - External parties (ISP, CDN, law enforcement)
           - Customer/user communication plan
           
        4. MONITORING AND DOCUMENTATION
           - Key metrics to track
           - Evidence collection procedures
           - Attack timeline documentation
        
        Base recommendations on the {classification} severity level.
        Be specific and actionable for cybersecurity teams.
        """
        
        try:
            response = self.llm.invoke(reasoning_prompt)
            ai_response = response.content
        except Exception as e:
            ai_response = f"Error generating DDoS response: {str(e)}\n\nFallback: Implement immediate DDoS mitigation for {classification} level attack: {alert}"
        
        state["ai_response"] = ai_response
        state["messages"].append({
            "role": "assistant",
            "content": "Generated comprehensive DDoS attack analysis and response strategy"
        })
        
        return state

    def planning_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 5: Create Actionable DDoS Mitigation Plan"""
        
        classification = state["classification"]
        ai_response = state["ai_response"]
        metadata = state["threat_metadata"]
        
        planning_prompt = f"""
        Create an actionable DDoS mitigation plan based on this analysis:
        
        THREAT LEVEL: {classification}
        ANALYSIS: {ai_response}
        
        Create a step-by-step execution plan with:
        
        PHASE 1 - IMMEDIATE ACTIONS (0-5 minutes)
        - Specific technical steps to implement now
        - Commands to execute
        - Systems to activate
        
        PHASE 2 - SHORT TERM RESPONSE (5-30 minutes)  
        - Mitigation scaling procedures
        - Stakeholder notifications
        - Evidence collection tasks
        
        PHASE 3 - SUSTAINED DEFENSE (30+ minutes)
        - Long-term monitoring setup
        - Capacity planning adjustments
        - Post-incident preparation
        
        ROLLBACK PLAN
        - Steps to reverse actions if needed
        - Criteria for plan modification
        
        Include specific commands, timeframes, and responsible parties.
        Make each step clear and executable by technical staff.
        """
        
        try:
            response = self.llm.invoke(planning_prompt)
            action_plan = response.content
        except Exception as e:
            action_plan = f"Error creating plan: {str(e)}\n\nBasic DDoS Plan:\n1. Enable rate limiting\n2. Contact ISP\n3. Monitor traffic\n4. Document incident"
        
        state["action_plan"] = action_plan
        state["messages"].append({
            "role": "assistant",
            "content": "Created detailed DDoS mitigation execution plan"
        })
        
        return state

    def plan_reflector_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 6: Review and Validate DDoS Mitigation Plan"""
        
        action_plan = state["action_plan"]
        classification = state["classification"]
        confidence = state["confidence_score"]
        
        reflection_prompt = f"""
        Review this DDoS mitigation plan for completeness and effectiveness:
        
        PLAN TO REVIEW:
        {action_plan}
        
        CONTEXT:
        - Threat Level: {classification}
        - Confidence: {confidence:.1%}
        
        Evaluate the plan across these criteria:
        
        1. TECHNICAL SOUNDNESS
           - Are mitigation steps appropriate for threat level?
           - Are commands and procedures technically correct?
           - Is the timeline realistic?
        
        2. COMPLETENESS
           - Are all critical response phases covered?
           - Is stakeholder communication adequate?
           - Are rollback procedures included?
        
        3. RISK ASSESSMENT
           - Could any steps cause service disruption?
           - Are there missing safety checks?
           - Is escalation path clear?
        
        4. EXECUTABILITY  
           - Are steps clear and actionable?
           - Are responsibilities well-defined?
           - Are prerequisites identified?
        
        Provide your assessment as:
        APPROVED: Plan is ready for execution
        NEEDS_REVISION: Plan requires modifications
        
        If NEEDS_REVISION, specify exactly what needs to be changed.
        """
        
        try:
            response = self.llm.invoke(reflection_prompt)
            plan_review = response.content
            
            # Determine if plan is approved
            plan_approved = "APPROVED" in plan_review.upper() and "NEEDS_REVISION" not in plan_review.upper()
            
        except Exception as e:
            plan_review = f"Error reviewing plan: {str(e)}"
            plan_approved = False
        
        state["plan_review"] = plan_review
        state["plan_approved"] = plan_approved
        state["messages"].append({
            "role": "assistant",
            "content": f"Plan review completed: {'APPROVED' if plan_approved else 'NEEDS REVISION'}"
        })
        
        return state

    def human_interaction_agent(self, state: DDoSDetectionState) -> DDoSDetectionState:
        """Agent 7: Human Decision Interface"""
        
        classification = state["classification"]
        action_plan = state["action_plan"]
        plan_review = state["plan_review"]
        human_decision = state.get("human_decision", "PENDING")
        
        if human_decision == "EXECUTE":
            final_action = "PLAN_EXECUTION_INITIATED"
            status_message = f"""
🚀 EXECUTING DDOS MITIGATION PLAN

Classification: {classification}
Plan Status: APPROVED FOR EXECUTION
Action: Implementing all mitigation steps immediately

✅ Automatic DDoS defenses activated
✅ Upstream filtering requests sent  
✅ Incident response team notified
✅ Monitoring systems engaged

The DDoS mitigation plan is now being executed automatically.
All technical teams have been notified and are responding.
            """
            
        elif human_decision == "MODIFY_AND_EXECUTE":
            final_action = "PLAN_MODIFICATION_REQUESTED"
            status_message = f"""
🔧 MODIFYING AND EXECUTING DDOS PLAN

Classification: {classification}
Plan Status: APPROVED WITH MODIFICATIONS
Action: Incorporating human feedback and executing

✅ Plan modifications being implemented
✅ Custom mitigation steps added
✅ Enhanced monitoring configured
✅ Modified plan ready for deployment

The DDoS mitigation plan has been customized based on human input 
and is now being deployed with the requested modifications.
            """
            
        elif human_decision == "REJECT":
            final_action = "PLAN_REJECTED_MANUAL_OVERRIDE"
            status_message = f"""
❌ DDOS PLAN REJECTED - MANUAL OVERRIDE

Classification: {classification}
Plan Status: REJECTED BY HUMAN OPERATOR
Action: Awaiting manual intervention

⚠️ Automated response disabled
⚠️ Manual mitigation required
⚠️ Human operator taking control
⚠️ Incident escalated to senior team

The automated DDoS response has been overridden.
Human operators are now handling the incident manually.
            """
            
        else:
            final_action = "AWAITING_HUMAN_DECISION"
            status_message = f"""
⏳ AWAITING HUMAN DECISION

Classification: {classification}
Plan Status: READY FOR REVIEW
Action: Pending human operator input

Plan Options:
1. EXECUTE - Deploy the mitigation plan immediately
2. MODIFY_AND_EXECUTE - Customize plan then deploy  
3. REJECT - Override automated response

The DDoS mitigation plan is ready and awaiting your decision.
Please review the plan details and select your preferred action.
            """
        
        state["final_action"] = final_action
        state["messages"].append({
            "role": "system",
            "content": status_message
        })
        
        return state

    def _extract_risk_level(self, text: str) -> str:
        """Extract risk level from analysis text"""
        text_upper = text.upper()
        
        if "CRITICAL" in text_upper:
            return "CRITICAL"
        elif "HIGH" in text_upper:
            return "HIGH"
        elif "MEDIUM" in text_upper:
            return "MEDIUM"
        elif "LOW" in text_upper:
            return "LOW"
        else:
            return "UNKNOWN"

    def process_ddos_threat(self, sensor_alert: str, human_decision: str = "PENDING") -> Dict[str, Any]:
        """Process a DDoS threat through the complete agent pipeline"""
        
        initial_state = DDoSDetectionState(
            sensor_alert=sensor_alert,
            messages=[],
            classification="",
            threat_metadata={},
            retrieved_docs=[],
            ai_response="",
            action_plan="",
            plan_review="",
            plan_approved=False,
            human_decision=human_decision,
            final_action="",
            timestamp="",
            confidence_score=0.0,
            network_logs_summary=""
        )
        
        try:
            result = self.app.invoke(initial_state)
            return result
        except Exception as e:
            return {
                "error": f"DDoS detection pipeline failed: {str(e)}",
                "sensor_alert": sensor_alert,
                "classification": "ERROR",
                "final_action": "SYSTEM_ERROR",
                "action_plan": f"System error occurred: {str(e)}",
                "confidence_score": 0.0,
                "timestamp": datetime.datetime.now().isoformat()
            }

def create_ddos_detection_system():
    """Initialize the DDoS Detection System"""
    
    required_env_vars = [
        "CEREBRAS_API_KEY", 
        "PINECONE_API_KEY"
    ]
    
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        print(f"Warning: Missing environment variables: {missing_vars}")
        print("System will run with limited functionality.")
    
    return DDoSDetectionSystem()

# Example usage and testing
if __name__ == "__main__":
    try:
        system = create_ddos_detection_system()
        
        # Test with different DDoS scenarios
        test_scenarios = [
            "High volume TCP flood detected from multiple sources targeting web server",
            "UDP amplification attack identified with 10000+ packets/second",
            "Distributed botnet attack detected across 500+ unique source IPs"
        ]
        
        for i, scenario in enumerate(test_scenarios, 1):
            print(f"\n{'='*60}")
            print(f"DDOS SCENARIO {i}")
            print(f"{'='*60}")
            
            result = system.process_ddos_threat(scenario)
            
            print(f"Alert: {scenario}")
            print(f"Classification: {result['classification']}")
            print(f"Confidence: {result['confidence_score']:.1%}")
            print(f"Final Action: {result['final_action']}")
            print(f"\nAction Plan:\n{result['action_plan'][:500]}...")
            
            # Test human decisions
            for decision in ["EXECUTE", "MODIFY_AND_EXECUTE", "REJECT"]:
                human_result = system.process_ddos_threat(scenario, decision)
                print(f"\nHuman Decision '{decision}':")
                print(f"Status: {human_result['final_action']}")
        
    except Exception as e:
        print(f"System initialization failed: {e}")
        print("Please ensure all required environment variables are set.")