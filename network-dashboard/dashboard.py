import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP, get_if_list
from datetime import datetime
import threading
import time
import logging
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""
    def __init__(self):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }
                    
                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })
                        
                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Keep only last 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            return pd.DataFrame(self.packet_data)

def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    
    if df.empty:
        st.info("No packet data available yet.")
        return
    
    protocol_counts = df['protocol'].value_counts()
    fig_protocol = px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution")
    st.plotly_chart(fig_protocol, use_container_width=True)

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
    fig_timeline = px.line(x=df_grouped.index, y=df_grouped.values, title="Packets per Second")
    st.plotly_chart(fig_timeline, use_container_width=True)

    top_sources = df['source'].value_counts().head(10)
    fig_sources = px.bar(x=top_sources.index, y=top_sources.values, title="Top Source IP Addresses")
    st.plotly_chart(fig_sources, use_container_width=True)

def start_packet_capture(interface: str):
    processor = PacketProcessor()

    def capture_packets():
        sniff(prn=processor.process_packet, store=False, iface=interface)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor

def simulate_packets(processor: PacketProcessor):
    for _ in range(10):
        fake_packet = {
            'timestamp': datetime.now(),
            'source': f'192.168.1.{random.randint(1, 100)}',
            'destination': f'10.0.0.{random.randint(1, 100)}',
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'size': random.randint(40, 1500),
            'time_relative': (datetime.now() - processor.start_time).total_seconds(),
        }
        processor.packet_data.append(fake_packet)

def main():
    """Main function to run the dashboard"""
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("Real-time Network Traffic Analysis")

    if 'interface' not in st.session_state:
        interfaces = get_if_list()
        selected_interface = st.selectbox("Select a network interface", interfaces)
        if st.button("Start Capture"):
            st.session_state.interface = selected_interface
            st.session_state.processor = start_packet_capture(selected_interface)
            st.session_state.start_time = time.time()
            st.rerun()
        st.stop()

    processor = st.session_state.processor
    df = processor.get_dataframe()

    st.sidebar.markdown("## Opciones")
    if st.sidebar.button("Simular tráfico"):
        simulate_packets(processor)

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    st.write("### Datos capturados (para depuración)")
    # Convertir flags a string para evitar errores de conversión
    if "tcp_flags" in df.columns:
        df["tcp_flags"] = df["tcp_flags"].astype(str)

    # Mostrar los últimos 10 paquetes
    st.dataframe(df.tail(10))


    create_visualizations(df)

    if st.button('Actualizar'):
        st.rerun()

if __name__ == "__main__":
    main()
