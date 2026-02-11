#!/usr/bin/env python3
"""
Multi-Routing Traffic Visualizer
Monitors and displays live traffic routing between LAN (eth0) and Internet (wlan0)
"""

import curses
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
import subprocess
import re
import sys

try:
    from scapy.all import sniff, IP, IPv6
except ImportError:
    print("Error: scapy not installed")
    print("Install with: sudo apt install python3-scapy")
    sys.exit(1)


class TrafficMonitor:
    def __init__(self, lan_iface='eth0', wan_iface='wlan0'):
        self.lan_iface = lan_iface
        self.wan_iface = wan_iface
        
        # Traffic counters
        self.stats = {
            lan_iface: {
                'packets': 0,
                'bytes': 0,
                'destinations': defaultdict(int),
                'protocols': defaultdict(int),
                'recent_dsts': deque(maxlen=20)
            },
            wan_iface: {
                'packets': 0,
                'bytes': 0,
                'destinations': defaultdict(int),
                'protocols': defaultdict(int),
                'recent_dsts': deque(maxlen=20)
            }
        }
        
        # Bandwidth tracking (last 5 seconds)
        self.bandwidth = {
            lan_iface: deque(maxlen=5),
            wan_iface: deque(maxlen=5)
        }
        
        # Locks for thread safety
        self.lock = threading.Lock()
        self.running = True
        
        # Routing table cache
        self.routes = []
        self.update_routing_table()

    def update_routing_table(self):
        """Fetch current routing table"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            self.routes = result.stdout.strip().split('\n')[:10]  # Top 10 routes
        except Exception as e:
            self.routes = [f"Error fetching routes: {e}"]

    def get_protocol_name(self, packet):
        """Extract protocol name from packet"""
        if packet.haslayer(IP):
            proto = packet[IP].proto
            proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            return proto_map.get(proto, f'Proto-{proto}')
        elif packet.haslayer(IPv6):
            return 'IPv6'
        return 'Other'

    def packet_handler(self, iface):
        """Handle captured packets for a specific interface"""
        def process_packet(packet):
            if not self.running:
                return
            
            try:
                with self.lock:
                    # Update packet count
                    self.stats[iface]['packets'] += 1
                    pkt_size = len(packet)
                    self.stats[iface]['bytes'] += pkt_size
                    
                    # Extract destination
                    dst = "Unknown"
                    if packet.haslayer(IP):
                        dst = packet[IP].dst
                    elif packet.haslayer(IPv6):
                        dst = packet[IPv6].dst
                    
                    # Update destination stats
                    self.stats[iface]['destinations'][dst] += 1
                    if dst not in [x[0] for x in list(self.stats[iface]['recent_dsts'])]:
                        self.stats[iface]['recent_dsts'].append((dst, time.time()))
                    
                    # Update protocol stats
                    proto = self.get_protocol_name(packet)
                    self.stats[iface]['protocols'][proto] += 1
                    
            except Exception as e:
                pass  # Silently ignore packet processing errors
        
        return process_packet

    def start_sniffing(self):
        """Start packet capture on both interfaces"""
        # Start sniffing threads
        lan_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.lan_iface,
                prn=self.packet_handler(self.lan_iface),
                store=False,
                stop_filter=lambda _: not self.running
            ),
            daemon=True
        )
        
        wan_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.wan_iface,
                prn=self.packet_handler(self.wan_iface),
                store=False,
                stop_filter=lambda _: not self.running
            ),
            daemon=True
        )
        
        lan_thread.start()
        wan_thread.start()
        
        # Bandwidth calculation thread
        bw_thread = threading.Thread(target=self.calculate_bandwidth, daemon=True)
        bw_thread.start()
        
        return lan_thread, wan_thread, bw_thread

    def calculate_bandwidth(self):
        """Calculate bandwidth every second"""
        last_bytes = {self.lan_iface: 0, self.wan_iface: 0}
        
        while self.running:
            time.sleep(1)
            with self.lock:
                for iface in [self.lan_iface, self.wan_iface]:
                    current_bytes = self.stats[iface]['bytes']
                    bps = current_bytes - last_bytes[iface]
                    self.bandwidth[iface].append(bps)
                    last_bytes[iface] = current_bytes

    def get_avg_bandwidth(self, iface):
        """Get average bandwidth in human readable format"""
        if not self.bandwidth[iface]:
            return "0 B/s"
        
        avg_bps = sum(self.bandwidth[iface]) / len(self.bandwidth[iface])
        
        if avg_bps < 1024:
            return f"{avg_bps:.0f} B/s"
        elif avg_bps < 1024 * 1024:
            return f"{avg_bps/1024:.1f} KB/s"
        else:
            return f"{avg_bps/(1024*1024):.2f} MB/s"

    def format_bytes(self, bytes_val):
        """Format bytes to human readable"""
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val/1024:.1f} KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val/(1024*1024):.1f} MB"
        else:
            return f"{bytes_val/(1024*1024*1024):.2f} GB"


def draw_ui(stdscr, monitor):
    """Draw the curses UI"""
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(1)   # Non-blocking input
    stdscr.timeout(100) # Refresh every 100ms
    
    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)   # LAN
    curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)    # WAN
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Headers
    curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)     # Alerts
    curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Info
    
    last_route_update = time.time()
    
    while monitor.running:
        try:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Title
            title = "═══ MULTI-ROUTING TRAFFIC MONITOR ═══"
            stdscr.addstr(0, (width - len(title)) // 2, title, curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(1, (width - 40) // 2, f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", curses.color_pair(5))
            
            row = 3
            
            # Update routing table every 5 seconds
            if time.time() - last_route_update > 5:
                monitor.update_routing_table()
                last_route_update = time.time()
            
            with monitor.lock:
                # Interface Statistics
                stdscr.addstr(row, 2, "┌─ INTERFACE STATISTICS " + "─" * (width - 28) + "┐", curses.color_pair(3))
                row += 1
                
                for iface_idx, iface in enumerate([monitor.lan_iface, monitor.wan_iface]):
                    color = curses.color_pair(1) if iface_idx == 0 else curses.color_pair(2)
                    label = "LAN (eth0)" if iface_idx == 0 else "WAN (wlan0)"
                    
                    stats = monitor.stats[iface]
                    stdscr.addstr(row, 4, f"├─ {label}:", color | curses.A_BOLD)
                    row += 1
                    
                    stdscr.addstr(row, 6, f"Packets: {stats['packets']:>10,}  │  ", color)
                    stdscr.addstr(f"Bytes: {monitor.format_bytes(stats['bytes']):>12}  │  ", color)
                    stdscr.addstr(f"Rate: {monitor.get_avg_bandwidth(iface):>12}", color)
                    row += 1
                    
                    # Top protocols
                    if stats['protocols']:
                        proto_str = "Protocols: " + ", ".join([f"{k}({v})" for k, v in 
                                                                 sorted(stats['protocols'].items(), 
                                                                       key=lambda x: x[1], reverse=True)[:5]])
                        stdscr.addstr(row, 6, proto_str[:width-8], color)
                    row += 1
                    
                    # Recent destinations
                    stdscr.addstr(row, 6, "Recent Destinations:", color)
                    row += 1
                    for dst, ts in list(stats['recent_dsts'])[-5:]:
                        age = int(time.time() - ts)
                        dst_str = f"    • {dst:<40} ({age}s ago)"
                        if row < height - 10 and len(dst_str) < width - 8:
                            stdscr.addstr(row, 6, dst_str[:width-8], color)
                            row += 1
                    
                    row += 1
                
                # Routing Table
                if row < height - 10:
                    stdscr.addstr(row, 2, "┌─ ROUTING TABLE " + "─" * (width - 21) + "┐", curses.color_pair(3))
                    row += 1
                    
                    for route in monitor.routes[:min(8, height - row - 3)]:
                        if row < height - 3 and len(route) < width - 8:
                            stdscr.addstr(row, 4, route[:width-6], curses.color_pair(5))
                            row += 1
            
            # Footer
            if height > 5:
                footer = "Press 'q' to quit | Press 'r' to reset stats"
                stdscr.addstr(height - 2, (width - len(footer)) // 2, footer, curses.color_pair(3))
            
            stdscr.refresh()
            
            # Handle input
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                monitor.running = False
                break
            elif key == ord('r') or key == ord('R'):
                with monitor.lock:
                    for iface in [monitor.lan_iface, monitor.wan_iface]:
                        monitor.stats[iface]['packets'] = 0
                        monitor.stats[iface]['bytes'] = 0
                        monitor.stats[iface]['destinations'].clear()
                        monitor.stats[iface]['protocols'].clear()
                        monitor.stats[iface]['recent_dsts'].clear()
            
        except curses.error:
            pass  # Ignore curses errors (usually from small terminal)
        except KeyboardInterrupt:
            monitor.running = False
            break


def main():
    # Check if running as root
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        print("Error: This script must be run as root (use sudo)")
        print("Reason: Packet capture requires root privileges")
        sys.exit(1)
    
    # Parse arguments
    lan_iface = 'eth0'
    wan_iface = 'wlan0'
    
    if len(sys.argv) > 1:
        lan_iface = sys.argv[1]
    if len(sys.argv) > 2:
        wan_iface = sys.argv[2]
    
    print(f"Starting Multi-Routing Monitor...")
    print(f"LAN Interface: {lan_iface}")
    print(f"WAN Interface: {wan_iface}")
    print(f"Initializing packet capture...")
    
    monitor = TrafficMonitor(lan_iface, wan_iface)
    
    # Start packet capture
    threads = monitor.start_sniffing()
    
    # Give it a moment to start
    time.sleep(1)
    
    try:
        # Start UI
        curses.wrapper(draw_ui, monitor)
    except KeyboardInterrupt:
        pass
    finally:
        print("\nStopping monitor...")
        monitor.running = False
        time.sleep(1)
        print("Done!")


if __name__ == "__main__":
    main()
