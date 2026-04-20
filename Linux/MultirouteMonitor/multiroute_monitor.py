#!/usr/bin/env python3
"""
Multi-Routing Traffic Visualizer - Dynamic Interface Version
Monitors and displays live traffic routing between any number of network interfaces
"""

import curses
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
import subprocess
import sys
import argparse

try:
    from scapy.all import sniff, IP, IPv6
except ImportError:
    print("Error: scapy not installed")
    print("Install with: sudo apt install python3-scapy")
    sys.exit(1)


class TrafficMonitor:
    def __init__(self, interfaces):
        if not interfaces:
            print("Error: At least one interface must be specified")
            sys.exit(1)
            
        self.interfaces = interfaces
        
        # Traffic counters - dynamically created for each interface
        self.stats = {}
        for iface in interfaces:
            self.stats[iface] = {
                'packets': 0,
                'bytes': 0,
                'destinations': defaultdict(int),
                'protocols': defaultdict(int),
                'recent_dsts': deque(maxlen=10)
            }
        
        # Bandwidth tracking (last 5 seconds)
        self.bandwidth = {iface: deque(maxlen=5) for iface in interfaces}
        
        # Locks for thread safety
        self.lock = threading.Lock()
        self.running = True
        
        # Routing table cache
        self.routes = []
        self.update_routing_table()
        
        # Validate interfaces
        self.validate_interfaces()

    def validate_interfaces(self):
        """Check if interfaces exist on the system"""
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            available_ifaces = []
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    iface_name = line.split(':')[1].strip().split('@')[0]
                    available_ifaces.append(iface_name)
            
            for iface in self.interfaces:
                if iface not in available_ifaces:
                    print(f"Warning: Interface '{iface}' not found on system")
                    print(f"Available interfaces: {', '.join(available_ifaces)}")
                    raise
                    
        except Exception as e:
            print(f"Warning: Could not validate interfaces: {e}")
            sys.exit(0)

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
        """Start packet capture on all interfaces"""
        threads = []
        
        for iface in self.interfaces:
            thread = threading.Thread(
                target=lambda i=iface: sniff(
                    iface=i,
                    prn=self.packet_handler(i),
                    store=False,
                    stop_filter=lambda _: not self.running
                ),
                daemon=True,
                name=f"Sniffer-{iface}"
            )
            thread.start()
            threads.append(thread)
        
        # Bandwidth calculation thread
        bw_thread = threading.Thread(target=self.calculate_bandwidth, daemon=True)
        bw_thread.start()
        threads.append(bw_thread)
        
        return threads

    def calculate_bandwidth(self):
        """Calculate bandwidth every second"""
        last_bytes = {iface: 0 for iface in self.interfaces}
        
        while self.running:
            time.sleep(1)
            with self.lock:
                for iface in self.interfaces:
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

    def get_total_stats(self):
        """Get combined stats across all interfaces"""
        total_packets = sum(self.stats[iface]['packets'] for iface in self.interfaces)
        total_bytes = sum(self.stats[iface]['bytes'] for iface in self.interfaces)
        return total_packets, total_bytes


def get_interface_color(index, total):
    """Assign colors to interfaces dynamically"""
    # Color pairs: 1=green, 2=cyan, 6=blue, 7=white, 8=magenta_alt
    colors = [1, 2, 6, 8, 7]  # Cycle through available colors
    return colors[index % len(colors)]


def draw_ui(stdscr, monitor):
    """Draw the curses UI"""
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(1)   # Non-blocking input
    stdscr.timeout(100) # Refresh every 100ms
    
    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(8, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    
    last_route_update = time.time()
    scroll_offset = 0
    max_scroll = 0
    
    while monitor.running:
        try:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Title
            title = "═══ MULTI-INTERFACE TRAFFIC MONITOR ═══"
            if len(title) < width:
                stdscr.addstr(0, (width - len(title)) // 2, title, curses.color_pair(3) | curses.A_BOLD)
            
            timestamp = f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            if len(timestamp) < width:
                stdscr.addstr(1, (width - len(timestamp)) // 2, timestamp, curses.color_pair(5))
            
            row = 3
            
            # Update routing table every 5 seconds
            if time.time() - last_route_update > 5:
                monitor.update_routing_table()
                last_route_update = time.time()
            
            with monitor.lock:
                # Summary bar
                total_packets, total_bytes = monitor.get_total_stats()
                summary = f"Total: {total_packets:,} packets │ {monitor.format_bytes(total_bytes)} │ {len(monitor.interfaces)} interface(s)"
                if len(summary) < width - 4:
                    stdscr.addstr(row, 2, summary, curses.color_pair(3))
                row += 2
                
                # Interface Statistics
                header = "┌─ INTERFACE STATISTICS " + "─" * (width - 28) + "┐"
                if len(header) <= width - 2:
                    stdscr.addstr(row, 2, header[:width-2], curses.color_pair(3))
                row += 1
                
                # Calculate content height for scrolling
                content_start_row = row
                virtual_row = 0  # Track virtual position for scrolling
                
                for iface_idx, iface in enumerate(monitor.interfaces):
                    color_idx = get_interface_color(iface_idx, len(monitor.interfaces))
                    color = curses.color_pair(color_idx)
                    
                    stats = monitor.stats[iface]
                    
                    # Only draw if within visible area (accounting for scroll)
                    display_row = row + virtual_row - scroll_offset
                    
                    if display_row >= content_start_row and display_row < height - 12:
                        iface_header = f"├─ {iface}:"
                        stdscr.addstr(display_row, 4, iface_header, color | curses.A_BOLD)
                    virtual_row += 1
                    
                    # Packet stats line
                    display_row = row + virtual_row - scroll_offset
                    if display_row >= content_start_row and display_row < height - 12:
                        stats_line = f"Packets: {stats['packets']:>10,}  │  Bytes: {monitor.format_bytes(stats['bytes']):>12}  │  Rate: {monitor.get_avg_bandwidth(iface):>12}"
                        stdscr.addstr(display_row, 6, stats_line[:width-8], color)
                    virtual_row += 1
                    
                    # Protocol line
                    display_row = row + virtual_row - scroll_offset
                    if display_row >= content_start_row and display_row < height - 12:
                        if stats['protocols']:
                            proto_str = "Protocols: " + ", ".join([f"{k}({v})" for k, v in 
                                                                     sorted(stats['protocols'].items(), 
                                                                           key=lambda x: x[1], reverse=True)[:5]])
                            stdscr.addstr(display_row, 6, proto_str[:width-8], color)
                    virtual_row += 1
                    
                    # Recent destinations
                    display_row = row + virtual_row - scroll_offset
                    if display_row >= content_start_row and display_row < height - 12:
                        stdscr.addstr(display_row, 6, "Recent Destinations:", color)
                    virtual_row += 1
                    
                    for dst, ts in list(stats['recent_dsts'])[-5:]:
                        display_row = row + virtual_row - scroll_offset
                        if display_row >= content_start_row and display_row < height - 12:
                            age = int(time.time() - ts)
                            dst_str = f"    • {dst:<40} ({age}s ago)"
                            stdscr.addstr(display_row, 6, dst_str[:width-8], color)
                        virtual_row += 1
                    
                    virtual_row += 1  # Spacing between interfaces
                
                max_scroll = max(0, virtual_row - (height - content_start_row - 12))
                
                # Routing Table section
                route_row = height - 11
                if route_row > row + 2:
                    header = "┌─ ROUTING TABLE " + "─" * (width - 21) + "┐"
                    if len(header) <= width - 2:
                        stdscr.addstr(route_row, 2, header[:width-2], curses.color_pair(3))
                    route_row += 1
                    
                    routes_to_show = min(6, height - route_row - 3)
                    for i, route in enumerate(monitor.routes[:routes_to_show]):
                        if route_row + i < height - 3:
                            stdscr.addstr(route_row + i, 4, route[:width-6], curses.color_pair(5))
            
            # Footer with scroll indicator
            if height > 5:
                if max_scroll > 0:
                    footer = f"↑/↓ to scroll ({scroll_offset}/{max_scroll}) | 'q' quit | 'r' reset | 'h' home | 'e' end"
                else:
                    footer = "Press 'q' to quit | Press 'r' to reset stats"
                
                if len(footer) < width:
                    stdscr.addstr(height - 2, (width - len(footer)) // 2, footer[:width-2], curses.color_pair(3))
            
            stdscr.refresh()
            
            # Handle input
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                monitor.running = False
                break
            elif key == ord('r') or key == ord('R'):
                with monitor.lock:
                    for iface in monitor.interfaces:
                        monitor.stats[iface]['packets'] = 0
                        monitor.stats[iface]['bytes'] = 0
                        monitor.stats[iface]['destinations'].clear()
                        monitor.stats[iface]['protocols'].clear()
                        monitor.stats[iface]['recent_dsts'].clear()
            elif key == curses.KEY_UP:
                scroll_offset = max(0, scroll_offset - 1)
            elif key == curses.KEY_DOWN:
                scroll_offset = min(max_scroll, scroll_offset + 1)
            elif key == ord('h') or key == ord('H'):
                scroll_offset = 0  # Home
            elif key == ord('e') or key == ord('E'):
                scroll_offset = max_scroll  # End
            
        except curses.error:
            pass  # Ignore curses errors (usually from small terminal)
        except KeyboardInterrupt:
            monitor.running = False
            break


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Multi-Interface Traffic Monitor - Monitor packet routing across network interfaces',
        epilog='Examples:\n'
               '  sudo %(prog)s eth0 wlan0\n'
               '  sudo %(prog)s eth0 eth1 wlan0 lo\n'
               '  sudo %(prog)s wlan0\n',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interfaces', nargs='+', metavar='INTERFACE',
                        help='Network interface(s) to monitor (e.g., eth0, wlan0, lo)')
    group.add_argument('-l', '--list', action='store_true',
                        help='List available network interfaces and exit')
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list:
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            print("Available network interfaces:")
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    iface_name = line.split(':')[1].strip().split('@')[0]
                    print(f"  - {iface_name}")
        except Exception as e:
            print(f"Error listing interfaces: {e}")
        sys.exit(0)
    
    interfaces = args.interfaces

    # Check if running as root
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        print("Error: This script must be run as root (use sudo)")
        print("Reason: Packet capture requires root privileges")
        sys.exit(1)
    
    
    print(f"Starting Multi-Interface Traffic Monitor...")
    print(f"Monitoring {len(interfaces)} interface(s): {', '.join(interfaces)}")
    print(f"Initializing packet capture...")
    
    monitor = TrafficMonitor(interfaces)
    
    # Start packet capture
    monitor.start_sniffing()
    
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
