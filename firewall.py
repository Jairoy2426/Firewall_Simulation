import json
import logging
# Configure logging
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)
# Example firewall rules
firewall_rules = [
    {"action": "allow", "src_ip": "192.168.1.10", "dest_ip": "192.168.1.20", "protocol": "TCP", "dest_port": 80},
    {"action": "deny", "src_ip": "10.0.0.5", "dest_ip": "192.168.1.20", "protocol": "TCP", "dest_port": 22}
]

def add_rule(action, src_ip, dest_ip, protocol, dest_port):
    rule = {
        "action": action,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "protocol": protocol,
        "dest_port": dest_port
    }
    firewall_rules.append(rule)
    logging.info(f"Rule added: {rule}")

def delete_rule(index):
    if 0 <= index < len(firewall_rules):
        removed = firewall_rules.pop(index)
        logging.info(f"Rule removed: {removed}")
    else:
        logging.warning("Invalid rule index.")
def packet_filter(packet):
    """
    Check if a packet matches any firewall rule.
    """
    for rule in firewall_rules:
        if (rule["src_ip"] == packet["src_ip"] or rule["src_ip"] == "*") and \
           (rule["dest_ip"] == packet["dest_ip"] or rule["dest_ip"] == "*") and \
           (rule["protocol"] == packet["protocol"]) and \
           (rule["dest_port"] == packet["dest_port"] or rule["dest_port"] == "*"):
            
            # Apply rule action
            if rule["action"] == "allow":
                logging.info(f"Packet allowed: {packet}")
                return True
            elif rule["action"] == "deny":
                logging.info(f"Packet denied: {packet}")
                return False
    # Default action: deny
    logging.info(f"Packet denied (default rule): {packet}")
    return False
def process_packets(packet_file):
    """
    Simulate traffic and process packets against firewall rules.
    """
    try:
        with open(packet_file, "r") as f:
            packets = json.load(f)
        
        for packet in packets:
            result = packet_filter(packet)
            print(f"Packet: {packet} -> {'Allowed' if result else 'Denied'}")
    except Exception as e:
        logging.error(f"Error processing packets: {e}")
if __name__ == "__main__":
    print("=== Firewall Simulation ===")
    print("1. Add Rule")
    print("2. Delete Rule")
    print("3. Show Rules")
    print("4. Process Packets")
    print("5. Exit")

    while True:
        choice = input("\nEnter your choice: ")
        
        if choice == "1":
            action = input("Action (allow/deny): ").strip().lower()
            src_ip = input("Source IP (or *): ").strip()
            dest_ip = input("Destination IP (or *): ").strip()
            protocol = input("Protocol (TCP/UDP): ").strip().upper()
            dest_port = input("Destination Port (or *): ").strip()
            dest_port = int(dest_port) if dest_port != "*" else "*"
            add_rule(action, src_ip, dest_ip, protocol, dest_port)
        
        elif choice == "2":
            index = int(input("Enter rule index to delete: ").strip())
            delete_rule(index)
        
        elif choice == "3":
            print("=== Firewall Rules ===")
            for idx, rule in enumerate(firewall_rules):
                print(f"{idx}: {rule}")
        
        elif choice == "4":
            process_packets("packets.json")
        
        elif choice == "5":
            print("Exiting Firewall Simulation.")
            break
        
        else:
            print("Invalid choice. Please try again.")
