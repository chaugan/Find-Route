import csv
import os
import sys
import heapq
from collections import defaultdict
from ipaddress import ip_network, ip_address

# Known sub-1024 ports dictionary
SUB_1024_PORTS = {
    20: 'FTP',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    137: 'NetBIOS',
    138: 'NetBIOS',
    139: 'NetBIOS',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP',
    179: 'BGP',
    194: 'IRC',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    514: 'Syslog',
    515: 'LPD',
    587: 'Submission',
    636: 'LDAPS',
    873: 'Rsync',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS',
    1194: 'OpenVPN',
    1433: 'MSSQL',
    1434: 'MSSQL',
    1521: 'ORACLE',
    1701: 'L2TP',
    1723: 'PPTP',
    3306: 'MySQL',
    3389: 'RDP',
    5060: 'SIP',
    5061: 'SIP-TLS',
}


def load_graph(file_path):
    graph = defaultdict(list)
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            src = row['src_ip']
            dst = row['dest_ip']
            port = row['dest_port']
            weight = float(row['dest_port_weight'])
            graph[src].append((dst, port, weight))
    return graph


def is_within_subnet(ip, subnet):
    return ip_address(ip) in ip_network(subnet)


def dijkstra(graph, start_nodes, end_subnet=None, end_ip=None):
    queue = [(0, start, [(start, None, 0)]) for start in start_nodes]
    seen = set()
    paths = []

    while queue:
        (cost, node, path) = heapq.heappop(queue)
        if node in seen:
            continue
        seen.add(node)

        if end_subnet and is_within_subnet(node, end_subnet):
            paths.append(path)
            continue
        if end_ip and node == end_ip:
            paths.append(path)
            continue

        for dst, port, weight in graph[node]:
            if dst not in seen:
                new_path = path + [(dst, port, weight)]
                heapq.heappush(queue, (cost + weight, dst, new_path))

    return paths


def parse_port(port, parse_port_flag):
    if parse_port_flag == '1' and port and int(port) in SUB_1024_PORTS:
        return SUB_1024_PORTS[int(port)]
    return f"TCP:{port}" if port else ''


def main():
    if len(sys.argv) < 5 or len(sys.argv) > 7:
        print(
            "Usage: find_route.py <delete_flag> <input_csv> <start_ip_or_subnet> <end_ip_or_subnet> [<pathColoring>] [<parsePort>]")
        return

    delete_flag = sys.argv[1]
    file_path = sys.argv[2]
    start_arg = sys.argv[3]
    end_arg = sys.argv[4]
    path_coloring = sys.argv[5] if len(sys.argv) >= 6 else None
    parse_port_flag = sys.argv[6] if len(sys.argv) == 7 else '0'

    if not os.path.isfile(file_path):
        print(f"File {file_path} does not exist.")
        return

    graph = load_graph(file_path)

    # Determine if start_arg and end_arg are IPs or subnets
    start_nodes = []
    start_subnet_str = start_arg
    end_subnet_str = end_arg
    end_subnet = None
    end_ip = None

    try:
        start_subnet = ip_network(start_arg)
        start_nodes = [ip for ip in graph.keys() if is_within_subnet(ip, start_subnet)]
        start_subnet_str = str(start_subnet.network_address)
    except ValueError:
        start_nodes = [start_arg]

    try:
        end_subnet = ip_network(end_arg)
        end_subnet_str = str(end_subnet.network_address)
    except ValueError:
        end_ip = end_arg

    if not start_nodes:
        print(f"No valid start IPs found in the subnet {start_arg}.")
        return

    if end_subnet is None and end_ip is None:
        print(f"No valid end IPs or subnet found in the argument {end_arg}.")
        return

    paths = dijkstra(graph, start_nodes, end_subnet, end_ip)

    if paths:
        # Find the minimum number of nodes in paths
        min_nodes = min(len(path) for path in paths)

        for path in paths:
            segments = []
            full_path = [(start_subnet_str, None, 0)] + path + [(end_subnet_str, None, 0)]
            total_nodes = len(full_path) - 2  # Subtract 2 for the start and end subnet

            for i in range(len(full_path) - 1):
                from_node, from_port, from_weight = full_path[i]
                to_node, to_port, to_weight = full_path[i + 1]

                link_text = parse_port(to_port, parse_port_flag)
                from_str = from_node
                to_str = to_node

                if path_coloring == "byFastest":
                    link_color = "red" if len(path) == min_nodes else "black"
                elif path_coloring == "byWeight":
                    link_color = "red" if to_weight == 10 else "black"
                else:
                    link_color = "black"

                value_str = from_str
                segments.append(
                    f"from={from_str}, to={to_str}, linkColor={link_color}, value={value_str}, linkWidth=5, type=server, linkText={link_text}, weight={to_weight}, nodeCount={total_nodes}")

            path_str = " ### ".join(segments)
            print(f"{path_str}")
    else:
        print("No route found")

    if delete_flag == '1':
        try:
            os.remove(file_path)
            print(f"File {file_path} has been deleted.")
        except OSError as e:
            print(f"Error: {file_path} : {e.strerror}")


if __name__ == "__main__":
    main()
