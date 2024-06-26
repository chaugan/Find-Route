# Firewall Route Analysis with Python and Splunk

This project analyzes permitted traffic from a user's firewall using a Python script. The script uses Dijkstra's algorithm to find the shortest paths in a network graph and outputs the paths with various details, including port/service names and path coloring based on specific criteria.

## Features

- **Network Graph Construction:** The script builds a network graph from a CSV file containing firewall traffic data.
- **Dijkstra's Algorithm:** Finds the shortest paths from a start IP or subnet to an end IP or subnet.
- **Port Parsing:** Converts known sub-1024 ports to their respective service names or formats them as `TCP:<port>`.
- **Path Coloring:** Highlights paths based on criteria such as the shortest path (`byFastest`) or specific weights (`byWeight`).
- **Detailed Path Output:** Includes information such as the source, destination, link color, link text (port/service name), weight, node count, and value.

## Usage

### CSV File Format

The input CSV file should have the following columns:

- `src_ip`: Source IP address
- `dest_ip`: Destination IP address
- `dest_port`: Destination port
- `dest_port_weight`: Weight of the destination port

### Running the Script

The script can be run with the following command:

```sh
python find_route.py <delete_flag> <input_csv> <start_ip_or_subnet> <end_ip_or_subnet> [<pathColoring>] [<parsePort>]

- `delete_flag`: Set to `1` to delete the input CSV file after processing.
- `input_csv`: Path to the input CSV file.
- `start_ip_or_subnet`: Start IP address or subnet.
- `end_ip_or_subnet`: End IP address or subnet.
- `pathColoring` (optional): Set to `byFastest` or `byWeight` for different path coloring criteria.
- `parsePort` (optional): Set to `1` to parse ports into service names, otherwise ports are formatted as `TCP:<port>`.

### Example Command

python find_route.py 0 traffic_data.csv 10.0.0.0/24 10.0.0.4 byFastest 1
```

### Splunk Integration

To integrate this script with Splunk, you can use the `| map` command to trigger the Python script based on search results.

1. **Save Permitted Traffic Data to CSV**

In Splunk, use the following search query to save permitted traffic data to a CSV file:

```spl
index=firewall_logs action=permitted | table src_ip dest_ip dest_port dest_port_weight | outputcsv traffic_data.csv
```

2. **Trigger the Python Script**

Use the `| map` command to trigger the Python script with the necessary arguments:

```spl
| map search="| script python find_route.py 0 $SPLUNK_HOME/var/run/splunk/csv/traffic_data.csv 10.0.0.0/24 10.0.0.4 byFastest 1"
```

Remember that the `| outputcsv` outputs only to the Splunk directory `$SPLUNK_HOME/var/run/splunk/csv`. This directory cannot be changed.

## Screenshots

Include three screenshots of a dashboard showing how the data can be presented. This can include visualizations of the network graph, path details, and any relevant metrics.

### Screenshot 1

*All jumphost routes between Subnet A and Subnet B, outlying routes which are single jumphost needed*

![Screenshot 1](screenshot1.png)

### Screenshot 2

*Zoomed in view of the diagram*

![Screenshot 2](screenshot2.png)

### Screenshot 3

*When only single jumphost is filtered, the jumps can be seen better. Here well-known ports are favourized in red*

![Screenshot 3](screenshot3.png)

## Project Structure

- **find_route.py:** The main script for analyzing firewall traffic and finding routes.
- **README.md:** Documentation for the project.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read the [CONTRIBUTING](CONTRIBUTING.md) file for guidelines on contributing to this project.

---
By following the steps and utilizing the provided script, you can effectively analyze and visualize network traffic paths based on firewall logs in Splunk.
```
