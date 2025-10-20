# server.py
from mcp.server.fastmcp import FastMCP
import hashlib
import json
import os
from typing import List, Dict, Any, Optional, Tuple, Union
from collections import defaultdict
import datetime
import csv



# Create an MCP server
mcp = FastMCP(name="rib_diff", host='0.0.0.0', port=8003)

# Confs
FLOW_FILE = "C:/Data/mcp_workdir/route-analysis-servers/data-plane/flow_data.csv"

TEMP_DIR = "C:/Data/mcp_workdir/route-analysis-servers/data-plane/tmpdata/"

# C:\Data\mcp_workdir\route-analysis-servers\data-plane
# date, hour, src_as, dst_as, ip_version, protocol, n_flows, n_bytes, n_pkts
# 2025-07-10,00,4134,132169,4,6,1,353,1
# 2025-07-10,00,4134,16904,4,6,14,20697,22





@mcp.tool()
def analyze_asn_traffic(
    src_data: List[dict] = None,
    dst_data: List[dict] = None,
    start_date: str = None,
    end_date: str = None,
    protocol: str = None
) -> Optional[str]:
    """
    Analyze network traffic data between source and destination ASNs over a time period.
    
    Reads from fixed CSV file 'flowdata.csv' and processes traffic data to generate
    hourly statistics between specified source and destination AS lists.
    Returns aggregated traffic data in CSV format string. Uses caching mechanism.
    
    Args:
        src_data: List containing source as_list configuration (None means all ASes)
        dst_data: List containing destination as_list configuration (None means all ASes)
        start_date: Start date in YYYYMMDD format
        end_date: End date in YYYYMMDD format
        protocol: Protocol type to filter (None means all protocols)
        
    Returns:
        CSV formatted string containing aggregated traffic statistics,
        or None if input data is invalid
    """
    # Validate input parameters
    if start_date is None or end_date is None:
        return "error,Start date and end date are required"
    
    # Extract AS lists from input data
    src_as_list = extract_as_list(src_data)
    dst_as_list = extract_as_list(dst_data)
    
    # Generate cache key based on input parameters
    cache_key = generate_cache_key(src_as_list, dst_as_list, start_date, end_date, protocol)
    cache_filename = TEMP_DIR + f"traffic_cache_{cache_key}.csv"
    
    # Check if cached result exists
    if os.path.exists(cache_filename):
        try:
            with open(cache_filename, 'r', encoding='utf-8') as f:
                cached_result = f.read()
            return cached_result
        except Exception as e:
            print(f"Error reading cached file: {e}")
            # Continue with normal calculation if cache read fails
    
    # Convert date strings to datetime objects for comparison
    try:
        start_dt = datetime.datetime.strptime(start_date, "%Y%m%d")
        end_dt = datetime.datetime.strptime(end_date, "%Y%m%d")
    except ValueError:
        return "error,Invalid date format. Use YYYYMMDD"
    
    # Initialize data structure for aggregation
    traffic_stats = defaultdict(lambda: defaultdict(lambda: {
        "n_flows": 0,
        "n_bytes": 0,
        "n_pkts": 0
    }))
    
    # Read and process data from the fixed CSV file
    try:
        with open(FLOW_FILE, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            
            for record in reader:
                # Parse record date and check if within time range
                try:
                    record_date = datetime.datetime.strptime(record["date"], "%Y-%m-%d")
                except ValueError:
                    continue
                
                if record_date < start_dt or record_date > end_dt:
                    continue
                
                # Filter by protocol if specified
                if protocol is not None:
                    record_protocol = record.get("protocol", "").strip()
                    if str(protocol) != '*' and str(record_protocol) != str(protocol):
                        continue
                
                # Check if source AS matches the filter
                if src_as_list:
                    src_as = record.get("src_as", "").strip()
                    if '*' not in src_as_list and src_as not in src_as_list:
                        continue
                
                # Check if destination AS matches the filter
                if dst_as_list:
                    dst_as = record.get("dst_as", "").strip()
                    if '*' not in dst_as_list and dst_as not in dst_as_list:
                        continue
                
                # Get date string and hour
                date_str = record["date"]
                hour_str = record["hour"].zfill(2)
                
                # Convert numeric values
                try:
                    n_flows = int(float(record["n_flows"])) if record["n_flows"].strip() else 0
                    n_bytes = int(float(record["n_bytes"])) if record["n_bytes"].strip() else 0
                    n_pkts = int(float(record["n_pkts"])) if record["n_pkts"].strip() else 0
                except (ValueError, KeyError):
                    continue
                
                # Aggregate traffic metrics
                traffic_stats[date_str][hour_str]["n_flows"] += n_flows
                traffic_stats[date_str][hour_str]["n_bytes"] += n_bytes
                traffic_stats[date_str][hour_str]["n_pkts"] += n_pkts
                
    except FileNotFoundError:
        return "error,CSV file 'flowdata.csv' not found"
    except Exception as e:
        return f"error,Error reading CSV file: {str(e)}"
    
    # Generate CSV output - 修改输出格式
    csv_lines = ["time,n_flows,n_bytes,n_pkts"]

    # Generate all possible date-hour combinations within the range
    current_dt = start_dt
    while current_dt <= end_dt:
        date_str = current_dt.strftime("%Y%m%d")  # 改为YYYYMMDD格式
        for hour in range(24):
            hour_str = str(hour).zfill(2)
            # Get data for this date-hour or use zeros if no data exists
            stats = traffic_stats[current_dt.strftime("%Y-%m-%d")].get(hour_str, {
                "n_flows": 0,
                "n_bytes": 0,
                "n_pkts": 0
            })
            
            # 合并date和hour为time字段，格式为YYYYMMDDHH
            time_str = f"{date_str}{hour_str}"
            csv_line = f"{time_str},{stats['n_flows']},{stats['n_bytes']},{stats['n_pkts']}"
            csv_lines.append(csv_line)
        
        current_dt += datetime.timedelta(days=1)

    
    # Create final CSV string
    csv_output = "\n".join(csv_lines)
    
    # Save result to cache file
    try:
        with open(cache_filename, 'w', encoding='utf-8') as f:
            f.write(csv_output)
    except Exception as e:
        print(f"Warning: Could not save cache file: {e}")
    
    return csv_output


def extract_as_list(data: List[dict]) -> List[str]:
    """
    Extract AS list from input data structure.
    
    Args:
        data: List containing as_list configuration
        
    Returns:
        List of AS numbers, or empty list if not specified
    """
    if not data or not isinstance(data, list) or len(data) == 0:
        return []
    
    first_item = data[0]
    if isinstance(first_item, dict) and "as_list" in first_item:
        return [str(asn) for asn in first_item["as_list"]]
    
    return []


def generate_cache_key(
    src_as_list: List[str],
    dst_as_list: List[str],
    start_date: str,
    end_date: str,
    protocol: str
) -> str:
    """
    Generate a unique cache key based on input parameters.
    
    Args:
        src_as_list: Source AS list
        dst_as_list: Destination AS list
        start_date: Start date string
        end_date: End date string
        protocol: Protocol type
        
    Returns:
        MD5 hash string representing the unique cache key
    """
    # Sort AS lists for consistent ordering
    sorted_src = sorted(src_as_list)
    sorted_dst = sorted(dst_as_list)
    
    # Create a unique string representation of parameters
    param_string = (
        f"src_{json.dumps(sorted_src)}_"
        f"dst_{json.dumps(sorted_dst)}_"
        f"start_{start_date}_"
        f"end_{end_date}_"
        f"proto_{protocol if protocol is not None else 'all'}"
    )
    
    # Generate MD5 hash
    return hashlib.md5(param_string.encode('utf-8')).hexdigest()


# Example usage (for testing purposes)
if __name__ == "__main__":
    # Sample configuration data structures
    #src_config = [{"as_list": ["4134", "2914"]}]
    #dst_config = [{"as_list": ["12660", "12880"]}]
    
    # Test the function with different scenarios
    # 1. Specific source to specific destination
    # result1 = analyze_asn_traffic(src_config, dst_config, "20250710", "20250711", "6")
    # print("Result 1:", result1[:200] + "..." if result1 else "None")
    
    # # 2. All sources to specific destination
    # result2 = analyze_asn_traffic(None, dst_config, "20250710", "20250711", None)
    # print("Result 2:", result2[:200] + "..." if result2 else "None")
    
    # # 3. Specific source to all destinations
    # result3 = analyze_asn_traffic(src_config, None, "20250710", "20250711", "17")
    # print("Result 3:", result3[:200] + "..." if result3 else "None")
    
    # # 4. All sources to all destinations
    # result4 = analyze_asn_traffic(None, None, "20250710", "20250711", None)
    # print("Result 4:", result4[:200] + "..." if result4 else "None")


    #result = analyze_asn_traffic(None, dst_config, "20250617", "20250619", "6")
    #print(result)

    
    #mcp.run(transport='stdio')
    mcp.run(transport='sse')


