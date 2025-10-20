# server.py
from mcp.server.fastmcp import FastMCP
import pandas as pd
import json
from collections import defaultdict
from typing import Dict, List, Tuple, Set
import re
import os
import glob
from datetime import datetime, timedelta
import ipaddress
import networkx as nx
import csv


# Create an MCP server
mcp = FastMCP(name="rib_diff", host='0.0.0.0', port=8002)

# Confs
BASE_DIR = "C:/code/route-analysis-servers/"
#BASE_DIR = "D:/ctct/"
RIB_DIR = BASE_DIR + "/ribs/"
OUTPUT_DIR = BASE_DIR + "/results/"
TMP_DIR = BASE_DIR + "/temp/"
PEER_IP = "127.0.0.1"


# Utilities
def parse_rib_file(filename: str) -> pd.DataFrame:
    """
    parser rib files
    Format : TABLE_DUMP2|timestamp|B|peer_ip|peer_as|prefix|as_path|origin|next_hop|...
    """
    data = []
    with open(filename, 'r') as f:
        line_ctr = 1
        for line in f:
            #if line_ctr % 50000 == 0:
            #    print(line_ctr, 'lines have been processed.')
            if not line.startswith('TABLE_DUMP2'):
                continue
            parts = line.strip().split('|')
            if len(parts) < 10:
                continue

            peer_ip = parts[3]
            #print(peer_as)
            if peer_ip != PEER_IP:
                continue
            
            prefix = parts[5]
            as_path = parts[6].split()
            origin_as = as_path[-1] if as_path else None
            
            try:
                origin_as = int(origin_as)
            except Exception as e:
                #print(e, as_path, line)
                continue

            # print('here')
            data.append({
                'prefix': prefix,
                'as_path': ' '.join(as_path),
                'origin_as': str(origin_as),
                'peer_ip': peer_ip,
                'peer_as': parts[4],
                'next_hop': parts[8]
            })

            line_ctr += 1

    # TABLE_DUMP2|1750154401|B|202.97.31.1|4134|1.0.5.0/24|1299 7545 38803|IGP|118.84.123.32|500|0|1299:25132 4134:2410|NAG||    
    return pd.DataFrame(data)


def load_comparison_results(filename: str) -> dict:
    with open(filename, 'r') as f:
        return json.load(f)


def query_as_changes(results: dict, asn: str) -> dict:
    """
    Query routing changes for a specific Autonomous System (AS)
    
    Args:
        results: Dictionary containing the comparison results
        asn: Autonomous System Number to query (as string or number)
        
    Returns:
        Dictionary containing:
        {
            'new_prefixes': [...],  # Newly reachable prefixes
            'lost_prefixes': [...], # Prefixes that became unreachable 
            'changed_paths': [...], # Prefixes with path changes (includes details)
            'unchanged_prefixes': [...] # Prefixes with no changes
        }
    """
    asn = str(asn)  # Ensure ASN is in string format
    as_data = results['as_analysis'].get(asn, {})
    
    # For changed_paths, add detailed path change information
    changed_details = []
    for prefix in as_data.get('changed_paths', []):
        prefix_info = results['prefix_details'].get(prefix, {})
        changed_details.append({
            'prefix': prefix,
            'path_a': prefix_info.get('path_a', []),  # Original path
            'path_b': prefix_info.get('path_b', [])    # New path
        })
    
    return {
        'new_prefixes': as_data.get('new_prefixes', []),
        'lost_prefixes': as_data.get('lost_prefixes', []),
        'changed_paths': changed_details,
        'unchanged_prefixes': as_data.get('unchanged_prefixes', [])
    }


def recursive_compare(before: list, after: list) -> list:
    """
    Recursively compare AS paths using LCS to identify changes.
    
    Args:
        before: Original AS path as list
        after: New AS path as list
    
    Returns:
        List of tuples (change_type, segment)
    """
    if not before and not after:
        return []
    
    lcs = find_longest_common_substring(before, after)
    
    if not lcs:
        # No common substring - treat entire before as deleted and after as added
        changes = []
        if before and after:
            changes.append(('replacement', '->'.join([' '.join(before), ' '.join(after)])))
        else:
            if before:
                changes.append(('deletion', ' '.join(before)))
            if after:
                changes.append(('addition', ' '.join(after)))
        return changes
    
    # Split around the LCS
    before_parts = split_around_substring(before, lcs)
    after_parts = split_around_substring(after, lcs)
    
    # Process prefix, LCS, and suffix recursively
    changes = []
    changes.extend(recursive_compare(before_parts['prefix'], after_parts['prefix']))
    changes.extend(recursive_compare(before_parts['suffix'], after_parts['suffix']))
    
    return changes

def find_longest_common_substring(a: list, b: list) -> list:
    """
    Find the longest contiguous common substring between two lists.
    
    Args:
        a: First list
        b: Second list
    
    Returns:
        Longest common substring as a list, or empty list if none found
    """
    max_len = 0
    result = []
    
    # Create a DP table
    dp = [[0] * (len(b)+1) for _ in range(len(a)+1)]
    
    # Fill the DP table
    for i in range(1, len(a)+1):
        for j in range(1, len(b)+1):
            if a[i-1] == b[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1
                if dp[i][j] > max_len:
                    max_len = dp[i][j]
                    result = a[i-max_len:i]
            else:
                dp[i][j] = 0
    
    return result

def split_around_substring(path: list, substring: list) -> dict:
    """
    Split a path into prefix, substring, and suffix parts.
    
    Args:
        path: Original path as list
        substring: Substring to split around
    
    Returns:
        Dictionary with 'prefix', 'substring', and 'suffix' keys
    """
    if not substring:
        return {'prefix': path, 'substring': [], 'suffix': []}
    
    try:
        start = find_sublist_index(path, substring)
        end = start + len(substring)
        return {
            'prefix': path[:start],
            'substring': path[start:end],
            'suffix': path[end:]
        }
    except ValueError:
        return {'prefix': path, 'substring': [], 'suffix': []}

def find_sublist_index(main_list: list, sublist: list) -> int:
    """
    Find the starting index of a sublist within a main list.
    
    Args:
        main_list: List to search in
        sublist: Sublist to find
    
    Returns:
        Starting index of sublist
    
    Raises:
        ValueError if sublist not found
    """
    len_sublist = len(sublist)
    for i in range(len(main_list) - len_sublist + 1):
        if main_list[i:i+len_sublist] == sublist:
            return i
    raise ValueError("Sublist not found")


# ===================================================================================

def compare_ribs(rib_a: str, rib_b: str):
    """
    Main comparison function that performs all analyses and saves results
    """
    # Generate output prefix from input filenames (sorted and joined)
    base_a = os.path.basename(rib_a).split('.')[0]
    base_b = os.path.basename(rib_b).split('.')[0]
    output_prefix = '_'.join(sorted([base_a, base_b]))
    result_file = OUTPUT_DIR + f'{output_prefix}_comparison.json'
    
    # Check if result file exists
    if os.path.exists(result_file):
        print('Loading existing comparison results')
        return load_comparison_results(result_file)

    print('Loading RIB file 1...')
    # 1. Parse RIB files
    df_a = parse_rib_file(rib_a)

    print('Loading RIB file 2...')
    df_b = parse_rib_file(rib_b)
    
    # 2. Build prefix to path mapping
    def build_prefix_map(df: pd.DataFrame) -> Dict[str, Set[str]]:
        prefix_map = defaultdict(set)
        for _, row in df.iterrows():
            prefix_map[row['prefix']].add(row['as_path'])
        return prefix_map
    
    print('Building prefix map for file 1')
    prefix_map_a = build_prefix_map(df_a)

    print('Building prefix map for file 2')
    prefix_map_b = build_prefix_map(df_b)
    
    all_prefixes = set(prefix_map_a.keys()) | set(prefix_map_b.keys())
    
    # 3. Overall difference analysis
    comparison_results = {
        'summary': {
            'only_in_a': 0,
            'only_in_b': 0,
            'in_both_same_path': 0,
            'in_both_diff_path': 0
        },
        'prefix_details': {},
        'as_analysis': defaultdict(lambda: {
            'new_prefixes': set(),
            'lost_prefixes': set(),
            'changed_paths': set(),
            'unchanged_prefixes': set()
        })
    }

    print('Comparing files by prefix...') 

    # 4. Compare each prefix
    for prefix in all_prefixes:
        paths_a = prefix_map_a.get(prefix, set())
        paths_b = prefix_map_b.get(prefix, set())
        
        # Get origin AS
        origin_as = None
        if paths_a:
            origin_as = list(paths_a)[0].split()[-1] if list(paths_a)[0] else None
        elif paths_b:
            origin_as = list(paths_b)[0].split()[-1] if list(paths_b)[0] else None
        
        if not paths_a and paths_b:
            comparison_results['summary']['only_in_b'] += 1
            comparison_results['prefix_details'][prefix] = {
                'status': 'only_in_b',
                'path_b': list(paths_b)
            }
            if origin_as:
                comparison_results['as_analysis'][origin_as]['new_prefixes'].add(prefix)
                
        elif paths_a and not paths_b:
            comparison_results['summary']['only_in_a'] += 1
            comparison_results['prefix_details'][prefix] = {
                'status': 'only_in_a',
                'path_a': list(paths_a)
            }
            if origin_as:
                comparison_results['as_analysis'][origin_as]['lost_prefixes'].add(prefix)
                
        else:
            if paths_a == paths_b:
                comparison_results['summary']['in_both_same_path'] += 1
                comparison_results['prefix_details'][prefix] = {
                    'status': 'same_path',
                    'path': list(paths_a)
                }
                if origin_as:
                    comparison_results['as_analysis'][origin_as]['unchanged_prefixes'].add(prefix)
            else:
                comparison_results['summary']['in_both_diff_path'] += 1
                comparison_results['prefix_details'][prefix] = {
                    'status': 'diff_path',
                    'path_a': list(paths_a),
                    'path_b': list(paths_b)
                }
                if origin_as:
                    comparison_results['as_analysis'][origin_as]['changed_paths'].add(prefix)
    
    print('Converting sets to lists for JSON serialization')
    # 5. Convert sets to lists for JSON serialization
    for asn in comparison_results['as_analysis']:
        for key in comparison_results['as_analysis'][asn]:
            comparison_results['as_analysis'][asn][key] = list(comparison_results['as_analysis'][asn][key])
    
    # 6. Save results
    print('Saving results')
    with open(result_file, 'w') as f:
        json.dump(comparison_results, f, indent=2)
    
    return comparison_results


# batch version of compare_rib
def compare_ribs_by_date_range(start_date: str, end_date: str):
    """
    Compare RIB files within a date range
    
    Args:
        start_date: Start date in YYYYMMDD format
        end_date: End date in YYYYMMDD format
    """
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # Convert date strings to datetime objects
    start_dt = datetime.strptime(start_date, "%Y%m%d")
    end_dt = datetime.strptime(end_date, "%Y%m%d")
    
    # Generate all dates in the range
    current_dt = start_dt
    date_dirs = []
    
    while current_dt <= end_dt:
        date_str = current_dt.strftime("%Y%m%d")
        date_dirs.append(os.path.join(RIB_DIR, date_str))
        current_dt += timedelta(days=1)
    
    # Collect and sort all RIB files
    rib_files = []
    for date_dir in date_dirs:
        if not os.path.isdir(date_dir):
            continue
            
        # Get all RIB files in the date directory (assuming files end with digits)
        files = glob.glob(os.path.join(date_dir, "*[0-9]"))
        files = [f for f in files if os.path.getsize(f) > 0]  # Skip empty files
        files.sort()  # Sort by filename
        
        rib_files.extend(files)
    
    if len(rib_files) < 2:
        print("Warning: Found fewer than 2 RIB files, comparison not possible")
        return
    
    # Compare RIB files pairwise
    for i in range(len(rib_files)-1):
        file_a = rib_files[i]
        file_b = rib_files[i+1]
        
        # Generate output filename from timestamps
        time_a = os.path.basename(file_a)
        time_b = os.path.basename(file_b)
        output_name = f"{time_a}_{time_b}_comparison.json"
        output_path = os.path.join(OUTPUT_DIR, output_name)

        
        # Skip if comparison already exists
        if os.path.exists(output_path):
            print(f"Skipping existing comparison: {output_name}")
            continue
        
        print(f"Comparing {time_a} and {time_b}...")
        try:
            # Generate output prefix from filenames (sorted and joined)
            base_a = os.path.basename(file_a).split('.')[0]
            base_b = os.path.basename(file_b).split('.')[0]
            output_prefix = '_'.join(sorted([base_a, base_b]))
            
            # Call compare_ribs with auto-generated prefix
            result = compare_ribs(file_a, file_b)
            
        except Exception as e:
            print(f"Error comparing {file_a} and {file_b}: {str(e)}")
    
    print("Date range comparison completed")


def analyze_as_changes(asns: str, start_date: str, end_date: str):
    """
    Analyze routing changes for specified ASNs within a time range
    
    Args:
        asns: Comma-separated string of AS numbers (e.g. "1234,5678")
        start_date: Start date in YYYYMMDD format
        end_date: End date in YYYYMMDD format
        
    Returns:
        Dictionary containing analysis results for each ASN
    """
    # Configuration (would typically come from config file/env vars)
    CONFIG = {
        'data_dir': OUTPUT_DIR,      # Directory containing comparison files
        'output_dir': TMP_DIR   # Directory for analysis results
    }

    compare_result = compare_ribs_by_date_range(start_date, end_date)
    
    # Prepare ASN list
    as_list = [asn.strip() for asn in asns.split(",")]
    
    # Convert input dates to datetime objects
    start_dt = datetime.strptime(start_date, "%Y%m%d")
    end_dt = datetime.strptime(end_date, "%Y%m%d")
    
    # Get all comparison files in data directory
    comparison_files = glob.glob(os.path.join(CONFIG['data_dir'], '*_comparison.json'))
    
    # Filter and sort files by time range
    valid_files = []
    for f in comparison_files:
        try:
            # Extract timestamps from filename (format: YYYYMMDDHH_YYYYMMDDHH_comparison.json)
            filename = os.path.basename(f)
            time_part = filename.split('_comparison.json')[0]
            start_str, end_str = time_part.split('_')
            
            # Convert to datetime (assuming format YYYYMMDDHH)
            file_start = datetime.strptime(start_str, "%Y%m%d%H")
            file_end = datetime.strptime(end_str, "%Y%m%d%H")
            
            # Check if file falls within requested time range
            if (file_start >= start_dt) and (file_end <= end_dt):
                valid_files.append((file_start, f))
                
        except ValueError:
            continue
    
    # Sort files chronologically by start time
    valid_files.sort(key=lambda x: x[0])
    comparison_files = [f[1] for f in valid_files]
    
    if not comparison_files:
        print("Warning: No comparison files found in specified time range")
        return None
    
    # Initialize result storage for each ASN
    as_results = {asn: {
        'timeline': [],
        'total_changes': {
            'new_prefixes': 0,
            'lost_prefixes': 0,
            'changed_paths': 0,
            'unchanged_prefixes': 0,
            'ip_coverage_change': 0  # Change in IP address coverage
        }
    } for asn in as_list}
    
    # Process each comparison file
    for comp_file in comparison_files:
        try:
            # Extract time range from filename
            filename = os.path.basename(comp_file)
            time_part = filename.split('_comparison.json')[0]
            time_a, time_b = time_part.split('_')
            
            # Load comparison results
            results = load_comparison_results(comp_file)
            
            # Analyze each ASN
            for asn in as_list:
                if asn in results['as_analysis']:
                    as_data = query_as_changes(results, asn)
                    
                    # Calculate IP address coverage
                    def count_ips(prefixes):
                        total = 0
                        for prefix in prefixes:
                            try:
                                network = ipaddress.ip_network(prefix)
                                total += network.num_addresses
                            except ValueError:
                                continue
                        return total
                    
                    new_ips = count_ips(as_data['new_prefixes'])
                    lost_ips = count_ips(as_data['lost_prefixes'])
                    
                    # Record timeline data
                    as_results[asn]['timeline'].append({
                        'time_range': f"{time_a}-{time_b}",
                        'new_prefixes': len(as_data['new_prefixes']),
                        'lost_prefixes': len(as_data['lost_prefixes']),
                        'changed_paths': len(as_data['changed_paths']),
                        'unchanged_prefixes': len(as_data['unchanged_prefixes']),
                        'new_ips': new_ips,
                        'lost_ips': lost_ips,
                        'ip_net_change': new_ips - lost_ips
                    })
                    
                    # Update total changes
                    as_results[asn]['total_changes']['new_prefixes'] += len(as_data['new_prefixes'])
                    as_results[asn]['total_changes']['lost_prefixes'] += len(as_data['lost_prefixes'])
                    as_results[asn]['total_changes']['changed_paths'] += len(as_data['changed_paths'])
                    as_results[asn]['total_changes']['unchanged_prefixes'] += len(as_data['unchanged_prefixes'])
                    as_results[asn]['total_changes']['ip_coverage_change'] += (new_ips - lost_ips)
                    
        except Exception as e:
            print(f"Error processing file {comp_file}: {str(e)}")
            continue
    
    # Save results
    os.makedirs(CONFIG['output_dir'], exist_ok=True)

    # Generate output filename with ASN information
    if len(as_list) <= 3:
        # If few ASNs, include them all in filename
        asn_part = "_".join(as_list)
        output_path = os.path.join(
            CONFIG['output_dir'],
            f"as_analysis_{start_date}-{end_date}_AS_{asn_part}.json"
        )
    else:
        # For many ASNs, just show count to avoid long filenames
        output_path = os.path.join(
            CONFIG['output_dir'],
            f"as_analysis_{start_date}-{end_date}_ASs_for_{len(as_list)}.json"
        )

    with open(output_path, 'w') as f:
        json.dump(as_results, f, indent=2)
    
    print(f"AS analysis results saved to {output_path}")
    
    return as_results



@mcp.tool()
def get_asns_change_stats_for_dify(data: List[dict], start_date: str, end_date: str) -> str:
    if not isinstance(data, list) or len(data) == 0:
        return None
    result = []
    first_item = data[0]
    if isinstance(first_item, dict) and "as_list" in first_item:
        result = first_item["as_list"]
    
    asn_dict =  get_asns_change_stats(result, start_date, end_date) 

    return '\n'.join(process_asn_data_to_csv(asn_dict))


def process_asn_data_to_csv(input_data: Dict) -> list:
    """
    Process ASN metrics data into CSV format with one row per ASN and timestamped columns.
    
    Args:
        input_data: Dictionary containing ASN metrics data in the specified format
        output_filename: Name of the output CSV file
        
    Output CSV format:
        ASN, YYYYMMDDHH_new, YYYYMMDDHH_lost, YYYYMMDDHH_unchanged, ... 
        (one column per metric per timestamp)
    """
    
    # Extract ASNs data and aggregate timestamps
    asns_data = input_data.get("asns", {})
    aggregate_data = input_data.get("aggregate", {})

    print(aggregate_data)
    
    # Get all unique timestamps from both ASN and aggregate data
    all_timestamps = set()
    for asn_data in asns_data.values():
        all_timestamps.update(asn_data.keys())
    all_timestamps.update(aggregate_data.keys())
    sorted_timestamps = sorted(all_timestamps)
    
    # Define the metrics we want to extract for each ASN
    metrics = [
        "new_prefixes",
        "lost_prefixes",
        "unchanged_prefixes",
        "changed_paths",
        "ip_coverage_change"
    ]
    
    # Prepare CSV header
    rows = []
    header = ['ASN']
    for timestamp in sorted_timestamps:
        for metric in metrics:
            header.append(f"{timestamp}_{metric}")
    rows.append(','.join(header))
    
    # Prepare CSV rows
    # rows = []
    for asn, asn_metrics in asns_data.items():
        row = [asn]
        for timestamp in sorted_timestamps:
            timestamp_data = asn_metrics.get(timestamp, {})
            for metric in metrics:
                row.append(str(timestamp_data.get(metric, "")))  # Empty string if data missing
        if "" in row:
            continue
        rows.append(','.join(row))


    row = ['aggr']
    for timestamp in sorted_timestamps:
        timestamp_data = aggregate_data.get(timestamp, {})
        for metric in metrics:
            row.append(str(timestamp_data.get("total_" +  metric, "")))  # Empty string if data missing
    print(row)
    if "" not in row:
        rows.append(','.join(row))


    return rows



# mcp interfaces
@mcp.tool()
def get_asns_change_stats(asns: list, start_date: str, end_date: str) -> dict:
    """
    Get routing change statistics for specified ASNs within a time range.
    
    Args:
        asns: List of AS numbers to analyze.
        start_date: Start date in YYYYMMDD format (inclusive)
        end_date: End date in YYYYMMDD format (inclusive)
        
    Returns:
        Dictionary containing routing change statistics, structured as:
        {
            "asns": {
                "<ASN>": {
                    "<YYYYMMDDHH>": {  # Timestamp from comparison file (end time)
                        "new_prefixes": int,
                        "lost_prefixes": int,
                        "unchanged_prefixes": int,
                        "changed_paths": int,
                        "ip_coverage_change": int
                    },
                    ...
                },
                ...
            },
            "aggregate": {
                "<YYYYMMDDHH>": {
                    "total_new_prefixes": int,
                    "total_lost_prefixes": int,
                    "total_unchanged_prefixes": int,
                    "total_changed_paths": int,
                    "total_ip_coverage_change": int,
                    "asn_count": int,
                    "unchanged_asn_count": int,  # ASNs with no changes (new=0, lost=0, changed=0)
                    "stable_prefix_asn_count": int  # ASNs with no prefix changes (new=0, lost=0)
                },
                ...
            }
        }
    """
    # Get analysis results using existing function
    asn_str = ",".join(asns)
    analysis_results = analyze_as_changes(asn_str, start_date, end_date)
    
    # Initialize output structure
    output = {
        "asns": {},
        "aggregate": {}
    }
    
    # First pass: collect individual ASN data and prepare aggregate structure
    for asn in asns:
        if asn not in analysis_results:
            continue
            
        asn_data = {}
        for timeline_entry in analysis_results[asn]['timeline']:
            end_timestamp = timeline_entry['time_range'].split('-')[1]
            
            # Store individual ASN data
            asn_data[end_timestamp] = {
                "new_prefixes": timeline_entry['new_prefixes'],
                "lost_prefixes": timeline_entry['lost_prefixes'],
                "unchanged_prefixes": timeline_entry['unchanged_prefixes'],
                "changed_paths": timeline_entry['changed_paths'],
                "ip_coverage_change": timeline_entry['ip_net_change']
            }
            
            # Initialize aggregate entry if not exists
            if end_timestamp not in output["aggregate"]:
                output["aggregate"][end_timestamp] = {
                    "total_new_prefixes": 0,
                    "total_lost_prefixes": 0,
                    "total_unchanged_prefixes": 0,
                    "total_changed_paths": 0,
                    "total_ip_coverage_change": 0,
                    "asn_count": 0,
                    "unchanged_asn_count": 0,      # ASNs with no changes at all
                    "stable_prefix_asn_count": 0   # ASNs with no prefix changes (new/lost)
                }
        
        output["asns"][asn] = asn_data
    
    # Second pass: calculate aggregates
    for asn in output["asns"]:
        for timestamp in output["asns"][asn]:
            stats = output["asns"][asn][timestamp]
            agg = output["aggregate"][timestamp]
            
            # Update basic aggregates
            agg["total_new_prefixes"] += stats["new_prefixes"]
            agg["total_lost_prefixes"] += stats["lost_prefixes"]
            agg["total_unchanged_prefixes"] += stats["unchanged_prefixes"]
            agg["total_changed_paths"] += stats["changed_paths"]
            agg["total_ip_coverage_change"] += stats["ip_coverage_change"]
            agg["asn_count"] += 1
            
            # Check for completely unchanged ASNs
            if (stats["new_prefixes"] == 0 and 
                stats["lost_prefixes"] == 0 and 
                stats["changed_paths"] == 0):
                agg["unchanged_asn_count"] += 1
            
            # Check for ASNs with stable prefixes (only path changes possible)
            if stats["new_prefixes"] == 0 and stats["lost_prefixes"] == 0 and stats["changed_paths"] > 0:
                agg["stable_prefix_asn_count"] += 1
    
    return output


@mcp.tool()
def get_asn_change_detail(asn: str, start_date: str, end_date: str) -> dict:
    """
    Get detailed routing changes for a specific ASN within a time range.
    
    Args:
        asn: Autonomous System Number to analyze (string)
        start_date: Start date in YYYYMMDD format (inclusive)
        end_date: End date in YYYYMMDD format (inclusive)
        
    Returns:
        Dictionary containing detailed changes for the ASN, structured as:
        {
            "<YYYYMMDDHH_YYYYMMDDHH>": {  # Time range from comparison file
                "summary": {
                    "new_prefixes": int,
                    "lost_prefixes": int,
                    "changed_paths": int,
                    "unchanged_prefixes": int
                },
                "details": {
                    "new_prefixes": [
                        {
                            "prefix": str,
                            "path": list  # AS path from the later RIB
                        },
                        ...
                    ],
                    "lost_prefixes": [
                        {
                            "prefix": str,
                            "path": list  # AS path from the earlier RIB
                        },
                        ...
                    ],
                    "unchanged_prefixes": [
                        {
                            "prefix": str,
                            "path": list  # Common AS path
                        },
                        ...
                    ],
                    "changed_paths": [
                        {
                            "prefix": str,
                            "path_before": list,  # AS path from earlier RIB
                            "path_after": list   # AS path from later RIB
                        },
                        ...
                    ]
                }
            },
            ...
        }
    """
    # Configuration
    COMPARISON_DIR = OUTPUT_DIR  # Directory with comparison JSONs
    
    compare_result = compare_ribs_by_date_range(start_date, end_date)

    # Convert input dates to datetime objects
    start_dt = datetime.strptime(start_date, "%Y%m%d")
    end_dt = datetime.strptime(end_date, "%Y%m%d")
    
    # Get all comparison files
    comparison_files = glob.glob(os.path.join(COMPARISON_DIR, "*_comparison.json"))
    
    result = {}
    
    print(comparison_files)

    for comp_file in comparison_files:
        try:
            # Extract timestamps from filename (format: YYYYMMDDHH_YYYYMMDDHH_comparison.json)
            filename = os.path.basename(comp_file)
            time_part = filename.split("_comparison.json")[0]
            time_start, time_end = time_part.split("_")
            
            # Convert to datetime
            file_start = datetime.strptime(time_start, "%Y%m%d%H")
            file_end = datetime.strptime(time_end, "%Y%m%d%H")
            
            # Check if within requested time range
            if not (file_start >= start_dt and file_end <= end_dt):
                continue
            
            # Load comparison data
            with open(comp_file, "r") as f:
                comp_data = json.load(f)
            
            # Check if ASN exists in this comparison
            if asn not in comp_data["as_analysis"]:
                continue
            
            # Initialize time range entry
            time_key = f"{time_start}_{time_end}"
            result[time_key] = {
                "summary": {
                    "new_prefixes": 0,
                    "lost_prefixes": 0,
                    "changed_paths": 0,
                    "unchanged_prefixes": 0
                },
                "details": {
                    "new_prefixes": [],
                    "lost_prefixes": [],
                    "unchanged_prefixes": [],
                    "changed_paths": []
                }
            }
            
            # Get AS-specific data
            as_data = comp_data["as_analysis"][asn]
            
            # Process new prefixes
            for prefix in as_data["new_prefixes"]:
                prefix_info = comp_data["prefix_details"].get(prefix, {})
                if prefix_info.get("status") == "only_in_b":
                    result[time_key]["details"]["new_prefixes"].append({
                        "prefix": prefix,
                        "path": prefix_info.get("path_b", [])
                    })
                    result[time_key]["summary"]["new_prefixes"] += 1
            
            # Process lost prefixes
            for prefix in as_data["lost_prefixes"]:
                prefix_info = comp_data["prefix_details"].get(prefix, {})
                if prefix_info.get("status") == "only_in_a":
                    result[time_key]["details"]["lost_prefixes"].append({
                        "prefix": prefix,
                        "path": prefix_info.get("path_a", [])
                    })
                    result[time_key]["summary"]["lost_prefixes"] += 1
            
            # Process unchanged prefixes
            for prefix in as_data["unchanged_prefixes"]:
                prefix_info = comp_data["prefix_details"].get(prefix, {})
                if prefix_info.get("status") == "same_path":
                    result[time_key]["details"]["unchanged_prefixes"].append({
                        "prefix": prefix,
                        "path": prefix_info.get("path", [])
                    })
                    result[time_key]["summary"]["unchanged_prefixes"] += 1
            
            # Process changed paths
            for prefix in as_data["changed_paths"]:
                prefix_info = comp_data["prefix_details"].get(prefix, {})
                if prefix_info.get("status") == "diff_path":
                    result[time_key]["details"]["changed_paths"].append({
                        "prefix": prefix,
                        "path_before": prefix_info.get("path_a", []),
                        "path_after": prefix_info.get("path_b", [])
                    })
                    result[time_key]["summary"]["changed_paths"] += 1
                    
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}")
            continue
    
    return result



@mcp.tool()
def get_prefix_change_detail(ip: str, start_date: str, end_date: str) -> dict:
    """
    Get detailed path changes for a specific IP address within a time range.
    
    Args:
        ip: IP address to analyze (e.g., "192.0.2.1")
        start_date: Start date in YYYYMMDD format (inclusive)
        end_date: End date in YYYYMMDD format (inclusive)
        
    Returns:
        Dictionary containing path changes for the IP address, structured as:
        {
            "<YYYYMMDDHH_YYYYMMDDHH>": {  # Time range from comparison file
                "prefixes": [  # All prefixes that contain this IP
                    {
                        "prefix": str,  # The containing prefix
                        "paths": list   # All AS paths to this prefix
                    },
                    ...
                ],
                "total_paths": int  # Sum of all paths across all containing prefixes
            },
            ...
        }
    """
    # Configuration
    COMPARISON_DIR = OUTPUT_DIR  # Directory with comparison JSONs

    compare_result = compare_ribs_by_date_range(start_date, end_date)

    
    # Convert input dates to datetime objects
    start_dt = datetime.strptime(start_date, "%Y%m%d")
    end_dt = datetime.strptime(end_date, "%Y%m%d")
    
    # Convert IP to IPv4/v6 object for prefix matching
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "Invalid IP address"}
    
    # Get all comparison files
    comparison_files = glob.glob(os.path.join(COMPARISON_DIR, "*_comparison.json"))
    
    result = {}
    
    for comp_file in comparison_files:
        try:
            # Extract timestamps from filename
            filename = os.path.basename(comp_file)
            time_part = filename.split("_comparison.json")[0]
            time_start, time_end = time_part.split("_")
            
            # Convert to datetime
            file_start = datetime.strptime(time_start, "%Y%m%d%H")
            file_end = datetime.strptime(time_end, "%Y%m%d%H")
            
            # Check if within requested time range
            if not (file_start >= start_dt and file_end <= end_dt):
                continue

            print(filename, 'is processing')
            
            # Load comparison data
            with open(comp_file, "r") as f:
                comp_data = json.load(f)
            
            # Initialize time range entry
            time_key = f"{time_start}_{time_end}"
            result[time_key] = {
                "prefixes": [],
                "total_paths": 0
            }
            
            # Find all prefixes that contain this IP
            containing_prefixes = []
            for prefix in comp_data["prefix_details"]:
                try:
                    network = ipaddress.ip_network(prefix)
                    if ip_obj in network:
                        containing_prefixes.append(prefix)
                except ValueError:
                    continue
            
            # Get path information for each containing prefix
            for prefix in containing_prefixes:
                prefix_info = comp_data["prefix_details"][prefix]
                paths = []
                
                # Determine paths based on status
                if prefix_info["status"] == "only_in_a":
                    paths = prefix_info.get("path_a", [])
                elif prefix_info["status"] == "only_in_b":
                    paths = prefix_info.get("path_b", [])
                elif prefix_info["status"] == "same_path":
                    paths = prefix_info.get("path", [])
                elif prefix_info["status"] == "diff_path":
                    # For changed paths, we return both before and after
                    paths = prefix_info.get("path_b", [])
                
                if isinstance(paths, list) and paths:
                    result[time_key]["prefixes"].append({
                        "prefix": prefix,
                        "paths": paths
                    })
                    result[time_key]["total_paths"] += len(paths)
                    
        except Exception as e:
            print(f"Error processing {filename}: {str(e)}")
            continue
    return result



@mcp.tool()
def get_asn_fluc_details(asn: str, start_date: str, end_date: str) -> dict:

    """
        Analyze AS path changes for a given ASN between two time periods and identify the reasons for path fluctuations.
        
        This tool examines BGP path changes for a specific ASN across multiple time intervals, identifying:
        - ASN replacements in paths
        - ASN deletions from paths
        - ASN additions to paths
        Results are organized by time period and include affected prefixes for each change type.
        
        Args:
            asn: The Autonomous System Number to analyze (e.g., "3356" for Level3)
            start_date: Start time in YYYYMMDDHH format (e.g., "2023060100" for June 1, 2023, 00:00)
            end_date: End time in YYYYMMDDHH format (inclusive)
        
        Returns:
            A nested dictionary structure containing analysis results organized by time period.
            Each time period contains categorized path changes with weights and affected prefixes.
            
            Example output structure:
            {
                "2023060100_2023060200": [
                    {
                        "type": "replacement",
                        "segment": "3356 -> 174",
                        "weight": 15,
                        "prefixes": ["203.0.113.0/24", "198.51.100.0/24"]
                    },
                    {
                        "type": "addition",
                        "segment": "1299",
                        "weight": 8,
                        "prefixes": ["192.0.2.0/24"]
                    }
                ],
                "2023060200_2023060300": [...]
            }
        
        
        Notes:
            - The 'weight' represents the number of prefixes affected by each specific change
            - Time periods are automatically determined by available BGP data snapshots
            - Only changed paths are included in the analysis (unchanged prefixes are excluded)
    """

    change_data = get_asn_change_detail(asn, start_date, end_date)
    result = {}
    
    for time_period, data in change_data.items():
        period_changes = []
        
        for change in data['details']['changed_paths']:
            before = ' '.join(change['path_before']).split()
            after = ' '.join(change['path_after']).split()
            
            changes = recursive_compare(before, after)
            for change_type, segment in changes:
                period_changes.append({
                    'type': change_type,
                    'segment': segment,
                    'prefix': change['prefix']
                })
        
        # Group changes by type and segment
        grouped_changes = {}
        for change in period_changes:
            key = (change['type'], change['segment'])
            if key not in grouped_changes:
                grouped_changes[key] = {
                    'weight': 0,
                    'prefixes': []
                }
            grouped_changes[key]['weight'] += 1
            grouped_changes[key]['prefixes'].append(change['prefix'])
        
        # Format final output
        result[time_period] = [
            {
                'type': k[0],
                'segment': k[1],
                'weight': v['weight'],
                'prefixes': v['prefixes']
            } for k, v in grouped_changes.items()
        ]
    
    return result



@mcp.tool()
def get_asn_fluc_asns(asn: str, start_date: str, end_date: str) -> dict:
    """
    Analyze ASN fluctuation scores based on path changes between time periods.
    
    This tool calculates impact scores for ASNs involved in path changes (additions, deletions, 
    and replacements) by analyzing the output from get_asn_fluc_reason. Each ASN receives a 
    score based on its participation in path modifications.
    
    Scoring Algorithm:
    - For ADDITIONS: Each ASN in the added segment gets +weight
    - For DELETIONS: Each ASN in the deleted segment gets -weight
    - For REPLACEMENTS: 
        * ASNs in the 'before' part (left of ->) get -weight
        * ASNs in the 'after' part (right of ->) get +weight
    
    Args:
        asn: The Autonomous System Number to analyze (e.g., "3356")
        start_date: Start time in YYYYMMDDHH format (e.g., "2023060100")
        end_date: End time in YYYYMMDDHH format (inclusive)
    
    Returns:
        A dictionary containing:
        {
            "time_period": {
                "asn_scores": {
                    "ASN": score (sum of all weight changes),
                    ...
                },
                "sorted_asns": [
                    ("ASN", absolute_score),
                    ... (sorted by absolute score descending)
                ]
            },
            ...
        }
    
    Examples:
        >>> result = get_asn_fluc_asns("3356", "2023060100", "2023060300")
        >>> print(result["2023060100_2023060200"]["sorted_asns"][:3])
        [("2914", 15), ("6939", -12), ("132602", 8)]
    
    Notes:
        - Positive scores indicate ASNs that were predominantly added to paths
        - Negative scores indicate ASNs that were predominantly removed from paths
        - The absolute score represents overall impact on routing changes
    """
    # Get the path fluctuation data
    fluctuation_data = get_asn_fluc_details(asn, start_date, end_date)
    result = {}
    
    for time_period, changes in fluctuation_data.items():
        asn_scores = {}
        
        for change in changes:
            weight = change['weight']
            
            if change['type'] == 'addition':
                # Split added ASNs and add weight for each
                for added_asn in change['segment'].split():
                    asn_scores[added_asn] = asn_scores.get(added_asn, 0) + weight
            
            elif change['type'] == 'deletion':
                # Split deleted ASNs and subtract weight for each
                for deleted_asn in change['segment'].split():
                    asn_scores[deleted_asn] = asn_scores.get(deleted_asn, 0) - weight
            
            elif change['type'] == 'replacement':
                # Split into before and after parts
                before_after = change['segment'].split('->')
                if len(before_after) == 2:
                    before, after = before_after
                    # Process before ASNs (subtract weight)
                    for old_asn in before.split():
                        asn_scores[old_asn] = asn_scores.get(old_asn, 0) - weight
                    # Process after ASNs (add weight)
                    for new_asn in after.split():
                        asn_scores[new_asn] = asn_scores.get(new_asn, 0) + weight
        
        # Sort ASNs by absolute score descending
        sorted_asns = sorted(
            [(asn, score) for asn, score in asn_scores.items()],
            key=lambda x: abs(x[1]),
            reverse=True
        )
        
        result[time_period] = {
            'asn_scores': asn_scores,
            'sorted_asns': sorted_asns
        }
    
    return result

    

if __name__ == '__main__':
    mcp.run(transport='sse')
