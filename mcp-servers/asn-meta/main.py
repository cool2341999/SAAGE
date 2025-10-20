# server.py
from mcp.server.fastmcp import FastMCP
import os
import pandas as pd

# Create an MCP server
mcp = FastMCP("Demo",port=8001, host='0.0.0.0')
filepath = "C:\\Work\\asn_20250601.txt"

class DataStore:
    def __init__(self):
        self.load_data()

    def load_data(self):
        try:
            print("loading asn info ...")
            filename = os.path.basename(filepath)
            datestr = filename[4:12]
            y = datestr[:4]
            m = datestr[4:6]
            d = datestr[6:]
            newdatestr = f'{y}-{m}-{d}'

            asnlist = []
            isolist = []
            namelist = []
            with open(filepath) as f:
                data = f.readlines()[1:]
                for line in data:
                    templine = line.strip()
                    if templine:
                        asnlist.append(int(templine.split(' ')[0]))
                        isolist.append(templine[-2:])
                        namelist.append(templine.split(' ', maxsplit=1)[1][:-4])
            self.df = pd.DataFrame({'date':newdatestr, 'asn':asnlist, 'iso':isolist, 'name':namelist})
            print(self.df)

        except FileNotFoundError:
            print("[DataStore] File not found!。")
            self.df


data_store = DataStore()

@mcp.tool()
def get_asn_by_country(country_code: str) -> dict:
    df = data_store.df
    country_as = df[df['iso'] == country_code]
    
    # 提取AS号并转为字符串列表
    as_list = country_as['asn'].astype(str).tolist()
    
    return {
        "as_list": as_list,
        "count": len(as_list)
    }


if __name__ == "__main__":
    #mcp.run(transport='stdio')
    mcp.run(transport='sse')







