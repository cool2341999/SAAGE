# server.py
from mcp.server.fastmcp import FastMCP
import os
import pandas as pd

# Create an MCP server
mcp = FastMCP("Demo",port=8001, host='0.0.0.0')
filepath = "C:\\Work\\CTCT\\论文撰写\\mcp-report\\code\\asn-server\\asn_20250601.txt"

# 预加载的数据存储
class DataStore:
    def __init__(self):
        self.load_data()

    def load_data(self):
        """从文件加载数据（Server启动时调用）"""
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
            print("[DataStore] 文件未找到，使用空数据。")
            self.df


# 全局数据存储
data_store = DataStore()


# @mcp.tool()
# def get_asn_by_country(country_code: str) -> list[str]:
#     """
#     用于根据输入国家代码，返回指定国家的所有AS号，格式为字符串列表
    
#     参数:
#         country_code: 国家ISO代码（如'US'）
#     返回:
#         AS号字符串列表（如['1', '2', '3']）
#     """
#     df = data_store.df
#     country_as = df[df['iso'] == country_code]

#     print(len(country_as))
    
#     # 提取AS号并转为字符串列表
#     as_list = country_as['asn'].astype(str).tolist()
    
#     return as_list


@mcp.tool()
def get_asn_by_country(country_code: str) -> dict:
    """
    根据国家代码返回该国家的所有AS号及其数量
    
    参数:
        country_code: 国家ISO代码（如'US'）
    返回:
        包含AS列表和数量的字典，格式为:
        {
            "as_list": ["1", "2", "3"],  # AS号字符串列表
            "count": 3                   # AS数量
        }
    """
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







