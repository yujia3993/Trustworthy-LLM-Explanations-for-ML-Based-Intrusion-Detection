import pandas as pd
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
df = pd.read_parquet("code/nbaiot_sampled.parquet")
col = "HH_jit_L0.01_mean"
# 1. 量级检查：是不是全数据集都在 1.5e9 附近
print(pd.to_datetime(df[col], unit="s").describe())
# 2. 时序检查：按 (device, label_type) 分组看均值，是否形成不重叠的时间带
print(df.groupby(["device_name","label_type"])[col]
        .agg(["min","median","max"]).sort_values("median"))