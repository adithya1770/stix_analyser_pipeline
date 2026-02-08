import pandas as pd

def build_dataframe(cti_list):

    df = pd.DataFrame(data=cti_list)

    df["values"] = df["values"].apply(lambda x: ",".join(x) if isinstance(x, list) else x)

    df["indicator_type"] = df["indicator_type"].apply(
        lambda x: ",".join(x) if isinstance(x, list) else x
    )

    df = df.drop_duplicates()
    df = df.dropna()

    if len(df) == df.index.nunique():
        print("All unique rows after removal of duplicates!")
    else:
        print("Some duplicate rows existed!")

    df["validation_flag"] = df["validation"].apply(lambda x: 1 if x == True else 0)

    feature_array = ["entity_type", "description"]

    for feature in feature_array:
        df[feature] = df[feature].astype(str).str.lower()

    df["datetime"] = pd.to_datetime(df["timestamp"])

    df["Time"] = df["datetime"].dt.time
    df["Date"] = df["datetime"].dt.date

    df = df.drop(columns=["datetime"])

    return df
