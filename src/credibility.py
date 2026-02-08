import re

def threat_label(row):
    threats = {"malware", "trojan", "attack", "malicious", "phish", "ransom"}

    ind_type = str(row.get("indicator_type", "")).lower()
    ent_type = str(row.get("entity_type", "")).lower()

    if ind_type in threats or ent_type in threats:
        return 1
    return 0

def credibility_score(row):

    if row["validation_flag"] != 1:
        return 0

    val_string = str(row.get("values", ""))
    val_arr = val_string.split(",")

    if len(val_arr) > 3:
        description = str(row.get("description", ""))

        if description:
            url_pattern = r'^https?://[^\s/$.?#].[^\s]*'

            if re.match(url_pattern, description):
                return 1

    return 0

def merge_values(row):

    return (
        str(row.get("indicator_type", "")).lower() +
        str(row.get("description", "")).lower() +
        str(row.get("values", "")).lower()
    )

def apply_credibility(df):

    df["Threat_Label"] = df.apply(threat_label, axis=1)

    df["Credibility_Score"] = df.apply(credibility_score, axis=1)

    df["Combined_Attribute"] = df.apply(merge_values, axis=1)

    combined_attribute_list = df["Combined_Attribute"].tolist()

    url_pattern = r'^https?://[^\s/$.?#].[^\s]*'

    combined_attribute_list_new = [
        ["URL_LINK" if re.match(url_pattern, word) else word
         for word in line.split()]
        for line in combined_attribute_list
    ]

    df["tokenized"] = combined_attribute_list_new

    return df
