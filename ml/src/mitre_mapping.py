"""
MITRE ATT&CK Stage Mapping Ontology for Network Traffic Anomaly Detection.
Maps open-source flow and packet dataset attack labels (e.g. CIC-IDS-2018, CIC-IoT-2023)
to canonical MITRE ATT&CK tactical phases.
"""

from typing import Dict, Tuple

# Canonical MITRE ATT&CK Tactical Stages
STAGE_BENIGN = 0
STAGE_RECONNAISSANCE = 1
STAGE_INITIAL_ACCESS = 2
STAGE_INFILTRATION_LATERAL = 3
STAGE_COMMAND_AND_CONTROL = 4
STAGE_EXFILTRATION_IMPACT = 5

NUM_STAGES = 6

STAGE_NAMES: Dict[int, str] = {
    STAGE_BENIGN: "Benign",
    STAGE_RECONNAISSANCE: "Reconnaissance",
    STAGE_INITIAL_ACCESS: "Initial Access",
    STAGE_INFILTRATION_LATERAL: "Infiltration / Lateral Movement",
    STAGE_COMMAND_AND_CONTROL: "Command & Control",
    STAGE_EXFILTRATION_IMPACT: "Exfiltration / Impact",
}

STAGE_DESCRIPTIONS: Dict[int, str] = {
    STAGE_BENIGN: "Normal baseline network operations.",
    STAGE_RECONNAISSANCE: "Active network probing, port scans, host discovery (T1046, T1595).",
    STAGE_INITIAL_ACCESS: "Brute-force credential attempts, web exploit injection (T1110, T1190).",
    STAGE_INFILTRATION_LATERAL: "Payload execution, internal pivoting, service exploitation (T1210, T1021).",
    STAGE_COMMAND_AND_CONTROL: "External botnet beaconing, command channel establishment (T1071, T1573).",
    STAGE_EXFILTRATION_IMPACT: "High-volume data transfer or denial of service disruption (T1048, T1499).",
}

# Mapping dataset specific label string to (is_attack: bool, stage_id: int)
LABEL_MAPPING: Dict[str, Tuple[bool, int]] = {
    # Benign
    "benign": (False, STAGE_BENIGN),
    
    # Infiltration / Lateral Movement (CIC-IDS-2018 Thursday-01-03)
    "infilteration": (True, STAGE_INFILTRATION_LATERAL),
    "infiltration": (True, STAGE_INFILTRATION_LATERAL),
    
    # Command and Control / Botnet (CIC-IDS-2018 Friday-02-03)
    "bot": (True, STAGE_COMMAND_AND_CONTROL),
    "backdoor_malware": (True, STAGE_COMMAND_AND_CONTROL),
    "mirai-greeth_flood": (True, STAGE_COMMAND_AND_CONTROL),
    "mirai-greip_flood": (True, STAGE_COMMAND_AND_CONTROL),
    "mirai-udpplain": (True, STAGE_COMMAND_AND_CONTROL),
    
    # Initial Access / Brute Force (CIC-IDS-2018 Wednesday-14-02, Friday-23-02)
    "ftp-bruteforce": (True, STAGE_INITIAL_ACCESS),
    "ssh-bruteforce": (True, STAGE_INITIAL_ACCESS),
    "brute force -web": (True, STAGE_INITIAL_ACCESS),
    "brute force -xss": (True, STAGE_INITIAL_ACCESS),
    "sql injection": (True, STAGE_INITIAL_ACCESS),
    "sqlinjection": (True, STAGE_INITIAL_ACCESS),
    "commandinjection": (True, STAGE_INITIAL_ACCESS),
    "dictionarybruteforce": (True, STAGE_INITIAL_ACCESS),
    
    # Reconnaissance (CIC-IoT-2023)
    "recon-portscan": (True, STAGE_RECONNAISSANCE),
    "recon-osscan": (True, STAGE_RECONNAISSANCE),
    "recon-pingsweep": (True, STAGE_RECONNAISSANCE),
    "recon-hostdiscovery": (True, STAGE_RECONNAISSANCE),
    "vulnerabilityscan": (True, STAGE_RECONNAISSANCE),
    "dns_spoofing": (True, STAGE_RECONNAISSANCE),
    
    # Exfiltration / Impact / DoS
    "dos attacks-goldeneye": (True, STAGE_EXFILTRATION_IMPACT),
    "dos attacks-slowloris": (True, STAGE_EXFILTRATION_IMPACT),
    "dos attacks-slowhttptest": (True, STAGE_EXFILTRATION_IMPACT),
    "dos attacks-hulk": (True, STAGE_EXFILTRATION_IMPACT),
    "ddos attacks-loic-http": (True, STAGE_EXFILTRATION_IMPACT),
    "ddos attack-loic-udp": (True, STAGE_EXFILTRATION_IMPACT),
    "ddos attack-hoic": (True, STAGE_EXFILTRATION_IMPACT),
    "uploading_attack": (True, STAGE_EXFILTRATION_IMPACT),
}


def map_label_to_mitre(label: str) -> Tuple[bool, int, str]:
    """
    Given a raw dataset label string, return:
    (is_attack: bool, stage_id: int, stage_name: str)
    """
    clean = str(label).strip().lower()
    if clean in LABEL_MAPPING:
        is_attack, stage_id = LABEL_MAPPING[clean]
        return is_attack, stage_id, STAGE_NAMES[stage_id]
    
    # Substring heuristics
    if "infilt" in clean:
        return True, STAGE_INFILTRATION_LATERAL, STAGE_NAMES[STAGE_INFILTRATION_LATERAL]
    if "bot" in clean:
        return True, STAGE_COMMAND_AND_CONTROL, STAGE_NAMES[STAGE_COMMAND_AND_CONTROL]
    if "brute" in clean or "injection" in clean:
        return True, STAGE_INITIAL_ACCESS, STAGE_NAMES[STAGE_INITIAL_ACCESS]
    if "recon" in clean or "scan" in clean:
        return True, STAGE_RECONNAISSANCE, STAGE_NAMES[STAGE_RECONNAISSANCE]
    if "dos" in clean or "flood" in clean or "exfilt" in clean:
        return True, STAGE_EXFILTRATION_IMPACT, STAGE_NAMES[STAGE_EXFILTRATION_IMPACT]
    
    return False, STAGE_BENIGN, STAGE_NAMES[STAGE_BENIGN]
