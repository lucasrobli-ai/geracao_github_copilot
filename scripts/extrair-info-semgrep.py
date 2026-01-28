import json
import pandas as pd
import os

BASE_PATH = os.getenv("EXPERIMENTOS_BASE_PATH", "experimentos")
OUTPUT_FILE = os.getenv("RESULTADOS_PATH", "resultados") + "/resultado_semgrep-experimentos.xlsx"
NUM_EXPERIMENTOS = 5

SEVERITY_MAP = {
    "INFO": "Baixa",
    "LOW": "Baixa",
    "MEDIUM": "Média",
    "HIGH": "Alta",
    "CRITICAL": "Crítica",
    "WARNING": "Média"
}

results = []

for i in range(1, NUM_EXPERIMENTOS + 1):
    experimento = f"experimento-{i:02d}"
    input_file = os.path.join(BASE_PATH, experimento, "semgrep.json")

    if not os.path.exists(input_file):
        print(f"Arquivo não encontrado: {input_file}")
        continue

    with open(input_file, "r", encoding="utf-16") as f:
        data = json.load(f)

    for item in data.get("results", []):
        path = item.get("path", "")
        llm_model = path.split(os.sep)[0] if path else "unknown"
        line = item.get("start", {}).get("line", "")

        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})

        # CWE (pode ter mais de um)
        cwe_list = metadata.get("cwe", [])
        cwe = ", ".join(cwe_list) if cwe_list else "N/A"

        # Nome da vulnerabilidade
        vuln_name = metadata.get(
            "display-name",
            extra.get("message", "N/A")
        )

        # Severidade normalizada
        raw_severity = extra.get("severity", "INFO")
        severity = SEVERITY_MAP.get(raw_severity, raw_severity)

        results.append({
            "Ferramenta": "Semgrep",
            "Experimento": experimento,
            "LLM_Model": llm_model,
            "Arquivo": path,
            "Linha": line,
            "CWE": cwe,
            "Vulnerabilidade": vuln_name,
            "Severidade": severity
        })

df = pd.DataFrame(results)
df.to_excel(OUTPUT_FILE, index=False)

print(f"Arquivo gerado com sucesso: {OUTPUT_FILE}")
