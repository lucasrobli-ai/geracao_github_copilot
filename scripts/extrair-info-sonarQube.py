import requests
import pandas as pd
import os
from dotenv import load_dotenv

load_dotenv()

SONAR_URL = "http://localhost:9000"

TOKENS = [
    os.getenv("TOKEN_EXPERIMENTO_1_Sonar"),
    os.getenv("TOKEN_EXPERIMENTO_2_Sonar"),
    os.getenv("TOKEN_EXPERIMENTO_3_Sonar"),
    os.getenv("TOKEN_EXPERIMENTO_4_Sonar"),
    os.getenv("TOKEN_EXPERIMENTO_5_Sonar")
]

EXPERIMENTOS = [
    {
        "nome": f"experimento-0{i+1}",
        "project_key": f"experimento0{i+1}",
        "token": TOKENS[i]
    }
    for i in range(5)
]

OUTPUT_FILE = os.getenv("RESULTADOS_PATH", "resultados") + "/resultado_sonarQube-experimentos.xlsx"

SEVERITY_MAP = {
    "INFO": "Baixa",
    "MINOR": "Baixa",
    "MAJOR": "Média",
    "CRITICAL": "Alta",
    "BLOCKER": "Crítica"
}

RULE_CWE_CACHE = {}

results = []
page_size = 500


def extract_llm_model(component):
    if not component:
        return "unknown"

    if ":" in component:
        component = component.split(":", 1)[1]

    component = component.replace("\\", "/")
    return component.split("/")[0]


def get_cwe_from_rule(rule_key, token):
    if rule_key in RULE_CWE_CACHE:
        return RULE_CWE_CACHE[rule_key]

    url = f"{SONAR_URL}/api/rules/show"
    params = {"key": rule_key}

    response = requests.get(url, params=params, auth=(token, ""))
    data = response.json()

    cwe_list = (
        data.get("rule", {})
            .get("securityStandards", {})
            .get("CWE", [])
    )

    cwe = ", ".join(cwe_list) if cwe_list else "N/A"
    RULE_CWE_CACHE[rule_key] = cwe

    return cwe


for exp in EXPERIMENTOS:
    print(f"🔍 Processando {exp['nome']}")

    page = 1

    while True:
        url = f"{SONAR_URL}/api/issues/search"
        params = {
            "componentKeys": exp["project_key"],
            "ps": page_size,
            "p": page
        }

        response = requests.get(url, params=params, auth=(exp["token"], ""))
        data = response.json()

        for issue in data.get("issues", []):
            rule = issue.get("rule")
            cwe = get_cwe_from_rule(rule, exp["token"])
            llm_model = extract_llm_model(issue.get("component"))

            results.append({
                "Ferramenta": "SonarQube",
                "Experimento": exp["nome"],
                "LLM_Model": llm_model,
                "Arquivo": issue.get("component"),
                "Linha": issue.get("line"),
                "CWE": cwe,
                "Vulnerabilidade": issue.get("message"),
                "Severidade": SEVERITY_MAP.get(
                    issue.get("severity"),
                    issue.get("severity")
                )
            })

        if page * page_size >= data.get("total", 0):
            break

        page += 1


df = pd.DataFrame(results)
df.to_excel(OUTPUT_FILE, index=False)

print(f"✅ Arquivo consolidado gerado: {OUTPUT_FILE}")
