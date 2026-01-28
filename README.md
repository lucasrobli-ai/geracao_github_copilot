# Avaliando códigos gerados pelo GitHub Copilot

## Visão Geral

Este repositório contém experimentos para avaliar a qualidade e a segurança de códigos-fonte gerados por *Large Language Models* (LLMs), por meio do GitHub Copilot.

O objetivo principal é avaliar fragilidades, vulnerabilidades presentes em códigos gerados automaticamente, utilizando ferramentas de mercado e de código aberto como Semgrep e SonarQube.

## Objetivos do Projeto

- Avaliar a segurança de código gerado por diferentes LLMs
- Identificar vulnerabilidades mapeadas em CWEs
- Comparar resultados entre ferramentas SAST
- Analisar padrões recorrentes de falhas em código gerado automaticamente

## Estrutura dos Experimentos

Cada experimento segue, de forma geral, o seguinte fluxo:

- Geração de código por um LLM, por meio do GitHub Copilot
- Execução de ferramentas SAST sobre o código gerado
- Extração e normalização dos resultados (JSON/CSV)

### Classificação por

- Linha do erro
- Tipo de vulnerabilidade
- CWE associada
- Severidade (BAIXA, MÉDIA, ALTA, CRÍTICA)

### Modelos avaliados

- Claude Haiku 4.5
- GPT-4.0
- GPT-4.1
- GPT-5.1 Mini

## Ferramentas Utilizadas

### Semgrep
- Análise estática baseada em padrões
- Detecção rápida de vulnerabilidades e más práticas
- Suporte a múltiplas linguagens

### SonarQube

- Análise de qualidade e segurança
- Identificação de Bugs, Vulnerabilidades e Security Hotspots
- Classificação por severidade

## Como Executar os Experimentos

### Observação Importante

Este projeto não executa o Semgrep nem o SonarQube automaticamente via script. As análises devem ser realizadas manualmente, por meio das ferramentas oficiais, e os resultados gerados devem ser salvos nos diretórios esperados pelo projeto.

Ou seja, o fluxo correto é:

- Executar o Semgrep manualmente
- Executar o SonarQube manualmente

Apenas depois disso, executar os scripts Python para processar os resultados

### Executar Semgrep (manual)

- Execute o Semgrep diretamente via linha de comando para gerar o arquivo de resultados:
- semgrep --config=auto ./experimentos --json > resultados/semgrep.json
- Certifique-se de que o arquivo semgrep.json esteja disponível no diretório esperado pelo script.

### Executar SonarQube (manual)

A análise com o SonarQube deve ser realizada por meio do SonarScanner, utilizando um servidor SonarQube previamente configurado.

Após a execução do scanner, exporte ou extraia os resultados necessários (issues/vulnerabilidades) conforme o padrão adotado nos scripts deste projeto.

A execução do SonarQube não ocorre via comando dentro deste repositório, sendo necessária a configuração externa do servidor e do scanner.

## Estrutura do Repositório

```text
.
├── experimentos/
│   ├── experimento-01/
│   │   ├── modelo-claude/
│   │   ├── modelo-copilot/
│   │   └── modelo-chatgpt/
│   └── experimento-02/
│
├── scripts/
│   ├── extrair-info-semgrep.py
│   ├── extrair-info-sonarqube.py
│   └── normalizar-resultados.py
│
├── prompts/
│   ├── prompt-1.md
│   ├── prompt-2.md
|   ├── prompt-3.md
|   ├── promtp-4.md
│   └── prompt-5.md
|
├── resultados/
│   ├── resultado_semgrep.xlsx
│   └── resultado_sonarqube.xlsx
│
└── README.md
