# NOC - Guardian | Observability & Proactivity System

O **NOC - Guardian** é um sistema de **Network Operations Center** Multi-Tenant de última geração. Ele utiliza uma arquitetura de "Inteligência Distribuída" para monitoramento proativo, eliminando as falhas de segurança e complexidade de ferramentas legadas.

> **REGRA DE OURO:** Todo arquivo gerado deve conter comentários detalhados explicando a função de cada bloco e cada linha de código para fins educacionais e de manutenção.

## 🏗️ Arquitetura de Inteligência Distribuída
O sistema opera em três camadas para garantir segurança máxima e carga mínima no servidor central:

1.  **Guardian Central (Cloud):** O cérebro do sistema. Gerencia o Dashboard Multi-Tenant, o banco de dados principal e a orquestração de IA para causa raiz.
2.  **Guardian NODE (Edge Proxy):** Um coletor inteligente instalado na rede local do cliente (suporta **Docker x86-64 e ARM6**). Ele realiza o scan SNMP local, centraliza os dados dos agentes e os envia via túnel seguro para a Central. Como instalar e configurar no cliente 
3.  **Guardian Agents:** Pequenos serviços instalados em servidores Windows/Linux que reportam telemetria diretamente ao NODE ou à Central.

## 🚀 Tecnologias Core
*   **Frontend:** React + Tailwind CSS (Interface reativa e intuitiva).
*   **Backend:** Python (FastAPI) + Ansible (Remediação e Proatividade).
*   **Banco de Dados:** PostgreSQL + TimeScaleDB (Séries temporais).
*   **Infraestrutura:** Docker Multi-Arch (Buildx para suporte a x86-64 e ARM6/Raspberry Pi).

## 🔒 NOC - Guardian NODE: Segurança e Operação
O NODE foi desenhado para ser "invisível" e inviolável:
*   **Outbound Only:** O NODE inicia todas as comunicações. Nenhuma porta de entrada (Inbound) precisa ser aberta no firewall do cliente.
*   **Zero Trust Tunnel:** Comunicação com a Central via **TLS 1.3** com certificados rotativos e **MTLS** (Mutual TLS) opcional.
*   **Data Scrubbing:** O NODE sanitiza e criptografa os dados locais com **AES-256** antes de despachá-los para a Central.
*   **Local Buffer:** Em caso de queda de internet no cliente, o NODE armazena os dados localmente e faz o "backfill" automaticamente quando a conexão retorna.

## 🛠️ Funcionalidades de "Linha de Frente"
*   **Network Scan Automático:** Varredura SNMP em tempo real para ativos (Switches, Roteadores, UniFi, Storages, Servidores Físicos, etc.).
*   **IA de Causa Raiz (RCA):** Motor de correlação que aponta o "paciente zero" de uma queda de rede.
*   **Diagnóstico Integrado:** Ferramentas de linha de comando acessíveis via interface web.

## 📂 Estrutura de Pastas
- `/central`: API Cloud e Dashboard Multi-Tenant.
- `/node`: Código do coletor inteligente (Proxy).
- `/agents`: Binários compilados para Windows/Linux/ARM.
- `/infra`: Scripts de Hardening e Dockerfiles Multi-Arch.

## 📦 Instalação e Configuração no Cliente (Guardian NODE)
A instalação no cliente é automatizada e baseada em Docker para facilitar o suporte.

## 🛡️ Hardening do Servidor/Node (Linux)
Procedimento obrigatório antes do deploy do Docker:
1.  **Fail2Ban & UFW:** Bloqueio de ataques de força bruta e fechamento total de portas desnecessárias.
2.  **SSH Hardening:** Acesso apenas via chave RSA/ED25519; login de root desabilitado.
3.  **Kernel Security:** Proteções contra ataques de rede (Spoofing, ICMP Redirects) via `sysctl` customizado.
4.  **Auto-Update:** Configuração de `unattended-upgrades` para patches de segurança do SO.


## 📊 Dashboards & Visualização (NOC UI)
O Dashboard é dividido em camadas de visibilidade para garantir que o administrador identifique gargalos em segundos:

### 1. Dashboard Principal (Visão Multi-Tenant)
*   **Grid de Cards:** Cada card representa um cliente com status de saúde (Verde/Amarelo/Vermelho).
*   **KPIs Globais:** Total de dispositivos monitorados, alertas críticos ativos e status dos links WAN principais de todos os clientes.

### 2. Dashboard do Cliente (Visão Detalhada)
*   **Medidores de Velocímetro (Gauge Charts):** Monitoramento em tempo real de latência (Ping) e consumo de largura de banda (Upload/Download) para cada ISP.
*   **Monitores de Rede WAN (ISP):** 
    *   Gráfico de estabilidade do link (Uptime/Downtime).
    *   Perda de pacotes e Jitter para monitorar a qualidade do link de internet.
*   **Monitores de Rede LAN:**
    *   **Tabelas de Ativos:** Lista dinâmica de switches, roteadores e antenas UniFi.
    *   **Mapa de Topologia:** Visualização gráfica de como os dispositivos estão conectados.
*   **Cards de Monitoramento/Alerta:**
    *   Logs de eventos recentes com cores por severidade.
    *   Status de saúde dos Agentes Windows/Linux (CPU, RAM, Disco).
*   **Bloco de Diagnóstico:** Ferramentas interativas (Ping/MTR) que exibem o resultado em um terminal simulado na tela.
