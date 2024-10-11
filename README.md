# Gatehunter

Gatehunter é uma ferramenta de escaneamento de portas e redes desenvolvida em Python. Ela permite escanear alvos individuais ou redes inteiras, descobrindo hosts ativos e gerando relatórios detalhados dos serviços disponíveis.

## Funcionalidades

- **Escaneamento de portas em um único IP ou domínio**.
- **Descoberta de hosts ativos em uma rede**.
- **Escaneamento de portas em todos os hosts ativos de uma rede**.
- **Descoberta automática da rede local**.
- **Geração de relatórios em formato JSON**.
- **Exibição de arte ASCII personalizada ao iniciar**.

## Pré-requisitos

- **Python 3.11** ou superior.
- **Sistema operacional Linux**.
- **Permissões de superusuário** (necessárias para algumas funcionalidades de rede).
- **Pacotes e bibliotecas Python**:
  - `scapy`
  - `netifaces`

## Instalação

1. **Clone o repositório:**

   ```bash
   git clone https://github.com/huotes/Gatehunter.git
   cd Gatehunter

2. **Crie um ambiente virtual:**

    ```bash
    python3.11 -m venv venv

3. **Ative o ambiente virtual:**

    ```bash
    source venv/bin/activate

4. **Instale as dependências:**

    ```bash
    pip install -r requirements.txt

## Uso

Nota: Algumas funcionalidades requerem permissões elevadas. Execute o script com sudo para garantir que todas as operações funcionem corretamente.

    ```bash
    sudo venv/bin/python3.11 gatehunter.py



