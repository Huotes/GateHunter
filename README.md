# GateHunter

GateHunter é uma ferramenta de escaneamento de portas e redes desenvolvida em Python. Ela permite escanear alvos individuais ou redes inteiras, descobrindo hosts ativos e gerando relatórios detalhados dos serviços disponíveis, incluindo vulnerabilidades conhecidas.

## Funcionalidades

- **Escaneamento de portas em um único IP ou domínio**.
- **Descoberta de hosts ativos em uma rede**.
- **Escaneamento de portas em todos os hosts ativos de uma rede**.
- **Descoberta automática da rede local**.
- **Geração de relatórios em formato JSON**.
- **(Experimental) Suporte a múltiplos idiomas - (Português, Inglês e Espanhol)**.

## Pré-requisitos

- **Python 3.11** ou superior.
- **Sistema operacional Linux**.
- **Permissões de superusuário** (necessárias para algumas funcionalidades de rede).
- **Pacotes e bibliotecas Python**:
  - `scapy`
  - `netifaces`
  - `pymongo`
  - `psycopg2-binary`
  - `PyQt5`
  - `requests`
  - `nmap`

## Instalação

1. **Clone o repositório:**

   ```bash
   git clone https://github.com/huotes/GateHunter.git
   cd GateHunter
2. **Crie um ambiente virtual:**

   ```bash
    python3.11 -m venv venv
3. **Ative o ambiente virtual:**

   ```bash
    source venv/bin/activate
4. **Atualize o pip:**

   ```bash
    pip install --upgrade pip
5. **Instale as dependências:**

   ```bash
    pip install -r requirements.txt
6. Configure a Chave de API da NVD:

Para habilitar a funcionalidade de análise de vulnerabilidades, é necessário obter uma chave de API da NVD (National Vulnerability Database).

- Obtenha uma Chave de API:

   - Registre-se no site da NVD para obter uma chave de API: NVD API Registration

- Defina a Chave de API como Variável de Ambiente:

   ```bash
   export NVD_API_KEY='SUA_CHAVE_DE_API'
   ```

**Nota:** Substitua 'SUA_CHAVE_DE_API' pela sua chave de API real. Mantenha sua chave de API segura e não a compartilhe publicamente.

- Persistência da Variável de Ambiente (Opcional):

   - Para que a variável de ambiente seja carregada automaticamente em novas sessões, adicione o comando export ao seu arquivo ~/.bashrc ou ~/.bash_profile.
## Uso

**Nota:** 
Algumas funcionalidades requerem permissões elevadas. Execute o script com 
sudo para garantir que todas as operações funcionem corretamente.

   ```bash
    sudo -E env "PATH=$PATH" venv/bin/python3.11 gatehunter.py
   ```

O uso do -E env "PATH=$PATH" preserva as variáveis de ambiente, incluindo a NVD_API_KEY, ao usar o sudo.

## Escaneando um Alvo Único

1. Escolha a opção 1 no menu principal para escanear um único IP ou domínio.

2. Digite o endereço IP ou domínio do alvo.

3. Escolha se deseja usar as portas comuns automaticamente ou especificar portas.

4. Selecione o tipo de escaneamento:
   - 1. TCP
   - 2. UDP
   - 3. TCP e UDP

O GateHunter realizará o escaneamento e gerará um relatório, incluindo quaisquer vulnerabilidades conhecidas para os serviços detectados.

## Escaneando uma Rede

1. Escolha a opção 2 ou 3 no menu principal para escanear uma rede.
2. Siga as instruções para descobrir hosts ativos e realizar escaneamentos nos mesmos.

## Relatórios
- Os relatórios são gerados no diretório reports/ em formato JSON.
- Cada relatório inclui informações detalhadas sobre as portas escaneadas, serviços identificados e vulnerabilidades conhecidas.
