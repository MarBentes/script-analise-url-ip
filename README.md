# Script de Análise de URLs e IPs

### Descrição

Este script, criado por Marcelo Bentes, é projetado para analisar URLs e endereços IP usando múltiplas APIs. Ele verifica a reputação, status de segurança e geolocalização das URLs ou IPs fornecidos. Os resultados são exibidos no console e salvos em um arquivo .xlsx para revisão posterior.

### Funcionalidades

- **Validação de URLs e IPs**: Valida se a entrada é uma URL ou um endereço IP.
- **Análise de Reputação e Segurança**: Utiliza as APIs URLScan e VirusTotal para verificar a reputação e o status de segurança de URLs e IPs.
- **Informações de Geolocalização**: Recupera informações de geolocalização usando a API do IPInfo.
- **Indicadores de Ameaça**: Coleta e exibe indicadores de ameaça do URLScan.
- **Exportação para .xlsx**: Salva os resultados da análise em um arquivo "resultados_analise.xlsx" para revisão e manutenção de registros.

### APIs Utilizadas

- **URLScan**: Para escanear URLs e recuperar análises detalhadas.
- **VirusTotal**: Para verificar a reputação e potenciais ameaças associadas a URLs e IPs.
- **IPInfo**: Para recuperar informações de geolocalização e detalhes de contato de abuso de IPs.

### Pré-requisitos

- Python 3.x
- Biblioteca `requests`: Você pode instalá-la usando `pip install requests`.
- Biblioteca `pandas openpyxl`: Você pode instalá-la usando `pip install pandas openpyxl`

### Como Usar

1. **Clonar o Repositório**:
   
   git clone https://github.com/seuusuario/script-analise-url-ip.git
   cd script-analise-url-ip
   
2. Instalar as Bibliotecas Requeridas:

   pip install requests
   pip install pandas openpyxl

4. Substituir as Chaves de API:

   Abra o arquivo do script e substitua as chaves de API pelos seus valores reais:

  URLSCAN_API_KEY = 'sua-chave-urlscan'
  VIRUSTOTAL_API_KEY = 'sua-chave-virustotal'
  IPINFO_API_KEY = 'sua-chave-ipinfo'


### Exemplo de Saída

Digite a URL ou IP que você deseja analisar: http://example.com

### Script criado por Marcelo Bentes ###

* Análise iniciada.
* ID da análise: 1929a9fa-cfe8-447b-85fb-101f6665c643
Resultados ainda não disponíveis. Tentando novamente em 5 segundos...
Resultados ainda não disponíveis. Tentando novamente em 5 segundos...

---- Scan Results (URLScan) ----
* URL: http://example.com
* IP: 93.184.216.34
* Status: 200
* Título: Example Domain
* Domínio: example.com
* Servidor: ECS (dca/37DD)
* Tipo MIME: text/html
* Geolocalização: Mountain View, United States (Org: Google LLC, Coordenadas: 37.751, -97.822)
* Hostname: 93.184.216.34
* Contato de Abuso: abuse@example.com
* ASN: ASN não encontrado
* Organizações: Organização não encontrada
* País: País não encontrado
* Indicadores de Ameaças: Nenhum

---- Vereditos ----
* URLScan: Não Malicioso (Score: 0)
* VirusTotal: Positivos: 0/70

---- Results ----
* Detecções:
  - Nenhuma detecção encontrada.
--------------------

Resultados salvos em resultados_analise.xlsx

### Notas
Certifique-se de ter chaves de API válidas para URLScan, VirusTotal e IPInfo.
O script lida com limites de taxa de API e tenta novamente até 10 vezes para obter os resultados.
Contribuições
Sinta-se à vontade para fazer fork deste repositório e enviar pull requests. Para grandes mudanças, abra uma issue primeiro para discutir o que você gostaria de mudar.

### Licença
Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para mais detalhes.

