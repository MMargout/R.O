# Introdução

Há bastante incerteza aqui em relação à entrada na área ou tópico específico, então elaborei um breve "guia" para ajudar.

O foco estará em web hacking, que envolve a exploração de sites e assuntos relacionados. Assim, herdamos o conceito de hacking e o aplicamos ao escopo web, e a partir de agora, tudo estará dentro deste mesmo escopo.

Contém links e referências para auxiliar.

Neste guia foi:

30% do tempo = Escrevendo.

70% do tempo = Revisando linguagem, termos, definições… :P

Gostaria de receber um feedback sobre como este guia foi produzido. Se você gostou ou não, se achou a linguagem clara e direta. :)

Tópicos:

1 - Requisitos da área

1.1 Introdução

1.2 Desenvolvimento web

1.3 Redes

1.4 Terminais

2 - Vulnerabilidades

2.1 Introdução

2.2 Vulnerabilidades comuns

2.3 Classificação de vulnerabilidades

2.4 Fique por dentro!

2.5 Identificação de vulnerabilidades

2.6 Treinando

3 - Bug Bounty

3.1 Introdução

3.2 Como participar de programas de Bug Bounty?

## 1 - Quais são os requisitos para começar a estudar nesta área?

### 1.1 Introdução

Antes de tudo, é preciso ter determinação. É necessário saber buscar informações e ser independente nesse aspecto. Há muitas informações descentralizadas e a própria programação exige isso. Não é fácil, mas é assim que funciona. Não espere facilidades. Não leve o que eu disse como algo exato e não pare de procurar explicações por conta disso. Vá atrás.

### 1.2 Desenvolvimento WEB

É importante possuir um conhecimento sólido em programação e desenvolvimento web. Se você já trabalha como programador há algum tempo, não terá grandes dificuldades. Caso não tenha experiência, aqui estão algumas instruções para começar:

Tenha uma base sólida em HTML, CSS e Javascript, que são os fundamentos de um website comum. É essencial aprender a estrutura e padronização dessas linguagens para identificar possíveis vulnerabilidades. Além disso, é importante ter conhecimentos em servidores (Back-end), sendo o PHP e o ambiente Javascript NodeJS os mais populares, ter noções sobre SQL/NoSQL ajuda também.

### 1.3 Redes

Compreenda os conceitos de rede e protocolos de rede, sendo algumas das camadas mais importantes as seguintes (os números não correspondem ao modelo OSI):

1. Camada de transporte: TCP, UDP…
2. Camada de rede: IP (IPv4 e IPv6).
3. Camada de aplicação: HTTP (é importante compreender também o TLS (até mesmo suas cifras, mas aí é mais para outro fim)), FTP, SSH, DNS...

Segue abaixo alguns links sobre protocolos de rede:

[https://www.manageengine.com/network-monitoring/network-protocols.html](https://www.manageengine.com/network-monitoring/network-protocols.html)

[https://www.internetsociety.org/deploy360/tls/basics/](https://www.internetsociety.org/deploy360/tls/basics/)

[https://www.youtube.com/watch?v=hExRDVZHhig](https://www.youtube.com/watch?v=hExRDVZHhig)

[https://www.youtube.com/watch?v=E5bSumTAHZE](https://www.youtube.com/watch?v=E5bSumTAHZE)

[https://www.youtube.com/watch?v=5WfiTHiU4x8](https://www.youtube.com/watch?v=5WfiTHiU4x8)

### 1.4 Terminais

Terminais são fundamentais, uma vez que muitas ferramentas e utilitários de sistemas são específicos para eles (CLI). O ideal é focar em terminais Linux (que mais lhe agrada), pois além de terem uma documentação rica, inclusive por parte de terceiros, há uma enorme quantidade de ferramentas dedicadas. Eu particularmente acho mais fácil utilizá-los.

Algumas ferramentas úteis para este contexto são: nmap, cURL, wget e netcat..

Aprender o básico do Git, como clonar um repositório, é muito útil para obter ferramentas disponibilizadas por terceiros em plataformas como o Github ou Gitlab.

## 2 - Vulnerabilidades

### 2.1 Introdução

É claro que não é possível listar todas as vulnerabilidades encontradas nessas aplicações, entretanto, há algumas que são particularmente relevantes e que serão discutidas a seguir.

### 2.2 Vulnerabilidades comuns

Dentre as mais comuns, estão:

- SQL Injection: é uma vulnerabilidade muito comum em sistemas de gerenciamento de banco de dados. Essa falha permite que um atacante execute comandos SQL maliciosos no banco de dados da aplicação, o que pode resultar em uma série de problemas de segurança. Uma vez que o atacante tenha acesso ao banco de dados, ele pode visualizar, editar e excluir informações sensíveis, como senhas, dados financeiros, informações pessoais e muito mais.
- Cross-Site Scripting (XSS): é um tipo de ataque que se aproveita de vulnerabilidades em páginas da web para injetar códigos maliciosos. Esses códigos aão executados pelo navegador dos usuários que visitam a página comprometida, o que pode resultar em diversas ações indesejadas, como roubo de informações, instalação de malware ou redirecionamento do usuário para outras páginas. é possível obter acesso a dados sensíveis e informações privadas dos usuários. Em muitos casos, os ataques XSS são realizados por meio de técnicas de engenharia social, como o phishing, que visam enganar os usuários para que eles cliquem em links maliciosos ou forneçam informações confidenciais sem saber.
- Cross-Site Request Forgery (CSRF): é uma vulnerabilidade que pode ser explorada por um atacante mal-intencionado para enviar solicitações falsas a um site em nome do usuário autenticado. Essa vulnerabilidade permite que um invasor possa realizar ações indesejadas, tais como transferência de fundos, exclusão de informações ou realizar alterações em configurações de conta.
- Remote File Inclusion (RFI): é uma vulnerabilidade que permite que um atacante execute códigos remotos em um servidor web. Essa vulnerabilidade ocorre quando a aplicação web não valida corretamente as entradas do usuário, permitindo que um atacante inclua arquivos remotos em uma página da web. Isso pode permitir que o atacante execute códigos maliciosos no servidor, como comandos do sistema operacional ou scripts em linguagem de programação.
- Local File Inclusion (LFI): A diferença entre RFI e LFI é que a LFI permite que um atacante inclua arquivos locais (que já estão presentes) em uma página da web, enquanto a RFI permite que um invasor inclua arquivos remotos (por sua parte) em uma página da web.

### 2.3 Classificação de vulnerabilidades.

Existem muitos catálogos de vulnerabilidades e sistemas de classificação diferentes. Vou abordar os mais populares neste guia.

1 - Common Vulnerability Scoring System (CVSS): é MUITO utilizado para avaliar e classificar a gravidade de vulnerabilidades. Ele leva em consideração vários fatores, como o impacto potencial, o nível de acesso necessário para explorar a vulnerabilidade e a probabilidade de ocorrer um ataque. O CVSS fornece uma maneira consistente e objetiva de comunicar a gravidade de um problema de segurança, o que é importante para que as organizações priorizem sua resposta e aloquem recursos de acordo. Além disso, as pontuações do CVSS podem ser usadas para acompanhar a eficácia dos controles de segurança ao longo do tempo e comparar a gravidade relativa de vulnerabilidades em diferentes sistemas e ambientes.

2 - Common Weakness Enumeration (CWE): É um catálogo de vulnerabilidades de segurança comuns em software e hardware. A CWE fornece uma lista muito extensa de “fraquezas” que podem ocorrer em software, hardware e sistemas relacionados. Cada item da CWE descreve uma “fraqueza” específica, com informações detalhadas sobre sua natureza, impacto e maneiras de prevenir ou mitigar a vulnerabilidade.

3 - Common Vulnerabilities and Exposures (CVE): é um repositório de informações sobre vulnerabilidades e exposições de segurança cibernética conhecidas. Cada entrada do CVE inclui um identificador exclusivo, uma descrição da vulnerabilidade ou exposição e, pelo menos, uma referência pública para que os usuários possam aprender mais sobre o problema. O objetivo do CVE é tornar mais fácil compartilhar dados entre diferentes capacidades de vulnerabilidade (ferramentas, bancos de dados e serviços) com essa "enumeração comum". Ao fazer isso, ajuda a reduzir o custo e o esforço da gestão de segurança, É mais comum usar este termo para descrever vulnerabilidades específicas em aplicações e bibliotecas, em vez de abordar um conceito mais amplo e genérico.

CVSS e CWE são os mais utilizados por profissionais para descrever vulnerabilidades em um conceito mais amplo de descrição (CWE) e urgência (CVSS), como, por exemplo, um XSS (que, dependendo de seu potencial ou tipo, pode ser classificado como CVSS ~6.5 e CWE-79). Enquanto, CVE é usado para descrever vulnerabilidades específicas em protocolos e aplicações…

Segue abaixo alguns links sobre os citados:

[https://crashtest-security.com/common-weakness-enumeration/](https://crashtest-security.com/common-weakness-enumeration/)

[https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf](https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf)

[https://www.mend.io/resources/blog/cvss-v3-1/](https://www.mend.io/resources/blog/cvss-v3-1/)

[https://www.redhat.com/en/topics/security/what-is-cve](https://www.redhat.com/en/topics/security/what-is-cve)

[https://www.cve.org/About/Overview](https://www.cve.org/About/Overview)

### 2.4 Fique por dentro!

Mantenha-se atualizado, já que as informações surgem constantemente! Por exemplo, um novo recurso de Javascript pode resultar em uma maneira mais fácil de contornar filtros XSS (como o optional chaining ([https://www.hahwul.com/2020/06/19/bypassing-base-xss-protection-with-optional-chaining/](https://www.hahwul.com/2020/06/19/bypassing-base-xss-protection-with-optional-chaining/))), e isso é muito útil!

Muitas organizações divulgam anualmente as vulnerabilidades mais comuns daquele período, sendo algumas delas:

A OWASP, que lança anualmente a lista OWASP TOP TEN ([https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/))

O CWE, que lança anualmente o CWE TOP 25 ([https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html](https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html))

Sites de tecnologia também podem ser muito úteis para acompanhar, por exemplo:

[https://www.bleepingcomputer.com/](https://www.bleepingcomputer.com/)

### 2.5 Identificação de vulnerabilidades

Então, como é feita a identificação? Principalmente:

1- Análise de código manual: Uma das maneiras mais eficazes de identificar vulnerabilidades em um site é por meio da análise manual de seu código. Ao conhecer a estrutura ideal de um site, é possível identificar problemas em outras aplicações simplesmente analisando seu código. Por meio dessa metodologia é possível identificar, por exemplo, ataques de XSS e outros que possam estar presentes no site.

2- Análise de código automatizada ou outros softwares automáticos: pode ser uma boa para identificar alguns problemas, mas é importante lembrar que não é infalível. Embora possa identificar alguns problemas, há sempre a possibilidade de que algo seja deixado passar, especialmente em casos complexos ou incomuns. Por isso, é importante usar a análise automatizada como um complemento à revisão manual, e não como uma substituição. Além disso, a análise manual permite que você examine mais de perto o código e procure problemas que possam ser difíceis de detectar automaticamente.

Alguns exemplos: Acunetix, Nikto, Wapiti, Burp suite (Esse é muito útil kk, por conta das ferramentas que poupam trabalho…), OWASP ZAP…

3- Google Hacking: Às vezes, apenas usando buscadores, você consegue identificar algumas vulnerabilidades, como serviços, padrões e dados sensíveis. Especificamente, o Google é frequentemente usado para essa finalidade, e a técnica é chamada de "Google Hacking". Há até comunidades que ajudam a usar essa técnica de maneira mais eficiente e identificar serviços. ([https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database))

### 2.6 Treinando

Treinar é muito importante, além de ser divertido. Existem sites que oferecem um ambiente com "vulnerabilidades" para você praticar, conhecidos como "Capture The Flag (CTF)".

Alguns sites:

Hack The Box ([https://www.hackthebox.com/](https://www.hackthebox.com/))

Try Hack Me ([https://tryhackme.com/](https://tryhackme.com/))

Root-Me ([https://www.root-me.org/](https://www.root-me.org/))

PicoCTF ([https://picoctf.com/](https://picoctf.com/))

OverTheWire ([https://overthewire.org/wargames/](https://overthewire.org/wargames/))

e muito mais…

## 3 - Bug Bounty

### 3.1 Introdução

Esse tópico é de interesse de muitos, haha!

Afinal, o que é um programa de Bug bounty?

É um programa oferecido por empresas de tecnologia, no qual indivíduos são incentivados a encontrar e relatar falhas em seus sistemas ou softwares. Pesquisadores de segurança são recompensados financeiramente ou de outra forma por encontrar essas falhas e reportá-las para a empresa. Isso é benéfico tanto para a empresa quanto para os pesquisadores, pois a empresa pode corrigir as falhas antes que sejam exploradas por pessoas mal-intencionadas, e os pesquisadores podem ganhar dinheiro por seus esforços. Alguns programas de bug bounty são muito lucrativos e podem oferecer recompensas de milhares de dólares por falhas encontradas!

### 3.2 Como participar de programas de Bug Bounty?

Existem várias plataformas que conectam pesquisadores e empresas. É importante seguir as diretrizes estabelecidas tanto pela plataforma quanto pela empresa que você está pesquisando. Algumas das plataformas mais populares são:

Hackerone ([https://hackerone.com/](https://hackerone.com/)) (Muito popular e profissional)

OpenBugBounty ([https://www.openbugbounty.org/](https://www.openbugbounty.org/)) (Muito popular, mas mais aberta)

Intigriti ([https://www.intigriti.com](https://www.intigriti.com/))

YesWeHack ([https://www.yeswehack.com](https://www.yeswehack.com/))

### Fim

É isso! Poderia escrever mais, mas esse foi apenas um teste para avaliar algumas coisas, haha.
