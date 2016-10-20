[![License](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000?style=flat-square)]()

# Sniffer Remoto para Monitorar Histórico de Navegação Web

## Objetivo

O objetivo geral do trabalho é desenvolver uma aplicação usando sockets para monitorar o
histórico de navegação Web de computadores alvo usando um ataque do tipo DHCP Spoofing
com man-in-the-middle. Os objetivos específicos incluem:

 - compreender de maneira prática o mecanismo de comunicação por sockets;
 - entender o funcionamento do protocolos da camada camada de aplicação (DHCP, DNS e HTTP) 
 e seus problemas de segurança em redes locais.
 
## Descrição 

 Utilizando um programa sniffer (analisador de pacotes) é possível monitorar todo o tráfego
de rede de um host e analisar seu conteúdo. Por exemplo, inspecionando pacotes dos
protocolos DNS e HTTP é possível obter todo o histórico de navegação Web de um host. No
entanto, isso normalmente necessita acesso físico a esse host. Uma forma de realizar essa
monitoração remotamente em outros hosts de uma rede local é utilizando um ataque do tipo
man-in-the-middle, explorando falhas de seguranças típicas de redes locais. Nesse trabalho,
usaremos um ataque do tipo DHCP spoofing para interceptar o tráfego de rede e monitorar o
histórico de navegação Web realizado por cada host atacado. A implementação desse
trabalho pode ser dividida em duas partes bem definidas:
 - Implementação de DHCP spoofing com man-in-the-middle (ANEXO I);
 - Monitoração do histórico de navegação Web dos hosts atacados (ANEXO II).

Tudo deve ser documentado na forma de um relatório. Este relatório deve primeiramente
descrever o funcionamento do protocolo DHCP e descrever como foi explorado o problema
de segurança usando digramas, trechos de códigos e/ou capturas de tela (sugestão: utilize
capturas de telas do Wireshark para facilitar a explicação). O relatório também deve descrever
como foram extraídas as informações necessárias para geração do histórico de navegação dos
hosts. Esse relatório deverá ser entregue juntamente com o código fonte utilizado.

O trabalho deve ser implementado na linguagem C. Exemplos utilizando sockets UDP/TCP e
sockets raw, bem como o uso de threads, foram disponibilizados no Moodle.

# Anexo I

## Ataque DHCP Spoofing

Ataques do tipo DHCP spoofing consistem basicamente em implementar um servidor DHCP
simplificado que seja capaz de responder requisições de clientes antes do servidor principal
da rede, informando endereços (IP do host, IP do gateway padrão e IP do servidor DNS)
forjados. Ambos os servidores irão responder as requisições, mas, por normalmente estar
mais próximo da vítima e possuir uma implementação mais simples, a resposta do atacante
tende a chegar primeiro garantindo o sucesso da técnica. O ataque é descrito em mais
detalhes nos diagramas a seguir, considerando um host atacante A e um host vítima D.

**Passo 1:** um host D que precisa de um endereço IP (por exemplo, durante a inicialização do
sistema) envia uma mensagem via broadcast (DHCP Discover) para descobrir o endereço do
servidor DHCP. Assim que o servidor DHCP responder (DHCP Offer), o host cliente irá enviar
uma mensagem a esse servidor requisitando um novo endereço IP (DHCP Request).

![passo1](https://cloud.githubusercontent.com/assets/6035873/19576889/a3bba92a-96f3-11e6-9baa-bf415c936cd1.png)

**Passo 2:** um host atacante A tenta responder a requisição enviada pelo host D antes do
servidor DHCP principal da rede.

![passo2](https://cloud.githubusercontent.com/assets/6035873/19576890/a3dd92b0-96f3-11e6-8355-4595d901a864.png)

**Passo 3:** em caso de sucesso, o host atacante A torna-se o servidor DHCP responsável por
atribuir endereços ao host vítima D (DHCP Ack).

![passo3](https://cloud.githubusercontent.com/assets/6035873/19576891/a3e572be-96f3-11e6-87df-02c9e43a953a.png)

Os endereços atribuídos ao host D podem, por exemplo, configurar o gateway padrão para
apontar para o host atacante, permitindo a implementação de um ataque do tipo man-in-the-
middle. Após esses passos, toda a comunição do host D com a Internet irá passar pelo host
atacante.

Obs: o protocolo DHCP tem alguns detalhes de funcionamento que precisam ser
estudados/entendidos para que essa técnica seja mais efetiva. Uma atenção especial deve ser
dada aos campos "Option" desse protocolo. Para um melhor entendimento do funcionamento
do protocolo, recomenda-se a realização de alguns experimentos em laboratório utilizando
Wireshark para monitorar as mensagens DHCP trocadas entre cliente e servidor e a análise do
seus conteúdos.

## Encaminhamento de pacotes

Por padrão, o Linux descarta pacotes que são destinados a outros hosts. Desta forma, para
implementar um ataque do tipo man-in-the-middle, é necessário habilitar a funcionalidade de
encaminhamento de pacotes do kernel do Linux (IP Forwarding). Isso fará com que o tráfego
entre o host alvo e o roteador não seja interrompido durante o ataque.
Para habilitar a funcionalidade de IP Forwarding, execute o seguinte comando no Linux:

```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
```
# ANEXO II

## Monitoração do Histórico de Navegação Web das Vítimas

Uma vez que um ataque do tipo man-in-the-middle foi realizado com sucesso, toda
comunicação realizada entre a vítima e a Internet irá passar pelo host atacante. Desta forma,
é possível implementar um programa sniffer utilizando sockets raw que analisa as resquisições
DNS e HTTP e gera um arquivo contendo o histórico de navegação Web dos hosts alvo.
O arquivo de saída deve estar no formato HTML e cada entrada do histórico deve conter as
seguintes informações:
 - data e hora do acesso;
 - endereço IP do host;
 - nome do host;
 - URL completa do endereço Web acessado (caso o endereço utilize HTTPS, fornecer
apenas o nome do domínio).

Um exemplo de arquivo de saida é fornecido a seguir.

```html
<html>
  <header>
    <title>Histórico de Navegação</title>
  </header>
  <body>
    <ul>
      <li>12/10/2016 22:24 - 192.168.25.21 (MBP-de-Marcelo) - <a href="https://site.com"></a>site</li>
      <li>12/10/2016 22:30 - 192.168.25.103 (Marcelo-PC) - <a href="http://site2.com">site2</a></li>
    </ul>
  </body>
</html>
```

Obs: para obter todas as informações necessárias para gerar um histórico de monitoração
como o demonstrado acima, será necessário combinar informações extraídas de pacotes DNS
e HTTP. Note que apesar de simples, essa tarefa não é trivial! Recomenda-se um estudo
detalhado desses protocolos e a realização de experimentos em laboratório utilizando
Wireshark para monitorar o conteúdo dos pacotes desses protocolos. Também será
necessário filtrar as requisições para não poluir o arquivo gerado. Por exemplo, o acesso a
uma página Web pode gerar centenas de requisicões HTTP adicionais para obter todos os
objetos ligados à página, tais como arquivos de imagens, folhas de estilo (CSS), java scripts,
etc. O nome do host alvo pode ser obtido de mais de uma forma. Uma sugestão é a extração
dessa informação dos campos "Option” de mensagens DHCP.
