# UDP Tunnel Implementation Tasklist

## ANÁLISE ARQUITETURAL

### Estado Atual (HTTP Proxy)
- **Servidor**: VPNRestServer - API REST HTTP na porta 8080
- **Cliente**: VPNClient - cria TUN interface local, conecta via HTTP
- **Comunicação**: TCP/HTTP request/response
- **Limitação**: Sem interface TUN no servidor, sem túnel UDP

### Estado Alvo (UDP Tunnel como OpenVPN)
- **Servidor**: UDP Tunnel Server com interface TUN 
- **Cliente**: UDP Tunnel Client com interface TUN
- **Comunicação**: UDP tunnel bidirecional
- **Funcionalidade**: Roteamento de pacotes através de túnel UDP

## TASKLIST DE IMPLEMENTAÇÃO

### 1. SERVIDOR UDP TUNNEL (CRÍTICO) ✅

#### 1.1 Nova Classe UDPTunnelServer ✅
**Arquivo**: `include/presentation/udp_tunnel_server.h`
```cpp
class UDPTunnelServer {
    // Socket UDP para cliente
    // Interface TUN do servidor  
    // Pool de endereços IP
    // Gerenciamento de clientes conectados
    // Roteamento de pacotes TUN <-> UDP
};
```

#### 1.2 Implementação UDPTunnelServer
**Arquivo**: `src/presentation/udp_tunnel_server.cpp`
- Socket UDP bind na porta configurada
- Criação de interface TUN no servidor (ex: cspvpn-server)
- Loop de recepção UDP de clientes
- Loop de leitura de pacotes da interface TUN
- Roteamento bidirecional: TUN -> UDP e UDP -> TUN
- Gerenciamento de sessões de clientes

#### 1.3 Configuração TUN do Servidor
- Interface TUN: `cspvpn-server` (ex: 10.8.0.1/24)
- Roteamento para subnet de clientes (ex: 10.8.0.0/24)
- IP forwarding habilitado
- iptables/netfilter para NAT se necessário

### 2. CLIENTE UDP TUNNEL (MODIFICAÇÃO)

#### 2.1 Nova Classe UDPTunnelClient  
**Arquivo**: `include/application/udp_tunnel_client.h`
```cpp
class UDPTunnelClient {
    // Socket UDP para servidor
    // Interface TUN do cliente
    // Autenticação e handshake
    // Roteamento de pacotes TUN <-> UDP
};
```

#### 2.2 Substituir VPNClientImpl
**Arquivo**: `src/application/vpn_client_simple_tun.cpp`
- Remover lógica HTTP/REST
- Implementar comunicação UDP com servidor
- Manter interface TUN do cliente
- Implementar protocolo de handshake UDP
- Roteamento: TUN -> UDP e UDP -> TUN

### 3. PROTOCOLO UDP TUNNEL

#### 3.1 Definir Estrutura de Pacotes
**Arquivo**: `include/protocol/udp_tunnel_protocol.h`
```cpp
struct TunnelPacket {
    uint32_t session_id;
    uint16_t packet_type;  // DATA, AUTH, KEEPALIVE, DISCONNECT
    uint16_t payload_size;
    uint8_t payload[];
};
```

#### 3.2 Tipos de Pacotes
- **AUTH**: Autenticação inicial do cliente
- **DATA**: Pacotes IP encapsulados
- **KEEPALIVE**: Manter conexão ativa
- **DISCONNECT**: Finalizar sessão

#### 3.3 Estados de Sessão
- **HANDSHAKE**: Autenticação em progresso
- **CONNECTED**: Túnel ativo, dados fluindo
- **DISCONNECTED**: Sessão terminada

### 4. MODIFICAÇÕES NO MAIN

#### 4.1 Alterar main.cpp
**Arquivo**: `src/main.cpp`
- Substituir VPNRestServer por UDPTunnelServer
- Manter parsing de argumentos (-p para porta UDP)
- Inicializar servidor UDP ao invés de HTTP

#### 4.2 Alterações no CMake
**Arquivo**: `CMakeLists.txt`
- Adicionar novos arquivos fonte UDP tunnel
- Manter dependências existentes

### 5. ROTEAMENTO E REDE

#### 5.1 Configuração de Rede no Servidor
- Habilitar IP forwarding: `echo 1 > /proc/sys/net/ipv4/ip_forward`
- Configurar iptables para NAT se necessário
- Atribuir IPs únicos para cada cliente conectado

#### 5.2 Pool de Endereços IP
**Arquivo**: `include/infrastructure/ip_pool.h`
```cpp
class IPPool {
    // Gerenciar range de IPs disponíveis (ex: 10.8.0.2-10.8.0.254)
    // Alocar IP para novo cliente
    // Liberar IP quando cliente desconecta
};
```

### 6. COMPATIBILIDADE E TESTES

#### 6.1 Manter Configuração .cspvpn
- Adicionar campo `proto udp` 
- Manter estrutura de configuração existente
- Suportar migração de config HTTP para UDP

#### 6.2 Scripts de Teste
**Arquivo**: `scripts/test_udp_tunnel.sh`
- Testar conectividade UDP tunnel
- Verificar roteamento de pacotes
- Teste de throughput e latência

### 7. SEQUÊNCIA DE IMPLEMENTAÇÃO

#### Fase 1: Estrutura Base
1. Criar UDPTunnelServer header e implementação básica
2. Modificar main.cpp para usar UDP server
3. Implementar socket UDP básico

#### Fase 2: TUN no Servidor  
1. Integrar TunInterface no servidor
2. Configurar interface TUN do servidor
3. Implementar roteamento básico

#### Fase 3: Protocolo UDP
1. Definir estrutura de pacotes tunnel
2. Implementar handshake de autenticação
3. Implementar encapsulamento de dados

#### Fase 4: Cliente UDP
1. Modificar VPNClient para UDP
2. Remover código HTTP/REST
3. Implementar cliente UDP tunnel

#### Fase 5: Roteamento Completo
1. Implementar roteamento bidirecional
2. Pool de IPs para clientes
3. Gerenciamento de sessões

#### Fase 6: Testes e Validação
1. Testes unitários de protocolo UDP
2. Testes de integração cliente-servidor
3. Testes de performance e estabilidade

## ARQUIVOS PRINCIPAIS A MODIFICAR

### Novos Arquivos
- `include/presentation/udp_tunnel_server.h`
- `src/presentation/udp_tunnel_server.cpp`
- `include/application/udp_tunnel_client.h`
- `include/protocol/udp_tunnel_protocol.h`
- `src/protocol/udp_tunnel_protocol.cpp`
- `include/infrastructure/ip_pool.h`
- `src/infrastructure/ip_pool.cpp`

### Arquivos Existentes a Modificar
- `src/main.cpp` - substituir HTTP por UDP server
- `src/application/vpn_client_simple_tun.cpp` - remover HTTP, implementar UDP
- `CMakeLists.txt` - adicionar novos arquivos
- `config/client.cspvpn` - adicionar suporte a proto udp

### Arquivos a Manter
- `src/infrastructure/tun_interface.cpp` - reutilizar para servidor
- `include/infrastructure/tun_interface.h` - reutilizar 
- Sistema de logging e configuração existente

## ESTIMATIVA DE COMPLEXIDADE

**Alta Complexidade**: Mudança arquitetural significativa
**Tempo Estimado**: 2-3 semanas de desenvolvimento
**Risco**: Compatibilidade com configurações existentes
**Benefício**: Túnel UDP real como OpenVPN com melhor performance

## VALIDAÇÃO FINAL

Após implementação, o sistema deverá:
1. ✅ Servidor cria interface TUN (ex: cspvpn-server 10.8.0.1/24)
2. ✅ Cliente conecta via UDP e cria TUN (ex: cspvpn0 10.8.0.2/24)  
3. ✅ Pacotes IP roteados através do túnel UDP
4. ✅ Tráfego bidirecional funcionando
5. ✅ Múltiplos clientes suportados
6. ✅ Performance superior ao HTTP proxy atual
