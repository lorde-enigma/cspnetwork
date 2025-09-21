# MindVoices Test Suite

Esta pasta contém arquivos de teste desenvolvidos para validação e compatibilidade dos algoritmos de geração de IPv6.

## Arquivos Incluídos

### `test_cspnetwork_compatibility.cpp`

- Código fonte para teste de compatibilidade do cspnetwork
- Implementa validação com namespace seeded_vpn::infrastructure

### `test_cspnetwork_compatibility`

- Executável compilado do teste de compatibilidade
- Gera endereços IPv6 usando IPv6AddressManager

### `test_compatibility`

- Executável de teste de compatibilidade geral
- Valida algoritmos de geração determinística

### `test_reverse_engineer`

- Executável para engenharia reversa de seeds
- Testa diferentes abordagens de geração

### `test_seed_finder.cpp`

- Código fonte para busca de seeds
- Implementa algoritmos de busca e validação

### `test_seed_finder`

- Executável compilado do buscador de seeds
- Encontra seeds que geram endereços específicos

### `test_seeds`

- Executável de teste de múltiplas seeds
- Valida geração com diferentes valores de entrada

### `test_generator.o`

- Arquivo objeto compilado
- Resultado intermediário da compilação

## Propósito

Estes testes foram criados para garantir que o algoritmo de geração de IPv6 seja:

- Determinístico e estático
- Compatível entre sistemas cspnetwork e cipherproxy  
- Produz endereços idênticos para as mesmas sementes

## Uso

```bash
./test_cspnetwork_compatibility
./test_compatibility
./test_reverse_engineer
./test_seed_finder
./test_seeds
```

---

*Gerado como parte do desenvolvimento de compatibilidade entre sistemas*
