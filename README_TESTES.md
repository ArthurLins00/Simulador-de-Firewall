# Guia de Execução de Testes

Este documento explica como executar os testes unitários do projeto Firewall Simulator.

## Pré-requisitos

- Python 3.6 ou superior instalado
- O projeto deve estar na estrutura correta com os diretórios `src/` e `tests/`

## Método para Executar os Testes

No PowerShell, execute:

```powershell
$env:PYTHONPATH="C:\Users\Arthur\Desktop\Projetos Redes"
python tests/test_firewall_core.py
```

**Resultado esperado:**
```
...................
----------------------------------------------------------------------
Ran 27 tests in 0.027s

OK
```

## Entendendo a Saída dos Testes

### Teste bem-sucedido:
```
test_add_rule_ip_allow ... ok
```

### Teste que falhou:
```
test_exemplo ... FAIL

======================================================================
FAIL: test_exemplo (tests.test_firewall_core.TestFirewallSimulator)
----------------------------------------------------------------------
Traceback (most recent call last):
  ...
AssertionError: ...
```

### Erro durante o teste:
```
test_exemplo ... ERROR

======================================================================
ERROR: test_exemplo (tests.test_firewall_core.TestFirewallSimulator)
----------------------------------------------------------------------
Traceback (most recent call last):
  ...
```

## Resumo dos Testes Implementados

O arquivo `tests/test_firewall_core.py` contém 27 testes que verificam:

1. **Inicialização** - Política padrão e lista de regras vazia
2. **Adição de regras** - IP e porta (ALLOW e BLOCK)
3. **Validação** - Formato de regras, IPs e portas inválidos
4. **Avaliação de pacotes** - Correspondência com regras, política padrão
5. **Carregamento de arquivos** - Leitura de arquivo de regras
6. **Matching** - Verificação de correspondência IP e porta
