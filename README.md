# 🔥 Firewall Simulator

Este é um **simulador de firewall** que simula como um firewall real funciona em uma rede. Ele permite que você defina regras de segurança e depois teste se pacotes de rede (representados por IP de origem e porta de destino) seriam **permitidos** ou **bloqueados** pelo firewall.

## 🚀 Como usar

### 1. Ver demonstração completa
Execute o script de demonstração que mostra vários cenários:
```powershell
python demonstracao.py
```

Este script mostra:
- ✅ Pacotes sendo permitidos
- ❌ Pacotes sendo bloqueados
- 📊 Estatísticas dos testes
- 💡 Explicações de cada cenário

### 2. Modo interativo (teste seus próprios pacotes)
```powershell
python main.py --rules regras_exemplo.txt --interactive
```

Depois digite pacotes no formato `IP:PORTA`:
```
>> Digite pacote (IP:PORTA): 192.168.1.100:80
[OK] Resultado: BLOCK

>> Digite pacote (IP:PORTA): 192.168.1.200:443
[OK] Resultado: ALLOW
```

### 3. Testar um pacote específico
```powershell
python main.py --rules regras_exemplo.txt --src-ip 192.168.1.100 --dst-port 80
```

Saída:
```
[RESUMO]
   Pacote: 192.168.1.100 -> :80/TCP
   Decisao: BLOCK
```

### 4. Listar todas as regras
```powershell
python main.py --rules regras_exemplo.txt --list-rules
```

## 📋 Funcionalidades

- Simulação de firewall
- Regras customizáveis
- Interface linha de comando
- Modo interativo

## 🔒 Arquivo de regras

Crie um arquivo de texto com suas regras (ex: `regras_exemplo.txt`):

```
# Comentários começam com #
BLOCK IP 192.168.1.100
ALLOW PORT 80
ALLOW PORT 443
BLOCK PORT 23
```

## 📁 Estrutura do projeto

```
Projetos Redes/
├── main.py                    # Ponto de entrada
├── demonstracao.py            # Script de demonstração
├── regras_exemplo.txt         # Arquivo de regras de exemplo
├── run_tests.py              # Script para executar testes
├── src/
│   ├── firewall_core.py       # Lógica principal do firewall
│   └── cli_interface.py      # Interface de linha de comando
└── tests/
    └── test_firewall_core.py # Testes unitários
```

## Executar testes

```powershell
python run_tests.py
```

Ou veja o guia completo em `README_TESTES.md`.

## 🛠️ Requisitos
- Python 3.8+

## 🧑‍💻 Integrantes

- [Arthur Borba Lins](https://github.com/ArthurLins00)
- [João Vitor da Silva](https://github.com/jvs360)
- [Michelangelo Morais do Rego](https://github.com/Mickeeyym)
- [Paulo Henrique A. de Barros](https://github.com/phabp)