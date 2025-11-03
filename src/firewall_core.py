class FirewallSimulator:
    """
    Simulador de firewall para filtragem de pacotes baseada em regras
    """
    
    def __init__(self, default_policy="ALLOW"):
        self.rules = []
        self.default_policy = default_policy.upper()
    
    def load_rules(self, filename):
        """
        Carrega regras de arquivo de configuração
        Args:
            filename (str): Caminho do arquivo de regras
        """
        try:
            # Tenta abrir com utf-8, se falhar tenta com latin-1 (mais compatível)
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                with open(filename, 'r', encoding='latin-1') as f:
                    lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                # Ignora linhas vazias e comentários
                if not line or line.startswith('#'):
                    continue
                try:
                    self.add_rule(line)
                except ValueError as e:
                    raise ValueError(f"Erro na linha {line_num}: {e}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Arquivo de regras não encontrado: {filename}")
        except ValueError:
            # Propaga ValueError sem modificação
            raise
        except Exception as e:
            raise Exception(f"Erro ao carregar regras: {e}")
    
    def add_rule(self, rule_string):
        """
        Adiciona uma regra a partir de string
        Args:
            rule_string (str): Regra no formato 'ACTION TIPO VALOR'
                              Exemplos: 'BLOCK IP 192.168.1.100', 'ALLOW PORT 80'
        """
        rule = self._parse_rule(rule_string)
        self.rules.append(rule)
    
    def evaluate_packet(self, src_ip, dst_port, protocol="TCP"):
        """
        Avalia um pacote contra todas as regras
        Args:
            src_ip (str): IP de origem
            dst_port (int): Porta de destino
            protocol (str): Protocolo (TCP/UDP)
        Returns:
            str: "ALLOW" ou "BLOCK"
        """
        packet = {
            'src_ip': src_ip,
            'dst_port': dst_port,
            'protocol': protocol.upper()
        }
        
        # Avalia regras na ordem (primeira correspondência decide)
        for rule in self.rules:
            if self._matches_rule(packet, rule):
                return rule['action']
        
        # Se nenhuma regra corresponde, usa política padrão
        return self.default_policy
    
    def _parse_rule(self, rule_string):
        """
        Interpreta string de regra e converte para objeto
        Args:
            rule_string (str): Regra no formato 'ACTION TIPO VALOR'
        Returns:
            dict: Regra parseada com campos 'action', 'type', 'value'
        """
        parts = rule_string.split()
        if len(parts) < 3:
            raise ValueError(f"Regra inválida: '{rule_string}'. Formato esperado: ACTION TIPO VALOR")
        
        action = parts[0].upper()
        rule_type = parts[1].upper()
        value = ' '.join(parts[2:])  # Permite valores com espaços (ex: IP ranges)
        
        if action not in ['ALLOW', 'BLOCK']:
            raise ValueError(f"Ação inválida: '{action}'. Deve ser ALLOW ou BLOCK")
        
        if rule_type not in ['IP', 'PORT']:
            raise ValueError(f"Tipo de regra inválido: '{rule_type}'. Deve ser IP ou PORT")
        
        # Validação de IP básica
        if rule_type == 'IP':
            self._validate_ip(value)
        
        # Validação de porta
        if rule_type == 'PORT':
            try:
                port = int(value)
                if port < 0 or port > 65535:
                    raise ValueError(f"Porta inválida: {port}. Deve estar entre 0 e 65535")
            except ValueError:
                raise ValueError(f"Porta inválida: '{value}'. Deve ser um número")
        
        return {
            'action': action,
            'type': rule_type,
            'value': value
        }
    
    def _validate_ip(self, ip_string):
        """
        Valida formato básico de IP
        Args:
            ip_string (str): String de IP a validar
        """
        parts = ip_string.split('.')
        if len(parts) != 4:
            raise ValueError(f"IP inválido: '{ip_string}'. Formato esperado: x.x.x.x")
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    raise ValueError(f"IP inválido: '{ip_string}'. Cada octeto deve estar entre 0 e 255")
            except ValueError:
                raise ValueError(f"IP inválido: '{ip_string}'. Octetos devem ser números")
    
    def _matches_rule(self, packet, rule):
        """
        Verifica se pacote corresponde à regra
        Args:
            packet (dict): Pacote com campos 'src_ip', 'dst_port', 'protocol'
            rule (dict): Regra com campos 'action', 'type', 'value'
        Returns:
            bool: True se o pacote corresponde à regra
        """
        if rule['type'] == 'IP':
            return packet['src_ip'] == rule['value']
        elif rule['type'] == 'PORT':
            return packet['dst_port'] == int(rule['value'])
        return False
    
    def list_rules(self):
        """
        Lista todas as regras carregadas
        """
        if not self.rules:
            print("[INFO] Nenhuma regra carregada.")
            return
        
        print(f"\n[INFO] Regras carregadas (total: {len(self.rules)}):")
        print("=" * 60)
        for idx, rule in enumerate(self.rules, 1):
            print(f"{idx:3d}. {rule['action']:6s} {rule['type']:6s} {rule['value']}")
        print("=" * 60)
        print(f"Politica padrao: {self.default_policy}")