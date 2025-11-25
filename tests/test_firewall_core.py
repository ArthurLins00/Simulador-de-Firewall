"""
Testes unitários para o módulo firewall_core
"""

import unittest
import os
import tempfile
from src.firewall_core import FirewallSimulator


class TestFirewallSimulator(unittest.TestCase):
    """Testes para a classe FirewallSimulator"""
    
    def setUp(self):
        """Configuração inicial para cada teste"""
        self.firewall = FirewallSimulator()
    
    def test_init_default_policy(self):
        """Testa inicialização com política padrão"""
        fw = FirewallSimulator()
        self.assertEqual(fw.default_policy, "ALLOW")
        self.assertEqual(len(fw.rules), 0)
        
        fw = FirewallSimulator("BLOCK")
        self.assertEqual(fw.default_policy, "BLOCK")
    
    def test_add_rule_ip_allow(self):
        """Testa adicionar regra de IP ALLOW"""
        self.firewall.add_rule("ALLOW IP 192.168.1.100")
        self.assertEqual(len(self.firewall.rules), 1)
        rule = self.firewall.rules[0]
        self.assertEqual(rule['action'], 'ALLOW')
        self.assertEqual(rule['type'], 'IP')
        self.assertEqual(rule['value'], '192.168.1.100')
    
    def test_add_rule_ip_block(self):
        """Testa adicionar regra de IP BLOCK"""
        self.firewall.add_rule("BLOCK IP 10.0.0.1")
        rule = self.firewall.rules[0]
        self.assertEqual(rule['action'], 'BLOCK')
        self.assertEqual(rule['type'], 'IP')
        self.assertEqual(rule['value'], '10.0.0.1')
    
    def test_add_rule_port_allow(self):
        """Testa adicionar regra de porta ALLOW"""
        self.firewall.add_rule("ALLOW PORT 80")
        rule = self.firewall.rules[0]
        self.assertEqual(rule['action'], 'ALLOW')
        self.assertEqual(rule['type'], 'PORT')
        self.assertEqual(rule['value'], '80')
    
    def test_add_rule_port_block(self):
        """Testa adicionar regra de porta BLOCK"""
        self.firewall.add_rule("BLOCK PORT 443")
        rule = self.firewall.rules[0]
        self.assertEqual(rule['action'], 'BLOCK')
        self.assertEqual(rule['type'], 'PORT')
        self.assertEqual(rule['value'], '443')
    
    def test_add_rule_case_insensitive(self):
        """Testa que regras são case-insensitive"""
        self.firewall.add_rule("allow ip 192.168.1.1")
        self.firewall.add_rule("block port 80")
        self.assertEqual(self.firewall.rules[0]['action'], 'ALLOW')
        self.assertEqual(self.firewall.rules[1]['action'], 'BLOCK')
    
    def test_parse_rule_invalid_format(self):
        """Testa erro ao parsear regra com formato inválido"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW")
        
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW IP")
    
    def test_parse_rule_invalid_action(self):
        """Testa erro ao parsear regra com ação inválida"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("DENY IP 192.168.1.1")
    
    def test_parse_rule_invalid_type(self):
        """Testa erro ao parsear regra com tipo inválido"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW PROTOCOL TCP")
    
    def test_validate_ip_invalid_format(self):
        """Testa validação de IP com formato inválido"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW IP 192.168.1")
        
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW IP 192.168.1.1.1")
    
    def test_validate_ip_invalid_octets(self):
        """Testa validação de IP com octetos inválidos"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW IP 256.1.1.1")
        
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW IP 192.168.1.abc")
    
    def test_validate_port_invalid_range(self):
        """Testa validação de porta com range inválido"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW PORT 65536")
        
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW PORT -1")
    
    def test_validate_port_invalid_type(self):
        """Testa validação de porta com tipo inválido"""
        with self.assertRaises(ValueError):
            self.firewall.add_rule("ALLOW PORT abc")
    
    def test_evaluate_packet_default_policy(self):
        """Testa avaliação de pacote sem regras (usa política padrão)"""
        result = self.firewall.evaluate_packet("192.168.1.100", 80)
        self.assertEqual(result, "ALLOW")
        
        fw_block = FirewallSimulator("BLOCK")
        result = fw_block.evaluate_packet("192.168.1.100", 80)
        self.assertEqual(result, "BLOCK")
    
    def test_evaluate_packet_ip_match_allow(self):
        """Testa avaliação de pacote que corresponde a regra IP ALLOW"""
        self.firewall.add_rule("ALLOW IP 192.168.1.100")
        result = self.firewall.evaluate_packet("192.168.1.100", 80)
        self.assertEqual(result, "ALLOW")
    
    def test_evaluate_packet_ip_match_block(self):
        """Testa avaliação de pacote que corresponde a regra IP BLOCK"""
        self.firewall.add_rule("BLOCK IP 192.168.1.100")
        result = self.firewall.evaluate_packet("192.168.1.100", 80)
        self.assertEqual(result, "BLOCK")
    
    def test_evaluate_packet_ip_no_match(self):
        """Testa avaliação de pacote que não corresponde a regra IP"""
        self.firewall.add_rule("BLOCK IP 192.168.1.100")
        result = self.firewall.evaluate_packet("192.168.1.200", 80)
        self.assertEqual(result, "ALLOW")
    
    def test_evaluate_packet_port_match_allow(self):
        """Testa avaliação de pacote que corresponde a regra PORT ALLOW"""
        self.firewall.add_rule("ALLOW PORT 80")
        result = self.firewall.evaluate_packet("192.168.1.100", 80)
        self.assertEqual(result, "ALLOW")
    
    def test_evaluate_packet_port_match_block(self):
        """Testa avaliação de pacote que corresponde a regra PORT BLOCK"""
        self.firewall.add_rule("BLOCK PORT 443")
        result = self.firewall.evaluate_packet("192.168.1.100", 443)
        self.assertEqual(result, "BLOCK")
    
    def test_evaluate_packet_port_no_match(self):
        """Testa avaliação de pacote que não corresponde a regra PORT"""
        self.firewall.add_rule("BLOCK PORT 80")
        result = self.firewall.evaluate_packet("192.168.1.100", 443)
        self.assertEqual(result, "ALLOW")
    
    def test_evaluate_packet_multiple_rules_first_match(self):
        """Testa que primeira regra correspondente decide"""
        self.firewall.add_rule("ALLOW IP 192.168.1.100")
        self.firewall.add_rule("BLOCK PORT 80")
        result = self.firewall.evaluate_packet("192.168.1.100", 80)
        self.assertEqual(result, "ALLOW")
    
    def test_evaluate_packet_protocol_parameter(self):
        """Testa que protocolo é aceito como parâmetro"""
        result = self.firewall.evaluate_packet("192.168.1.100", 80, "TCP")
        self.assertEqual(result, "ALLOW")
        
        result = self.firewall.evaluate_packet("192.168.1.100", 80, "UDP")
        self.assertEqual(result, "ALLOW")
    
    def test_load_rules_from_file(self):
        """Testa carregar regras de arquivo"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("ALLOW IP 192.168.1.100\n")
            f.write("BLOCK PORT 80\n")
            f.write("# Este é um comentário\n")
            f.write("ALLOW PORT 443\n")
            temp_file = f.name
        
        try:
            fw = FirewallSimulator()
            fw.load_rules(temp_file)
            self.assertEqual(len(fw.rules), 3)
            self.assertEqual(fw.rules[0]['action'], 'ALLOW')
            self.assertEqual(fw.rules[0]['type'], 'IP')
            self.assertEqual(fw.rules[1]['action'], 'BLOCK')
            self.assertEqual(fw.rules[1]['type'], 'PORT')
        finally:
            os.unlink(temp_file)
    
    def test_load_rules_file_not_found(self):
        """Testa erro ao carregar arquivo inexistente"""
        with self.assertRaises(FileNotFoundError):
            self.firewall.load_rules("arquivo_inexistente.txt")
    
    def test_load_rules_invalid_rule_in_file(self):
        """Testa erro ao carregar arquivo com regra inválida"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("ALLOW IP 192.168.1.100\n")
            f.write("INVALID RULE\n")
            temp_file = f.name
        
        try:
            with self.assertRaises(ValueError):
                self.firewall.load_rules(temp_file)
        finally:
            os.unlink(temp_file)
    
    def test_matches_rule_ip(self):
        """Testa método _matches_rule para IP"""
        rule = {'action': 'BLOCK', 'type': 'IP', 'value': '192.168.1.100'}
        packet = {'src_ip': '192.168.1.100', 'dst_port': 80, 'protocol': 'TCP'}
        self.assertTrue(self.firewall._matches_rule(packet, rule))
        
        packet = {'src_ip': '192.168.1.200', 'dst_port': 80, 'protocol': 'TCP'}
        self.assertFalse(self.firewall._matches_rule(packet, rule))
    
    def test_matches_rule_port(self):
        """Testa método _matches_rule para PORT"""
        rule = {'action': 'BLOCK', 'type': 'PORT', 'value': '80'}
        packet = {'src_ip': '192.168.1.100', 'dst_port': 80, 'protocol': 'TCP'}
        self.assertTrue(self.firewall._matches_rule(packet, rule))
        
        packet = {'src_ip': '192.168.1.100', 'dst_port': 443, 'protocol': 'TCP'}
        self.assertFalse(self.firewall._matches_rule(packet, rule))


if __name__ == '__main__':
    unittest.main()

