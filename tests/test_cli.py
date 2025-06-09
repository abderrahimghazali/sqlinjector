"""
Tests for CLI interface
"""

import pytest
import json
from click.testing import CliRunner

from sqlinjector.cli import main


class TestCLI:
    
    def setup_method(self):
        """Setup test method"""
        self.runner = CliRunner()
    
    def test_version(self):
        """Test version command"""
        result = self.runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert '1.0.0' in result.output
    
    def test_help(self):
        """Test help command"""
        result = self.runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'SQLInjector' in result.output
    
    def test_disclaimer_command(self):
        """Test disclaimer command"""
        result = self.runner.invoke(main, ['disclaimer'])
        assert result.exit_code == 0
        assert 'LEGAL AND ETHICAL USE ONLY' in result.output
    
    def test_payloads_command(self):
        """Test payloads command"""
        result = self.runner.invoke(main, ['payloads'])
        assert result.exit_code == 0
        assert 'Payload Statistics' in result.output
    
    def test_payloads_by_type(self):
        """Test payloads command with specific type"""
        result = self.runner.invoke(main, ['payloads', '--type', 'boolean_blind', '--limit', '3'])
        assert result.exit_code == 0
        assert 'BOOLEAN_BLIND' in result.output
    
    def test_init_command(self, temp_dir):
        """Test init command"""
        output_file = f"{temp_dir}/config.yaml"
        result = self.runner.invoke(main, ['init', '--output', output_file])
        
        assert result.exit_code == 0
        assert 'created' in result.output
        
        import os
        assert os.path.exists(output_file)
    
    def test_scan_command_help(self):
        """Test scan command help"""
        result = self.runner.invoke(main, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'Scan a URL' in result.output
    
    def test_test_command_help(self):
        """Test test command help"""
        result = self.runner.invoke(main, ['test', '--help'])
        assert result.exit_code == 0
        assert 'Test a specific payload' in result.output