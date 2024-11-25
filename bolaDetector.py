import click
import re
import json

class BOLADetector:
    def __init__(self):
        self.vulnerabilities = []

    def detect_bola_risks(self, code):
        """Detect potential BOLA vulnerabilities in the code"""
        # Check balance access method
        if self._check_balance_access_control(code):
            self.vulnerabilities.append("Potential BOLA in Balance Handling")

        # Check accounts handler
        if self._check_accounts_handler_authorization(code):
            self.vulnerabilities.append("Potential BOLA in Accounts Endpoint")

        return self.vulnerabilities

    def _check_balance_access_control(self, code):
        """Analyze balance access control method"""
        # Look for weak access control in balance operations
        balance_access_risks = [
            # Checking if user ID verification is weak
            "if !checkBalanceAccess(claims, userID)" in code,
            # Potential parameter manipulation risk
            "userIDStr := r.URL.Query().Get(\"user_id\")" in code
        ]
        return any(balance_access_risks)

    def _check_accounts_handler_authorization(self, code):
        """Check accounts handler for authorization vulnerabilities"""
        # Look for weak authorization checks
        accounts_auth_risks = [
            # Minimal role-based access control
            "if claims.Role != RoleAdmin" in code,
            # Direct user ID manipulation possibilities
            "input.UserID  int     `json:\"user_id\"`" in code
        ]
        return any(accounts_auth_risks)

@click.command()
@click.argument('filepath', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file for vulnerability report')
def detect_bola(filepath, output):
    """Detect Broken Object Level Authorization (BOLA) vulnerabilities"""
    with open(filepath, 'r') as file:
        code = file.read()

    detector = BOLADetector()
    vulnerabilities = detector.detect_bola_risks(code)

    if vulnerabilities:
        click.echo("BOLA Vulnerabilities Detected:")
        for vuln in vulnerabilities:
            click.echo(f"- {vuln}")
        
        if output:
            with open(output, 'w') as out_file:
                json.dump(vulnerabilities, out_file, indent=2)
    else:
        click.echo("No BOLA vulnerabilities detected.")

if __name__ == '__main__':
    detect_bola()