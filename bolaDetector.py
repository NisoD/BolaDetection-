import click
import json
from collections import defaultdict
from typing import Dict, List


def extract_auth_info(headers_str: str) -> str:
    """Extract authentication information from headers string."""
    try:
        # Handle different header formats
        if isinstance(headers_str, dict):
            return headers_str.get('Authorization', 'unknown')
        elif isinstance(headers_str, str):
            # Look for Authorization header in string format
            if 'Authorization' in headers_str:
                return headers_str.split('Authorization')[1].split(',')[0].strip()
        return 'unknown'
    except Exception:
        return 'unknown'


@click.command()
@click.argument('logfile', type=click.Path(exists=True))
def detect_bola(logfile):
    """Analyze JSON Lines log file for potential BOLA attacks."""
    logs = []
    with open(logfile) as f:
        for line in f:
            try:
                logs.append(json.loads(line.strip()))
            except json.JSONDecodeError as e:
                click.echo(f"Warning: Skipping invalid JSON line: {e}")
                continue

    # Track access patterns
    user_patterns: Dict[str, List[Dict]] = defaultdict(list)
    alerts = []

    sensitive_paths = {
        '/accounts': 'account',
        '/balance': 'balance'
    }

    for idx, entry in enumerate(logs):
        try:
            url = entry['req']['url']
            # Skip non-sensitive endpoints
            if not any(path in url for path in sensitive_paths):
                continue

            user_id = extract_auth_info(entry['req']['headers'])
            resource_type = next(
                (v for k, v in sensitive_paths.items() if k in url), '')
            params = entry['req'].get('qs_params', '')

            # Track access pattern
            user_patterns[user_id].append({
                'url': url,
                'params': params,
                'index': idx
            })

            # Analyze patterns for potential BOLA
            if len(user_patterns[user_id]) >= 3:
                last_3_accesses = user_patterns[user_id][-3:]
                unique_resources = len(
                    set(access['params'] for access in last_3_accesses))

                if unique_resources >= 3:
                    alerts.append({
                        'entry_index': idx,
                        'severity': 'HIGH',
                        'type': 'Potential BOLA Attack',
                        'description': f'Rapid access to multiple {resource_type} resources',
                        'evidence': f'User accessed {unique_resources} different resources in last 3 requests'
                    })

            # Check for 403 responses indicating attempted unauthorized access
            if entry['rsp']['status_class'].startswith('4'):
                alerts.append({
                    'entry_index': idx,
                    'severity': 'MEDIUM',
                    'type': 'Unauthorized Access Attempt',
                    'description': f'Failed authorization on {resource_type} endpoint',
                    'evidence': f'{entry["rsp"]["status_class"]} response on {url}'
                })
        except Exception as e:
            click.echo(f"Warning: Error processing entry {idx}: {str(e)}")
            continue

    # Output results
    if alerts:
        click.echo('🚨 Potential BOLA attacks detected:')
        for alert in alerts:
            click.echo(f"\nEntry #{alert['entry_index']}:")
            click.echo(f"Severity: {alert['severity']}")
            click.echo(f"Type: {alert['type']}")
            click.echo(f"Description: {alert['description']}")
            click.echo(f"Evidence: {alert['evidence']}")
        click.echo(f"\nTotal alerts: {len(alerts)}")
    else:
        click.echo('✅ No potential BOLA attacks detected')


if __name__ == '__main__':
    detect_bola()
