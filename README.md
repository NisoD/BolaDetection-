# **BOLA Detector**

This tool analyzes code files to detect potential **Broken Object Level Authorization (BOLA)** vulnerabilities. It checks for weak access control in balance operations and insufficient authorization in account handling endpoints.

## **How It Works**
- **Balance Handling Risks**: Identifies weak or missing access controls for balance operations.
- **Accounts Endpoint Risks**: Detects vulnerabilities like minimal role-based access control or user ID manipulation.

## **Usage**

1. **Install Requirements**  
   Make sure Python is installed on your system. Install the `click` library if not already installed:
   pip install click

2. **Run the Script**  
   To scan a code file for BOLA vulnerabilities, use the following command:
   python bolaDetector.py <path_to_code_file>

3. **Optional: Save Results**  
   To save the output to a JSON file, use the `--output` option:
   python bolaDetector.py <path_to_code_file> --output <output_file>

## **Example**
```bash
python bolaDetector.py access-2024-11-25.json --output vulnerabilities_report.json
```
## **Output**  
- If vulnerabilities are found, they are listed in the terminal and (optionally) saved to the specified output file.
- If no vulnerabilities are detected, a confirmation message is displayed.
