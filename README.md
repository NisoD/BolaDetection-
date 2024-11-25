# BOLA Attack Detection Tool

A Python-based CLI tool for detecting potential BOLA (Broken Object Level Authorization) attacks by analyzing API access logs.

## Overview

This tool analyzes JSON Lines formatted log files to detect potential BOLA attacks and unauthorized access attempts on sensitive endpoints (/accounts and /balance). It specifically looks for:

- Multiple rapid accesses to different resources by the same user (HIGH severity)
- Failed authorization attempts indicated by 4xx responses (MEDIUM severity)

## How it Works

The script processes each log entry and:
1. Tracks user access patterns to sensitive endpoints
2. Flags when a user accesses 3 different resources in quick succession
3. Identifies unauthorized access attempts through 4xx response codes
4. Generates detailed alerts for suspicious patterns


## **Example**
```bash
python bolaDetector.py access-2024-11-25.json 
```

