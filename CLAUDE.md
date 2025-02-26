# macOS Security Compliance Project (mSCP) Documentation

## Build/Run Commands
- Generate baseline: `python3 scripts/generate_baseline.py -k <keyword>`
- Generate guidance: `python3 scripts/generate_guidance.py -b <baseline>`
- Generate mapping: `python3 scripts/generate_mapping.py -b <baseline>`
- Generate SCAP: `python3 scripts/generate_scap.py -b <baseline>`
- Run local report: `python3 scripts/util/mscp_local_report.py -p <plist_path> -o <output_path>`

## Code Style Guidelines
- Use PEP 8 styling for Python code
- Indent with 4 spaces (not tabs)
- Use descriptive variable names
- YAML files should include proper indentation and structure
- Follow existing patterns for rule definitions in YAML files
- When adding new rules, maintain consistent structure with existing ones
- Error handling: Use try/except blocks with specific exception types

## Repository Structure
- `/rules/`: Contains security rules organized by category
- `/baselines/`: Contains predefined security baseline configurations
- `/scripts/`: Contains Python tools for generating reports and guidance
- `/templates/`: Contains AsciiDoc templates for documentation