# Report builder skill
import sys
import json
from karasugakure.reports.dossier import DossierCompiler

if __name__ == "__main__":
    compiler = DossierCompiler(case_name="automated")
    # Stub nodes and edges
    nodes = [{"labels": ["Target"], "properties": {"value": "example.com", "source": "heimdall"}}]
    edges = [{"source_value": "operator", "relationship": "INVESTIGATED", "target_value": "example.com"}]
    report_path = compiler.compile_markdown_report(nodes, edges)
    print(f"Report compiled successfully at: {report_path}")
