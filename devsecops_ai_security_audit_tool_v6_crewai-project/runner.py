#!/usr/bin/env python3
import sys
import json
import os

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"status": "failed", "error": "No arguments provided"}))
        sys.exit(1)

    payload = json.loads(sys.argv[1])
    mode = payload.get("mode", "guided")
    target = payload.get("target", "")
    provider = payload.get("provider", "gemini")
    stage_index = payload.get("stage_index", 0)
    prior_reports = payload.get("prior_reports", [])

    os.environ["AI_PROVIDER"] = provider

    # Ensure local directory is in path
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_dir = os.path.join(project_dir, "src")
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    # Load local .env
    env_file = os.path.join(project_dir, ".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

    from devsecops_ai_security_audit_tool.crew import DevsecopsAiSecurityAuditToolCrew

    try:
        crew_inst = DevsecopsAiSecurityAuditToolCrew()
        if mode == "guided":
            crew_obj = crew_inst.stage_crew(stage_index, prior_reports)
            result = crew_obj.kickoff(inputs={"target": target})
            report = getattr(result, "raw", str(result))
            print(json.dumps({"status": "complete", "report": report}))
        else:
            crew_obj = crew_inst.crew()
            result = crew_obj.kickoff(inputs={"target": target})
            report = getattr(result, "raw", str(result))
            print(json.dumps({"status": "complete", "report": report}))
    except Exception as e:
        print(json.dumps({"status": "failed", "error": str(e)}))

if __name__ == "__main__":
    main()
