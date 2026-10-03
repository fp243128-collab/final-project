# DevsecopsAiSecurityAuditTool Crew

Welcome to the DevsecopsAiSecurityAuditTool Crew project, powered by [crewAI](https://crewai.com). This template is designed to help you set up a multi-agent AI system with ease, leveraging the powerful and flexible framework provided by crewAI. Our goal is to enable your agents to collaborate effectively on complex tasks, maximizing their collective intelligence and capabilities.

## Installation

Ensure you have Python >=3.10 <3.14 installed on your system. This project uses [UV](https://docs.astral.sh/uv/) for dependency management and package handling, offering a seamless setup and execution experience.

First, if you haven't already, install uv:

```bash
pip install uv
```

Next, navigate to your project directory and install the dependencies:

(Optional) Lock the dependencies and install them by using the CLI command:
```bash
crewai install
```
### Customizing

**Add your `OPENAI_API_KEY` into the `.env` file**

- Modify `src/devsecops_ai_security_audit_tool/config/agents.yaml` to define your agents
- Modify `src/devsecops_ai_security_audit_tool/config/tasks.yaml` to define your tasks
- Modify `src/devsecops_ai_security_audit_tool/crew.py` to add your own logic, tools and specific args
- Modify `src/devsecops_ai_security_audit_tool/main.py` to add custom inputs for your agents and tasks

## Frontend workspace

The project includes a Streamlit control room for launching authorized assessments and reviewing the generated markdown report.

Install dependencies and start the UI from the project root:

```bash
uv sync
uv run streamlit run src/devsecops_ai_security_audit_tool/ui.py
```

Add your `OPENAI_API_KEY` and any tool credentials to `.env` before launching an assessment. The UI requires an explicit authorization confirmation because several configured tools make active requests to the target.

The sidebar lets you choose the AI provider. Use `gemini` with `GEMINI_API_KEY`, `grok` with `XAI_API_KEY`, or `openai` with `OPENAI_API_KEY`. See `.env.example` for the complete configuration shape.

For an easy one-command start, run the included launcher from the project root:

```bash
./run_dashboard.sh
```

It starts the dashboard in the background, uses Grok by default, avoids duplicate processes, and reports the local URL. Set `AI_PROVIDER=gemini` before running if you want Gemini instead.

## Running the Project

To kickstart your crew of AI agents and begin task execution, run this from the root folder of your project:

```bash
$ crewai run
```

This command initializes the devsecops_ai_security_audit_tool Crew, assembling the agents and assigning them tasks as defined in your configuration.

This example, unmodified, will run the create a `report.md` file with the output of a research on LLMs in the root folder.

## Understanding Your Crew

The devsecops_ai_security_audit_tool Crew is composed of multiple AI agents, each with unique roles, goals, and tools. These agents collaborate on a series of tasks, defined in `config/tasks.yaml`, leveraging their collective skills to achieve complex objectives. The `config/agents.yaml` file outlines the capabilities and configurations of each agent in your crew.

## Support

For support, questions, or feedback regarding the DevsecopsAiSecurityAuditTool Crew or crewAI.
- Visit our [documentation](https://docs.crewai.com)
- Reach out to us through our [GitHub repository](https://github.com/joaomdmoura/crewai)
- [Join our Discord](https://discord.com/invite/X4JWnZnxPb)
- [Chat with our docs](https://chatg.pt/DWjSBZn)

Let's create wonders together with the power and simplicity of crewAI.
