import os

from dotenv import load_dotenv

from crewai import LLM
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import (
	ScrapeWebsiteTool,
	ExaSearchTool,
	URLReadTool
)
from devsecops_ai_security_audit_tool.tools.dns_ip_recon_tool import DnsIpReconTool
from devsecops_ai_security_audit_tool.tools.shodan_port_service_lookup import ShodanPortServiceLookupTool
from devsecops_ai_security_audit_tool.tools.http_security_headers_inspector import HttpSecurityHeadersInspectorTool
from devsecops_ai_security_audit_tool.tools.cookie_security_analyzer import CookieSecurityAnalyzerTool
from devsecops_ai_security_audit_tool.tools.ssl_tls_certificate_inspector import SslTlsCertificateInspectorTool
from devsecops_ai_security_audit_tool.tools.sql_injection_vulnerability_tester import SqlInjectionVulnerabilityTesterTool
from devsecops_ai_security_audit_tool.tools.authentication_security_tester import AuthenticationSecurityTesterTool
from devsecops_ai_security_audit_tool.tools.deep_endpoint_directory_discovery_tool import DeepEndpointDirectoryDiscoveryTool
from devsecops_ai_security_audit_tool.tools.metadata_information_disclosure_extractor import MetadataInformationDisclosureExtractorTool
from devsecops_ai_security_audit_tool.tools.rate_limiting_dos_resilience_tester import RateLimitingDoSResilienceTesterTool

load_dotenv()


MODEL_CONFIG = {
    "gemini": ("gemini/gemini-3.8-flash", "GEMINI_API_KEY"),
    "grok": ("xai/grok-3-mini", "XAI_API_KEY"),
    "openai": ("openai/gpt-4o-mini", "OPENAI_API_KEY"),
}




@CrewBase
class DevsecopsAiSecurityAuditToolCrew:
    """DevsecopsAiSecurityAuditTool crew"""

    progress_sink = None

    def _llm(self) -> LLM:
        provider = os.getenv("AI_PROVIDER", "gemini").lower()
        if provider not in MODEL_CONFIG:
            supported = ", ".join(MODEL_CONFIG)
            raise ValueError(f"Unsupported AI_PROVIDER '{provider}'. Use: {supported}.")

        model, key_name = MODEL_CONFIG[provider]
        if not os.getenv(key_name):
            raise RuntimeError(f"{key_name} is missing from .env for the {provider} provider.")
        return LLM(model=model)

    def _task_callback(self, task_output):
        if self.progress_sink:
            self.progress_sink(task_output)
        return task_output

    def stage_crew(self, stage_index: int, prior_reports: list[str] | None = None) -> Crew:
        """Build a crew containing only one audit stage for guided runs."""
        full_crew = self.crew()
        selected_task = full_crew.tasks[stage_index]
        selected_task.context = []
        if prior_reports:
            selected_task.description = (
                f"Previous completed stage reports:\n\n{chr(10).join(prior_reports)}\n\n"
                f"Continue with this stage for {{target}}:\n{selected_task.description}"
            )
        return Crew(
            agents=[selected_task.agent],
            tasks=[selected_task],
            process=Process.sequential,
            verbose=True,
            chat_llm=self._llm(),
            task_callback=self._task_callback,
        )

    
    @agent
    def security_audit_report_generator(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["security_audit_report_generator"],
            
            
            tools=[],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=self._llm(),
            
        )
        
    
    @agent
    def target_reconnaissance_agent(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["target_reconnaissance_agent"],
            
            
            tools=[				DnsIpReconTool(),
				ShodanPortServiceLookupTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=self._llm(),
            
        )
        
    
    @agent
    def web_application_security_inspector(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["web_application_security_inspector"],
            
            
            tools=[				HttpSecurityHeadersInspectorTool(),
				CookieSecurityAnalyzerTool(),
				SslTlsCertificateInspectorTool(),
				ScrapeWebsiteTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=20,
            max_rpm=None,
            
            
            max_execution_time=300,
            llm=self._llm(),
            
        )
        
    
    @agent
    def vulnerability_analyst(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["vulnerability_analyst"],
            
            
            tools=[				ExaSearchTool(),
				URLReadTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=20,
            max_rpm=None,
            
            
            max_execution_time=300,
            llm=self._llm(),
            
        )
        
    
    @agent
    def sql_injection_and_input_vulnerability_tester(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["sql_injection_and_input_vulnerability_tester"],
            
            
            tools=[				SqlInjectionVulnerabilityTesterTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=self._llm(),
            
        )
        
    
    @agent
    def authentication_and_session_security_tester(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["authentication_and_session_security_tester"],
            
            
            tools=[				AuthenticationSecurityTesterTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=self._llm(),
            
        )
        
    
    @agent
    def deep_endpoint_discovery_and_metadata_analyst(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["deep_endpoint_discovery_and_metadata_analyst"],
            
            
            tools=[				DeepEndpointDirectoryDiscoveryTool(),
				MetadataInformationDisclosureExtractorTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=self._llm(),
            
        )
        
    
    @agent
    def dos_resilience_and_http_attack_tester(self) -> Agent:
        
        
        return Agent(
            config=self.agents_config["dos_resilience_and_http_attack_tester"],
            
            
            tools=[				RateLimitingDoSResilienceTesterTool()],
            
            reasoning=False,
            max_reasoning_attempts=None,
            inject_date=True,
            allow_delegation=False,
            max_iter=25,
            max_rpm=None,
            
            
            max_execution_time=None,
            llm=self._llm(),
            
        )
        
    

    
    @task
    def dns_and_network_reconnaissance(self) -> Task:
        return Task(
            config=self.tasks_config["dns_and_network_reconnaissance"],
            markdown=False,
            
            
        )
    
    @task
    def web_application_security_inspection(self) -> Task:
        return Task(
            config=self.tasks_config["web_application_security_inspection"],
            markdown=False,
            
            
        )
    
    @task
    def deep_endpoint_discovery_and_metadata_extraction(self) -> Task:
        return Task(
            config=self.tasks_config["deep_endpoint_discovery_and_metadata_extraction"],
            markdown=False,
            
            
        )
    
    @task
    def dos_resilience_and_http_attack_testing(self) -> Task:
        return Task(
            config=self.tasks_config["dos_resilience_and_http_attack_testing"],
            markdown=False,
            
            
        )
    
    @task
    def sql_injection_and_input_vulnerability_testing(self) -> Task:
        return Task(
            config=self.tasks_config["sql_injection_and_input_vulnerability_testing"],
            markdown=False,
            
            
        )
    
    @task
    def authentication_and_session_security_testing(self) -> Task:
        return Task(
            config=self.tasks_config["authentication_and_session_security_testing"],
            markdown=False,
            
            
        )
    
    @task
    def vulnerability_analysis_and_cve_research(self) -> Task:
        return Task(
            config=self.tasks_config["vulnerability_analysis_and_cve_research"],
            markdown=False,
            
            
        )
    
    @task
    def generate_full_security_audit_report(self) -> Task:
        return Task(
            config=self.tasks_config["generate_full_security_audit_report"],
            markdown=False,
            
            
        )
    

    @crew
    def crew(self) -> Crew:
        """Creates the DevsecopsAiSecurityAuditTool crew"""

        return Crew(
            agents=self.agents,  # Automatically created by the @agent decorator
            tasks=self.tasks,  # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True,

            chat_llm=self._llm(),
            task_callback=self._task_callback,
        )


